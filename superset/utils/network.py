# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
import ipaddress
import platform
import socket
import subprocess
from typing import Union

from flask import current_app

PORT_TIMEOUT = 5
PING_TIMEOUT = 5

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Default blocklist of IP ranges that should never be used as database hosts.
# Covers private, loopback, link-local, carrier-grade NAT, multicast,
# documentation/test, broadcast/reserved ranges (IPv4) plus their IPv6
# equivalents. The link-local range (169.254.0.0/16) also covers cloud
# metadata endpoints such as AWS IMDS and Azure IMDS.
DEFAULT_BLOCKED_IP_RANGES: list[str] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "100::/64",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]


def is_port_open(host: str, port: int) -> bool:
    """
    Test if a given port in a host is open.
    """
    # pylint: disable=invalid-name
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, _, _, _, sockaddr = res
        s = socket.socket(af, socket.SOCK_STREAM)
        try:
            s.settimeout(PORT_TIMEOUT)
            s.connect(sockaddr)
            s.shutdown(socket.SHUT_RDWR)
            return True
        except OSError as _:
            continue
        finally:
            s.close()
    return False


def is_hostname_valid(host: str) -> bool:
    """
    Test if a given hostname can be resolved.
    """
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False


def is_host_up(host: str) -> bool:
    """
    Ping a host to see if it's up.

    Note that if we don't get a response the host might still be up,
    since many firewalls block ICMP packets.
    """
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    try:
        output = subprocess.call(command, timeout=PING_TIMEOUT)  # noqa: S603
    except subprocess.TimeoutExpired:
        return False

    return output == 0


def _parse_blocked_networks(raw_ranges: list[str]) -> list[IPNetwork]:
    """
    Parse a list of CIDR strings into ipaddress network objects, ignoring
    any entries that fail to parse.
    """
    networks: list[IPNetwork] = []
    for cidr in raw_ranges:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except (TypeError, ValueError):
            continue
    return networks


def _get_blocked_networks() -> list[IPNetwork]:
    """
    Return the configured list of blocked IP networks.

    Reads ``BLOCKED_DB_HOST_RANGES`` from the Flask config when available,
    falling back to :data:`DEFAULT_BLOCKED_IP_RANGES` otherwise.
    """
    raw_ranges: list[str] = DEFAULT_BLOCKED_IP_RANGES
    try:
        configured = current_app.config.get(
            "BLOCKED_DB_HOST_RANGES", DEFAULT_BLOCKED_IP_RANGES
        )
        if configured is not None:
            raw_ranges = list(configured)
    except RuntimeError:
        # Outside of application context; fall back to defaults.
        pass
    return _parse_blocked_networks(raw_ranges)


def _resolve_addresses(host: str) -> list[IPAddress]:
    """
    Resolve ``host`` to a list of ``ipaddress`` objects.

    Accepts either an IP literal or a hostname. Returns an empty list when
    resolution fails.
    """
    addresses: list[IPAddress] = []
    try:
        addresses.append(ipaddress.ip_address(host))
        return addresses
    except ValueError:
        pass

    try:
        results = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []

    seen: set[str] = set()
    for res in results:
        sockaddr = res[4]
        if not sockaddr:
            continue
        raw_addr = sockaddr[0]
        if not isinstance(raw_addr, str):
            continue
        addr = raw_addr.split("%", 1)[0] if "%" in raw_addr else raw_addr
        if addr in seen:
            continue
        seen.add(addr)
        try:
            addresses.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return addresses


def is_address_blocked(host: str) -> bool:
    """
    Return ``True`` when ``host`` resolves to any address in the configured
    blocklist of IP ranges.

    This is used to prevent SSRF (Server-Side Request Forgery) against
    internal/private networks, loopback, link-local (including cloud
    metadata endpoints such as AWS/Azure IMDS), and other non-routable
    addresses when Superset validates or establishes database connections.

    Hosts that cannot be resolved are treated as not blocked; callers are
    expected to perform their own validity checks (see
    :func:`is_hostname_valid`).
    """
    if not host:
        return False
    blocked_networks = _get_blocked_networks()
    if not blocked_networks:
        return False
    for address in _resolve_addresses(host):
        for network in blocked_networks:
            if address.version != network.version:
                continue
            if address in network:
                return True
    return False
