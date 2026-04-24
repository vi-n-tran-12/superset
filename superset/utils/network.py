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
from ipaddress import IPv4Network, IPv6Network

from flask import current_app

PORT_TIMEOUT = 5
PING_TIMEOUT = 5

DEFAULT_BLOCKED_HOST_RANGES: list[IPv4Network | IPv6Network] = [
    IPv4Network("10.0.0.0/8"),
    IPv4Network("172.16.0.0/12"),
    IPv4Network("192.168.0.0/16"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("169.254.0.0/16"),
    IPv4Network("0.0.0.0/8"),
    IPv6Network("::1/128"),
    IPv6Network("fc00::/7"),
    IPv6Network("fe80::/10"),
    IPv6Network("::/128"),
]


def is_blocked_ip(ip_str: str) -> bool:
    """Check if an IP address falls within blocked network ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    blocked_ranges: list[IPv4Network | IPv6Network] = (
        current_app.config.get("BLOCKED_DB_HOST_RANGES") or DEFAULT_BLOCKED_HOST_RANGES
    )
    return any(addr in network for network in blocked_ranges)


def resolve_host_to_ips(host: str) -> list[str]:
    """Resolve a hostname to a list of IP address strings."""
    try:
        results = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    return list({str(result[4][0]) for result in results})


def is_host_safe(host: str) -> bool:
    """
    Check that a hostname does not resolve to any blocked IP ranges.

    Returns True if the host is safe to connect to.
    """
    ips = resolve_host_to_ips(host)
    if not ips:
        return True
    return not any(is_blocked_ip(ip) for ip in ips)


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
