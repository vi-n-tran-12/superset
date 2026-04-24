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
import socket
from typing import Any, Callable

import pytest
from pytest_mock import MockerFixture

from superset.utils import network


def _fake_getaddrinfo(
    addresses: list[str],
) -> Callable[..., list[tuple[int, int, int, str, tuple[str, int]]]]:
    def _inner(
        host: str, port: Any = None, *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:  # noqa: ARG001
        return [(socket.AF_INET, 0, 0, "", (addr, port or 0)) for addr in addresses]

    return _inner


@pytest.mark.parametrize(
    "host,resolved,expected",
    [
        # Loopback / link-local / private / cloud metadata.
        ("localhost", ["127.0.0.1"], True),
        ("metadata.local", ["169.254.169.254"], True),
        ("internal-db", ["10.0.0.5"], True),
        ("intranet.db", ["192.168.1.10"], True),
        ("corp.db", ["172.20.3.4"], True),
        ("broadcast.invalid", ["255.255.255.255"], True),
        ("multicast.invalid", ["224.0.0.1"], True),
        # Public IPv4 that should not be blocked.
        ("db.example.com", ["93.184.216.34"], False),
        # IP literals.
        ("127.0.0.1", ["127.0.0.1"], True),
        ("8.8.8.8", ["8.8.8.8"], False),
        # IPv6 loopback and link-local.
        ("ip6-localhost", ["::1"], True),
        ("link-local-v6", ["fe80::1"], True),
        # Multiple resolved addresses: block if any is internal.
        ("mixed", ["93.184.216.34", "10.0.0.1"], True),
    ],
)
def test_is_address_blocked(
    mocker: MockerFixture, host: str, resolved: list[str], expected: bool
) -> None:
    mocker.patch.object(socket, "getaddrinfo", side_effect=_fake_getaddrinfo(resolved))
    assert network.is_address_blocked(host) is expected


def test_is_address_blocked_empty_host() -> None:
    assert network.is_address_blocked("") is False


def test_is_address_blocked_unresolvable(mocker: MockerFixture) -> None:
    mocker.patch.object(socket, "getaddrinfo", side_effect=socket.gaierror)
    assert network.is_address_blocked("nonexistent.invalid") is False


def test_is_address_blocked_respects_config(mocker: MockerFixture) -> None:
    """A custom ``BLOCKED_DB_HOST_RANGES`` overrides the defaults."""

    fake_app = mocker.MagicMock()
    fake_app.config = {"BLOCKED_DB_HOST_RANGES": ["203.0.113.0/24"]}
    mocker.patch.object(network, "current_app", fake_app)
    mocker.patch.object(
        socket, "getaddrinfo", side_effect=_fake_getaddrinfo(["127.0.0.1"])
    )
    # 127.0.0.1 is in the defaults but not in the narrowed config.
    assert network.is_address_blocked("localhost") is False

    mocker.patch.object(
        socket, "getaddrinfo", side_effect=_fake_getaddrinfo(["203.0.113.5"])
    )
    assert network.is_address_blocked("doc.example.com") is True


def test_is_address_blocked_empty_config_disables_check(
    mocker: MockerFixture,
) -> None:
    fake_app = mocker.MagicMock()
    fake_app.config = {"BLOCKED_DB_HOST_RANGES": []}
    mocker.patch.object(network, "current_app", fake_app)
    mocker.patch.object(
        socket, "getaddrinfo", side_effect=_fake_getaddrinfo(["127.0.0.1"])
    )
    assert network.is_address_blocked("localhost") is False


def test_parse_blocked_networks_ignores_invalid_entries() -> None:
    parsed = network._parse_blocked_networks(
        ["10.0.0.0/8", "not-a-cidr", "", "fe80::/10"]
    )
    assert len(parsed) == 2
