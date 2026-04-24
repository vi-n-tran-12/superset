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
from ipaddress import IPv4Network
from unittest import mock

import pytest

from superset.utils.network import (
    DEFAULT_BLOCKED_HOST_RANGES,
    is_blocked_ip,
    is_host_safe,
    resolve_host_to_ips,
)


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("10.0.0.1", True),
        ("10.255.255.255", True),
        ("172.16.0.1", True),
        ("172.31.255.255", True),
        ("192.168.1.1", True),
        ("127.0.0.1", True),
        ("169.254.169.254", True),
        ("0.0.0.0", True),  # noqa: S104
        ("::1", True),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("203.0.113.1", False),
        ("not_an_ip", True),
    ],
)
def test_is_blocked_ip_defaults(ip: str, expected: bool, app_context: None) -> None:
    assert is_blocked_ip(ip) == expected


@pytest.mark.parametrize(
    "ip,expected",
    [
        ("169.254.169.254", True),
        ("169.254.0.1", True),
        ("10.0.0.1", False),
        ("192.168.1.1", False),
        ("8.8.8.8", False),
    ],
)
def test_is_blocked_ip_custom_ranges(
    ip: str, expected: bool, app_context: None
) -> None:
    from flask import current_app

    original = current_app.config.get("BLOCKED_DB_HOST_RANGES")
    current_app.config["BLOCKED_DB_HOST_RANGES"] = [IPv4Network("169.254.0.0/16")]
    try:
        assert is_blocked_ip(ip) == expected
    finally:
        if original is None:
            current_app.config.pop("BLOCKED_DB_HOST_RANGES", None)
        else:
            current_app.config["BLOCKED_DB_HOST_RANGES"] = original


@mock.patch("superset.utils.network.socket.getaddrinfo")
def test_resolve_host_to_ips(mock_getaddrinfo: mock.MagicMock) -> None:
    mock_getaddrinfo.return_value = [
        (2, 1, 6, "", ("93.184.216.34", 0)),
        (2, 1, 6, "", ("93.184.216.34", 0)),
    ]
    result = resolve_host_to_ips("example.com")
    assert result == ["93.184.216.34"]


@mock.patch("superset.utils.network.socket.getaddrinfo")
def test_resolve_host_to_ips_failure(mock_getaddrinfo: mock.MagicMock) -> None:
    import socket

    mock_getaddrinfo.side_effect = socket.gaierror("Name resolution failed")
    result = resolve_host_to_ips("nonexistent.invalid")
    assert result == []


@mock.patch("superset.utils.network.resolve_host_to_ips")
@mock.patch("superset.utils.network.is_blocked_ip")
def test_is_host_safe_public_ip(
    mock_is_blocked: mock.MagicMock,
    mock_resolve: mock.MagicMock,
) -> None:
    mock_resolve.return_value = ["8.8.8.8"]
    mock_is_blocked.return_value = False
    assert is_host_safe("dns.google") is True


@mock.patch("superset.utils.network.resolve_host_to_ips")
@mock.patch("superset.utils.network.is_blocked_ip")
def test_is_host_safe_private_ip(
    mock_is_blocked: mock.MagicMock,
    mock_resolve: mock.MagicMock,
) -> None:
    mock_resolve.return_value = ["127.0.0.1"]
    mock_is_blocked.return_value = True
    assert is_host_safe("localhost") is False


@mock.patch("superset.utils.network.resolve_host_to_ips")
def test_is_host_safe_unresolvable(mock_resolve: mock.MagicMock) -> None:
    mock_resolve.return_value = []
    assert is_host_safe("nonexistent.invalid") is True


@mock.patch("superset.utils.network.resolve_host_to_ips")
@mock.patch("superset.utils.network.is_blocked_ip")
def test_is_host_safe_metadata_endpoint(
    mock_is_blocked: mock.MagicMock,
    mock_resolve: mock.MagicMock,
) -> None:
    mock_resolve.return_value = ["169.254.169.254"]
    mock_is_blocked.return_value = True
    assert is_host_safe("169.254.169.254") is False


@mock.patch("superset.utils.network.resolve_host_to_ips")
@mock.patch("superset.utils.network.is_blocked_ip")
def test_is_host_safe_mixed_ips(
    mock_is_blocked: mock.MagicMock,
    mock_resolve: mock.MagicMock,
) -> None:
    mock_resolve.return_value = ["8.8.8.8", "10.0.0.1"]
    mock_is_blocked.side_effect = lambda ip: ip == "10.0.0.1"
    assert is_host_safe("mixed-host.example.com") is False


def test_default_blocked_ranges_coverage() -> None:
    """Verify the default blocklist covers the expected range categories."""
    range_strs = {str(n) for n in DEFAULT_BLOCKED_HOST_RANGES}
    assert "10.0.0.0/8" in range_strs
    assert "172.16.0.0/12" in range_strs
    assert "192.168.0.0/16" in range_strs
    assert "127.0.0.0/8" in range_strs
    assert "169.254.0.0/16" in range_strs
    assert "0.0.0.0/8" in range_strs
    assert "::1/128" in range_strs
    assert "fc00::/7" in range_strs
    assert "fe80::/10" in range_strs
