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
from unittest import mock

import pytest
from sqlalchemy.engine.url import make_url

from superset.errors import SupersetErrorType
from superset.exceptions import SupersetSecurityException
from superset.security.analytics_db_safety import check_sqlalchemy_uri


@mock.patch(
    "superset.security.analytics_db_safety.is_host_safe",
    return_value=False,
)
def test_check_sqlalchemy_uri_blocks_private_host(
    mock_is_host_safe: mock.MagicMock,
    app_context: None,
) -> None:
    uri = make_url("postgresql://user:pass@10.0.0.1/mydb")
    with pytest.raises(SupersetSecurityException) as exc_info:
        check_sqlalchemy_uri(uri)
    error = exc_info.value.error
    assert error.error_type == SupersetErrorType.CONNECTION_BLOCKED_HOST_ERROR
    mock_is_host_safe.assert_called_once_with("10.0.0.1")


@mock.patch(
    "superset.security.analytics_db_safety.is_host_safe",
    return_value=False,
)
def test_check_sqlalchemy_uri_blocks_loopback(
    mock_is_host_safe: mock.MagicMock,
    app_context: None,
) -> None:
    uri = make_url("postgresql://user:pass@127.0.0.1/mydb")
    with pytest.raises(SupersetSecurityException) as exc_info:
        check_sqlalchemy_uri(uri)
    error = exc_info.value.error
    assert error.error_type == SupersetErrorType.CONNECTION_BLOCKED_HOST_ERROR


@mock.patch(
    "superset.security.analytics_db_safety.is_host_safe",
    return_value=False,
)
def test_check_sqlalchemy_uri_blocks_metadata_endpoint(
    mock_is_host_safe: mock.MagicMock,
    app_context: None,
) -> None:
    uri = make_url("postgresql://user:pass@169.254.169.254/mydb")
    with pytest.raises(SupersetSecurityException) as exc_info:
        check_sqlalchemy_uri(uri)
    error = exc_info.value.error
    assert error.error_type == SupersetErrorType.CONNECTION_BLOCKED_HOST_ERROR


@mock.patch(
    "superset.security.analytics_db_safety.is_host_safe",
    return_value=True,
)
def test_check_sqlalchemy_uri_allows_public_host(
    mock_is_host_safe: mock.MagicMock,
    app_context: None,
) -> None:
    uri = make_url("postgresql://user:pass@db.example.com/mydb")
    check_sqlalchemy_uri(uri)
    mock_is_host_safe.assert_called_once_with("db.example.com")


@mock.patch(
    "superset.security.analytics_db_safety.is_host_safe",
    return_value=True,
)
def test_check_sqlalchemy_uri_no_host(
    mock_is_host_safe: mock.MagicMock,
    app_context: None,
) -> None:
    uri = make_url("sqlite:///path/to/db.sqlite")
    with pytest.raises(SupersetSecurityException):
        check_sqlalchemy_uri(uri)
    mock_is_host_safe.assert_not_called()
