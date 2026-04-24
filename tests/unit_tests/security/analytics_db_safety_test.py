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
import pytest
from pytest_mock import MockerFixture
from sqlalchemy.engine.url import make_url, URL

from superset.exceptions import SupersetSecurityException
from superset.security import analytics_db_safety


@pytest.mark.parametrize(
    "uri",
    [
        # Cloud metadata endpoints.
        "postgresql://user:pwd@169.254.169.254:80/db",
        # Loopback.
        "postgresql://user:pwd@127.0.0.1:5432/db",
        # Private ranges.
        "mysql://user:pwd@10.0.0.5:3306/db",
        "mysql://user:pwd@192.168.1.1:3306/db",
        "postgresql://user:pwd@172.16.0.3:5432/db",
        # IPv6 loopback.
        "postgresql://user:pwd@[::1]:5432/db",
    ],
)
def test_check_sqlalchemy_uri_blocks_internal_hosts(
    mocker: MockerFixture, uri: str
) -> None:
    mocker.patch.object(analytics_db_safety, "is_address_blocked", return_value=True)
    with pytest.raises(SupersetSecurityException) as excinfo:
        analytics_db_safety.check_sqlalchemy_uri(make_url(uri))
    assert "blocked" in str(excinfo.value).lower()


def test_check_sqlalchemy_uri_allows_public_hosts(mocker: MockerFixture) -> None:
    mocker.patch.object(analytics_db_safety, "is_address_blocked", return_value=False)
    # Should not raise.
    analytics_db_safety.check_sqlalchemy_uri(
        make_url("postgresql://user:pwd@db.example.com:5432/db")
    )


def test_check_sqlalchemy_uri_skips_host_check_when_no_host(
    mocker: MockerFixture,
) -> None:
    spy = mocker.patch.object(
        analytics_db_safety, "is_address_blocked", return_value=True
    )
    # URIs without a host should not invoke the host block; the dialect
    # check is responsible for those.
    analytics_db_safety.check_sqlalchemy_uri(
        URL.create(drivername="mysql", username="user")
    )
    spy.assert_not_called()
