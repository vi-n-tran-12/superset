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
from typing import Any

from pytest_mock import MockerFixture

from superset.db_engine_specs.base import BasicParametersMixin, BasicPropertiesType
from superset.errors import SupersetErrorType


def _payload(host: str = "db.example.com", port: int = 5432) -> BasicPropertiesType:
    parameters: dict[str, Any] = {
        "host": host,
        "port": port,
        "username": "superset",
        "password": "XXX",
        "database": "test",
        "query": {},
    }
    return {"parameters": parameters}  # type: ignore[typeddict-item]


def test_validate_parameters_rejects_blocked_host(mocker: MockerFixture) -> None:
    """The SSRF-protection check short-circuits with a DB security error
    when the host resolves to a blocked address."""
    mocker.patch("superset.db_engine_specs.base.is_hostname_valid", return_value=True)
    mocker.patch("superset.db_engine_specs.base.is_address_blocked", return_value=True)
    port_spy = mocker.patch(
        "superset.db_engine_specs.base.is_port_open", return_value=True
    )

    errors = BasicParametersMixin.validate_parameters(_payload(host="169.254.169.254"))

    assert len(errors) == 1
    assert errors[0].error_type == SupersetErrorType.DATABASE_SECURITY_ACCESS_ERROR
    assert errors[0].extra == {"invalid": ["host"]}
    # The port probe must not run once the host is rejected.
    port_spy.assert_not_called()


def test_validate_parameters_allows_public_host(mocker: MockerFixture) -> None:
    mocker.patch("superset.db_engine_specs.base.is_hostname_valid", return_value=True)
    mocker.patch("superset.db_engine_specs.base.is_address_blocked", return_value=False)
    mocker.patch("superset.db_engine_specs.base.is_port_open", return_value=True)

    errors = BasicParametersMixin.validate_parameters(_payload())
    assert errors == []
