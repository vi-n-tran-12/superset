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
"""
Tests for RLS clause validation in guest tokens.

Ensures that SQL injection attacks via malicious RLS clauses are rejected
at both guest token creation time (schema validation) and query execution
time (defense-in-depth in the model layer).
"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from marshmallow import ValidationError
from sqlalchemy.sql.elements import TextClause

from superset.connectors.sqla.models import BaseDatasource
from superset.exceptions import (
    QueryClauseValidationException,
    QueryObjectValidationError,
)
from superset.security.api import RlsRuleSchema
from superset.security.guest_token import (
    GuestToken,
    GuestTokenResourceType,
    GuestTokenRlsRule,
    GuestUser,
)
from superset.sql.parse import validate_rls_clause

# ---------------------------------------------------------------------------
# validate_rls_clause unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "clause",
    [
        "tenant_id = 1",
        "region = 'US'",
        "user_id = 42 AND active = 1",
        "(org_id = 5)",
        "status IN ('active', 'pending')",
    ],
)
def test_validate_rls_clause_accepts_valid(clause: str) -> None:
    """Simple WHERE-clause predicates should pass validation."""
    result = validate_rls_clause(clause, "base")
    assert isinstance(result, str)


@pytest.mark.parametrize(
    "clause",
    [
        "1=1 UNION SELECT username, password FROM ab_user--",
        "1=1 UNION ALL SELECT * FROM ab_user",
        "id IN (SELECT id FROM secret_table)",
        "1=1; DROP TABLE ab_user",
        "TRUE; SELECT 1",
    ],
)
def test_validate_rls_clause_rejects_dangerous(clause: str) -> None:
    """UNION, subqueries, multi-statement, and DDL/DML must be rejected."""
    with pytest.raises(QueryClauseValidationException):
        validate_rls_clause(clause, "base")


# ---------------------------------------------------------------------------
# Schema-level validation tests (guest token creation time)
# ---------------------------------------------------------------------------

rls_rule_schema = RlsRuleSchema()


@pytest.mark.parametrize(
    "clause",
    [
        "tenant_id = 1",
        "region = 'US'",
        "user_id = 42 AND active = 1",
        "(org_id = 5)",
        "status IN ('active', 'pending')",
    ],
)
def test_rls_schema_accepts_valid_clauses(clause: str) -> None:
    """Valid SQL WHERE-clause fragments should be accepted by the schema."""
    result = rls_rule_schema.load({"clause": clause})
    assert result["clause"] == clause


@pytest.mark.parametrize(
    "clause",
    [
        "1=1 UNION SELECT username, password FROM ab_user--",
        "1=1; DROP TABLE ab_user",
        "TRUE; SELECT 1",
        "1=1 UNION ALL SELECT * FROM ab_user",
        "id IN (SELECT id FROM secret_table)",
    ],
)
def test_rls_schema_rejects_sql_injection(clause: str) -> None:
    """Malicious clauses with UNION, multiple statements, or DDL must be rejected."""
    with pytest.raises(ValidationError):
        rls_rule_schema.load({"clause": clause})


# ---------------------------------------------------------------------------
# Defense-in-depth tests (query execution time)
# ---------------------------------------------------------------------------


def _make_datasource(dataset_id: int) -> MagicMock:
    """Create a mock datasource for testing get_sqla_row_level_filters."""
    datasource = MagicMock(spec=BaseDatasource)
    datasource.get_template_processor.return_value = MagicMock()
    datasource.get_template_processor.return_value.process_template = lambda x: x
    datasource.text = lambda x: TextClause(x)
    datasource.data = {"id": dataset_id}
    datasource.is_rls_supported = True
    datasource.database = MagicMock()
    datasource.database.db_engine_spec.engine = "postgresql"
    return datasource


def _make_guest_user(rules: list[GuestTokenRlsRule]) -> GuestUser:
    token: GuestToken = {
        "user": {},
        "resources": [
            {"type": GuestTokenResourceType.DASHBOARD, "id": "test-dashboard-uuid"}
        ],
        "rls_rules": rules,
        "iat": 10,
        "exp": 20,
    }
    return GuestUser(token=token, roles=[])


def _guest_rls_filter(
    guest_user: GuestUser,
) -> Callable[[MagicMock], list[GuestTokenRlsRule]]:
    def _filter(dataset: MagicMock) -> list[GuestTokenRlsRule]:
        return [
            rule
            for rule in guest_user.rls
            if not rule.get("dataset")
            or str(rule.get("dataset")) == str(dataset.data["id"])
        ]

    return _filter


def test_defense_in_depth_valid_clause(app: Flask) -> None:
    """Valid guest RLS clause passes through the defense-in-depth check."""
    ds = _make_datasource(42)
    rule = GuestTokenRlsRule(dataset=None, clause="tenant_id = 5")
    guest_user = _make_guest_user(rules=[rule])

    with (
        patch(
            "superset.connectors.sqla.models.security_manager.get_rls_filters",
            return_value=[],
        ),
        patch(
            "superset.connectors.sqla.models.security_manager.get_guest_rls_filters",
            wraps=_guest_rls_filter(guest_user),
        ),
        patch(
            "superset.connectors.sqla.models.is_feature_enabled",
            return_value=True,
        ),
    ):
        filters = BaseDatasource.get_sqla_row_level_filters(ds)
        assert len(filters) == 1
        assert "tenant_id" in str(filters[0])


def test_defense_in_depth_rejects_union_injection(app: Flask) -> None:
    """UNION-based SQL injection in guest RLS clause is caught at query time."""
    ds = _make_datasource(42)
    rule = GuestTokenRlsRule(
        dataset=None,
        clause="1=1 UNION SELECT username, password FROM ab_user--",
    )
    guest_user = _make_guest_user(rules=[rule])

    with (
        patch(
            "superset.connectors.sqla.models.security_manager.get_rls_filters",
            return_value=[],
        ),
        patch(
            "superset.connectors.sqla.models.security_manager.get_guest_rls_filters",
            wraps=_guest_rls_filter(guest_user),
        ),
        patch(
            "superset.connectors.sqla.models.is_feature_enabled",
            return_value=True,
        ),
    ):
        with pytest.raises(QueryObjectValidationError):
            BaseDatasource.get_sqla_row_level_filters(ds)


def test_defense_in_depth_rejects_multi_statement(app: Flask) -> None:
    """Multi-statement SQL injection in guest RLS clause is caught at query time."""
    ds = _make_datasource(42)
    rule = GuestTokenRlsRule(dataset=None, clause="1=1; DROP TABLE ab_user")
    guest_user = _make_guest_user(rules=[rule])

    with (
        patch(
            "superset.connectors.sqla.models.security_manager.get_rls_filters",
            return_value=[],
        ),
        patch(
            "superset.connectors.sqla.models.security_manager.get_guest_rls_filters",
            wraps=_guest_rls_filter(guest_user),
        ),
        patch(
            "superset.connectors.sqla.models.is_feature_enabled",
            return_value=True,
        ),
    ):
        with pytest.raises(QueryObjectValidationError):
            BaseDatasource.get_sqla_row_level_filters(ds)


def test_defense_in_depth_rejects_subquery(app: Flask) -> None:
    """Subquery-based SQL injection in guest RLS clause is caught at query time."""
    ds = _make_datasource(42)
    rule = GuestTokenRlsRule(
        dataset=None,
        clause="id IN (SELECT id FROM secret_table)",
    )
    guest_user = _make_guest_user(rules=[rule])

    with (
        patch(
            "superset.connectors.sqla.models.security_manager.get_rls_filters",
            return_value=[],
        ),
        patch(
            "superset.connectors.sqla.models.security_manager.get_guest_rls_filters",
            wraps=_guest_rls_filter(guest_user),
        ),
        patch(
            "superset.connectors.sqla.models.is_feature_enabled",
            return_value=True,
        ),
    ):
        with pytest.raises(QueryObjectValidationError):
            BaseDatasource.get_sqla_row_level_filters(ds)
