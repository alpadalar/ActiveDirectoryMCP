"""Tripwire: fabricated/mock-data methods must stay deleted (SEC-04)."""

import re
from pathlib import Path

import pytest

from active_directory_mcp.registry import ToolContext, build_tool_specs
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
from active_directory_mcp.tools.security import SecurityTools

DELETED = [
    (SecurityTools, "find_weak_passwords"),
    (SecurityTools, "analyze_permissions"),
    (SecurityTools, "detect_privilege_escalation"),
    (SecurityTools, "check_service_accounts"),
    (SecurityTools, "_assess_account_risk"),
    (SecurityTools, "_calculate_password_age"),
    (OrganizationalUnitTools, "get_ou_permissions"),
    (OrganizationalUnitTools, "delegate_ou_control"),
    (ComputerTools, "get_computer_status"),
    (ComputerTools, "search_stale_computers"),
    (ComputerTools, "get_computer_groups"),
    (ComputerTools, "_is_computer_stale"),
]

TOOLS_DIR = Path(__file__).resolve().parents[2] / "src" / "active_directory_mcp" / "tools"


@pytest.mark.parametrize("cls,name", DELETED)
def test_deleted_method_absent(cls, name):
    assert not hasattr(cls, name)


def test_registry_never_exposes_deleted_names(mock_ldap_manager):
    from unittest.mock import MagicMock

    ctx = ToolContext(
        user_tools=MagicMock(),
        group_tools=MagicMock(),
        computer_tools=MagicMock(),
        ou_tools=MagicMock(),
        security_tools=MagicMock(),
        ldap_manager=mock_ldap_manager,
        server_name="t",
    )
    names = {spec.name for spec in build_tool_specs(ctx)}
    assert len(names) == 45
    assert names.isdisjoint({n for _, n in DELETED})


@pytest.mark.parametrize("path", sorted(TOOLS_DIR.glob("*.py")), ids=lambda p: p.name)
def test_no_hardcoded_sample_data(path):
    text = path.read_text(encoding="utf-8")
    assert "DC=test,DC=local" not in text
    for marker in ("testuser", "svc_backup"):
        assert marker not in text
    assert not re.search(r"\bMock\b", text)
    assert "fabricated" not in text.lower()


@pytest.mark.parametrize("fixture", ["computer_tools", "ou_tools", "security_tools"])
def test_schema_info_lists_only_real_operations(fixture, request):
    tools = request.getfixturevalue(fixture)
    registered = {
        "list_ous",
        "get_ou",
        "create_ou",
        "modify_ou",
        "delete_ou",
        "move_ou",
        "get_ou_contents",
    }
    for op in tools.get_schema_info()["operations"]:
        assert callable(getattr(tools, op, None)) or op in registered, op
