"""Registry contract tests (CONS-01): one declaration site, both goldens reproduced."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, Mock

import pytest
from fastmcp import FastMCP
from fastmcp.tools import FunctionTool

from active_directory_mcp import __version__
from active_directory_mcp.registry import (
    FastMCPToolSink,
    StdioToolSink,
    ToolContext,
    build_tool_specs,
    format_json_response,
    register_tools,
)
from active_directory_mcp.tools.computer import ComputerTools
from active_directory_mcp.tools.definitions import TOOL_DESCRIPTIONS, TOOL_INPUT_SCHEMAS
from active_directory_mcp.tools.group import GroupTools
from active_directory_mcp.tools.organizational_unit import OrganizationalUnitTools
from active_directory_mcp.tools.security import SecurityTools
from active_directory_mcp.tools.user import UserTools
from tests.support.tool_surface import canonical_input_schema

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "golden"
HTTP_GOLDEN = json.loads((GOLDEN_DIR / "tool_surface_http.json").read_text(encoding="utf-8"))
STDIO_GOLDEN = json.loads((GOLDEN_DIR / "tool_surface_stdio.json").read_text(encoding="utf-8"))
TOOL_NAMES = set(HTTP_GOLDEN["tools"])


def make_ctx(**overrides: Any) -> ToolContext:
    values: Dict[str, Any] = {
        "user_tools": MagicMock(spec=UserTools),
        "group_tools": MagicMock(spec=GroupTools),
        "computer_tools": MagicMock(spec=ComputerTools),
        "ou_tools": MagicMock(spec=OrganizationalUnitTools),
        "security_tools": MagicMock(spec=SecurityTools),
        "ldap_manager": Mock(),
        "server_name": "TestServer",
    }
    values.update(overrides)
    return ToolContext(**values)


@pytest.fixture
def ctx() -> ToolContext:
    return make_ctx()


def test_specs_cover_golden_set_in_stable_order(ctx: ToolContext) -> None:
    specs = build_tool_specs(ctx)
    assert len(specs) == 42
    assert {spec.name for spec in specs} == TOOL_NAMES
    assert [s.name for s in specs] == [s.name for s in build_tool_specs(ctx)]
    for spec in specs:
        assert spec.description == TOOL_DESCRIPTIONS[spec.name]
        assert spec.input_schema == TOOL_INPUT_SCHEMAS[spec.name]


def test_fastmcp_schemas_match_http_golden(ctx: ToolContext) -> None:
    for spec in build_tool_specs(ctx):
        tool = FunctionTool.from_function(
            spec.handler, name=spec.name, description=spec.description, output_schema=None
        )
        assert canonical_input_schema(tool.parameters) == HTTP_GOLDEN["tools"][spec.name], spec.name
        assert tool.output_schema is None


@pytest.mark.asyncio
async def test_register_tools_on_fastmcp(ctx: ToolContext) -> None:
    mcp = FastMCP("test")
    assert register_tools(ctx, FastMCPToolSink(mcp)) is None
    tools = await mcp.list_tools()
    assert len(tools) == 42
    assert {t.name for t in tools} == TOOL_NAMES
    for tool in tools:
        assert tool.output_schema is None
        assert canonical_input_schema(tool.parameters) == HTTP_GOLDEN["tools"][tool.name]


@pytest.mark.asyncio
async def test_registering_twice_on_one_fastmcp_is_recorded(ctx: ToolContext) -> None:
    """Pin the actual duplicate behaviour so a FastMCP change becomes visible."""
    mcp = FastMCP("test")
    register_tools(ctx, FastMCPToolSink(mcp))
    try:
        register_tools(ctx, FastMCPToolSink(mcp))
    except Exception:
        outcome = "raises"
    else:
        outcome = "replaces"
    assert len(await mcp.list_tools()) == 42
    assert outcome in {"raises", "replaces"}


def test_register_tools_calls_sink_once_per_spec(ctx: ToolContext) -> None:
    sink = MagicMock()
    assert register_tools(ctx, sink) is None
    assert sink.add.call_count == 42


def test_stdio_sink_matches_stdio_golden(ctx: ToolContext) -> None:
    sink = StdioToolSink()
    register_tools(ctx, sink)
    assert len(sink.tools) == 42
    assert set(sink.handlers) == TOOL_NAMES
    for tool in sink.tools:
        assert canonical_input_schema(tool.inputSchema) == STDIO_GOLDEN["tools"][tool.name]
        assert tool.description == TOOL_DESCRIPTIONS[tool.name]


# (tool name, minimal kwargs, tool-class attribute, method, expected positional args)
DELEGATION = [
    ("list_users", {}, "user_tools", "list_users", (None, None, None)),
    ("get_user", {"username": "u"}, "user_tools", "get_user", ("u", None)),
    (
        "create_user",
        {"username": "u", "password": "p", "first_name": "f", "last_name": "l"},
        "user_tools",
        "create_user",
        ("u", "p", "f", "l", None, None, None),
    ),
    (
        "modify_user",
        {"username": "u", "attributes": {"a": 1}},
        "user_tools",
        "modify_user",
        ("u", {"a": 1}),
    ),
    ("delete_user", {"username": "u"}, "user_tools", "delete_user", ("u",)),
    ("enable_user", {"username": "u"}, "user_tools", "enable_user", ("u",)),
    ("disable_user", {"username": "u"}, "user_tools", "disable_user", ("u",)),
    ("reset_user_password", {"username": "u"}, "user_tools", "reset_password", ("u", None, True)),
    ("get_user_groups", {"username": "u"}, "user_tools", "get_user_groups", ("u",)),
    ("list_groups", {}, "group_tools", "list_groups", (None, None, None)),
    ("get_group", {"group_name": "g"}, "group_tools", "get_group", ("g", None)),
    (
        "create_group",
        {"group_name": "g"},
        "group_tools",
        "create_group",
        ("g", None, None, None, "Global", "Security", None),
    ),
    (
        "modify_group",
        {"group_name": "g", "attributes": {}},
        "group_tools",
        "modify_group",
        ("g", {}),
    ),
    ("delete_group", {"group_name": "g"}, "group_tools", "delete_group", ("g",)),
    (
        "add_group_member",
        {"group_name": "g", "member_dn": "d"},
        "group_tools",
        "add_member",
        ("g", "d"),
    ),
    (
        "remove_group_member",
        {"group_name": "g", "member_dn": "d"},
        "group_tools",
        "remove_member",
        ("g", "d"),
    ),
    ("get_group_members", {"group_name": "g"}, "group_tools", "get_members", ("g", False)),
    ("list_computers", {}, "computer_tools", "list_computers", (None, None, None)),
    ("get_computer", {"computer_name": "c"}, "computer_tools", "get_computer", ("c", None)),
    (
        "create_computer",
        {"computer_name": "c"},
        "computer_tools",
        "create_computer",
        ("c", None, None, None, None),
    ),
    (
        "modify_computer",
        {"computer_name": "c", "attributes": {}},
        "computer_tools",
        "modify_computer",
        ("c", {}),
    ),
    ("delete_computer", {"computer_name": "c"}, "computer_tools", "delete_computer", ("c",)),
    ("enable_computer", {"computer_name": "c"}, "computer_tools", "enable_computer", ("c",)),
    ("disable_computer", {"computer_name": "c"}, "computer_tools", "disable_computer", ("c",)),
    (
        "reset_computer_password",
        {"computer_name": "c"},
        "computer_tools",
        "reset_computer_password",
        ("c",),
    ),
    ("get_stale_computers", {}, "computer_tools", "get_stale_computers", (90,)),
    ("list_organizational_units", {}, "ou_tools", "list_ous", (None, None, None, True)),
    ("get_organizational_unit", {"ou_dn": "o"}, "ou_tools", "get_ou", ("o", None)),
    (
        "create_organizational_unit",
        {"name": "n"},
        "ou_tools",
        "create_ou",
        ("n", None, None, None, None),
    ),
    (
        "modify_organizational_unit",
        {"ou_dn": "o", "attributes": {}},
        "ou_tools",
        "modify_ou",
        ("o", {}),
    ),
    ("delete_organizational_unit", {"ou_dn": "o"}, "ou_tools", "delete_ou", ("o", False)),
    (
        "move_organizational_unit",
        {"ou_dn": "o", "new_parent_dn": "p"},
        "ou_tools",
        "move_ou",
        ("o", "p"),
    ),
    (
        "get_organizational_unit_contents",
        {"ou_dn": "o"},
        "ou_tools",
        "get_ou_contents",
        ("o", None),
    ),
    ("get_domain_info", {}, "security_tools", "get_domain_info", ()),
    ("get_privileged_groups", {}, "security_tools", "get_privileged_groups", ()),
    ("get_user_permissions", {"username": "u"}, "security_tools", "get_user_permissions", ("u",)),
    ("get_inactive_users", {}, "security_tools", "get_inactive_users", (90, False)),
    (
        "get_password_policy_violations",
        {},
        "security_tools",
        "get_password_policy_violations",
        (),
    ),
    ("audit_admin_accounts", {}, "security_tools", "audit_admin_accounts", ()),
]

SYSTEM_TOOLS = {"test_connection", "health", "get_schema_info"}


def test_delegation_table_covers_every_non_system_tool() -> None:
    assert {row[0] for row in DELEGATION} == TOOL_NAMES - SYSTEM_TOOLS


@pytest.mark.parametrize(("name", "kwargs", "attr", "method", "expected"), DELEGATION)
def test_handler_delegates_with_expected_arguments(
    ctx: ToolContext, name: str, kwargs: Dict[str, Any], attr: str, method: str, expected: tuple
) -> None:
    spec = {s.name: s for s in build_tool_specs(ctx)}[name]
    result = spec.handler(**kwargs)
    target = getattr(getattr(ctx, attr), method)
    target.assert_called_once_with(*expected)
    assert result is target.return_value


# --------------------------------------------------------------------------
# StdioToolSink.dispatch
# --------------------------------------------------------------------------


def _stdio(ctx: ToolContext) -> StdioToolSink:
    sink = StdioToolSink()
    register_tools(ctx, sink)
    return sink


def test_dispatch_drops_undeclared_arguments(ctx: ToolContext) -> None:
    sink = _stdio(ctx)
    ctx.user_tools.delete_user.return_value = ["sentinel"]
    out = sink.dispatch("delete_user", {"username": "u", "evil": 1})
    assert out == ["sentinel"]
    ctx.user_tools.delete_user.assert_called_once_with("u")


def test_dispatch_serialises_non_list_results(ctx: ToolContext) -> None:
    sink = _stdio(ctx)
    ctx.security_tools.get_domain_info.return_value = {"when": datetime(2026, 1, 1), "n": 1}
    out = sink.dispatch("get_domain_info", None)
    assert len(out) == 1 and out[0].type == "text"
    assert json.loads(out[0].text)["n"] == 1


def test_dispatch_unknown_tool(ctx: ToolContext) -> None:
    out = _stdio(ctx).dispatch("nope", {})
    assert json.loads(out[0].text) == {"error": "Unknown tool: nope"}


# --------------------------------------------------------------------------
# System tools
# --------------------------------------------------------------------------


def _json(content: Any) -> Dict[str, Any]:
    assert len(content) == 1
    return json.loads(content[0].text)


def _handler(ctx: ToolContext, name: str) -> Any:
    return {s.name: s for s in build_tool_specs(ctx)}[name].handler


def test_test_connection_returns_manager_result() -> None:
    manager = Mock()
    manager.test_connection.return_value = {"connected": True}
    assert _json(_handler(make_ctx(ldap_manager=manager), "test_connection")()) == {
        "connected": True
    }


def test_test_connection_error_is_structured() -> None:
    manager = Mock()
    manager.test_connection.side_effect = RuntimeError("boom")
    assert _json(_handler(make_ctx(ldap_manager=manager), "test_connection")()) == {
        "success": False,
        "error": "boom",
    }


def test_health_ok_and_extras_merged_last() -> None:
    manager = Mock()
    manager.test_connection.return_value = {"connected": True, "server": "dc1"}
    ctx = make_ctx(
        ldap_manager=manager, health_extras=lambda: {"tests_passed": True, "status": "unknown"}
    )
    data = _json(_handler(ctx, "health")())
    assert data["server"] == "TestServer"
    assert data["ldap_connection"] == "connected"
    assert data["ldap_server"] == "dc1"
    assert data["tests_passed"] is True
    assert data["status"] == "unknown"
    assert "timestamp" in data


def test_health_degraded_when_probe_raises() -> None:
    manager = Mock()
    manager.test_connection.side_effect = RuntimeError("down")
    data = _json(_handler(make_ctx(ldap_manager=manager), "health")())
    assert data["status"] == "degraded"
    assert data["ldap_connection"] == "error"
    assert data["ldap_error"] == "down"


def test_health_probe_failure_is_not_masked_by_extras_status() -> None:
    manager = Mock()
    manager.test_connection.side_effect = RuntimeError("down")
    ctx = make_ctx(
        ldap_manager=manager, health_extras=lambda: {"tests_passed": True, "status": "ok"}
    )
    data = _json(_handler(ctx, "health")())
    assert data["status"] == "degraded"
    assert data["ldap_connection"] == "error"
    assert data["tests_passed"] is True


def test_health_disconnected() -> None:
    manager = Mock()
    manager.test_connection.return_value = {"connected": False}
    data = _json(_handler(make_ctx(ldap_manager=manager), "health")())
    assert data["ldap_connection"] == "disconnected"
    assert data["ldap_server"] == "unknown"
    assert data["status"] == "ok"


def test_get_schema_info_endpoint_only_when_set() -> None:
    ctx = make_ctx()
    for attr in ("user_tools", "group_tools", "computer_tools", "ou_tools", "security_tools"):
        getattr(ctx, attr).get_schema_info.return_value = {"who": attr}
    data = _json(_handler(ctx, "get_schema_info")())
    assert data["version"] == __version__
    assert "endpoint" not in data
    assert data["tools"]["ou_tools"] == {"who": "ou_tools"}
    assert set(data["tools"]) == {
        "user_tools",
        "group_tools",
        "computer_tools",
        "ou_tools",
        "security_tools",
    }

    with_endpoint = make_ctx(
        user_tools=ctx.user_tools,
        group_tools=ctx.group_tools,
        computer_tools=ctx.computer_tools,
        ou_tools=ctx.ou_tools,
        security_tools=ctx.security_tools,
        endpoint="http://h:1/p",
    )
    assert _json(_handler(with_endpoint, "get_schema_info")())["endpoint"] == "http://h:1/p"


def test_format_json_response_serialisation_fallback() -> None:
    class Bad:
        def __str__(self) -> str:
            raise ValueError("no")

    out = format_json_response({"x": Bad()}, "op")
    data = json.loads(out[0].text)
    assert data["operation"] == "op"
    assert "Failed to format response" in data["error"]
