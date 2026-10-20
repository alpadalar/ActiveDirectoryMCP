"""SEC-01: risk classification completeness and the default-deny dispatch gate."""

import asyncio
import inspect
import json
from typing import Any, Dict, List
from unittest.mock import Mock

import pytest
from fastmcp import Client, FastMCP

from active_directory_mcp.policy import (
    RISK_CLASSIFICATION,
    Risk,
    ToolPolicy,
    guard,
)
from active_directory_mcp.registry import (
    FastMCPToolSink,
    StdioToolSink,
    build_tool_specs,
    register_tools,
)
from tests.support.tool_surface import _offline_env
from tests.unit.test_registry import make_ctx

DESTRUCTIVE = {"delete_user", "delete_group", "delete_computer", "delete_organizational_unit"}
WRITE = {n for n, r in RISK_CLASSIFICATION.items() if r is Risk.WRITE}
NON_READ = sorted(WRITE | DESTRUCTIVE)
# Minimal valid arguments for every non-read tool (values only need to satisfy the schema).
ARGS: Dict[str, Dict[str, Any]] = {
    "create_user": {"username": "u", "password": "p", "first_name": "f", "last_name": "l"},
    "modify_user": {"username": "u", "attributes": {}},
    "enable_user": {"username": "u"},
    "disable_user": {"username": "u"},
    "reset_user_password": {"username": "u"},
    "create_group": {"group_name": "g"},
    "modify_group": {"group_name": "g", "attributes": {}},
    "add_group_member": {"group_name": "g", "member_dn": "d"},
    "remove_group_member": {"group_name": "g", "member_dn": "d"},
    "create_computer": {"computer_name": "c"},
    "modify_computer": {"computer_name": "c", "attributes": {}},
    "enable_computer": {"computer_name": "c"},
    "disable_computer": {"computer_name": "c"},
    "reset_computer_password": {"computer_name": "c"},
    "create_organizational_unit": {"name": "n"},
    "modify_organizational_unit": {"ou_dn": "d", "attributes": {}},
    "move_organizational_unit": {"ou_dn": "d", "new_parent_dn": "p"},
    "delete_user": {"username": "u"},
    "delete_group": {"group_name": "g"},
    "delete_computer": {"computer_name": "c"},
    "delete_organizational_unit": {"ou_dn": "d", "force": True},
}
TOOL_ATTRS = ("user_tools", "group_tools", "computer_tools", "ou_tools", "security_tools")


def _code(out: Any) -> Any:
    return out.get("error_code") if isinstance(out, dict) else None


def _any_tool_called(ctx: Any) -> bool:
    return any(getattr(ctx, attr).method_calls for attr in TOOL_ATTRS)


# ---------------------------------------------------------------- classification


def test_classification_covers_exactly_the_registered_tools() -> None:
    names = {spec.name for spec in build_tool_specs(make_ctx())}
    assert set(RISK_CLASSIFICATION) == names
    assert len(names) == 42
    assert all(isinstance(r, Risk) for r in RISK_CLASSIFICATION.values())


@pytest.mark.parametrize(
    "name,risk",
    [
        ("list_users", Risk.READ),
        ("health", Risk.READ),
        ("get_schema_info", Risk.READ),
        ("create_user", Risk.WRITE),
        ("reset_user_password", Risk.WRITE),
        ("reset_computer_password", Risk.WRITE),
        ("move_organizational_unit", Risk.WRITE),
        ("add_group_member", Risk.WRITE),
        ("delete_user", Risk.DESTRUCTIVE),
        ("delete_organizational_unit", Risk.DESTRUCTIVE),
    ],
)
def test_classification_spot_checks(name: str, risk: Risk) -> None:
    assert RISK_CLASSIFICATION[name] is risk


def test_destructive_set_is_exactly_the_four_deletes() -> None:
    got = {n for n, r in RISK_CLASSIFICATION.items() if r is Risk.DESTRUCTIVE}
    assert got == DESTRUCTIVE


def test_unclassified_tool_fails_build(monkeypatch: pytest.MonkeyPatch) -> None:
    import active_directory_mcp.registry as registry

    trimmed = {k: v for k, v in RISK_CLASSIFICATION.items() if k != "get_user"}
    monkeypatch.setattr(registry, "RISK_CLASSIFICATION", trimmed)
    with pytest.raises(RuntimeError, match="get_user"):
        build_tool_specs(make_ctx())


# ---------------------------------------------------------------- decide matrix


@pytest.mark.parametrize("writes", [False, True])
@pytest.mark.parametrize("destructive", [False, True])
@pytest.mark.parametrize(
    "tool,risk", [("get_user", "read"), ("create_user", "write"),
                  ("delete_user", "destructive"), ("no_such_tool", "unknown")]
)
def test_decide_matrix(writes: bool, destructive: bool, tool: str, risk: str) -> None:
    result = ToolPolicy(writes, destructive).decide(tool)
    if risk == "read":
        assert result is None
    elif risk == "write":
        assert (result is None) == writes
    else:  # destructive and unknown (fail closed)
        assert (result is None) == (writes and destructive)


def test_blocked_payload_shape() -> None:
    w = ToolPolicy().decide("create_user")
    assert w is not None
    assert set(w) == {"success", "error", "error_code", "tool", "risk", "setting"}
    assert w["success"] is False and w["error_code"] == "write_blocked"
    assert w["setting"] == "security.allow_writes" and w["risk"] == "write"
    assert "security.allow_writes" in w["error"]
    d = ToolPolicy(True, False).decide("delete_user")
    assert d is not None
    assert d["error_code"] == "destructive_blocked"
    assert d["setting"] == "security.allow_destructive" and d["tool"] == "delete_user"


def test_from_security() -> None:
    from active_directory_mcp.config.models import SecurityConfig

    assert ToolPolicy.from_security(SecurityConfig()) == ToolPolicy(False, False)
    assert ToolPolicy.from_security(
        SecurityConfig(allow_writes=True, allow_destructive=True)
    ) == ToolPolicy(True, True)


# ---------------------------------------------------------------- guard


def test_guard_preserves_signature_and_calls_through() -> None:
    def create_user(username: str, email: str = "x") -> Any:
        return handler(username, email)

    handler = Mock(return_value="ok")
    wrapped = guard("create_user", create_user, ToolPolicy(True, False))
    assert wrapped.__name__ == "create_user"
    assert inspect.signature(wrapped) == inspect.signature(create_user)
    assert wrapped("bob", email="e") == "ok"
    handler.assert_called_once_with("bob", "e")


def test_guard_blocks_without_calling_handler() -> None:
    handler = Mock()
    wrapped = guard("delete_user", handler, ToolPolicy(True, False))
    out = wrapped("bob")
    handler.assert_not_called()
    assert json.loads(out[0].text)["error_code"] == "destructive_blocked"


# ---------------------------------------------------------------- registry gate


def _stdio_dispatch(ctx: Any, name: str) -> Dict[str, Any]:
    sink = StdioToolSink()
    register_tools(ctx, sink)
    return json.loads(sink.dispatch(name, ARGS[name])[0].text)


def _fastmcp_call(ctx: Any, name: str) -> Dict[str, Any]:
    async def run() -> Dict[str, Any]:
        mcp = FastMCP("t")
        register_tools(ctx, FastMCPToolSink(mcp))
        async with Client(mcp) as client:
            result = await client.call_tool(name, ARGS[name], raise_on_error=False)
        return json.loads(result.content[0].text)

    return asyncio.run(run())


CALLERS = [_stdio_dispatch, _fastmcp_call]


@pytest.mark.parametrize("caller", CALLERS, ids=["stdio", "fastmcp"])
@pytest.mark.parametrize("name", NON_READ)
def test_default_context_blocks_every_non_read_tool(caller: Any, name: str) -> None:
    ctx = make_ctx(policy=None)
    out = caller(ctx, name)
    expected = "destructive_blocked" if name in DESTRUCTIVE else "write_blocked"
    assert out["error_code"] == expected and out["tool"] == name
    assert not _any_tool_called(ctx)


@pytest.mark.parametrize("caller", CALLERS, ids=["stdio", "fastmcp"])
@pytest.mark.parametrize("name", NON_READ)
def test_writes_allowed_destructive_still_blocked(caller: Any, name: str) -> None:
    ctx = make_ctx(policy=ToolPolicy(True, False))
    out = caller(ctx, name)
    if name in DESTRUCTIVE:
        assert out["error_code"] == "destructive_blocked"
        assert not _any_tool_called(ctx)
    else:
        assert _code(out) != "write_blocked"
        assert _any_tool_called(ctx)


@pytest.mark.parametrize("name", NON_READ)
def test_allow_all_passes_everything(name: str) -> None:
    ctx = make_ctx(policy=ToolPolicy(True, True))
    out = _stdio_dispatch(ctx, name)
    assert not str(_code(out) or "").endswith("_blocked")
    assert _any_tool_called(ctx)


def test_read_tools_unaffected_by_default_policy() -> None:
    ctx = make_ctx(policy=None)
    sink = StdioToolSink()
    register_tools(ctx, sink)
    sink.dispatch("get_user", {"username": "u"})
    ctx.user_tools.get_user.assert_called_once()


def test_gate_does_not_change_surface() -> None:
    def surface(policy: Any) -> List[Any]:
        return [
            (s.name, s.description, s.parameters, str(inspect.signature(s.handler)))
            for s in build_tool_specs(make_ctx(policy=policy))
        ]

    assert surface(None) == surface(ToolPolicy(True, True))


# ---------------------------------------------------------------- stdio server wiring


def _stdio_call(server: Any, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    import mcp.types as types

    handler = server.mcp.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(
        method="tools/call",
        params=types.CallToolRequestParams(name=name, arguments=arguments),
    )
    return json.loads(asyncio.run(handler(req)).root.content[0].text)


def test_stdio_server_blocks_writes_by_default() -> None:
    import active_directory_mcp.server as mod

    with _offline_env("active_directory_mcp.server"):
        server = mod.ActiveDirectoryMCPServer()
        server.user_tools.disable_user = Mock()
        out = _stdio_call(server, "disable_user", {"username": "u"})
    assert out["error_code"] == "write_blocked"
    server.user_tools.disable_user.assert_not_called()


def test_stdio_server_honours_allow_writes_config() -> None:
    import active_directory_mcp.server as mod
    from active_directory_mcp.config.models import SecurityConfig

    with _offline_env("active_directory_mcp.server"):
        original = mod.load_config

        def load_with_writes(path: Any = None) -> Any:
            cfg = original(path)
            cfg.security = SecurityConfig(allow_writes=True)
            return cfg

        mod_load = Mock(side_effect=load_with_writes)
        from unittest.mock import patch

        with patch.object(mod, "load_config", mod_load):
            server = mod.ActiveDirectoryMCPServer()
        server.user_tools.disable_user = Mock(return_value={"success": True})
        out = _stdio_call(server, "disable_user", {"username": "u"})
        assert out == {"success": True}
        server.user_tools.disable_user.assert_called_once_with("u")
        out = _stdio_call(server, "delete_user", {"username": "u"})
        assert out["error_code"] == "destructive_blocked"
