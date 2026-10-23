"""One server instance serving several domains (config loading, routing, policy, audit)."""

import asyncio
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator
from unittest.mock import MagicMock, Mock, patch

import pytest

from active_directory_mcp.audit import AuditLogger
from active_directory_mcp.config.loader import load_server_config

STDIO_MOD = "active_directory_mcp.server"
HTTP_MOD = "active_directory_mcp.server_http"
HTTP_BEARER = "multi-domain-test-key-0123456789abcdef"


def _domain(name: str, **security: Any) -> Dict[str, Any]:
    return {
        "active_directory": {
            "server": f"ldaps://dc.{name}.example.com",
            "domain": f"{name}.example.com",
            "base_dn": f"DC={name},DC=example,DC=com",
            "bind_dn": f"CN=svc,DC={name},DC=example,DC=com",
            "password": f"{name}-placeholder-password",
        },
        "security": security,
        "logging": {"level": "WARNING"},
    }


def _write(path: Path, data: Any) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


@pytest.fixture(autouse=True)
def _no_global_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in (
        "AD_BIND_DN",
        "AD_PASSWORD",
        "AZURE_KEYVAULT_URL",
        "AZURE_KEYVAULT_SECRET_USERNAME",
        "AZURE_KEYVAULT_SECRET_PASSWORD",
    ):
        monkeypatch.delenv(var, raising=False)


# ------------------------------------------------------------------ config loading


def test_single_domain_file_becomes_one_named_domain(tmp_path: Path) -> None:
    cfg = load_server_config(_write(tmp_path / "a.json", _domain("alpha")))
    assert list(cfg.domains) == ["alpha.example.com"]
    assert cfg.default_domain == "alpha.example.com"
    assert cfg.multi is False
    assert cfg.security is cfg.default.security


def test_multi_file_mixes_relative_paths_and_inline_configs(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    _write(tmp_path / "sub" / "alpha.json", _domain("alpha"))
    path = _write(
        tmp_path / "multi.json",
        {"domains": {"a": "sub/alpha.json", "b": _domain("beta")}},
    )
    cfg = load_server_config(path)
    assert list(cfg.domains) == ["a", "b"]
    assert cfg.default_domain == "a"  # first one when not set
    assert cfg.multi is True
    assert cfg.domains["b"].active_directory.domain == "beta.example.com"


def test_explicit_default_domain_and_unknown_default(tmp_path: Path) -> None:
    domains = {"a": _domain("alpha"), "b": _domain("beta")}
    cfg = load_server_config(
        _write(tmp_path / "m.json", {"domains": domains, "default_domain": "b"})
    )
    assert cfg.default_domain == "b"
    with pytest.raises(ValueError, match="default_domain"):
        load_server_config(
            _write(tmp_path / "bad.json", {"domains": domains, "default_domain": "zzz"})
        )


def test_domain_errors_name_the_domain(tmp_path: Path) -> None:
    broken = _domain("beta")
    broken["active_directory"]["server"] = "http://nope"
    path = _write(tmp_path / "m.json", {"domains": {"a": _domain("alpha"), "b": broken}})
    with pytest.raises(ValueError, match="domain 'b'"):
        load_server_config(path)
    missing = _write(tmp_path / "m2.json", {"domains": {"a": "absent.json", "b": _domain("b")}})
    with pytest.raises(ValueError, match="domain 'a'"):
        load_server_config(missing)


def test_global_credential_env_is_refused_with_several_domains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AD_PASSWORD", "would-overwrite-every-domain")
    path = _write(tmp_path / "m.json", {"domains": {"a": _domain("alpha"), "b": _domain("beta")}})
    with pytest.raises(ValueError, match="AD_PASSWORD"):
        load_server_config(path)


def test_global_credential_env_still_applies_to_a_single_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AD_PASSWORD", "from-env-placeholder")
    cfg = load_server_config(_write(tmp_path / "m.json", {"domains": {"a": _domain("alpha")}}))
    password = cfg.default.active_directory.password
    assert password is not None and password.get_secret_value() == "from-env-placeholder"


def test_per_domain_password_placeholders(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ALPHA_PW", "alpha-env-placeholder")
    alpha = _domain("alpha")
    alpha["active_directory"]["password"] = "${ALPHA_PW}"
    path = _write(tmp_path / "m.json", {"domains": {"a": alpha, "b": _domain("beta")}})
    cfg = load_server_config(path)
    password = cfg.domains["a"].active_directory.password
    assert password is not None and password.get_secret_value() == "alpha-env-placeholder"


def test_invalid_domain_name_is_rejected(tmp_path: Path) -> None:
    path = _write(tmp_path / "m.json", {"domains": {"bad name": _domain("alpha")}})
    with pytest.raises(ValueError, match="invalid domain name"):
        load_server_config(path)


# ------------------------------------------------------------------ servers


def _fake_manager(ad: Any, security: Any, performance: Any, ous: Any) -> MagicMock:
    manager = MagicMock(ad_config=ad, security_config=security)
    manager.test_connection.return_value = {"connected": False}
    return manager


@contextmanager
def _server_env(tmp_path: Path, module: str, data: Dict[str, Any]) -> Iterator[None]:
    env = {
        "AD_MCP_CONFIG": _write(tmp_path / "multi.json", data),
        "AD_MCP_HTTP_API_KEY": HTTP_BEARER,
    }
    with (
        patch.dict(os.environ, env),
        patch(f"{module}.LDAPManager", side_effect=_fake_manager),
    ):
        yield


TWO_DOMAINS = {
    "domains": {"a": _domain("alpha"), "b": _domain("beta", allow_writes=True)},
}


def _stdio_raw(server: Any, name: str, args: Dict[str, Any]) -> str:
    import mcp.types as types

    handler = server.mcp.request_handlers[types.CallToolRequest]
    req = types.CallToolRequest(
        method="tools/call", params=types.CallToolRequestParams(name=name, arguments=args)
    )
    return str(asyncio.run(handler(req)).root.content[0].text)


def _stdio_call(server: Any, name: str, args: Dict[str, Any]) -> Any:
    return json.loads(_stdio_raw(server, name, args))


def test_stdio_routes_each_call_to_the_named_domain(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPServer()
    for name, ctx in server.domains.items():
        ctx.user_tools.get_user = Mock(return_value={"from": name})

    assert _stdio_call(server, "get_user", {"username": "u", "domain": "b"}) == {"from": "b"}
    assert _stdio_call(server, "get_user", {"username": "u"}) == {"from": "a"}
    server.domains["b"].user_tools.get_user.assert_called_once_with("u", None)

    # The advertised enum rejects an unknown domain before any handler runs ...
    assert "not one of" in _stdio_raw(server, "get_user", {"username": "u", "domain": "zzz"})
    # ... and the router itself never falls back to the default domain either.
    unknown = json.loads(
        server._tool_handlers["get_user"].handler(username="u", domain="zzz")[0].text
    )
    assert unknown["success"] is False and unknown["available_domains"] == ["a", "b"]
    assert server.domains["a"].user_tools.get_user.call_count == 1


def test_stdio_surface_gains_domain_and_list_domains(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPServer()
    tools = {tool.name: tool for tool in server._tools}
    assert len(tools) == 46 and "list_domains" in tools
    for name, tool in tools.items():
        if name == "list_domains":
            continue
        assert tool.inputSchema["properties"]["domain"]["enum"] == ["a", "b"], name
        assert "domain" not in tool.inputSchema.get("required", []), name

    listed = _stdio_call(server, "list_domains", {})
    assert listed["default_domain"] == "a"
    assert [(d["name"], d["allow_writes"]) for d in listed["domains"]] == [
        ("a", False),
        ("b", True),
    ]
    assert "password" not in json.dumps(listed)


def test_multi_domain_tools_carry_annotations(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPServer()
    tools = {tool.name: tool.annotations for tool in server._tools}
    assert tools["list_domains"].readOnlyHint is True
    assert tools["get_user"].readOnlyHint is True
    assert tools["disable_user"].readOnlyHint is False
    assert tools["delete_user"].destructiveHint is True


def test_single_domain_surface_has_no_domain_argument(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, {"domains": {"a": _domain("alpha")}}):
        server = ActiveDirectoryMCPServer()
    names = {tool.name for tool in server._tools}
    assert len(names) == 45 and "list_domains" not in names
    assert all("domain" not in t.inputSchema.get("properties", {}) for t in server._tools)


def test_each_domain_keeps_its_own_write_policy(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPServer()
    for ctx in server.domains.values():
        ctx.user_tools.disable_user = Mock(return_value={"success": True})

    blocked = _stdio_call(server, "disable_user", {"username": "u", "domain": "a"})
    assert blocked["error_code"] == "write_blocked"
    server.domains["a"].user_tools.disable_user.assert_not_called()
    assert _stdio_call(server, "disable_user", {"username": "u", "domain": "b"}) == {
        "success": True
    }


def test_unreachable_domain_does_not_delay_startup(tmp_path: Path) -> None:
    import threading
    import time

    from active_directory_mcp.server import ActiveDirectoryMCPServer

    release = threading.Event()

    def hanging_manager(ad: Any, security: Any, performance: Any, ous: Any) -> MagicMock:
        manager = _fake_manager(ad, security, performance, ous)
        if ad.domain == "beta.example.com":  # a DC that only answers after its timeout
            manager.test_connection.side_effect = lambda: release.wait(5) and {}
        return manager

    env = {"AD_MCP_CONFIG": _write(tmp_path / "multi.json", TWO_DOMAINS)}
    started = time.monotonic()
    with (
        patch.dict(os.environ, env),
        patch(f"{STDIO_MOD}.LDAPManager", side_effect=hanging_manager),
    ):
        server = ActiveDirectoryMCPServer()
    try:
        assert time.monotonic() - started < 2
        assert len(server._tools) == 46
    finally:
        release.set()


def test_shutdown_disconnects_every_domain(tmp_path: Path) -> None:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    with _server_env(tmp_path, STDIO_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPServer()
    server._disconnect_all()
    for ctx in server.domains.values():
        ctx.ldap_manager.disconnect.assert_called_once()


def test_http_routes_by_domain_and_advertises_it(tmp_path: Path) -> None:
    import fastmcp

    from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

    with _server_env(tmp_path, HTTP_MOD, TWO_DOMAINS):
        server = ActiveDirectoryMCPHTTPServer()
    for name, ctx in server.domains.items():
        ctx.user_tools.get_user = Mock(return_value={"from": name})

    async def go() -> Any:
        async with fastmcp.Client(server.mcp) as client:
            tools = {t.name: t for t in await client.list_tools()}
            routed = await client.call_tool("get_user", {"username": "u", "domain": "b"})
            default = await client.call_tool("get_user", {"username": "u"})
            return tools, json.loads(routed.content[0].text), json.loads(default.content[0].text)

    tools, routed, default = asyncio.run(go())
    assert "list_domains" in tools
    assert "domain" in tools["get_user"].inputSchema["properties"]
    assert routed == {"from": "b"} and default == {"from": "a"}


def test_http_auth_comes_from_the_top_level_of_a_multi_file(tmp_path: Path) -> None:
    from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

    data = {**TWO_DOMAINS, "http_auth": {"required": False}}
    with _server_env(tmp_path, HTTP_MOD, data):
        os.environ.pop("AD_MCP_HTTP_API_KEY")
        server = ActiveDirectoryMCPHTTPServer()
    assert server._verifier is None
    assert server.build_app() is not None  # auth opt-out is honoured, not refused


# ------------------------------------------------------------------ audit


def test_audit_records_carry_the_domain(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    audit = AuditLogger(str(path), domain="b")
    assert audit.record("disable_user", "write", {"username": "u"}, "ok")
    audit.close()
    assert json.loads(path.read_text(encoding="utf-8"))["domain"] == "b"

    plain = AuditLogger(str(tmp_path / "plain.log"))
    plain.record("disable_user", "write", {"username": "u"}, "ok")
    plain.close()
    assert "domain" not in json.loads((tmp_path / "plain.log").read_text(encoding="utf-8"))
