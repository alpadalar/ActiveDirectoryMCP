"""Structural and behavioural guards for the consolidated servers (CONS-01, CONS-02)."""

import ast
import asyncio
import json
from pathlib import Path
from typing import Any, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tests.support.tool_surface import _offline_env

SRC = Path(__file__).parents[2] / "src" / "active_directory_mcp"
SERVER = SRC / "server.py"
SERVER_HTTP = SRC / "server_http.py"
HTTP_MOD = "active_directory_mcp.server_http"
STDIO_MOD = "active_directory_mcp.server"


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _called_attr_names(tree: ast.AST) -> List[str]:
    return [
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    ]


def _defined_names(tree: ast.AST) -> List[str]:
    return [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _all_src_files() -> List[Path]:
    return sorted(SRC.rglob("*.py"))


# ---------------------------------------------------------------- structure


@pytest.mark.parametrize("path", [SERVER, SERVER_HTTP], ids=lambda p: p.name)
def test_no_per_tool_registration_code(path: Path) -> None:
    tree = _tree(path)
    defined = set(_defined_names(tree))
    assert not defined & {"_setup_tools", "_define_tools", "_add_tool"}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                target = dec.func if isinstance(dec, ast.Call) else dec
                assert not (
                    isinstance(target, ast.Attribute) and target.attr == "tool"
                ), f"{path.name}:{node.lineno} uses a .tool decorator"
    assert "register_tools" in _called_attr_names(tree) or any(
        isinstance(n, ast.Call) and getattr(n.func, "id", None) == "register_tools"
        for n in ast.walk(tree)
    ), f"{path.name} does not call register_tools"


def test_http_app_called_only_in_http_app_module() -> None:
    offenders = [
        f"{p.name}:{n.lineno}"
        for p in _all_src_files()
        if p.name != "http_app.py"
        for n in ast.walk(_tree(p))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "http_app"
    ]
    assert not offenders, offenders


def test_server_http_has_no_alternate_serving_paths() -> None:
    source = SERVER_HTTP.read_text(encoding="utf-8")
    for needle in ("run_http_async", "uvicorn.run(", "self.mcp.run("):
        hits = [
            f"line {i}: {line.strip()}"
            for i, line in enumerate(source.splitlines(), 1)
            if needle in line
        ]
        assert not hits, f"{needle!r} found in server_http.py: {hits}"


def test_uvicorn_config_only_in_server_http() -> None:
    for p in _all_src_files():
        has = "uvicorn.Config(" in p.read_text(encoding="utf-8")
        assert has == (p.name == "server_http.py"), p.name


# ------------------------------------------------------------------ behaviour


def _http_server() -> Any:
    from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

    return ActiveDirectoryMCPHTTPServer()


def test_http_server_registers_42_tools_and_health_route() -> None:
    from active_directory_mcp.http_app import HEALTH_PATH

    with _offline_env(HTTP_MOD):
        server = _http_server()
        names = {t.name for t in asyncio.run(server.mcp.list_tools())}
        assert len(names) == 42 and "health" in names
        app = server.build_app()
        assert HEALTH_PATH in [getattr(r, "path", None) for r in app.routes]


def test_serve_hands_build_http_app_object_to_uvicorn() -> None:
    import active_directory_mcp.server_http as mod

    recorded: List[Any] = []
    built: List[Any] = []
    servers: List[Any] = []
    real_build = mod.build_http_app

    def spy(*args: Any, **kwargs: Any) -> Any:
        app = real_build(*args, **kwargs)
        built.append(app)
        return app

    class FakeServer:
        def __init__(self, config: Any, on_shutdown: Any = None) -> None:
            recorded.append(config)
            servers.append(self)
            self.on_shutdown = on_shutdown
            self.should_exit = False

        async def serve(self, sockets: Optional[List[Any]] = None) -> None:
            return None

    with _offline_env(HTTP_MOD):
        server = _http_server()
        with patch.object(mod, "build_http_app", spy), patch.object(
            mod, "_ShutdownHookServer", FakeServer
        ):
            asyncio.run(server.serve())
            server.stop()
    assert len(built) == 1 and len(recorded) == 1
    assert recorded[0].app is built[0]
    assert recorded[0].host == server.host and recorded[0].port == server.port
    assert recorded[0].lifespan == "on"
    assert servers[0].on_shutdown == server.ldap_manager.disconnect


def test_run_awaits_serve_once_and_disconnects() -> None:
    with _offline_env(HTTP_MOD):
        server = _http_server()
        server.serve = AsyncMock()
        server.ldap_manager = MagicMock()
        server.run()
        server.serve.assert_awaited_once()
        server.ldap_manager.disconnect.assert_called_once()


def test_run_exits_nonzero_and_disconnects_when_serve_fails() -> None:
    with _offline_env(HTTP_MOD):
        server = _http_server()
        server.serve = AsyncMock(side_effect=RuntimeError("boom"))
        server.ldap_manager = MagicMock()
        server.logger = MagicMock()
        with pytest.raises(SystemExit) as exc:
            server.run()
        assert exc.value.code == 1
        server.ldap_manager.disconnect.assert_called_once()
        assert server.logger.error.called


def test_stdio_registers_once_with_42_tools_and_error_shape() -> None:
    import mcp.types as types

    import active_directory_mcp.server as mod

    with _offline_env(STDIO_MOD):
        with patch.object(mod, "register_tools", wraps=mod.register_tools) as spy:
            server = mod.ActiveDirectoryMCPServer()
        spy.assert_called_once()
        assert len(server._tools) == 42

        handler = server.mcp.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="no_such_tool", arguments={}),
        )
        result = asyncio.run(handler(req))
        text = result.root.content[0].text
        assert json.loads(text) == {"error": "Unknown tool: no_such_tool"}


def test_stdio_handler_exception_returns_error_json() -> None:
    import mcp.types as types

    import active_directory_mcp.server as mod

    with _offline_env(STDIO_MOD):
        server = mod.ActiveDirectoryMCPServer()
        server.user_tools.get_user = MagicMock(side_effect=RuntimeError("kaboom"))
        handler = server.mcp.request_handlers[types.CallToolRequest]
        req = types.CallToolRequest(
            method="tools/call",
            params=types.CallToolRequestParams(name="get_user", arguments={"username": "x"}),
        )
        result = asyncio.run(handler(req))
        assert json.loads(result.root.content[0].text) == {"error": "kaboom"}
