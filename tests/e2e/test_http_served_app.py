"""CONS-03: the middleware and /health run on the app that is actually served."""

import asyncio
import json
import socket
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import fastmcp
import httpx
import pytest
from fastmcp.client.transports import StreamableHttpTransport

from tests.e2e.conftest import ServedApp, serve_ad_http, serve_bare_app
from tests.support.mock_directory import MockDirectory

GOLDEN = Path(__file__).resolve().parents[1] / "golden" / "tool_surface_http.json"
INIT_BODY = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "e2e-probe", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def probe_served_app(base_url: str, mcp_path: str) -> Dict[str, Any]:
    """Observe statuses and headers of /health and an MCP initialize POST."""
    out: Dict[str, Any] = {}
    health = httpx.get(f"{base_url}/health", timeout=5)
    out["health_status"] = health.status_code
    out["health_headers"] = dict(health.headers)
    with httpx.stream(
        "POST", f"{base_url}{mcp_path}", json=INIT_BODY, headers=MCP_HEADERS, timeout=5
    ) as resp:
        out["mcp_status"] = resp.status_code
        out["mcp_headers"] = dict(resp.headers)
    return out


def _golden_names() -> set:
    return set(json.loads(GOLDEN.read_text(encoding="utf-8"))["tools"])


def _client(served: ServedApp, path: str = "/mcp") -> fastmcp.Client:
    return fastmcp.Client(StreamableHttpTransport(f"{served.base_url}{path}"))


def test_health_is_unauthenticated_and_leak_free(
    served_http_server: ServedApp, mock_directory: MockDirectory
) -> None:
    url = f"{served_http_server.base_url}/health"
    resp = httpx.get(url, timeout=5)
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {"status", "server", "version"}
    assert body["status"] == "ok"
    for secret in (mock_directory.bind_dn, mock_directory.bind_password, "dc.test.local"):
        assert secret not in resp.text
    assert httpx.head(url, timeout=5).status_code == 200
    assert httpx.post(url, timeout=5).status_code == 405


def test_middleware_runs_on_served_http_app(served_http_server: ServedApp) -> None:
    observed = probe_served_app(served_http_server.base_url, "/mcp")
    assert observed["health_status"] == 200
    assert observed["mcp_status"] == 200
    for headers in (observed["health_headers"], observed["mcp_headers"]):
        assert len(headers["x-request-id"]) >= 8
        assert headers["x-content-type-options"] == "nosniff"
    assert observed["health_headers"]["cache-control"] == "no-store"

    echoed = httpx.get(
        f"{served_http_server.base_url}/health", headers={"X-Request-ID": "trace-123"}, timeout=5
    )
    assert echoed.headers["x-request-id"] == "trace-123"
    for hostile in ("bad id with space", "x" * 200):
        resp = httpx.get(
            f"{served_http_server.base_url}/health", headers={"X-Request-ID": hostile}, timeout=5
        )
        assert resp.headers["x-request-id"] != hostile
        assert len(resp.headers["x-request-id"]) <= 64


def test_mcp_client_session_end_to_end(served_http_server: ServedApp) -> None:
    async def scenario() -> None:
        async with _client(served_http_server) as client:
            tools = await client.list_tools()
            assert {t.name for t in tools} == _golden_names()
            assert len(tools) == 42

            health = await client.call_tool("health", {})
            info = json.loads(health.content[0].text)
            assert info["status"] in ("ok", "degraded")

            listed = await client.call_tool("list_users", {})
            text = listed.content[0].text
            assert "alice" in text and "bob" in text

            got = await client.call_tool("get_user", {"username": "alice"})
            assert "alice" in got.content[0].text

    asyncio.run(scenario())


def test_configured_path_is_the_served_path(tmp_path: Path, mock_directory: MockDirectory) -> None:
    with serve_ad_http(tmp_path, mock_directory, path="/mcp-e2e") as served:

        async def scenario() -> None:
            async with _client(served, "/mcp-e2e") as client:
                assert len(await client.list_tools()) == 42

        asyncio.run(scenario())
        default = httpx.get(f"{served.base_url}/activedirectory-mcp", timeout=5)
        assert default.status_code in (404, 405)


def test_negative_control_unwrapped_app_fails_probe() -> None:
    bare = fastmcp.FastMCP("control").http_app(path="/mcp")
    with serve_bare_app(bare) as served:
        observed = probe_served_app(served.base_url, "/mcp")
    assert observed["health_status"] == 404
    assert "x-request-id" not in observed["mcp_headers"]
    assert "x-request-id" not in observed["health_headers"]


def test_served_object_is_factory_output(tmp_path: Path, mock_directory: MockDirectory) -> None:
    import uvicorn

    from active_directory_mcp import server_http

    built: list = []
    configs: list = []
    real_build = server_http.build_http_app
    real_config = uvicorn.Config

    def build_spy(*args: Any, **kwargs: Any) -> Any:
        app = real_build(*args, **kwargs)
        built.append(app)
        return app

    def config_spy(app: Any, *args: Any, **kwargs: Any) -> Any:
        configs.append(app)
        return real_config(app, *args, **kwargs)

    with patch.object(server_http, "build_http_app", build_spy), patch.object(
        server_http.uvicorn, "Config", config_spy
    ):
        with serve_ad_http(tmp_path, mock_directory, path="/mcp"):
            pass
    assert len(built) == 1 and len(configs) == 1
    assert configs[0] is built[0]
    assert isinstance(configs[0], type(built[0]))


def test_teardown_releases_port_and_thread(tmp_path: Path, mock_directory: MockDirectory) -> None:
    with serve_ad_http(tmp_path, mock_directory, path="/mcp") as served:
        port, thread = served.port, served.thread
        assert httpx.get(f"{served.base_url}/health", timeout=5).status_code == 200
    assert not thread.is_alive()
    with pytest.raises(ConnectionError):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass
