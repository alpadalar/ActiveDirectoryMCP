"""Unit tests for build_http_app() and RequestContextMiddleware."""

import asyncio
from typing import Any, Dict, List

import pytest
from fastmcp import FastMCP
from starlette.middleware import Middleware
from starlette.testclient import TestClient
from starlette.types import ASGIApp, Receive, Scope, Send

from active_directory_mcp import __version__
from active_directory_mcp.http_app import HEALTH_PATH, build_http_app
from active_directory_mcp.middleware import RequestContextMiddleware, default_middleware

MCP_PATH = "/mcp"
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-03-26",
        "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"},
    },
}
MCP_HEADERS = {"Accept": "application/json, text/event-stream"}


def _mcp() -> FastMCP:
    mcp = FastMCP("test")

    @mcp.tool
    def ping() -> str:
        return "pong"

    return mcp


class _Marker:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async def wrapped(message: Dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                message = {**message, "headers": [*message["headers"], (b"x-marker", b"1")]}
            await send(message)

        await self.app(scope, receive, wrapped)


def test_health_unauthenticated_exact_body_and_headers() -> None:
    app = build_http_app(_mcp(), path=MCP_PATH)
    with TestClient(app) as client:
        resp = client.get(HEALTH_PATH)
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "server": "test", "version": __version__}
    assert set(resp.json()) == {"status", "server", "version"}
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-request-id"]


def test_health_rejects_post() -> None:
    with TestClient(build_http_app(_mcp(), path=MCP_PATH)) as client:
        assert client.post(HEALTH_PATH).status_code == 405


def test_mcp_route_reaches_handler_with_middleware_headers() -> None:
    with TestClient(build_http_app(_mcp(), path=MCP_PATH)) as client:
        resp = client.post(MCP_PATH, json=INIT, headers=MCP_HEADERS)
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["x-request-id"]


def test_valid_request_id_is_echoed() -> None:
    with TestClient(build_http_app(_mcp(), path=MCP_PATH)) as client:
        resp = client.get(HEALTH_PATH, headers={"X-Request-ID": "abc-123_4.5"})
    assert resp.headers["x-request-id"] == "abc-123_4.5"


@pytest.mark.parametrize("bad", ["a" * 65, "has space", "semi;colon", "tab\tchar", ""])
def test_invalid_request_id_is_replaced(bad: str) -> None:
    with TestClient(build_http_app(_mcp(), path=MCP_PATH)) as client:
        resp = client.get(HEALTH_PATH, headers={"X-Request-ID": bad})
    rid = resp.headers["x-request-id"]
    assert rid != bad
    assert len(rid) == 32 and rid.isalnum()


def test_extra_middleware_is_applied() -> None:
    app = build_http_app(_mcp(), path=MCP_PATH, extra_middleware=[Middleware(_Marker)])
    with TestClient(app) as client:
        resp = client.get(HEALTH_PATH)
    assert resp.headers["x-marker"] == "1"


def test_build_twice_gives_independent_apps_one_health_route_each() -> None:
    mcp = _mcp()
    first = build_http_app(mcp, path=MCP_PATH)
    second = build_http_app(mcp, path=MCP_PATH)
    assert first is not second
    for app in (first, second):
        assert [r.path for r in app.routes if getattr(r, "path", None) == HEALTH_PATH] == [
            HEALTH_PATH
        ]


def test_default_middleware_contains_request_context() -> None:
    assert [m.cls for m in default_middleware()] == [RequestContextMiddleware]


def _run(app: ASGIApp, scope: Scope) -> List[Dict[str, Any]]:
    sent: List[Dict[str, Any]] = []

    async def receive() -> Dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: Dict[str, Any]) -> None:
        sent.append(message)

    asyncio.run(app(scope, receive, send))  # type: ignore[arg-type]
    return sent


def test_existing_cache_control_not_overwritten() -> None:
    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"cache-control", b"no-cache")],
            }
        )
        await send({"type": "http.response.body", "body": b"x"})

    sent = _run(RequestContextMiddleware(inner), {"type": "http", "headers": []})
    headers = sent[0]["headers"]
    assert [v for k, v in headers if k == b"cache-control"] == [b"no-cache"]
    assert sent[1] == {"type": "http.response.body", "body": b"x"}


def test_non_http_scope_passes_through() -> None:
    seen: List[str] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(scope["type"])

    _run(RequestContextMiddleware(inner), {"type": "lifespan"})
    assert seen == ["lifespan"]
