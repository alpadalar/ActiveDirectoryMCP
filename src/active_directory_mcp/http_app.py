"""The single factory for the served HTTP application.

``build_http_app`` is the only place an ASGI app is produced from a FastMCP
instance; ``ActiveDirectoryMCPHTTPServer.serve`` hands exactly that object to
uvicorn.

Phase 4 contract: authentication middleware joins through
``middleware.default_middleware()`` / ``extra_middleware`` and MUST exempt
``HEALTH_PATH`` so container health checks stay unauthenticated. ``HEALTH_PATH``
is exported for that reason.
"""

from typing import Any, Sequence

from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .middleware import default_middleware

HEALTH_PATH = "/health"


def build_http_app(mcp: Any, *, path: str, extra_middleware: Sequence[Middleware] = ()) -> Any:
    """Build the Starlette app for ``mcp`` with middleware and the liveness route.

    ``/health`` is liveness only: it performs no LDAP I/O and discloses no
    hostnames or credentials. The auth-gated ``health`` MCP tool reports LDAP state.
    """

    async def health(request: Request) -> JSONResponse:
        # Lazy import: the package __init__ imports server modules at import time.
        from . import __version__

        return JSONResponse({"status": "ok", "server": mcp.name, "version": __version__})

    app = mcp.http_app(path=path, middleware=[*default_middleware(), *extra_middleware])
    app.add_route(HEALTH_PATH, health, methods=["GET", "HEAD"], name="health")
    return app
