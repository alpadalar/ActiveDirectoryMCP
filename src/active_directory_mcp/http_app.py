"""The single factory for the served HTTP application.

``build_http_app`` is the only place an ASGI app is produced from a FastMCP
instance; ``ActiveDirectoryMCPHTTPServer.serve`` hands exactly that object to
uvicorn.

Authentication (SEC-02): when a ``TokenVerifier`` is supplied the pure-ASGI
``ApiKeyAuthMiddleware`` is composed inside ``RequestContextMiddleware`` (so 401s
carry ``x-request-id``) and exempts exactly ``GET|HEAD HEALTH_PATH`` so container
health checks stay unauthenticated. The factory fails closed: without a verifier
it raises unless ``allow_unauthenticated=True`` is passed explicitly.
"""

from typing import Any, Optional, Sequence

from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .auth import ApiKeyAuthMiddleware, HTTPAuthConfigError, TokenVerifier
from .middleware import default_middleware

HEALTH_PATH = "/health"


def build_http_app(
    mcp: Any,
    *,
    path: str,
    auth: Optional[TokenVerifier] = None,
    allow_unauthenticated: bool = False,
    extra_middleware: Sequence[Middleware] = (),
) -> Any:
    """Build the Starlette app for ``mcp`` with middleware and the liveness route.

    Raises ``HTTPAuthConfigError`` when ``auth`` is None and ``allow_unauthenticated``
    is not explicitly True (fail closed).

    ``/health`` is liveness only: it performs no LDAP I/O and discloses no
    hostnames or credentials. The auth-gated ``health`` MCP tool reports LDAP state.
    """

    async def health(request: Request) -> JSONResponse:
        # Lazy import: the package __init__ imports server modules at import time.
        from . import __version__

        return JSONResponse({"status": "ok", "server": mcp.name, "version": __version__})

    middleware = default_middleware()
    if auth is not None:
        middleware.append(
            Middleware(
                ApiKeyAuthMiddleware,
                verifier=auth,
                exempt=[("GET", HEALTH_PATH), ("HEAD", HEALTH_PATH)],
            )
        )
    elif not allow_unauthenticated:
        raise HTTPAuthConfigError(
            "build_http_app requires an auth verifier or allow_unauthenticated=True"
        )
    app = mcp.http_app(path=path, middleware=[*middleware, *extra_middleware])
    app.add_route(HEALTH_PATH, health, methods=["GET", "HEAD"], name="health")
    return app
