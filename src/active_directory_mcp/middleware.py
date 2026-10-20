"""Pure-ASGI middleware for the HTTP transport.

Phase 4 contract: authentication middleware is added to the served app by
extending :func:`default_middleware` (or through ``extra_middleware`` of
``build_http_app``). It MUST exempt ``http_app.HEALTH_PATH`` so container health
checks stay unauthenticated.

The classes here are plain ASGI (not ``BaseHTTPMiddleware``) so streaming and SSE
responses are never buffered.
"""

import logging
import re
import uuid
from typing import List, MutableMapping

from starlette.middleware import Middleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("active-directory-mcp.middleware")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_REQUEST_ID_HEADER = b"x-request-id"


class RequestContextMiddleware:
    """Attach a request id and baseline security headers to every HTTP response."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    @staticmethod
    def _request_id(scope: Scope) -> str:
        for key, value in scope.get("headers", []):
            if key.lower() == _REQUEST_ID_HEADER:
                try:
                    candidate: str = value.decode("ascii")
                except UnicodeDecodeError:
                    break
                if _REQUEST_ID_RE.fullmatch(candidate):
                    return candidate
                break
        return uuid.uuid4().hex

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = self._request_id(scope)
        state: MutableMapping[str, object] = scope.setdefault("state", {})
        state["request_id"] = request_id

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [
                    (k, v)
                    for k, v in message.get("headers", [])
                    if k.lower() not in (_REQUEST_ID_HEADER, b"x-content-type-options")
                ]
                has_cache_control = any(k.lower() == b"cache-control" for k, _ in headers)
                headers.append((_REQUEST_ID_HEADER, request_id.encode("ascii")))
                headers.append((b"x-content-type-options", b"nosniff"))
                if not has_cache_control:
                    headers.append((b"cache-control", b"no-store"))
                message = {**message, "headers": headers}
                logger.debug(
                    "request method=%s path=%s status=%s id=%s",
                    scope.get("method"),
                    scope.get("path"),
                    message.get("status"),
                    request_id,
                )
            await send(message)

        await self.app(scope, receive, send_wrapper)


def default_middleware() -> List[Middleware]:
    """Middleware applied to every route of the served app, outermost first."""
    return [Middleware(RequestContextMiddleware)]
