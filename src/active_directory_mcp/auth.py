"""API-key authentication for the HTTP transport (SEC-02).

Design:

* Credentials are held only as SHA-256 digests. Verification hashes the presented
  token and compares it against EVERY configured digest with
  :func:`hmac.compare_digest`, without early exit, so timing reveals neither which
  digest matched nor how long the token was (digests are fixed length).
* :class:`ApiKeyAuthMiddleware` is plain ASGI (not ``BaseHTTPMiddleware``) so
  streamed/SSE responses are never buffered.
* Secrets stay out of JSON files by design: the config file may carry digests
  (``security.http_auth.api_key_sha256``) but there is deliberately NO plaintext
  key field. Plaintext keys come from the environment (``AD_MCP_HTTP_API_KEY``)
  and are hashed immediately; the plaintext is not retained.
* Header values are never logged and never echoed in responses.

This module is used by the HTTP transport only; the stdio server does not import it.
"""

import hashlib
import hmac
import json
import logging
import re
from typing import Collection, Iterable, List, Mapping, Optional, Tuple

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .audit import audit_actor
from .config.models import SecurityConfig

logger = logging.getLogger("active-directory-mcp.auth")

ENV_API_KEY = "AD_MCP_HTTP_API_KEY"
ENV_API_KEY_SHA256 = "AD_MCP_HTTP_API_KEY_SHA256"
MIN_KEY_LENGTH = 24

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")


class HTTPAuthConfigError(Exception):
    """The HTTP transport authentication is missing or misconfigured."""


def _digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest().encode("ascii")


class TokenVerifier:
    """Constant-time verifier over a set of SHA-256 hex digests."""

    __slots__ = ("_digests",)

    def __init__(self, digests: Iterable[str]) -> None:
        stored: List[bytes] = []
        for item in digests:
            value = item.strip().lower()
            if not _DIGEST_RE.match(value):
                raise HTTPAuthConfigError("API key digests must be 64 lowercase hex characters")
            stored.append(value.encode("ascii"))
        self._digests = tuple(stored)

    def __repr__(self) -> str:
        return "<TokenVerifier>"

    def __len__(self) -> int:
        return len(self._digests)

    def verify(self, token: Optional[str]) -> bool:
        if not token:
            return False
        try:
            presented = _digest(token)
        except Exception:
            return False
        matched = False
        for stored in self._digests:
            # Evaluate every digest; OR the results (no early return).
            matched |= hmac.compare_digest(presented, stored)
        return matched

    def key_id(self, token: Optional[str]) -> Optional[str]:
        """Short non-secret id (first 8 hex of the SHA-256) of the matching key, else None."""
        if not token:
            return None
        try:
            presented = _digest(token)
        except Exception:
            return None
        found: Optional[str] = None
        for stored in self._digests:
            if hmac.compare_digest(presented, stored):
                found = presented[:8].decode("ascii")
        return found


def resolve_auth(security: SecurityConfig, environ: Mapping[str, str]) -> Optional[TokenVerifier]:
    """Collect credentials from config and environment.

    Returns a verifier when any credential exists. With none, raises
    :class:`HTTPAuthConfigError` if ``http_auth.required`` (default) else returns
    ``None`` after logging a warning.
    """
    digests: List[str] = list(security.http_auth.api_key_sha256)

    env_digests = environ.get(ENV_API_KEY_SHA256, "")
    for part in env_digests.split(","):
        part = part.strip()
        if part:
            digests.append(part)

    # Strip like the presented header (_extract), so a trailing newline from an env_file or
    # secret file cannot make the stored key unmatchable.
    plaintext = environ.get(ENV_API_KEY, "").strip()
    if plaintext:
        if len(plaintext) < MIN_KEY_LENGTH:
            raise HTTPAuthConfigError(
                f"{ENV_API_KEY} must be at least {MIN_KEY_LENGTH} characters. Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(32))"'
            )
        digests.append(_digest(plaintext).decode("ascii"))
        del plaintext

    if digests:
        return TokenVerifier(digests)

    if security.http_auth.required:
        raise HTTPAuthConfigError(
            "The HTTP transport requires an API key and none is configured. To create one run: "
            'python -c "import secrets; print(secrets.token_urlsafe(32))" '
            f"and set it in the environment as {ENV_API_KEY}. To avoid keeping the plaintext on "
            "the server, store its SHA-256 hex digest in "
            f"{ENV_API_KEY_SHA256} (comma-separated for several keys) or in "
            "security.http_auth.api_key_sha256 instead "
            '(python -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode())'
            '.hexdigest())" <key>). Clients send it as "Authorization: Bearer <key>" or '
            '"X-API-Key: <key>". To explicitly run without authentication (not recommended) '
            "set security.http_auth.required to false in the configuration file."
        )
    logger.warning(
        "HTTP transport authentication is DISABLED (security.http_auth.required=false): "
        "anyone who can reach this port can call the tools"
    )
    return None


class ApiKeyAuthMiddleware:
    """Pure-ASGI API-key gate; ``exempt`` is a collection of (METHOD, path) pairs."""

    def __init__(
        self,
        app: ASGIApp,
        verifier: TokenVerifier,
        exempt: Collection[Tuple[str, str]] = (),
    ) -> None:
        self.app = app
        self.verifier = verifier
        self.exempt = frozenset((m.upper(), p) for m, p in exempt)

    @staticmethod
    def _extract(scope: Scope) -> Optional[str]:
        bearer: Optional[str] = None
        api_key: Optional[str] = None
        for name, value in scope.get("headers", []):
            lname = name.lower()
            if lname == b"authorization" and bearer is None:
                try:
                    text = value.decode("latin-1")
                except Exception:
                    return None
                scheme, _, rest = text.partition(" ")
                if scheme.lower() == "bearer":
                    bearer = rest.strip()
                else:
                    bearer = ""
            elif lname == b"x-api-key" and api_key is None:
                try:
                    api_key = value.decode("latin-1").strip()
                except Exception:
                    api_key = ""
        if bearer is not None:
            return bearer  # Authorization wins when both are present
        return api_key

    def _is_exempt(self, scope: Scope) -> bool:
        return (scope.get("method", "").upper(), scope.get("path", "")) in self.exempt

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "http":
            if self._is_exempt(scope):
                await self.app(scope, receive, send)
                return
            token = self._extract(scope)
            if self.verifier.verify(token):
                client = scope.get("client")
                actor = {"key_id": self.verifier.key_id(token) or "-"}
                if client:
                    actor["client"] = str(client[0])
                actor["request_id"] = str(scope.get("state", {}).get("request_id", "-"))
                reset = audit_actor.set(actor)
                try:
                    await self.app(scope, receive, send)
                finally:
                    audit_actor.reset(reset)
                return
            await self._deny_http(scope, send)
            return
        if kind == "websocket":
            if self.verifier.verify(self._extract(scope)):
                await self.app(scope, receive, send)
                return
            await receive()
            await send({"type": "websocket.close", "code": 1008})
            return
        await self.app(scope, receive, send)

    async def _deny_http(self, scope: Scope, send: Send) -> None:
        request_id = scope.get("state", {}).get("request_id", "-")
        logger.warning(
            "auth failure method=%s path=%.200r request_id=%s",
            scope.get("method"),
            scope.get("path"),
            request_id,
        )
        body = json.dumps({"error": "unauthorized"}).encode("utf-8")
        start: Message = {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"www-authenticate", b"Bearer"),
                (b"cache-control", b"no-store"),
            ],
        }
        await send(start)
        await send({"type": "http.response.body", "body": body})
