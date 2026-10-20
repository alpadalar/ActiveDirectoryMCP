"""SEC-02: hashed API-key verification, pure-ASGI middleware and fail-fast resolution."""

import hashlib
import logging
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from active_directory_mcp import auth
from active_directory_mcp.auth import (
    ApiKeyAuthMiddleware,
    HTTPAuthConfigError,
    TokenVerifier,
    resolve_auth,
)
from active_directory_mcp.config.models import SecurityConfig
from active_directory_mcp.middleware import RequestContextMiddleware

KEY = "unit-test-key-" + "a" * 20
OTHER = "other-test-key-" + "b" * 20
EXEMPT = [("GET", "/health"), ("HEAD", "/health")]


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _app(*keys: str) -> Starlette:
    async def ok(request: Any) -> PlainTextResponse:
        return PlainTextResponse("ok")

    verifier = TokenVerifier([sha(k) for k in (keys or (KEY,))])
    return Starlette(
        routes=[
            Route("/health", ok, methods=["GET", "HEAD", "POST"]),
            Route("/mcp", ok, methods=["GET", "POST"]),
        ],
        middleware=[
            Middleware(RequestContextMiddleware),
            Middleware(ApiKeyAuthMiddleware, verifier=verifier, exempt=EXEMPT),
        ],
    )


@pytest.fixture
def client() -> TestClient:
    return TestClient(_app())


def test_valid_bearer_and_lowercase_scheme(client: TestClient) -> None:
    assert client.get("/mcp", headers={"Authorization": f"Bearer {KEY}"}).status_code == 200
    assert client.get("/mcp", headers={"Authorization": f"bearer {KEY}"}).status_code == 200


def test_valid_x_api_key(client: TestClient) -> None:
    assert client.get("/mcp", headers={"X-API-Key": KEY}).status_code == 200


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer"},
        {"Authorization": f"Basic {KEY}"},
        {"Authorization": f"Bearer {OTHER}"},
        {"X-API-Key": OTHER},
        {"X-API-Key": ""},
    ],
)
def test_rejected(client: TestClient, headers: Dict[str, str]) -> None:
    resp = client.get("/mcp", headers=headers)
    assert resp.status_code == 401
    assert resp.json() == {"error": "unauthorized"}
    assert resp.headers["www-authenticate"] == "Bearer"
    assert resp.headers["x-request-id"]
    assert resp.headers["cache-control"] == "no-store"


def test_authorization_wins_over_x_api_key(client: TestClient) -> None:
    both_bad_auth = {"Authorization": f"Bearer {OTHER}", "X-API-Key": KEY}
    assert client.get("/mcp", headers=both_bad_auth).status_code == 401
    both_good_auth = {"Authorization": f"Bearer {KEY}", "X-API-Key": OTHER}
    assert client.get("/mcp", headers=both_good_auth).status_code == 200


def test_health_exemptions_exact(client: TestClient) -> None:
    assert client.get("/health").status_code == 200
    assert client.head("/health").status_code == 200
    assert client.get("/health", headers={"X-API-Key": OTHER}).status_code == 200
    assert client.post("/health").status_code == 401
    assert client.get("/health/").status_code == 401


def test_unknown_path_is_401_not_404(client: TestClient) -> None:
    assert client.get("/nope").status_code == 401


def test_no_token_or_digest_leaks(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    resp = client.get("/mcp", headers={"Authorization": f"Bearer {OTHER}", "X-API-Key": OTHER})
    blob = resp.text + str(dict(resp.headers)) + caplog.text
    for secret in (OTHER, KEY, sha(OTHER), sha(KEY)):
        assert secret not in blob
    assert "auth failure" in caplog.text


def test_verifier_compares_every_digest() -> None:
    digests = [sha(f"k{i}" * 12) for i in range(4)]
    verifier = TokenVerifier(digests)
    real = auth.hmac.compare_digest
    for token, expected in (("k0" * 12, True), ("k3" * 12, True), ("nope", False)):
        calls: List[int] = []

        def spy(a: Any, b: Any, calls: List[int] = calls) -> bool:
            calls.append(1)
            return real(a, b)

        with patch.object(auth.hmac, "compare_digest", spy):
            assert verifier.verify(token) is expected
        assert len(calls) == len(digests)


def test_verifier_edge_cases_and_repr() -> None:
    verifier = TokenVerifier([sha(KEY)])
    assert not verifier.verify("") and not verifier.verify(None)
    assert verifier.verify("é\ud800") is False
    assert sha(KEY) not in repr(verifier) and "TokenVerifier" in repr(verifier)
    with pytest.raises(HTTPAuthConfigError):
        TokenVerifier(["not-a-digest"])


def test_middleware_is_pure_asgi() -> None:
    assert not issubclass(ApiKeyAuthMiddleware, BaseHTTPMiddleware)


def test_lifespan_passes_through() -> None:
    with TestClient(_app()):
        pass  # lifespan startup/shutdown must not be blocked by auth


def _sec(**http_auth: Any) -> SecurityConfig:
    return SecurityConfig(http_auth=http_auth)


def test_resolve_config_digest() -> None:
    verifier = resolve_auth(_sec(api_key_sha256=[sha(KEY)]), {})
    assert verifier is not None and verifier.verify(KEY)


def test_resolve_env_digests_comma_separated() -> None:
    verifier = resolve_auth(_sec(), {auth.ENV_API_KEY_SHA256: f"{sha(KEY)}, {sha(OTHER)}"})
    assert verifier is not None and verifier.verify(KEY) and verifier.verify(OTHER)


def test_resolve_env_plaintext_hashed_not_retained() -> None:
    verifier = resolve_auth(_sec(), {auth.ENV_API_KEY: KEY})
    assert verifier is not None and verifier.verify(KEY)
    assert KEY.encode() not in b"".join(verifier._digests)


def test_resolve_short_plaintext_rejected_without_echo() -> None:
    with pytest.raises(HTTPAuthConfigError) as exc:
        resolve_auth(_sec(), {auth.ENV_API_KEY: "short"})
    assert "short" not in str(exc.value).replace("shortest", "")


def test_resolve_none_required_raises_with_guidance() -> None:
    with pytest.raises(HTTPAuthConfigError) as exc:
        resolve_auth(_sec(), {})
    msg = str(exc.value)
    assert "secrets.token_urlsafe" in msg and auth.ENV_API_KEY in msg
    assert "sha256" in msg and "required to false" in msg


def test_resolve_none_not_required_warns(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="active-directory-mcp.auth")
    assert resolve_auth(_sec(required=False), {}) is None
    assert "DISABLED" in caplog.text


def test_resolve_env_plaintext_is_stripped_like_presented_header() -> None:
    verifier = resolve_auth(_sec(), {auth.ENV_API_KEY: f"{KEY}\n"})
    assert verifier is not None and verifier.verify(KEY)
    verifier = resolve_auth(_sec(), {auth.ENV_API_KEY: f"  {KEY} "})
    assert verifier is not None and verifier.verify(KEY)


def test_resolve_env_plaintext_length_counted_after_strip() -> None:
    padded = "short" + " " * 30
    with pytest.raises(HTTPAuthConfigError):
        resolve_auth(_sec(), {auth.ENV_API_KEY: padded})


def test_auth_failure_log_neutralises_request_path(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    client.get("/%0a2099-01-01 CRITICAL forged%0d" + "x" * 500)
    messages = [r.getMessage() for r in caplog.records if "auth failure" in r.getMessage()]
    assert messages
    for message in messages:
        assert "\n" not in message and "\r" not in message
        assert len(message) < 400


def test_key_id_identifies_the_matching_key_only() -> None:
    import hashlib

    token = "k" * 30
    digest = hashlib.sha256(token.encode()).hexdigest()
    verifier = TokenVerifier([digest])
    assert verifier.key_id(token) == digest[:8]
    assert verifier.key_id("wrong") is None and verifier.key_id(None) is None


def test_authenticated_request_sets_audit_actor() -> None:
    import hashlib

    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    from active_directory_mcp.audit import audit_actor

    token = "z" * 30
    digest = hashlib.sha256(token.encode()).hexdigest()
    seen = {}

    async def endpoint(request):  # type: ignore[no-untyped-def]
        seen["actor"] = audit_actor.get()
        return JSONResponse({})

    app = Starlette(
        routes=[Route("/x", endpoint)],
        middleware=[Middleware(ApiKeyAuthMiddleware, verifier=TokenVerifier([digest]))],
    )
    TestClient(app).get("/x", headers={"X-API-Key": token})
    assert seen["actor"]["key_id"] == digest[:8]
    assert token not in str(seen["actor"])
    assert audit_actor.get() is None
