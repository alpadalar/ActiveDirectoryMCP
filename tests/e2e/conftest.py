"""Live-uvicorn fixtures for the end-to-end tests (CONS-03).

``serve_asgi_in_thread`` owns the ephemeral loopback socket, the server thread,
the bounded readiness wait and an idempotent shutdown. The same helper serves the
real ``ActiveDirectoryMCPHTTPServer`` and the negative-control app.
"""

import asyncio
import os
import socket
import threading
import time
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine, Iterator, Optional
from unittest.mock import patch

import pytest
import uvicorn

from tests.support.mock_directory import MockDirectory

READY_TIMEOUT = 5.0


@dataclass
class ServedApp:
    host: str
    port: int
    thread: threading.Thread
    sock: socket.socket
    stop: Callable[[], None]
    server: Any = None
    extra: dict = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@contextmanager
def serve_asgi_in_thread(
    make_coro: Callable[[socket.socket], Coroutine[Any, Any, None]],
    stop: Callable[[], None],
    is_ready: Callable[[], bool],
) -> Iterator[ServedApp]:
    """Run ``make_coro(sock)`` in a daemon thread bound to an ephemeral 127.0.0.1 port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    errors: list = []

    def target() -> None:
        try:
            asyncio.run(make_coro(sock))
        except BaseException as exc:  # surfaced through the readiness failure message
            errors.append(exc)

    thread = threading.Thread(target=target, name="e2e-uvicorn", daemon=True)
    stopped = False

    def stop_once() -> None:
        nonlocal stopped
        if not stopped:
            stopped = True
            stop()

    try:
        thread.start()
        deadline = time.monotonic() + READY_TIMEOUT
        while not is_ready():
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError(
                    f"served app did not become ready within {READY_TIMEOUT}s "
                    f"(thread alive={thread.is_alive()}, error={errors[:1]!r})"
                )
            time.sleep(0.05)
        yield ServedApp("127.0.0.1", port, thread, sock, stop_once)
    finally:
        stop_once()
        thread.join(5)
        alive = thread.is_alive()
        sock.close()
        assert not alive, "uvicorn thread did not stop"


@contextmanager
def serve_bare_app(app: Any) -> Iterator[ServedApp]:
    """Serve any ASGI app (negative control) through the same helper."""
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="on"))

    def stop() -> None:
        server.should_exit = True

    with serve_asgi_in_thread(
        lambda sock: server.serve(sockets=[sock]), stop, lambda: server.started
    ) as served:
        served.server = server
        yield served


@contextmanager
def serve_ad_http(tmp_path: Path, directory: MockDirectory, **server_kwargs: Any) -> Iterator[ServedApp]:
    """Build ActiveDirectoryMCPHTTPServer over the mock directory and serve it live."""
    from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

    with ExitStack() as stack:
        stack.enter_context(directory.patch())
        stack.enter_context(patch.dict(os.environ, directory.env(tmp_path)))
        for var in ("AD_BIND_DN", "AZURE_KEYVAULT_URL"):
            os.environ.pop(var, None)
        server = ActiveDirectoryMCPHTTPServer(
            config_path=None, host="127.0.0.1", port=0, **server_kwargs
        )
        spy_state: dict = {}

        def ready() -> bool:
            uv = server._uvicorn_server
            return bool(uv is not None and uv.started)

        with serve_asgi_in_thread(
            lambda sock: server.serve(sockets=[sock]), server.stop, ready
        ) as served:
            served.server = server
            served.extra = spy_state
            try:
                yield served
            finally:
                server.ldap_manager.disconnect()


@pytest.fixture
def mock_directory() -> MockDirectory:
    directory = MockDirectory()
    directory.add_user("alice")
    directory.add_user("bob")
    return directory


@pytest.fixture
def served_http_server(tmp_path: Path, mock_directory: MockDirectory) -> Iterator[ServedApp]:
    with serve_ad_http(tmp_path, mock_directory, path="/mcp") as served:
        yield served
