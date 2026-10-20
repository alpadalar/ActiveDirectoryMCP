"""Subprocess regression test: SIGTERM/SIGINT must disconnect LDAP and exit 0 (WR-01).

uvicorn re-raises a captured SIGTERM before ``serve()`` returns, so cleanup that
only ran after ``serve()`` was skipped and the process died with exit code 143.
"""

import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from tests.support.mock_directory import MockDirectory

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

CHILD = textwrap.dedent(
    """
    import sys
    from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer
    from tests.support.mock_directory import MockDirectory

    marker, port = sys.argv[1], int(sys.argv[2])
    directory = MockDirectory()
    with directory.patch():
        server = ActiveDirectoryMCPHTTPServer(config_path=None, host="127.0.0.1", port=port)
        real = server.ldap_manager.disconnect

        def spy():
            with open(marker, "a") as fh:
                fh.write("disconnect\\n")
            real()

        server.ldap_manager.disconnect = spy
        server.run()
    """
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_listening(port: int, proc: subprocess.Popen, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise AssertionError(f"server exited early with {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError("server did not start listening in time")


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_signal_disconnects_ldap_and_exits_zero(tmp_path: Path, sig: int) -> None:
    directory = MockDirectory()
    env = {**os.environ, **directory.env(tmp_path)}
    for var in ("AD_BIND_DN", "AZURE_KEYVAULT_URL"):
        env.pop(var, None)
    repo_root = Path(__file__).resolve().parents[2]
    env["PYTHONPATH"] = os.pathsep.join(
        [str(repo_root), str(repo_root / "src"), env.get("PYTHONPATH", "")]
    )
    marker = tmp_path / "disconnect.log"
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(marker), str(port)],
        env=env,
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_listening(port, proc)
        proc.send_signal(sig)
        _, err = proc.communicate(timeout=20)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    assert proc.returncode == 0, err.decode(errors="replace")[-2000:]
    assert marker.exists() and "disconnect" in marker.read_text()
