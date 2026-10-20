"""FEAT-01: JSON-lines audit trail for write/destructive tool calls."""

import asyncio
import base64
import json
import os
import stat
import threading
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock

import pytest
from fastmcp import Client, FastMCP

from active_directory_mcp.audit import (
    AUDIT_TARGET_KEYS,
    AuditConfigError,
    AuditLogger,
    build_record,
    classify_outcome,
)
from active_directory_mcp.config.models import SecurityConfig
from active_directory_mcp.policy import ToolPolicy
from active_directory_mcp.redaction import REDACTED, clear_secrets, register_secret
from active_directory_mcp.registry import (
    FastMCPToolSink,
    StdioToolSink,
    register_tools,
)
from tests.unit.test_registry import make_ctx


@pytest.fixture(autouse=True)
def _clean_secrets() -> Any:
    clear_secrets()
    yield
    clear_secrets()


def _lines(path: Path) -> List[Dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    return [json.loads(line) for line in text.split("\n") if line]


def test_build_record_schema_and_default_deny() -> None:
    rec = build_record(
        "create_user",
        "write",
        {
            "username": "bob",
            "password": "Sup3r-Secret!",
            "first_name": "Bob",
            "additional_attributes": {"title": "VP", "mail": "x@y"},
        },
        "success",
    )
    assert rec["tool"] == "create_user" and rec["risk"] == "write"
    assert rec["outcome"] == "success"
    assert rec["ts"].endswith("+00:00")
    assert rec["target"] == {"username": "bob"}
    assert rec["redacted_args"] == {
        "password": REDACTED,
        "first_name": REDACTED,
        "additional_attributes": {"title": REDACTED, "mail": REDACTED},
    }
    assert "error_code" not in rec
    assert set(AUDIT_TARGET_KEYS) >= {"username", "ou_dn", "new_parent_dn"}


def test_target_values_pass_through_redact() -> None:
    register_secret("tok-123", persistent=False)
    rec = build_record("create_group", "write", {"group_name": "g-tok-123"}, "success")
    assert "tok-123" not in json.dumps(rec)


def test_error_code_recorded() -> None:
    rec = build_record("delete_user", "destructive", {"username": "u"}, "blocked", "x_blocked")
    assert rec["error_code"] == "x_blocked"


def test_audit_file_mode_and_one_line_per_record(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    log = AuditLogger(str(path))
    log.record("create_user", "write", {"username": "a\nb c"}, "success")
    log.record("delete_user", "destructive", {"username": "z"}, "blocked", "destructive_blocked")
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    raw = path.read_text(encoding="utf-8")
    assert len(raw.splitlines()) == 2 and len(raw.split("\n")) == 3
    first = json.loads(raw.split("\n")[0])
    assert first["target"]["username"] == "a\nb c"


def test_appends_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "a.log"
    AuditLogger(str(path)).record("create_group", "write", {}, "success")
    AuditLogger(str(path)).record("create_group", "write", {}, "success")
    assert len(_lines(path)) == 2


def test_concurrent_writes_yield_valid_lines(tmp_path: Path) -> None:
    path = tmp_path / "c.log"
    log = AuditLogger(str(path))

    def work(n: int) -> None:
        for i in range(20):
            log.record("create_user", "write", {"username": f"u{n}-{i}"}, "success")

    threads = [threading.Thread(target=work, args=(n,)) for n in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_lines(path)) == 1000


def test_bad_path_raises_config_error(tmp_path: Path) -> None:
    with pytest.raises(AuditConfigError):
        AuditLogger(str(tmp_path / "missing-dir" / "audit.log"))
    with pytest.raises(AuditConfigError):
        AuditLogger(str(tmp_path))  # a directory


def test_existing_loose_file_is_tightened_to_0600(tmp_path: Path) -> None:
    path = tmp_path / "loose.log"
    path.write_text("")
    os.chmod(path, 0o644)
    AuditLogger(str(path))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_symlink_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "victim.txt"
    target.write_text("keep")
    link = tmp_path / "audit.log"
    link.symlink_to(target)
    with pytest.raises(AuditConfigError):
        AuditLogger(str(link))
    assert target.read_text() == "keep"


def test_fifo_is_refused(tmp_path: Path) -> None:
    fifo = tmp_path / "pipe.log"
    os.mkfifo(fifo)
    with pytest.raises(AuditConfigError):
        AuditLogger(str(fifo))


def test_rotation_by_rename_is_followed(tmp_path: Path) -> None:
    path = tmp_path / "r.log"
    log = AuditLogger(str(path))
    log.record("create_user", "write", {"username": "a"}, "success")
    rotated = tmp_path / "r.log.1"
    os.rename(path, rotated)
    log.record("create_user", "write", {"username": "b"}, "success")
    assert [r["target"]["username"] for r in _lines(rotated)] == ["a"]
    assert [r["target"]["username"] for r in _lines(path)] == ["b"]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_deleted_file_is_recreated(tmp_path: Path) -> None:
    path = tmp_path / "d.log"
    log = AuditLogger(str(path))
    os.unlink(path)
    log.record("create_user", "write", {"username": "a"}, "success")
    assert len(_lines(path)) == 1


def test_failed_writes_are_counted(tmp_path: Path) -> None:
    log = AuditLogger(str(tmp_path / "c.log"))
    assert log.failed_writes == 0 and log.healthy
    log.close()
    log.record("create_user", "write", {}, "success")
    assert log.failed_writes == 1 and not log.healthy


def test_record_never_raises_when_write_fails(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    log = AuditLogger(str(tmp_path / "x.log"))
    log.close()
    log.record("create_user", "write", {"password": "hunter2-secret"}, "success")
    assert "audit write failed" in caplog.text
    assert "hunter2-secret" not in caplog.text


def test_from_security(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    assert AuditLogger.from_security(SecurityConfig()) is None
    assert "without an audit trail" not in caplog.text
    assert AuditLogger.from_security(SecurityConfig(allow_writes=True)) is None
    assert caplog.text.count("without an audit trail") == 1
    sec = SecurityConfig(allow_writes=True, audit_log_path=str(tmp_path / "f.log"))
    assert isinstance(AuditLogger.from_security(sec), AuditLogger)
    with pytest.raises(AuditConfigError):
        AuditLogger.from_security(
            SecurityConfig(allow_writes=True, audit_log_path=str(tmp_path / "no" / "f.log"))
        )


def _text(payload: Any) -> List[Any]:
    return [MagicMock(text=json.dumps(payload))]


def test_classify_outcome() -> None:
    assert classify_outcome(_text({"success": True})) == ("success", None)
    assert classify_outcome(_text({"error_code": "write_blocked", "success": False})) == (
        "blocked",
        "write_blocked",
    )
    assert classify_outcome(_text({"success": False, "error_code": "not_found"})) == (
        "failure",
        "not_found",
    )
    assert classify_outcome(_text({"error": "boom"})) == ("failure", None)
    assert classify_outcome([MagicMock(text="not json")]) == ("success", None)
    assert classify_outcome({"success": False}) == ("failure", None)
    assert classify_outcome([]) == ("success", None)


# ------------------------------------------------------------ integration


def _ctx(path: Path, writes: bool = True, destructive: bool = False) -> Any:
    return make_ctx(
        policy=ToolPolicy(writes, destructive), audit=AuditLogger(str(path))
    )


def test_stdio_outcomes_and_reads_silent(tmp_path: Path) -> None:
    path = tmp_path / "s.log"
    ctx = _ctx(path)
    ctx.group_tools.create_group.return_value = {"success": True}
    ctx.user_tools.modify_user.return_value = {"success": False, "error_code": "not_found"}
    ctx.user_tools.get_user.return_value = {"success": True}
    sink = StdioToolSink()
    register_tools(ctx, sink)
    sink.dispatch("create_group", {"group_name": "g1"})
    sink.dispatch("delete_user", {"username": "bob"})
    sink.dispatch("modify_user", {"username": "bob", "attributes": {"title": "secret-title"}})
    sink.dispatch("get_user", {"username": "bob"})
    recs = _lines(path)
    assert [(r["tool"], r["outcome"]) for r in recs] == [
        ("create_group", "success"),
        ("delete_user", "blocked"),
        ("modify_user", "failure"),
    ]
    assert recs[1]["risk"] == "destructive" and recs[1]["error_code"] == "destructive_blocked"
    assert recs[2]["error_code"] == "not_found"
    assert "secret-title" not in path.read_text()


def test_fastmcp_transport_is_audited(tmp_path: Path) -> None:
    path = tmp_path / "f.log"
    ctx = _ctx(path)
    ctx.group_tools.create_group.return_value = {"success": True}

    async def run() -> None:
        mcp = FastMCP("t")
        register_tools(ctx, FastMCPToolSink(mcp))
        async with Client(mcp) as client:
            await client.call_tool("create_group", {"group_name": "g1"}, raise_on_error=False)
            await client.call_tool("delete_group", {"group_name": "g1"}, raise_on_error=False)
            await client.call_tool("get_group", {"group_name": "g1"}, raise_on_error=False)

    asyncio.run(run())
    recs = _lines(path)
    assert [(r["tool"], r["outcome"]) for r in recs] == [
        ("create_group", "success"),
        ("delete_group", "blocked"),
    ]
    assert recs[0]["target"] == {"group_name": "g1"}


def test_exception_records_error_and_reraises(tmp_path: Path) -> None:
    path = tmp_path / "e.log"
    ctx = _ctx(path)
    ctx.user_tools.enable_user.side_effect = RuntimeError("kaboom")
    sink = StdioToolSink()
    register_tools(ctx, sink)
    with pytest.raises(RuntimeError):
        sink.dispatch("enable_user", {"username": "bob"})
    assert [(r["tool"], r["outcome"]) for r in _lines(path)] == [("enable_user", "error")]


def test_passwords_never_reach_the_file(tmp_path: Path) -> None:
    path = tmp_path / "p.log"
    ctx = _ctx(path)
    reset_pw = "Reset-Pw-9f3!x"
    create_pw = "Create-Pw-7a2#y"
    resp_pw = "Generated-Pw-5k1$z"
    register_secret(reset_pw, persistent=False)
    register_secret(create_pw, persistent=False)
    ctx.user_tools.reset_password.return_value = {"success": True, "new_password": resp_pw}
    ctx.user_tools.create_user.return_value = {"success": True}
    ctx.computer_tools.reset_computer_password.return_value = {
        "success": True,
        "password": resp_pw,
    }
    sink = StdioToolSink()
    register_tools(ctx, sink)
    sink.dispatch("reset_user_password", {"username": "bob", "new_password": reset_pw})
    sink.dispatch(
        "create_user",
        {
            "username": "carl",
            "password": create_pw,
            "first_name": "C",
            "last_name": "D",
            "additional_attributes": {"description": create_pw},
        },
    )
    sink.dispatch("reset_computer_password", {"computer_name": "PC1"})
    raw = path.read_text()
    assert len(raw.splitlines()) == 3
    for secret in (reset_pw, create_pw, resp_pw):
        variants = {
            secret,
            base64.b64encode(secret.encode()).decode(),
            base64.b64encode(('"' + secret + '"').encode("utf-16-le")).decode(),
        }
        for variant in variants:
            assert variant not in raw
    assert "carl" in raw  # identifying target is kept


def test_newline_in_username_stays_one_line(tmp_path: Path) -> None:
    path = tmp_path / "n.log"
    ctx = _ctx(path)
    ctx.user_tools.disable_user.return_value = {"success": True}
    sink = StdioToolSink()
    register_tools(ctx, sink)
    sink.dispatch("disable_user", {"username": 'x\n{"forged":true}\r'})
    assert len(path.read_text().splitlines()) == 1
    assert "forged" not in _lines(path)[0]["target"].keys()


def test_audit_none_leaves_behaviour_unchanged() -> None:
    ctx = make_ctx(policy=ToolPolicy(True, True))
    ctx.group_tools.create_group.return_value = {"success": True}
    sink = StdioToolSink()
    register_tools(ctx, sink)
    out = sink.dispatch("create_group", {"group_name": "g"})
    assert json.loads(out[0].text) == {"success": True}
