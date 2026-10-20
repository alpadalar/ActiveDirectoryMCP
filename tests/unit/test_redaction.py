"""Tests for secret redaction and its logging wiring."""

import base64
import logging
import urllib.parse

import pytest
from pydantic import SecretStr

from active_directory_mcp import redaction
from active_directory_mcp.config.models import LoggingConfig
from active_directory_mcp.core.logging import setup_logging

SECRET = "S3cr3t!pw"


@pytest.fixture(autouse=True)
def _clean():
    redaction.clear_secrets()
    yield
    redaction.clear_secrets()


def test_redact_replaces_secret():
    redaction.register_secret(SECRET)
    assert redaction.redact(f"bind failed for pw {SECRET}") == "bind failed for pw ***REDACTED***"


def test_redact_unregistered_unchanged():
    assert redaction.redact("nothing here") == "nothing here"


def test_empty_and_none_ignored():
    redaction.register_secret(None)
    redaction.register_secret("")
    assert redaction.redact("abc") == "abc"


def test_secretstr_accepted():
    redaction.register_secret(SecretStr(SECRET))
    assert SECRET not in redaction.redact(f"x {SECRET} y")


def test_longest_first_and_multiple():
    redaction.register_secret("pass")
    redaction.register_secret("password123")
    redaction.register_secret("other")
    out = redaction.redact("password123 pass other")
    assert "pass" not in out.replace("***REDACTED***", "")
    assert out == "***REDACTED*** ***REDACTED*** ***REDACTED***"


def test_encoded_forms_redacted():
    redaction.register_secret(SECRET)
    assert urllib.parse.quote(SECRET) != SECRET
    assert urllib.parse.quote(SECRET) not in redaction.redact(urllib.parse.quote(SECRET))
    b64 = base64.b64encode(SECRET.encode()).decode()
    assert b64 not in redaction.redact(f"Basic {b64}")


def _record(msg, args=(), exc_info=None):
    return logging.LogRecord("t", logging.ERROR, __file__, 1, msg, args, exc_info)


def test_filter_scrubs_msg_args_tuple_and_never_drops():
    redaction.register_secret(SECRET)
    rec = _record("pw %s and %d", (SECRET, 5))
    assert redaction.RedactingFilter().filter(rec) is True
    assert SECRET not in rec.getMessage()
    assert "5" in rec.getMessage()


def test_filter_scrubs_dict_args():
    redaction.register_secret(SECRET)
    rec = _record("pw %(p)s", None)
    rec.args = {"p": SECRET}
    redaction.RedactingFilter().filter(rec)
    assert SECRET not in rec.getMessage()


def test_filter_scrubs_exception_text():
    redaction.register_secret(SECRET)
    try:
        raise RuntimeError(f"boom {SECRET}")
    except RuntimeError:
        import sys

        rec = _record("failed", exc_info=sys.exc_info())
    redaction.RedactingFilter().filter(rec)
    assert SECRET not in rec.exc_text
    assert "boom" in rec.exc_text


def test_setup_logging_redacts_stderr_and_file(tmp_path, capsys):
    redaction.register_secret(SECRET)
    log_file = tmp_path / "logs" / "ad.log"
    logger = setup_logging(LoggingConfig(level="DEBUG", file=str(log_file)))
    child = logging.getLogger("active-directory-mcp.Child")
    child.info("plain %s", SECRET)
    child.info(f"fstring {SECRET} {urllib.parse.quote(SECRET)}")
    try:
        raise ValueError(f"bad {SECRET}")
    except ValueError:
        child.exception("with traceback")
    for h in logger.handlers:
        h.flush()
    err = capsys.readouterr().err
    content = log_file.read_text()
    for text in (err, content):
        assert SECRET not in text
        assert urllib.parse.quote(SECRET) not in text
        assert "***REDACTED***" in text
    assert all(
        any(isinstance(f, redaction.RedactingFilter) for f in h.filters) for h in logger.handlers
    )
    for h in list(logger.handlers):
        h.close()
        logger.removeHandler(h)


# --- review fixes (WR-03, WR-04, WR-05, WR-06a) ------------------------------


def test_json_and_repr_escaped_forms_redacted():
    import json

    secret = 'pa\\ss"word'
    redaction.register_secret(secret)
    assert secret not in redaction.redact(secret)
    assert "ss" not in redaction.redact(json.dumps({"p": secret})).replace("***REDACTED***", "")
    assert "ss" not in redaction.redact(repr(secret)).replace("***REDACTED***", "")
    assert "ss" not in redaction.redact(repr(ValueError(secret))).replace("***REDACTED***", "")


def test_unicodepwd_wire_form_redacted():
    redaction.register_secret(SECRET)
    wire = base64.b64encode(f'"{SECRET}"'.encode("utf-16-le")).decode()
    assert wire not in redaction.redact(wire)


def test_record_factory_redacts_foreign_loggers_and_late_handlers():
    redaction.install_record_factory()
    redaction.install_record_factory()  # idempotent
    redaction.register_secret(SECRET)
    stream = []

    class Collect(logging.Handler):
        def emit(self, record):
            stream.append(self.format(record))

    handler = Collect()  # no RedactingFilter on purpose
    other = logging.getLogger("some.third.party")
    other.addHandler(handler)
    other.setLevel(logging.DEBUG)
    try:
        other.error("pw %s", SECRET)
        try:
            raise ValueError(f"boom {SECRET}")
        except ValueError:
            other.exception("failed")
    finally:
        other.removeHandler(handler)
    assert stream and all(SECRET not in line for line in stream)


def test_secret_split_between_msg_and_args_is_redacted():
    redaction.register_secret("ab12cd")
    rec = _record("prefix ab%s", ("12cd",))
    redaction.RedactingFilter().filter(rec)
    assert "ab12cd" not in rec.getMessage()


def test_filter_fails_closed(monkeypatch):
    redaction.register_secret(SECRET)
    rec = _record(f"x {SECRET}")

    def boom(_):
        raise RuntimeError("nope")

    monkeypatch.setattr(redaction, "redact", boom)
    assert redaction.RedactingFilter().filter(rec) is True
    assert rec.getMessage() == redaction.SUPPRESSED
    assert rec.exc_info is None and rec.exc_text is None


def test_runtime_secrets_are_bounded_and_persistent_ones_kept():
    redaction.register_secret("bind-pw-0001", persistent=True)
    for i in range(redaction.MAX_RUNTIME_SECRETS + 10):
        redaction.register_secret(f"runtime-secret-{i:04d}", persistent=False)
    assert len(redaction._runtime) == redaction.MAX_RUNTIME_SECRETS
    assert redaction.redact("bind-pw-0001") == redaction.REDACTED
    assert redaction.redact("runtime-secret-0000") == "runtime-secret-0000"
    assert redaction.redact("runtime-secret-0073") == redaction.REDACTED
