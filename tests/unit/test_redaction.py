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
