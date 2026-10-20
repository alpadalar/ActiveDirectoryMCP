"""Secret redaction for log output.

Standard library only; imports nothing from this package. Secrets (and their
URL-quoted and base64 encodings) registered here are replaced by
``***REDACTED***`` in every record that passes through :class:`RedactingFilter`.
"""

import base64
import logging
import threading
import urllib.parse
from typing import Any, Dict, Set

REDACTED = "***REDACTED***"

_lock = threading.Lock()
_secrets: Set[str] = set()


def _variants(secret: str) -> Set[str]:
    out = {secret, urllib.parse.quote(secret), urllib.parse.quote(secret, safe=""),
           urllib.parse.quote_plus(secret)}
    raw = secret.encode("utf-8")
    out.add(base64.b64encode(raw).decode("ascii"))
    out.add(base64.urlsafe_b64encode(raw).decode("ascii"))
    return {v for v in out if v}


def register_secret(secret: Any) -> None:
    """Register a secret (str or SecretStr-like) for redaction; empty values are ignored."""
    if secret is None:
        return
    getter = getattr(secret, "get_secret_value", None)
    if callable(getter):
        secret = getter()
    if not isinstance(secret, str) or not secret:
        return
    with _lock:
        _secrets.update(_variants(secret))


def clear_secrets() -> None:
    """Forget all registered secrets (used by tests)."""
    with _lock:
        _secrets.clear()


def redact(text: str) -> str:
    """Replace every registered secret in ``text``, longest first."""
    with _lock:
        ordered = sorted(_secrets, key=len, reverse=True)
    for secret in ordered:
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, (int, float, bool, type(None))):
        return value
    try:
        rendered = str(value)
    except Exception:
        return value
    cleaned = redact(rendered)
    return cleaned if cleaned != rendered else value


class RedactingFilter(logging.Filter):
    """Scrub registered secrets from message, args and exception text; never drops records."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.msg) if isinstance(record.msg, str) else _scrub(record.msg)
            args = record.args
            if isinstance(args, tuple):
                record.args = tuple(_scrub(a) for a in args)
            elif isinstance(args, dict):
                record.args = {k: _scrub(v) for k, v in args.items()}
            if record.exc_info and not record.exc_text:
                record.exc_text = logging.Formatter().formatException(record.exc_info)
            if record.exc_text:
                record.exc_text = redact(record.exc_text)
            if record.stack_info:
                record.stack_info = redact(record.stack_info)
        except Exception:  # never let redaction break logging
            pass
        return True
