"""Secret redaction for log output.

Standard library only; imports nothing from this package. Secrets (and their
URL-quoted, base64, JSON/repr-escaped and ``unicodePwd`` encodings) registered here are replaced by
``***REDACTED***`` in every record that passes through :class:`RedactingFilter`.
"""

import base64
import json
import logging
import threading
import urllib.parse
from collections import OrderedDict
from typing import Any, Dict, Set

REDACTED = "***REDACTED***"
SUPPRESSED = "<log record suppressed: redaction failed>"

# Runtime secrets (passwords handed to create_user / reset_password) are kept in a
# bounded LRU so a long-lived server cannot grow the registry without limit.
# Persistent secrets (the bind password) are never evicted.
MAX_RUNTIME_SECRETS = 64

_lock = threading.Lock()
_persistent: Dict[str, Set[str]] = {}
_runtime: "OrderedDict[str, Set[str]]" = OrderedDict()


def _variants(secret: str) -> Set[str]:
    out = {secret, urllib.parse.quote(secret), urllib.parse.quote(secret, safe=""),
           urllib.parse.quote_plus(secret)}
    raw = secret.encode("utf-8")
    out.add(base64.b64encode(raw).decode("ascii"))
    out.add(base64.urlsafe_b64encode(raw).decode("ascii"))
    # JSON / repr escaped forms (a backslash or quote becomes \\ or \"), plus a
    # second level for escaped text embedded in another JSON string or repr.
    for dumped in (json.dumps(secret), json.dumps(secret, ensure_ascii=False)):
        inner = dumped[1:-1]
        out.add(inner)
        out.add(json.dumps(inner)[1:-1])
    out.add(repr(secret)[1:-1])
    out.add(repr(repr(secret))[1:-1])
    # AD ``unicodePwd`` wire form: UTF-16-LE of the double-quoted password.
    quoted = ('"' + secret + '"').encode("utf-16-le")
    out.add(base64.b64encode(quoted).decode("ascii"))
    return {v for v in out if v}


def register_secret(secret: Any, *, persistent: bool = True) -> None:
    """Register a secret (str or SecretStr-like) for redaction; empty values are ignored.

    ``persistent=False`` registers a short-lived runtime secret in a bounded LRU.
    """
    if secret is None:
        return
    getter = getattr(secret, "get_secret_value", None)
    if callable(getter):
        secret = getter()
    if not isinstance(secret, str) or not secret:
        return
    variants = _variants(secret)
    with _lock:
        if persistent:
            _persistent[secret] = variants
            _runtime.pop(secret, None)
        elif secret not in _persistent:
            _runtime[secret] = variants
            _runtime.move_to_end(secret)
            while len(_runtime) > MAX_RUNTIME_SECRETS:
                _runtime.popitem(last=False)


def clear_secrets() -> None:
    """Forget all registered secrets (used by tests)."""
    with _lock:
        _persistent.clear()
        _runtime.clear()


def redact(text: str) -> str:
    """Replace every registered secret in ``text``, longest first."""
    with _lock:
        pool: Set[str] = set()
        for variants in _persistent.values():
            pool |= variants
        for variants in _runtime.values():
            pool |= variants
    for secret in sorted(pool, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, REDACTED)
    return text


def sanitize_record(record: logging.LogRecord) -> None:
    """Redact a record in place: the fully formatted message, exception and stack text.

    The message is formatted first (so a secret split across ``msg`` and ``args`` is
    still caught), then ``args`` is cleared. Raises on failure; callers fail closed.
    """
    record.msg = redact(record.getMessage())
    record.args = ()
    if record.exc_info and not record.exc_text:
        record.exc_text = logging.Formatter().formatException(record.exc_info)
    if record.exc_text:
        record.exc_text = redact(record.exc_text)
    if record.stack_info:
        record.stack_info = redact(record.stack_info)


def _suppress(record: logging.LogRecord) -> None:
    record.msg = SUPPRESSED
    record.args = ()
    record.exc_info = None
    record.exc_text = None
    record.stack_info = None


class RedactingFilter(logging.Filter):
    """Scrub registered secrets from a record; fails closed (never lets a raw record through)."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            sanitize_record(record)
        except Exception:
            _suppress(record)
        return True


_FACTORY_MARK = "_ad_mcp_redacting_factory"


def install_record_factory() -> None:
    """Redact every ``LogRecord`` at creation, whatever logger or handler emits it.

    Covers third-party loggers (fastmcp, uvicorn, ldap3), the root logger, handlers
    added later and records emitted before ``setup_logging`` runs. Idempotent.
    """
    current = logging.getLogRecordFactory()
    if getattr(current, _FACTORY_MARK, False):
        return

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = current(*args, **kwargs)
        try:
            sanitize_record(record)
        except Exception:
            _suppress(record)
        return record

    setattr(factory, _FACTORY_MARK, True)
    logging.setLogRecordFactory(factory)
