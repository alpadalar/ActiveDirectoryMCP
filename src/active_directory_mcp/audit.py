"""JSON-lines audit trail for write and destructive tool calls (FEAT-01).

One JSON object per line is appended for every mutating tool call, whether it
was allowed, blocked by policy or raised. Values are default-deny: only the
identifying arguments in :data:`AUDIT_TARGET_KEYS` are kept (and still pass
through :func:`redaction.redact`); every other argument value is replaced by
``***REDACTED***``. Dict-valued arguments keep their key names only. Response
bodies are never written.

Audit I/O never changes a tool result: :meth:`AuditLogger.record` swallows and
logs ``OSError`` without the arguments.
"""

import contextvars
import json
import logging
import os
import stat
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional, Tuple

from .config.models import SecurityConfig
from .redaction import REDACTED, redact

logger = logging.getLogger("active-directory-mcp.audit")

# Allow-list of identifying argument names whose (string) values are kept. It is global,
# not per tool: a new tool that names a parameter like one of these has its value written,
# so choose parameter names deliberately. Non-string values are always redacted.
AUDIT_TARGET_KEYS: Tuple[str, ...] = (
    "username",
    "group_name",
    "computer_name",
    "ou_dn",
    "member_dn",
    "ou",
    "new_parent_dn",
    "name",
    "parent_ou",
)

OUTCOMES = ("success", "failure", "blocked", "error", "intent", "unknown")

MAX_VALUE_LENGTH = 512

# Who is calling (HTTP transport): set by the auth middleware, read when a record is built.
audit_actor: "contextvars.ContextVar[Optional[Mapping[str, str]]]" = contextvars.ContextVar(
    "audit_actor", default=None
)

_LINE_BREAKS = {" ": "\\u2028", " ": "\\u2029", "\x85": "\\u0085"}


class AuditConfigError(RuntimeError):
    """The configured audit file cannot be opened for append."""


def _safe_text(value: Any) -> str:
    text = redact(value if isinstance(value, str) else str(value))
    if len(text) > MAX_VALUE_LENGTH:
        text = text[:MAX_VALUE_LENGTH] + "...[truncated]"
    return text


def _target_text(value: Any) -> str:
    # Only plain strings are identifiers; anything structured is never written.
    return _safe_text(value) if isinstance(value, str) else REDACTED


def _redact_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        # Attribute NAMES are kept, values dropped.
        return {_safe_text(key): REDACTED for key in value}
    return REDACTED


def redact_args(args: Mapping[str, Any]) -> Dict[str, Any]:
    """Redacted view of the non-target arguments (default deny)."""
    return {
        str(key): _redact_value(value)
        for key, value in args.items()
        if key not in AUDIT_TARGET_KEYS
    }


def build_record(
    tool: str,
    risk: str,
    args: Mapping[str, Any],
    outcome: str,
    error_code: Optional[str] = None,
) -> Dict[str, Any]:
    """Build one audit record (no I/O)."""
    target = {
        key: _target_text(args[key])
        for key in AUDIT_TARGET_KEYS
        if key in args and args[key] is not None
    }
    record: Dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "risk": getattr(risk, "value", risk),
        "target": target,
        "outcome": outcome,
    }
    if error_code:
        record["error_code"] = _safe_text(error_code)
    record["redacted_args"] = redact_args(args)
    actor = audit_actor.get()
    if actor:
        record["actor"] = {_safe_text(k): _safe_text(v) for k, v in actor.items()}
    return record


def classify_outcome(result: Any) -> Tuple[str, Optional[str]]:
    """Map a guard result to (outcome, error_code) without keeping the body.

    Only an explicit ``"success": true`` counts as success; a result whose shape
    cannot be read is ``"unknown"``, never silently ``"success"``.
    """
    payload: Any = result
    if isinstance(result, list):
        text = getattr(result[0], "text", None) if result else None
        if not isinstance(text, str):
            return "unknown", None
        try:
            payload = json.loads(text)
        except ValueError:
            return "unknown", None
    if not isinstance(payload, dict):
        return "unknown", None
    code = payload.get("error_code")
    code = code if isinstance(code, str) else None
    if code and code.endswith("_blocked"):
        return "blocked", code
    if payload.get("success") is True:
        return "success", None
    if payload.get("success") is False or "error" in payload:
        return "failure", code
    return "unknown", code


def _dumps(record: Mapping[str, Any]) -> str:
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
    for char, escaped in _LINE_BREAKS.items():
        line = line.replace(char, escaped)
    return line


class AuditLogger:
    """Append-only JSON-lines writer; thread-safe, flushed per record, mode 0o600.

    The path is re-checked on every record (like ``WatchedFileHandler``): after a
    rotation by rename or deletion the file is reopened, so records never go to an
    unlinked inode. Destructive records are fsynced.
    """

    def __init__(self, path: str, fail_closed: bool = False) -> None:
        self.path = path
        self.fail_closed = fail_closed
        self.failed_writes = 0
        self.healthy = True
        self._closed = False
        self._lock = threading.Lock()
        self._file, self._ident = self._open()

    def _open(self) -> Tuple[Any, Tuple[int, int]]:
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | os.O_NOFOLLOW
            | os.O_NONBLOCK
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise AuditConfigError(
                f"Cannot open audit log '{self.path}' for append: {exc.strerror or exc}"
            ) from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise AuditConfigError(f"Audit log '{self.path}' must be a regular file")
            if st.st_uid != os.geteuid():
                raise AuditConfigError(f"Audit log '{self.path}' must be owned by the server user")
            if st.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            handle = os.fdopen(fd, "a", encoding="utf-8")
        except AuditConfigError:
            os.close(fd)
            raise
        except OSError as exc:
            os.close(fd)
            raise AuditConfigError(
                f"Cannot open audit log '{self.path}' for append: {exc.strerror or exc}"
            ) from exc
        self._warn_if_parent_writable()
        return handle, (st.st_dev, st.st_ino)

    def _warn_if_parent_writable(self) -> None:
        try:
            parent = os.stat(os.path.dirname(os.path.abspath(self.path)))
        except OSError:
            return
        if parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX:
            logger.warning(
                "audit log directory is group- or world-writable; use a private directory"
            )

    def _reopen_if_rotated(self) -> None:
        try:
            st = os.stat(self.path)
            current: Optional[Tuple[int, int]] = (st.st_dev, st.st_ino)
        except FileNotFoundError:
            current = None
        if current == self._ident:
            return
        try:
            self._file.close()
        except OSError as exc:
            logger.debug("closing rotated audit handle failed: %s", type(exc).__name__)
        self._file, self._ident = self._open()

    @classmethod
    def from_security(cls, security: SecurityConfig) -> Optional["AuditLogger"]:
        """Build the logger from config; None when no path is set."""
        if security.audit_log_path is None:
            if security.allow_writes:
                logger.warning(
                    "security.allow_writes is true but security.audit_log_path is not set: "
                    "mutating tools run without an audit trail"
                )
            return None
        return cls(security.audit_log_path, fail_closed=security.audit_fail_closed)

    def record(
        self,
        tool: str,
        risk: str,
        args: Mapping[str, Any],
        outcome: str,
        error_code: Optional[str] = None,
    ) -> bool:
        """Append one record. Never raises; returns False when the write failed."""
        try:
            line = _dumps(build_record(tool, risk, args, outcome, error_code))
            with self._lock:
                if self._closed:
                    raise ValueError("audit logger is closed")
                self._reopen_if_rotated()
                self._file.write(line + "\n")
                self._file.flush()
                if getattr(risk, "value", risk) == "destructive":
                    os.fsync(self._file.fileno())
            self.healthy = True
            return True
        except Exception as exc:  # audit must never alter the tool result
            self.failed_writes += 1
            self.healthy = False
            logger.error("audit write failed for tool=%s: %s", tool, type(exc).__name__)
            return False

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._file.close()
