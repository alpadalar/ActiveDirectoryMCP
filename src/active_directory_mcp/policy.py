"""Risk classification and the read-only-by-default dispatch gate (SEC-01).

``RISK_CLASSIFICATION`` is the single source Phase 5 generates the SECURITY.md
tool-risk table from, so keep it a plain module-level dict.

:func:`guard` wraps ALL tools, reads included, so the registry has one uniform
dispatch seam (the Phase 4.1 audit hook attaches here). Gating happens before
any LDAP call: a blocked call never reaches the underlying tool method.
"""

import functools
import inspect
import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from mcp.types import TextContent as Content

from .audit import AuditLogger, classify_outcome
from .config.models import SecurityConfig

logger = logging.getLogger("active-directory-mcp.policy")


class Risk(str, Enum):
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


_READ = (
    "list_users", "get_user", "get_user_groups",
    "list_groups", "get_group", "get_group_members",
    "list_computers", "get_computer", "get_stale_computers",
    "list_organizational_units", "get_organizational_unit",
    "get_organizational_unit_contents",
    "get_domain_info", "get_privileged_groups", "get_user_permissions",
    "get_inactive_users", "get_password_policy_violations", "audit_admin_accounts",
    "test_connection", "health", "get_schema_info",
    "get_nested_group_members", "get_rootdse_info", "get_tls_posture",
)
_WRITE = (
    "create_user", "modify_user", "enable_user", "disable_user", "reset_user_password",
    "create_group", "modify_group", "add_group_member", "remove_group_member",
    "create_computer", "modify_computer", "enable_computer", "disable_computer",
    "reset_computer_password",
    "create_organizational_unit", "modify_organizational_unit", "move_organizational_unit",
)
# delete_organizational_unit is destructive for force=True and force=False alike:
# even deleting an empty OU is irreversible.
_DESTRUCTIVE = (
    "delete_user", "delete_group", "delete_computer", "delete_organizational_unit",
)

RISK_CLASSIFICATION: Dict[str, Risk] = {
    **{name: Risk.READ for name in _READ},
    **{name: Risk.WRITE for name in _WRITE},
    **{name: Risk.DESTRUCTIVE for name in _DESTRUCTIVE},
}


@dataclass(frozen=True)
class ToolPolicy:
    """Which risk classes may run."""

    allow_writes: bool = False
    allow_destructive: bool = False

    @classmethod
    def from_security(cls, security: SecurityConfig) -> "ToolPolicy":
        return cls(
            allow_writes=security.allow_writes,
            allow_destructive=security.allow_destructive,
        )

    def decide(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """Return None when permitted, else the blocked payload. Unknown tools fail closed."""
        risk = RISK_CLASSIFICATION.get(tool_name, Risk.DESTRUCTIVE)
        if risk is Risk.READ:
            return None
        if risk is Risk.WRITE:
            if self.allow_writes:
                return None
            return blocked_response(tool_name, risk)
        if self.allow_writes and self.allow_destructive:
            return None
        return blocked_response(tool_name, risk)


def blocked_response(tool_name: str, risk: Risk) -> Dict[str, Any]:
    """Structured refusal naming the tool, its risk and the config key to change."""
    if risk is Risk.WRITE:
        code, setting = "write_blocked", "security.allow_writes"
    else:
        code, setting = "destructive_blocked", "security.allow_destructive"
    return {
        "success": False,
        "error": (
            f"Tool '{tool_name}' is classified {risk.value} and is blocked by the current "
            f"policy. Set {setting} to true in the server configuration to permit it."
        ),
        "error_code": code,
        "tool": tool_name,
        "risk": risk.value,
        "setting": setting,
    }


def _bound_args(
    handler: Callable[..., Any], args: Any, kwargs: Dict[str, Any]
) -> Dict[str, Any]:
    try:
        bound = inspect.signature(handler).bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return dict(kwargs)


def guard(
    name: str,
    handler: Callable[..., Any],
    policy: ToolPolicy,
    audit: Optional[AuditLogger] = None,
) -> Callable[..., Any]:
    """Wrap ``handler`` so blocked calls return a refusal and never reach it.

    With ``audit`` set, every write/destructive call (unknown tools count as
    destructive) appends one audit record; read tools are never audited.
    """
    risk = RISK_CLASSIFICATION.get(name, Risk.DESTRUCTIVE)
    audited = audit is not None and risk is not Risk.READ

    @functools.wraps(handler)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        blocked = policy.decide(name)
        if blocked is not None:
            # Tool name and risk only: arguments may carry passwords or DNs.
            logger.warning("policy blocked tool=%s risk=%s", name, blocked.get("risk"))
            payload: List[Content] = [
                Content(type="text", text=json.dumps(blocked, indent=2))
            ]
            if audited and audit is not None:
                audit.record(
                    name, risk.value, _bound_args(handler, args, kwargs),
                    "blocked", blocked.get("error_code"),
                )
            return payload
        if not audited or audit is None:
            return handler(*args, **kwargs)
        bound = _bound_args(handler, args, kwargs)
        if risk is Risk.DESTRUCTIVE or audit.fail_closed:
            # Intent first: a crash or kill mid-operation still leaves a trace.
            if not audit.record(name, risk.value, bound, "intent") and audit.fail_closed:
                logger.error("audit sink unavailable: refusing tool=%s", name)
                return [
                    Content(
                        type="text",
                        text=json.dumps(
                            {
                                "success": False,
                                "error": (
                                    f"Tool '{name}' was refused because the audit log is "
                                    "unwritable and security.audit_fail_closed is set."
                                ),
                                "error_code": "audit_unavailable",
                                "tool": name,
                                "risk": risk.value,
                            },
                            indent=2,
                        ),
                    )
                ]
        try:
            result = handler(*args, **kwargs)
        except BaseException:
            audit.record(name, risk.value, bound, "error")
            raise
        outcome, code = classify_outcome(result)
        audit.record(name, risk.value, bound, outcome, code)
        return result

    return wrapper
