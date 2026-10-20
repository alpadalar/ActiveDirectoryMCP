"""Base class for Active Directory tools."""

import json
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ldap3.core.exceptions import LDAPException
from mcp.types import TextContent as Content

from .. import validation
from ..attribute_policy import AttributeNotAllowedError, validate_modify_attributes
from ..core.ldap_manager import LDAPManager
from ..core.logging import get_logger, log_ldap_operation
from ..redaction import redact
from ..validation import ValidationError

# Active Directory FILETIME: 100-nanosecond ticks since 1601-01-01 UTC.
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
FILETIME_TICKS_PER_MICROSECOND = 10
FILETIME_NEVER = 9223372036854775807  # 0x7FFFFFFFFFFFFFFF, "never expires"


# sAMAccountNames of built-in privileged groups and well-known accounts (compared
# case-insensitively). adminCount=1 additionally protects anything AD has marked as
# protected (AdminSDHolder), when the tool can read it from the lookup it already does.
PRIVILEGED_TARGET_NAMES = frozenset(
    name.lower()
    for name in (
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "krbtgt",
        "Administrator",
    )
)


class BaseTool(ABC):
    """Base class for all Active Directory tools."""

    def __init__(self, ldap_manager: LDAPManager):
        """
        Initialize base tool.

        Args:
            ldap_manager: LDAP manager instance
        """
        self.ldap = ldap_manager
        self.logger = get_logger(self.__class__.__name__)

    def _serialize_datetime(self, obj):
        """Helper function to serialize datetime objects."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dict):
            return {key: self._serialize_datetime(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_datetime(item) for item in obj]
        else:
            return obj

    # ------------------------------------------------------------------
    # Shared AD time helpers
    # ------------------------------------------------------------------

    def _ad_datetime(self, value: Any) -> Optional[datetime]:
        """Normalise an AD time value to a tz-aware UTC datetime, or None if unset.

        Accepts tz-aware or naive datetimes (naive assumed UTC), int/float/numeric-str
        FILETIME values. Returns None for empty, 0, the "never" sentinel, ldap3's
        year-1601 / year-9999 placeholders, and anything unparseable. Never raises.
        """
        try:
            if value is None or isinstance(value, (bool, bytes, bytearray)):
                return None
            if isinstance(value, datetime):
                dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
                dt = dt.astimezone(timezone.utc)
                if dt.year <= 1601 or dt.year >= 9999:
                    return None
                return dt
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    return None
                ticks = int(text)
            elif isinstance(value, (int, float)):
                ticks = int(value)
            else:
                return None
            if ticks <= 0 or ticks >= FILETIME_NEVER:
                return None
            dt = FILETIME_EPOCH + timedelta(microseconds=ticks // FILETIME_TICKS_PER_MICROSECOND)
            if dt.year >= 9999:
                return None
            return dt
        except (TypeError, ValueError, OverflowError) as e:
            self.logger.debug(f"Unparseable AD time value {value!r}: {e}")
            return None

    def _convert_filetime_to_datetime(self, value: Any) -> Optional[datetime]:
        """Convert an AD time value to an aware UTC datetime; None when unset/never."""
        return self._ad_datetime(value)

    def _convert_datetime_to_filetime(self, dt: datetime) -> int:
        """Convert a datetime (naive assumed UTC) to an AD FILETIME integer."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = dt.astimezone(timezone.utc) - FILETIME_EPOCH
        return (delta // timedelta(microseconds=1)) * FILETIME_TICKS_PER_MICROSECOND

    def _days_since(self, value: Any, now: Optional[datetime] = None) -> Optional[int]:
        """Whole days elapsed since an AD time value; None if unset, never negative."""
        dt = self._ad_datetime(value)
        if dt is None:
            return None
        current = now if now is not None else datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return max((current - dt).days, 0)

    def _is_past(self, value: Any, now: Optional[datetime] = None) -> bool:
        """True only if value is a real timestamp strictly before now."""
        dt = self._ad_datetime(value)
        if dt is None:
            return False
        current = now if now is not None else datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        return dt < current

    def _format_response(self, data: Any, operation: str = "operation") -> List[Content]:
        """
        Format response data for MCP.

        Args:
            data: Data to format
            operation: Operation name for logging

        Returns:
            List of MCP content objects
        """
        try:
            # Serialize datetime objects before JSON conversion
            serialized_data = self._serialize_datetime(data)

            if isinstance(serialized_data, dict):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            elif isinstance(serialized_data, list):
                formatted_data = json.dumps(serialized_data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(serialized_data)

            return [Content(type="text", text=formatted_data)]

        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {redact(str(e))}",
                "operation": operation,
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def _handle_ldap_error(self, e: Exception, operation: str, dn: str = "") -> List[Content]:
        """
        Handle LDAP errors and format error response.

        Args:
            e: Exception that occurred
            operation: Operation that failed
            dn: Distinguished name (if applicable)

        Returns:
            List of MCP content objects with error information
        """
        error_msg = redact(str(e))

        if isinstance(e, LDAPException):
            self.logger.error(f"LDAP error during {operation}: {error_msg}")
        else:
            self.logger.error(f"Unexpected error during {operation}: {error_msg}")

        # Log for audit
        if dn:
            log_ldap_operation(operation, dn, False, error_msg)

        error_response = {
            "success": False,
            "error": error_msg,
            "operation": operation,
            "type": type(e).__name__,
        }

        if dn:
            error_response["dn"] = dn

        return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def _get_first_value(self, attributes: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Safely get first value from LDAP attribute list."""
        value = attributes.get(key)
        if isinstance(value, list):
            return value[0] if value else default
        if value is None:
            return default
        return value

    def _base_dn(self) -> str:
        """Configured base DN used to confine caller-supplied DNs."""
        return self.ldap.ad_config.base_dn

    def _validate_dn(self, dn: str) -> bool:
        """
        Check that a DN is well formed and inside the configured base_dn.

        Returns:
            True if valid and confined to base_dn, False otherwise
        """
        try:
            validation.validate_dn(dn, self._base_dn())
        except ValidationError:
            return False
        return True

    def _confined_dn(self, dn: str, allow_base: bool = True) -> str:
        """Return the validated DN (confined to base_dn) or raise ValidationError.

        With ``allow_base=False`` the DN must be a strict descendant of base_dn
        (used by destructive/modifying operations).
        """
        return validation.validate_dn(dn, self._base_dn(), allow_base=allow_base)

    def _build_dn(self, name: str, ou: str) -> str:
        """
        Build a DN ``CN=<escaped name>,<ou>`` with the parent confined to base_dn.

        Raises:
            ValidationError: if name or ou is invalid or ou is outside base_dn
        """
        return validation.build_dn("CN", name, ou, self._base_dn())

    def _validation_error_response(
        self, exc: Exception, operation: str, dn: str = ""
    ) -> List[Content]:
        """Format a validation failure with the same JSON shape as _handle_ldap_error."""
        return self._handle_ldap_error(exc, operation, dn)

    def _success_response(
        self, message: str, data: Optional[Dict[str, Any]] = None
    ) -> List[Content]:
        """
        Create success response.

        Args:
            message: Success message
            data: Optional additional data

        Returns:
            List of MCP content objects
        """
        response = {"success": True, "message": message}

        if data:
            response.update(data)

        return [Content(type="text", text=json.dumps(response, indent=2, ensure_ascii=False))]

    def _escape_ldap_filter(self, value: str) -> str:
        """Escape a value for use in an LDAP filter (delegates to validation module)."""
        return validation.escape_filter_value(value)

    @staticmethod
    def _to_int(value, default=None):
        """Convert an LDAP value to int; returns `default` (None) if it cannot be parsed."""
        if isinstance(value, (list, tuple)):
            value = value[0] if value else None
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _get_attr_value(
        self, attributes: Dict[str, Any], attr_name: str, default: Any = None
    ) -> Any:
        """
        Safely get an attribute value from LDAP attributes dict.

        LDAP attributes can be returned as:
        - A single value (int, str, bytes, datetime)
        - A list of values
        - None if not present

        This method normalizes access to always return a single value (first element if list).

        Args:
            attributes: Dictionary of LDAP attributes
            attr_name: Name of attribute to get
            default: Default value if attribute not found

        Returns:
            Single attribute value or default
        """
        value = attributes.get(attr_name)

        if value is None:
            return default

        # If it's a list, return the first element
        if isinstance(value, (list, tuple)):
            return value[0] if value else default

        # Otherwise return the value directly
        return value

    def _get_attr_list(
        self, attributes: Dict[str, Any], attr_name: str, default: Any = None
    ) -> list:
        """
        Safely get an attribute value as a list from LDAP attributes dict.

        LDAP attributes can be returned as:
        - A single value (int, str, bytes, datetime)
        - A list of values
        - None if not present

        This method normalizes access to always return a list.

        Args:
            attributes: Dictionary of LDAP attributes
            attr_name: Name of attribute to get
            default: Default value if attribute not found (will be wrapped in list)

        Returns:
            List of attribute values
        """
        value = attributes.get(attr_name)

        if value is None:
            return [default] if default is not None else []

        # If it's already a list, return it
        if isinstance(value, (list, tuple)):
            return list(value)

        # Otherwise wrap in a list
        return [value]

    # ------------------------------------------------------------------
    # Security enforcement helpers (SEC-03 / SEC-05 / SEC-06)
    # ------------------------------------------------------------------

    def _check_modify_attributes(
        self,
        object_type: str,
        attributes: Mapping[str, Any],
        operation: str,
        target: str = "",
    ) -> Optional[List[Content]]:
        """Return a structured rejection if any attribute is not allow-listed, else None.

        Only attribute names are logged or returned, never values.
        """
        if not isinstance(attributes, Mapping):
            return self._format_response(
                {
                    "success": False,
                    "error_code": "invalid_attributes",
                    "error": (
                        "attributes must be an object mapping attribute names to values, "
                        f"not {type(attributes).__name__}"
                    ),
                    "operation": operation,
                    "object_type": object_type,
                    "target": target,
                },
                operation,
            )
        try:
            validate_modify_attributes(object_type, attributes)
        except AttributeNotAllowedError as e:
            self.logger.warning(
                f"{operation}: rejected attributes for {object_type}: {', '.join(e.rejected)}"
            )
            return self._format_response(
                {
                    "success": False,
                    "error_code": "attribute_not_allowed",
                    "error": str(e),
                    "operation": operation,
                    "object_type": object_type,
                    "rejected_attributes": list(e.rejected),
                    "allowed_attributes": list(e.allowed),
                    "target": target,
                },
                operation,
            )
        return None

    def _protected_target_refusal(
        self, operation: str, names: List[str], admin_count: Any = None
    ) -> Optional[List[Content]]:
        """Refuse a privilege-sensitive change to a privileged group or account.

        ``names`` are the sAMAccountNames involved (requested and as read back);
        ``admin_count`` is the target's adminCount when it was fetched. Returns None
        when permitted. ``security.protect_privileged_targets: false`` opts out.
        """
        if not self.ldap.security_config.protect_privileged_targets:
            return None
        matched = next(
            (
                n
                for n in names
                if isinstance(n, str) and n.strip().lower() in PRIVILEGED_TARGET_NAMES
            ),
            None,
        )
        marked = self._to_int(admin_count, 0) == 1
        if matched is None and not marked:
            return None
        target = (matched or (names[-1] if names else "")).strip()
        self.logger.warning(f"{operation}: refused privileged target '{target}'")
        return self._format_response(
            {
                "success": False,
                "error_code": "protected_target",
                "error": (
                    f"'{target}' is a privileged group or account (built-in privileged name "
                    "or adminCount=1). Set security.protect_privileged_targets to false in "
                    "the server configuration to permit changes to it."
                ),
                "operation": operation,
                "target": target,
                "setting": "security.protect_privileged_targets",
            },
            operation,
        )

    def _require_secure_channel(self, operation: str) -> Optional[List[Content]]:
        """Pre-flight for password writes; call BEFORE any mutation.

        Returns None when the connection is LDAPS/StartTLS, otherwise an error
        response. Fails closed: any error determining the channel counts as insecure.
        """
        try:
            secure = self.ldap.is_secure_channel() is True
        except Exception as e:
            self.logger.warning(
                f"{operation}: could not verify channel security ({type(e).__name__})"
            )
            secure = False
        if secure:
            return None
        return self._format_response(
            {
                "success": False,
                "error_code": "unicodePwd_requires_tls",
                "error": (
                    "Refusing to send a password over a non-TLS LDAP connection or one without "
                    "certificate validation. Use an ldaps:// server URL with "
                    "security.validate_certificate enabled and retry."
                ),
                "operation": operation,
            },
            operation,
        )

    def _capped_search(self, **search_kwargs: Any) -> Tuple[List[Dict[str, Any]], bool, int]:
        """Search honouring security.max_list_results.

        Returns (entries, truncated, limit). limit 0 means unlimited (explicit
        opt-out). Otherwise limit+1 is requested so truncation is detected exactly.
        """
        limit = int(self.ldap.security_config.max_list_results)
        if limit <= 0:
            return self.ldap.search(**search_kwargs), False, 0
        entries = self.ldap.search(**search_kwargs, size_limit=limit + 1)
        truncated = len(entries) > limit
        return entries[:limit], truncated, limit

    def _audit_scan(self, **search_kwargs: Any) -> List[Dict[str, Any]]:
        """Search for an audit report: never capped before the report's own filtering.

        Audit tools test each entry client-side (age, UAC bits), so a pre-filter cap
        would silently audit an arbitrary subset. Pair with :meth:`_cap_findings`.
        """
        return self.ldap.search(**search_kwargs)

    def _cap_findings(self, findings: List[Any]) -> Tuple[List[Any], bool, int]:
        """Cap the findings an audit returns (after filtering) to security.max_list_results."""
        limit = int(self.ldap.security_config.max_list_results)
        if limit <= 0:
            return findings, False, 0
        return findings[:limit], len(findings) > limit, limit

    @staticmethod
    def _cap_metadata(truncated: bool, limit: int) -> Dict[str, Any]:
        """Response metadata describing result capping (limit 0 -> null)."""
        return {"truncated": truncated, "result_limit": limit if limit > 0 else None}

    @abstractmethod
    def get_schema_info(self) -> Dict[str, Any]:
        """
        Get schema information for this tool's operations.

        Returns:
            Dictionary with schema information
        """
        pass
