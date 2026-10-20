"""Central input validation and LDAP escaping for Active Directory MCP.

This module is deliberately dependency-free: it imports only the standard
library and ``ldap3.utils`` / ``ldap3.operation.search.parse_filter`` and never
imports another module of this package, so any layer may use it without
creating import cycles.

TRUSTED-INPUT POLICY (filter_criteria and search bases)
-------------------------------------------------------
``filter_criteria`` is an advanced, raw LDAP filter fragment supplied by the MCP
caller. It is *constrained*, not *sanitized*. A fragment must:

* be one or more complete parenthesized filter terms, e.g. ``(department=IT)``
  or ``(a=1)(b=2)``;
* be balanced, with the depth never dropping below zero before the end, so it
  cannot close the enclosing ``(&base_filter ...)`` early or inject a sibling
  term;
* contain no NUL character;
* be at most ``MAX_FILTER_CRITERIA_LENGTH`` characters (checked before any
  parsing); and
* parse as a valid LDAP filter when wrapped as ``(&`` + fragment + ``)``.

Attribute values inside the fragment remain the caller's responsibility.
Operators who expose this server to untrusted prompts should front it with a
proxy or simply not allow ``filter_criteria``.

Search-base / DN parameters are covered by :func:`validate_dn`, which confines
a DN to the configured ``base_dn`` using component-aware comparison.

Design decision: confinement is against the single configured ``base_dn``.
``server_pool`` entries are redundancy for the same domain, so no multi-root
allow-list is introduced; it can be added later without an API change.
"""

import re
from typing import Any, List, Optional, Tuple

from ldap3.core.exceptions import LDAPException
from ldap3.operation.search import parse_filter
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn, parse_dn

__all__ = [
    "ValidationError",
    "OBJECT_CLASS_RE",
    "ATTRIBUTE_NAME_RE",
    "MAX_FILTER_CRITERIA_LENGTH",
    "escape_filter_value",
    "eq_filter",
    "validate_attribute_name",
    "validate_object_class",
    "validate_dn",
    "is_dn_under",
    "escape_rdn_value",
    "build_dn",
    "validate_filter_criteria",
    "combine_filters",
]

OBJECT_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
ATTRIBUTE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
MAX_FILTER_CRITERIA_LENGTH = 1024

_RdnComponent = Tuple[str, str, str]


class ValidationError(ValueError):
    """Raised when a caller-supplied value fails validation."""


# ---------------------------------------------------------------------------
# Filter values and names
# ---------------------------------------------------------------------------

def escape_filter_value(value: Any) -> str:
    """Escape a value for use inside an LDAP filter (RFC 4515)."""
    return escape_filter_chars(value if isinstance(value, str) else str(value))


def validate_attribute_name(name: Any) -> str:
    """Return ``name`` if it is a plain attribute description, else raise."""
    if not isinstance(name, str) or not ATTRIBUTE_NAME_RE.match(name):
        raise ValidationError(f"Invalid LDAP attribute name: {name!r}")
    return name


def validate_object_class(name: Any) -> str:
    """Return ``name`` if it is a plausible objectClass name, else raise."""
    if not isinstance(name, str) or not OBJECT_CLASS_RE.match(name):
        raise ValidationError(f"Invalid LDAP object class: {name!r}")
    return name


def eq_filter(attribute: Any, value: Any) -> str:
    """Build a single ``(attribute=value)`` atom with the value escaped."""
    return f"({validate_attribute_name(attribute)}={escape_filter_value(value)})"


# ---------------------------------------------------------------------------
# Distinguished names
# ---------------------------------------------------------------------------

def _parse(dn: Any) -> List[_RdnComponent]:
    if not isinstance(dn, str) or not dn.strip():
        raise ValidationError("DN must be a non-empty string")
    if "\x00" in dn:
        raise ValidationError("DN must not contain NUL")
    try:
        parts = parse_dn(dn.strip(), strip=True)
    except (LDAPException, ValueError, IndexError) as exc:
        raise ValidationError(f"Malformed DN: {exc}") from exc
    if not parts:
        raise ValidationError("DN has no components")
    for attr, value, _sep in parts:
        if not attr or not value.strip():
            raise ValidationError("DN contains an empty attribute or value")
    return parts


def _normalize(parts: List[_RdnComponent]) -> List[Tuple[str, str, str]]:
    return [(a.strip().lower(), v.strip().lower(), s.strip()) for a, v, s in parts]


def _under(candidate: List[_RdnComponent], base: List[_RdnComponent]) -> bool:
    cand = _normalize(candidate)
    root = _normalize(base)
    if len(cand) < len(root):
        return False
    tail = cand[len(cand) - len(root):]
    # The separator of the final component is always empty; compare type/value
    # for every component and separators for all but the last.
    return [(a, v) for a, v, _ in tail] == [(a, v) for a, v, _ in root]


def validate_dn(dn: Any, base_dn: Optional[str] = None) -> str:
    """Validate ``dn`` and return it (stripped).

    With ``base_dn`` the DN must equal or sit beneath it, compared component by
    component (case-insensitive, whitespace-tolerant, escape-aware). Without
    ``base_dn`` only the *shape* is checked (it parses, no empty values); that
    mode gives no confinement and is for callers that have no base available.
    """
    parts = _parse(dn)
    if base_dn is not None:
        if not _under(parts, _parse(base_dn)):
            raise ValidationError("DN is outside the configured base DN")
    return dn.strip()


def is_dn_under(dn: Any, base_dn: str) -> bool:
    """True if ``dn`` is valid and equal to or beneath ``base_dn``."""
    try:
        validate_dn(dn, base_dn)
    except ValidationError:
        return False
    return True


def escape_rdn_value(value: str) -> str:
    """Escape a value for use as an RDN attribute value (RFC 4514)."""
    return escape_rdn(value)


def build_dn(rdn_type: str, value: Any, parent_dn: str, base_dn: Optional[str] = None) -> str:
    """Build ``<rdn_type>=<escaped value>,<parent_dn>`` and verify its structure.

    The parent must be a valid DN (confined to ``base_dn`` when given). The
    escaped value can never introduce extra RDN components.
    """
    validate_attribute_name(rdn_type)
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("RDN value must be a non-empty string")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValidationError("RDN value must not contain control characters")
    parent = validate_dn(parent_dn, base_dn)
    dn = f"{rdn_type}={escape_rdn_value(value)},{parent}"
    parts = _parse(dn)
    if len(parts) != len(_parse(parent)) + 1:
        raise ValidationError("RDN value would add extra DN components")
    return dn


# ---------------------------------------------------------------------------
# Raw filter fragments
# ---------------------------------------------------------------------------

def validate_filter_criteria(fragment: Any) -> str:
    """Validate a raw filter fragment (see TRUSTED-INPUT POLICY) and return it."""
    if not isinstance(fragment, str):
        raise ValidationError("filter_criteria must be a string")
    if len(fragment) > MAX_FILTER_CRITERIA_LENGTH:
        raise ValidationError(
            f"filter_criteria exceeds {MAX_FILTER_CRITERIA_LENGTH} characters"
        )
    if "\x00" in fragment:
        raise ValidationError("filter_criteria must not contain NUL")
    text = fragment.strip()
    if not text:
        raise ValidationError("filter_criteria must not be empty")
    if text[0] != "(":
        raise ValidationError("filter_criteria must consist of parenthesized filter terms")

    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                raise ValidationError("filter_criteria has unbalanced parentheses")
        elif depth == 0 and not ch.isspace():
            raise ValidationError("filter_criteria must consist of parenthesized filter terms")
    if depth != 0:
        raise ValidationError("filter_criteria has unbalanced parentheses")

    try:
        parse_filter("(&" + text + ")", None, False, False, None, False)
    except (LDAPException, ValueError, IndexError, KeyError) as exc:
        raise ValidationError(f"filter_criteria is not a valid LDAP filter: {exc}") from exc
    return text


def combine_filters(base_filter: str, criteria: Optional[str] = None) -> str:
    """AND a validated criteria fragment onto ``base_filter`` (no-op if empty)."""
    if criteria is None or (isinstance(criteria, str) and not criteria.strip()):
        return base_filter
    return f"(&{base_filter}{validate_filter_criteria(criteria)})"
