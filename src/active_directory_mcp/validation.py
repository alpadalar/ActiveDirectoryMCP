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

* not reference a sensitive attribute (``SENSITIVE_FILTER_ATTRIBUTES``: password
  hashes, ``unicodePwd``, LAPS, gMSA, key credentials, security descriptors, BitLocker
  recovery data, ...) and not use an OID instead of an attribute name. Rationale: a
  filter is a blind oracle, since result counts reveal secret attributes one prefix
  at a time even when output is filtered; and
* not use extensible-match terms (``attr:rule:=value``), which blocks expensive
  matching-rule-in-chain queries such as ``memberOf:1.2.840.113556.1.4.1941:=``.

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
from typing import Any, FrozenSet, List, Optional, Tuple

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
    "validate_host_label",
    "validate_dns_hostname",
]

OBJECT_CLASS_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
HOST_LABEL_RE = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")
ATTRIBUTE_NAME_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
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
    if not isinstance(name, str) or not ATTRIBUTE_NAME_RE.fullmatch(name):
        raise ValidationError(f"Invalid LDAP attribute name: {name!r}")
    return name


def validate_object_class(name: Any) -> str:
    """Return ``name`` if it is a plausible objectClass name, else raise."""
    if not isinstance(name, str) or not OBJECT_CLASS_RE.fullmatch(name):
        raise ValidationError(f"Invalid LDAP object class: {name!r}")
    return name


def validate_host_label(label: Any) -> str:
    """Return ``label`` if it is a single DNS/NetBIOS host label, else raise."""
    if not isinstance(label, str) or not HOST_LABEL_RE.fullmatch(label):
        raise ValidationError(f"Invalid host name label: {label!r}")
    return label


def validate_dns_hostname(hostname: Any, domain: str) -> str:
    """Return ``hostname`` if it is a valid FQDN strictly inside ``domain``, else raise.

    Used wherever a caller-supplied host name feeds a Kerberos identity (SPN).
    """
    if not isinstance(hostname, str) or len(hostname) > 253:
        raise ValidationError(f"Invalid DNS host name: {hostname!r}")
    suffix = "." + str(domain).strip(".").lower()
    if len(hostname) <= len(suffix) or hostname[-len(suffix) :].lower() != suffix:
        raise ValidationError(
            f"dns_hostname must be inside the configured domain ({str(domain).strip('.')})"
        )
    for label in hostname.split("."):
        if not HOST_LABEL_RE.fullmatch(label) or label.startswith("-"):
            raise ValidationError(f"Invalid DNS host name: {hostname!r}")
    return hostname


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
    return list(parts)


def _rdns(parts: List[_RdnComponent]) -> List[FrozenSet[Tuple[str, str]]]:
    """Group parsed components into RDNs (a ``+`` separator joins a component to the next).

    Each RDN becomes a frozenset of lower-cased ``(type, value)`` pairs so a
    multi-valued RDN is compared as one unit, never as separate DN levels.
    """
    groups: List[FrozenSet[Tuple[str, str]]] = []
    current: List[Tuple[str, str]] = []
    for attr, value, sep in parts:
        current.append((attr.strip().lower(), value.strip().lower()))
        if sep.strip() != "+":
            groups.append(frozenset(current))
            current = []
    if current:  # dangling "+" at the end: keep it as its own (unmatchable) group
        groups.append(frozenset(current))
    return groups


def _under(candidate: List[_RdnComponent], base: List[_RdnComponent]) -> bool:
    cand = _rdns(candidate)
    root = _rdns(base)
    if len(cand) < len(root):
        return False
    return cand[len(cand) - len(root) :] == root


def validate_dn(dn: Any, base_dn: Optional[str] = None, *, allow_base: bool = True) -> str:
    """Validate ``dn`` and return it (stripped).

    With ``base_dn`` the DN must equal or sit beneath it, compared RDN by RDN
    (case-insensitive, whitespace-tolerant; multi-valued RDNs are compared as a
    unit). Hex escapes such as ``\\63`` are *not* canonicalised, so an escaped
    spelling of the base is rejected (fails closed). With ``allow_base=False``
    the DN must be a strict descendant: equal to ``base_dn`` is rejected, which
    destructive operations use to protect the whole managed tree. Without
    ``base_dn`` only the *shape* is checked (it parses, no empty values); that
    mode gives no confinement and is for callers that have no base available.
    """
    parts = _parse(dn)
    if base_dn is not None:
        base_parts = _parse(base_dn)
        if not _under(parts, base_parts):
            raise ValidationError("DN is outside the configured base DN")
        if not allow_base and _rdns(parts) == _rdns(base_parts):
            raise ValidationError("DN must be beneath the base DN, not equal to it")
    return str(dn.strip())


def is_dn_under(dn: Any, base_dn: str) -> bool:
    """True if ``dn`` is valid and equal to or beneath ``base_dn``."""
    try:
        validate_dn(dn, base_dn)
    except ValidationError:
        return False
    return True


def escape_rdn_value(value: str) -> str:
    """Escape a value for use as an RDN attribute value (RFC 4514).

    Trailing spaces are written as the hex escape ``\\20``: ldap3's parser
    rejects the ``\\ `` form as a "final character", which would make such names
    unusable even though they are legal.
    """
    text = value if isinstance(value, str) else str(value)
    stripped = text.rstrip(" ")
    trailing = len(text) - len(stripped)
    return escape_rdn(stripped) + "\\20" * trailing


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

# Attributes that hold or protect secrets. A filter on them is a blind oracle
# (presence / prefix matching through result counts), which output filtering
# cannot prevent, so they are rejected inside ``filter_criteria``.
SENSITIVE_FILTER_ATTRIBUTES = frozenset(
    name.lower()
    for name in (
        "userPassword",
        "unicodePwd",
        "dBCSPwd",
        "lmPwdHistory",
        "ntPwdHistory",
        "pwdHistory",
        "supplementalCredentials",
        "unixUserPassword",
        "ntSecurityDescriptor",
        "msDS-KeyCredentialLink",
        "msDS-ManagedPassword",
        "msDS-ManagedPasswordId",
        "msDS-ManagedPasswordPreviousId",
        "ms-Mcs-AdmPwd",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msFVE-RecoveryPassword",
        "msFVE-KeyPackage",
        "msFVE-RecoveryGuid",
        "msFVE-VolumeGuid",
        "priorValue",
        "currentValue",
        "initialAuthIncoming",
        "initialAuthOutgoing",
        "trustAuthIncoming",
        "trustAuthOutgoing",
        "msPKI-CredentialRoamingTokens",
        "msPKI-DPAPIMasterKeys",
        "securityIdentifier",
        "sidHistory",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
    )
)

_EXTENSIBLE_MATCH_TAG = 7


def _check_filter_node(node: Any) -> None:
    if node.tag == _EXTENSIBLE_MATCH_TAG:
        raise ValidationError(
            "filter_criteria must not use extensible match (':rule:=' / ':dn:=') "
            "terms such as memberOf matching-rule-in-chain"
        )
    assertion = node.assertion if isinstance(node.assertion, dict) else {}
    attr = assertion.get("attr")
    if isinstance(attr, str):
        # Strip options (";binary") and compare case-insensitively.
        base = attr.split(";", 1)[0].strip().lower()
        if base[:1].isdigit():
            raise ValidationError("filter_criteria must use attribute names, not OIDs")
        if base in SENSITIVE_FILTER_ATTRIBUTES:
            raise ValidationError(
                f"filter_criteria must not reference sensitive attribute {attr!r}"
            )
    for child in node.elements or []:
        _check_filter_node(child)


def validate_filter_criteria(fragment: Any) -> str:
    """Validate a raw filter fragment (see TRUSTED-INPUT POLICY) and return it."""
    if not isinstance(fragment, str):
        raise ValidationError("filter_criteria must be a string")
    if len(fragment) > MAX_FILTER_CRITERIA_LENGTH:
        raise ValidationError(f"filter_criteria exceeds {MAX_FILTER_CRITERIA_LENGTH} characters")
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
        tree = parse_filter("(&" + text + ")", None, False, False, None, False)
    except (LDAPException, ValueError, IndexError, KeyError) as exc:
        raise ValidationError(f"filter_criteria is not a valid LDAP filter: {exc}") from exc
    _check_filter_node(tree)
    return text


def combine_filters(base_filter: str, criteria: Optional[str] = None) -> str:
    """AND a validated criteria fragment onto ``base_filter`` (no-op if empty)."""
    if criteria is None or (isinstance(criteria, str) and not criteria.strip()):
        return base_filter
    return f"(&{base_filter}{validate_filter_criteria(criteria)})"
