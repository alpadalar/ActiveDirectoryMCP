"""Attribute allow-lists for the generic ``modify_*`` tools (SEC-03).

The allow-list is the supported way to change directory attributes through this
server. Anything not listed is rejected, and the names in :data:`HARD_DENY` can
never be allowed: attributes such as ``userAccountControl``, ``memberOf`` or
``servicePrincipalName`` are privilege-escalation vectors, and dedicated tools
(``add_group_member``, ``reset_user_password`` ...) exist for the legitimate
cases.

Widening an allow-list is a code change reviewed in a pull request, not
configuration. That is deliberate. The sets are frozensets so callers cannot
widen them at runtime.

Only attribute *names* are ever inspected or reported, never values.
"""

from typing import Any, Dict, FrozenSet, Iterable, Mapping, Tuple

USER = "user"
GROUP = "group"
COMPUTER = "computer"
OU = "ou"

HARD_DENY: FrozenSet[str] = frozenset(
    {
        "unicodePwd",
        "userPassword",
        "userAccountControl",
        "pwdLastSet",
        "objectClass",
        "objectSid",
        "sIDHistory",
        "memberOf",
        "member",
        "primaryGroupID",
        "adminCount",
        "servicePrincipalName",
        "msDS-AllowedToDelegateTo",
        "msDS-AllowedToActOnBehalfOfOtherIdentity",
        "gPLink",
        "gPOptions",
        "nTSecurityDescriptor",
        "sAMAccountName",
        "distinguishedName",
    }
)

MODIFY_ALLOWLIST: Dict[str, FrozenSet[str]] = {
    USER: frozenset(
        {
            "displayName",
            "givenName",
            "sn",
            "initials",
            "mail",
            "telephoneNumber",
            "mobile",
            "homePhone",
            "department",
            "title",
            "company",
            "division",
            "description",
            "physicalDeliveryOfficeName",
            "streetAddress",
            "l",
            "st",
            "postalCode",
            "c",
            "co",
            "employeeID",
            "employeeNumber",
            "manager",
            "info",
            "wWWHomePage",
        }
    ),
    GROUP: frozenset({"description", "displayName", "info", "managedBy", "mail"}),
    COMPUTER: frozenset(
        {
            "description",
            "location",
            "managedBy",
            "displayName",
            "operatingSystem",
            "operatingSystemVersion",
            "operatingSystemServicePack",
        }
    ),
    OU: frozenset(
        {"description", "displayName", "managedBy", "street", "l", "st", "postalCode", "c", "co"}
    ),
}


def _lower(names: Iterable[str]) -> FrozenSet[str]:
    return frozenset(n.lower() for n in names)


_HARD_DENY_LOWER = _lower(HARD_DENY)


def _check_allowlists_disjoint(
    allowlists: Mapping[str, Iterable[str]], hard_deny_lower: FrozenSet[str]
) -> None:
    """Raise if any allow-list names a hard-denied attribute (kept out of ``assert``
    so ``python -O`` cannot strip the invariant)."""
    for object_type, names in allowlists.items():
        overlap = _lower(names) & hard_deny_lower
        if overlap:
            raise RuntimeError(
                f"allow-list for {object_type} intersects HARD_DENY: {', '.join(sorted(overlap))}"
            )


_check_allowlists_disjoint(MODIFY_ALLOWLIST, _HARD_DENY_LOWER)


class AttributeNotAllowedError(ValueError):
    """Raised when a modify request names attributes outside the allow-list."""

    def __init__(self, rejected: Iterable[str], allowed: Iterable[str], object_type: str):
        self.rejected: Tuple[str, ...] = tuple(sorted(rejected, key=lambda s: (s.lower(), s)))
        self.allowed: Tuple[str, ...] = tuple(sorted(allowed, key=lambda s: (s.lower(), s)))
        self.object_type = object_type
        super().__init__(
            f"Attribute(s) not permitted for {object_type}: {', '.join(self.rejected)}"
        )


def validate_modify_attributes(object_type: str, attributes: Mapping[str, Any]) -> None:
    """Reject the whole request if any attribute name is not allowed for the type.

    Raises:
        ValueError: unknown ``object_type``.
        AttributeNotAllowedError: one or more names are denied or not allow-listed.
    """
    if object_type not in MODIFY_ALLOWLIST:
        raise ValueError(f"Unknown object type: {object_type!r}")
    allowed = MODIFY_ALLOWLIST[object_type]
    allowed_lower = _lower(allowed)
    rejected = []
    for name in attributes:
        if (
            not isinstance(name, str)
            or name.lower() in _HARD_DENY_LOWER
            or name.lower() not in allowed_lower
        ):
            rejected.append(name if isinstance(name, str) else repr(type(name).__name__))
    if rejected:
        raise AttributeNotAllowedError(rejected, allowed, object_type)
