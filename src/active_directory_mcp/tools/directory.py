"""Directory-level read tools: nested group membership and rootDSE."""

from typing import Any, Dict, List

import ldap3

from .. import validation
from ..core.logging import log_ldap_operation
from ..validation import ValidationError
from .base import BaseTool

# LDAP_MATCHING_RULE_IN_CHAIN: server-side transitive membership evaluation.
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

# Fixed allow-list; the rootDSE tool takes no user input.
ROOTDSE_ATTRIBUTES = (
    "defaultNamingContext",
    "rootDomainNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "dnsHostName",
    "serverName",
    "ldapServiceName",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "supportedLDAPVersion",
    "supportedSASLMechanisms",
    "currentTime",
    "isSynchronized",
    "isGlobalCatalogReady",
)

_FORBIDDEN_NAME_CHARS = frozenset('()*\\\x00')
_MAX_NAME_LENGTH = 256


def _validate_group_name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("group_name must be a non-empty string")
    if len(value) > _MAX_NAME_LENGTH:
        raise ValidationError("group_name is too long")
    if any(ch in _FORBIDDEN_NAME_CHARS or ord(ch) < 0x20 for ch in value):
        raise ValidationError("group_name contains characters that are not allowed")
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            return bytes(value).hex()
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


class DirectoryTools(BaseTool):
    """Read-only directory tools that span groups and the server's rootDSE."""

    def get_nested_group_members(self, group_name: str) -> List[Any]:
        """Return all direct and nested members of a group (single server-side chain query)."""
        try:
            name = _validate_group_name(group_name)
            base_dn = self._base_dn()
            group_filter = (
                f"(&(objectClass={self.ldap.ad_config.group_object_class})"
                f"{validation.eq_filter('sAMAccountName', name)})"
            )
            groups = self.ldap.search(
                search_base=base_dn,
                search_filter=group_filter,
                attributes=["sAMAccountName"],
            )
            if not groups:
                return self._format_response(
                    {
                        "success": False,
                        "error": f"Group '{name}' not found",
                        "group_name": name,
                    },
                    "get_nested_group_members",
                )

            group_dn = groups[0]["dn"]
            escaped_group_dn = validation.escape_filter_value(group_dn)
            # OID == MATCHING_RULE_IN_CHAIN, literal so the filter guard sees only escaped parts.
            chain_filter = f"(memberOf:1.2.840.113556.1.4.1941:={escaped_group_dn})"
            entries, truncated, limit = self._capped_search(
                search_base=base_dn,
                search_filter=chain_filter,
                attributes=["sAMAccountName", "displayName", "objectClass"],
            )

            members = []
            for entry in entries:
                if not validation.is_dn_under(entry["dn"], base_dn):
                    continue
                attrs = entry["attributes"]
                classes = [str(c).lower() for c in self._get_attr_list(attrs, "objectClass")]
                if "group" in classes:
                    kind = "group"
                elif "computer" in classes:
                    kind = "computer"
                elif "user" in classes:
                    kind = "user"
                else:
                    kind = "other"
                members.append(
                    {
                        "dn": entry["dn"],
                        "sAMAccountName": self._get_attr_value(attrs, "sAMAccountName", ""),
                        "displayName": self._get_attr_value(attrs, "displayName", ""),
                        "type": kind,
                    }
                )

            log_ldap_operation(
                "get_nested_group_members", group_dn, True, f"Resolved {len(members)} members"
            )
            return self._format_response(
                {
                    "success": True,
                    "group_name": name,
                    "group_dn": group_dn,
                    "count": len(members),
                    "members": members,
                    **self._cap_metadata(truncated, limit),
                },
                "get_nested_group_members",
            )
        except ValidationError as exc:
            return self._validation_error_response(exc, "get_nested_group_members")
        except Exception as exc:
            return self._handle_ldap_error(exc, "get_nested_group_members")

    def get_rootdse_info(self) -> List[Any]:
        """Return an allow-listed subset of the server's rootDSE."""
        try:
            entries = self.ldap.search(
                search_base="",
                search_filter="(objectClass=*)",
                attributes=list(ROOTDSE_ATTRIBUTES),
                search_scope=ldap3.BASE,
            )
            if not entries:
                return self._format_response(
                    {"success": False, "error": "rootDSE returned no data"},
                    "get_rootdse_info",
                )
            attrs = entries[0].get("attributes", {})
            info: Dict[str, Any] = {}
            for attr in ROOTDSE_ATTRIBUTES:
                value = attrs.get(attr)
                if value is None or value == [] or value == "":
                    continue
                if isinstance(value, (list, tuple)) and len(value) == 1:
                    value = value[0]
                info[attr] = _json_safe(value)
            log_ldap_operation("get_rootdse_info", "", True, f"Read {len(info)} attributes")
            return self._format_response({"success": True, "rootdse": info}, "get_rootdse_info")
        except Exception as exc:
            return self._handle_ldap_error(exc, "get_rootdse_info")

    def get_schema_info(self) -> Dict[str, Any]:
        return {
            "operations": ["get_nested_group_members", "get_rootdse_info"],
            "rootdse_attributes": list(ROOTDSE_ATTRIBUTES),
            "matching_rule_in_chain": MATCHING_RULE_IN_CHAIN,
        }
