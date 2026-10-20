"""Helpers shared by unit tests."""

import json
from typing import Any, Dict, List

from mcp.types import TextContent


def parse_response(result: List[Any]) -> Any:
    """Assert a single TextContent response and return its decoded JSON payload."""
    assert isinstance(result, list) and len(result) == 1, f"unexpected response: {result!r}"
    assert isinstance(result[0], TextContent)
    return json.loads(result[0].text)


def ldap_entry(dn: str, **attributes: Any) -> Dict[str, Any]:
    """Build an entry shaped like LDAPManager.search results (values are always lists)."""
    return {
        "dn": dn,
        "attributes": {
            name: list(value) if isinstance(value, (list, tuple)) else [value]
            for name, value in attributes.items()
        },
    }
