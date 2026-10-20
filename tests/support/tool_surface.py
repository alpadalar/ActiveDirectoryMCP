"""Tool-surface snapshot support (STAB-06).

Builds both server classes without a directory server, extracts the tool input
schemas and reduces them to a canonical, library-version-independent form.
"""

import asyncio
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple
from unittest.mock import MagicMock, patch

_DROPPED_KEYS = {"title", "description", "additionalProperties", "$schema", "examples"}


# --------------------------------------------------------------------------
# Canonicalization
# --------------------------------------------------------------------------


def _reject_refs(schema: Dict[str, Any]) -> None:
    for key in ("$ref", "$defs", "definitions"):
        if key in schema:
            raise ValueError(
                f"Unsupported {key} in tool schema: {json.dumps(schema, sort_keys=True)[:200]}"
            )


def _types(schema: Any) -> Tuple[Set[str], bool]:
    """Return (set of canonical type names, has explicit null member)."""
    if not isinstance(schema, dict) or not schema:
        return {"any"}, False
    _reject_refs(schema)

    members = None
    for key in ("anyOf", "oneOf"):
        if key in schema:
            members = schema[key]
            break
    if members is not None:
        types: Set[str] = set()
        nullable = False
        for member in members:
            sub_types, sub_null = _types(member)
            types |= sub_types
            nullable = nullable or sub_null
        return types, nullable

    declared = schema.get("type")
    if declared is None:
        return {"any"}, False
    names: List[str] = declared if isinstance(declared, list) else [declared]
    types = set()
    nullable = False
    for name in names:
        if name == "null":
            nullable = True
        elif name == "array":
            items = schema.get("items")
            if isinstance(items, dict) and items:
                item_types, item_null = _types(items)
                item = "|".join(sorted(item_types))
                if item_null:
                    item += "|null"
            else:
                item = "any"
            types.add(f"array<{item}>")
        else:
            types.add(name)
    return types, nullable


def canonical_property(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce one property schema to {"type", "nullable"?, "default"?, "enum"?}."""
    types, nullable = _types(schema)
    out: Dict[str, Any] = {"type": "|".join(sorted(types)) if types else "any"}
    if nullable:
        out["nullable"] = True
    if isinstance(schema, dict):
        if "default" in schema:
            out["default"] = schema["default"]
        if "enum" in schema:
            out["enum"] = list(schema["enum"])
    return out


def canonical_input_schema(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce a tool input schema to {"params": {...}, "required": [...]}."""
    schema = schema or {}
    _reject_refs(schema)
    props = schema.get("properties") or {}
    return {
        "params": {name: canonical_property(props[name]) for name in sorted(props)},
        "required": sorted(schema.get("required") or []),
    }


def _surface(schemas: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    tools = {name: canonical_input_schema(schemas[name]) for name in sorted(schemas)}
    return {"tool_count": len(tools), "tools": tools}


def serialize_surface(surface: Dict[str, Any]) -> bytes:
    return (json.dumps(surface, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Server builders
# --------------------------------------------------------------------------


@contextmanager
def _offline_env(module: str) -> Iterator[None]:
    """Temporary config + dummy password, LDAPManager patched at its import site."""
    with tempfile.TemporaryDirectory(prefix="tool-surface-") as tmp:
        config = {
            "active_directory": {
                "server": "ldaps://dc.test.local",
                "domain": "test.local",
                "base_dn": "DC=test,DC=local",
                "bind_dn": "CN=svc,DC=test,DC=local",
            },
            "organizational_units": {
                "users_ou": "CN=Users,DC=test,DC=local",
                "groups_ou": "CN=Groups,DC=test,DC=local",
                "computers_ou": "CN=Computers,DC=test,DC=local",
                "service_accounts_ou": "CN=Service,DC=test,DC=local",
            },
            "logging": {"level": "WARNING", "file": None},
        }
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        env = {
            "AD_MCP_CONFIG": str(path),
            "AD_PASSWORD": "dummy-password",
            "AD_MCP_HTTP_API_KEY": "offline-surface-key-0123456789abcdef",
        }
        manager = MagicMock()
        manager.test_connection.return_value = {"connected": False}
        with patch.dict(os.environ, env), patch(f"{module}.LDAPManager", return_value=manager):
            for var in (
                "AD_BIND_DN",
                "AZURE_KEYVAULT_URL",
                "AZURE_KEYVAULT_SECRET_USERNAME",
                "AZURE_KEYVAULT_SECRET_PASSWORD",
            ):
                os.environ.pop(var, None)
            yield


def _schema_of(tool: Any) -> Dict[str, Any]:
    for attr in ("parameters", "inputSchema"):
        value = getattr(tool, attr, None)
        if value is not None:
            return value
    raise AttributeError(
        f"Tool object {type(tool).__name__} exposes neither .parameters nor .inputSchema"
    )


def build_stdio_surface() -> Dict[str, Any]:
    with _offline_env("active_directory_mcp.server"):
        from active_directory_mcp.server import ActiveDirectoryMCPServer

        server = ActiveDirectoryMCPServer()
        return _surface({tool.name: _schema_of(tool) for tool in server._tools})


def build_http_surface() -> Dict[str, Any]:
    with _offline_env("active_directory_mcp.server_http"):
        from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

        server = ActiveDirectoryMCPHTTPServer()
        tools = asyncio.run(server.mcp.list_tools())
        return _surface({tool.name: _schema_of(tool) for tool in tools})
