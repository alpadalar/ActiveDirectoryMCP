"""The one place MCP tools are declared.

Every tool (name, description, typed handler) is declared exactly once in
:func:`build_tool_specs`. Transports only supply a :class:`ToolContext` and a
sink (:class:`FastMCPToolSink` for HTTP, :class:`StdioToolSink` for stdio) and
call :func:`register_tools`, so the two transports cannot drift apart.

The handler signatures (parameter names, annotations, defaults) define the
frozen HTTP tool surface recorded in ``tests/golden/tool_surface_http.json``;
do not tidy them without regenerating and reviewing that golden file.
"""

import inspect
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from mcp import types
from mcp.types import TextContent as Content

from .audit import AuditLogger
from .policy import RISK_CLASSIFICATION, ToolPolicy, guard
from .redaction import redact
from .tools.definitions import TOOL_DESCRIPTIONS, TOOL_INPUT_SCHEMAS
from .tools.directory import DirectoryTools

logger = logging.getLogger("active-directory-mcp.registry")


def _no_extras() -> Dict[str, Any]:
    return {}


@dataclass(frozen=True)
class ToolContext:
    """Everything the tool handlers need from the hosting server."""

    user_tools: Any
    group_tools: Any
    computer_tools: Any
    ou_tools: Any
    security_tools: Any
    ldap_manager: Any
    server_name: str
    endpoint: Optional[str] = None
    health_extras: Callable[[], Dict[str, Any]] = _no_extras
    policy: Optional[ToolPolicy] = None  # None resolves to the most restrictive policy
    audit: Optional[AuditLogger] = None  # None disables the write/destructive audit trail


@dataclass(frozen=True)
class ToolSpec:
    """One registered tool: name, description, stdio schema and typed handler."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[..., Any]
    parameters: Tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        names = tuple(inspect.signature(self.handler).parameters)
        object.__setattr__(self, "parameters", names)


class ToolSink(Protocol):
    """Receiver of tool declarations."""

    def add(self, spec: ToolSpec) -> None: ...


def format_json_response(data: Any, operation: str = "operation") -> List[Content]:
    """Format response data as a single JSON text content item."""
    try:
        if isinstance(data, (dict, list)):
            formatted = json.dumps(data, indent=2, ensure_ascii=False, default=str)
        else:
            formatted = str(data)
        return [Content(type="text", text=formatted)]
    except Exception as exc:
        logger.error("Error formatting response for %s: %s", operation, exc)
        error_response = {
            "error": f"Failed to format response: {exc}",
            "operation": operation,
        }
        return [Content(type="text", text=json.dumps(error_response, indent=2))]


# --------------------------------------------------------------------------
# Shared system tools
# --------------------------------------------------------------------------


def _test_connection(ctx: ToolContext) -> List[Content]:
    try:
        result = ctx.ldap_manager.test_connection()
    except Exception as exc:
        logger.error("test_connection failed: %s", exc)
        result = {"success": False, "error": redact(str(exc))}
    return format_json_response(result, "test_connection")


def _health(ctx: ToolContext) -> List[Content]:
    info: Dict[str, Any] = {
        "status": "ok",
        "server": ctx.server_name,
        "timestamp": datetime.now().isoformat(),
        "ldap_connection": "unknown",
    }
    try:
        connection = ctx.ldap_manager.test_connection()
        info["ldap_connection"] = "connected" if connection.get("connected") else "disconnected"
        info["ldap_server"] = connection.get("server", "unknown")
    except Exception as exc:
        logger.error("health probe failed: %s", exc)
        info["ldap_connection"] = "error"
        info["ldap_error"] = redact(str(exc))
        info["status"] = "degraded"
    extras = dict(ctx.health_extras())
    if info["status"] == "degraded":
        # A failed LDAP probe is never masked by a transport-specific status.
        extras.pop("status", None)
    info.update(extras)
    return format_json_response(info, "health")


def _get_schema_info(ctx: ToolContext) -> List[Content]:
    # Lazy: the package __init__ imports server at import time.
    from . import __version__

    info: Dict[str, Any] = {"server": ctx.server_name, "version": __version__}
    if ctx.endpoint:
        info["endpoint"] = ctx.endpoint
    info["tools"] = {
        "user_tools": ctx.user_tools.get_schema_info(),
        "group_tools": ctx.group_tools.get_schema_info(),
        "computer_tools": ctx.computer_tools.get_schema_info(),
        "ou_tools": ctx.ou_tools.get_schema_info(),
        "security_tools": ctx.security_tools.get_schema_info(),
        "directory_tools": DirectoryTools(ctx.ldap_manager).get_schema_info(),
    }
    return format_json_response(info, "get_schema_info")


# --------------------------------------------------------------------------
# Declarations
# --------------------------------------------------------------------------


def _handlers(ctx: ToolContext) -> Dict[str, Callable[..., Any]]:
    """Typed handlers by exposed tool name, in registration order."""
    users = ctx.user_tools
    groups = ctx.group_tools
    computers = ctx.computer_tools
    ous = ctx.ou_tools
    security = ctx.security_tools
    directory = DirectoryTools(ctx.ldap_manager)

    # User Management Tools
    def list_users(
        ou: Optional[str] = None,
        filter_criteria: Optional[str] = None,
        attributes: Optional[list] = None,
    ) -> Any:
        return users.list_users(ou, filter_criteria, attributes)

    def get_user(username: str, attributes: Optional[list] = None) -> Any:
        return users.get_user(username, attributes)

    def create_user(
        username: str,
        password: str,
        first_name: str,
        last_name: str,
        email: Optional[str] = None,
        ou: Optional[str] = None,
        additional_attributes: Optional[dict] = None,
    ) -> Any:
        return users.create_user(
            username, password, first_name, last_name, email, ou, additional_attributes
        )

    def modify_user(username: str, attributes: dict) -> Any:
        return users.modify_user(username, attributes)

    def delete_user(username: str) -> Any:
        return users.delete_user(username)

    def enable_user(username: str) -> Any:
        return users.enable_user(username)

    def disable_user(username: str) -> Any:
        return users.disable_user(username)

    def reset_user_password(
        username: str, new_password: Optional[str] = None, force_change: bool = True
    ) -> Any:
        return users.reset_password(username, new_password, force_change)

    def get_user_groups(username: str) -> Any:
        return users.get_user_groups(username)

    # Group Management Tools
    def list_groups(
        ou: Optional[str] = None,
        filter_criteria: Optional[str] = None,
        attributes: Optional[list] = None,
    ) -> Any:
        return groups.list_groups(ou, filter_criteria, attributes)

    def get_group(group_name: str, attributes: Optional[list] = None) -> Any:
        return groups.get_group(group_name, attributes)

    def create_group(
        group_name: str,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        ou: Optional[str] = None,
        group_scope: str = "Global",
        group_type: str = "Security",
        additional_attributes: Optional[dict] = None,
    ) -> Any:
        return groups.create_group(
            group_name,
            display_name,
            description,
            ou,
            group_scope,
            group_type,
            additional_attributes,
        )

    def modify_group(group_name: str, attributes: dict) -> Any:
        return groups.modify_group(group_name, attributes)

    def delete_group(group_name: str) -> Any:
        return groups.delete_group(group_name)

    def add_group_member(group_name: str, member_dn: str) -> Any:
        return groups.add_member(group_name, member_dn)

    def remove_group_member(group_name: str, member_dn: str) -> Any:
        return groups.remove_member(group_name, member_dn)

    def get_group_members(group_name: str, recursive: bool = False) -> Any:
        return groups.get_members(group_name, recursive)

    # Computer Management Tools
    def list_computers(
        ou: Optional[str] = None,
        filter_criteria: Optional[str] = None,
        attributes: Optional[list] = None,
    ) -> Any:
        return computers.list_computers(ou, filter_criteria, attributes)

    def get_computer(computer_name: str, attributes: Optional[list] = None) -> Any:
        return computers.get_computer(computer_name, attributes)

    def create_computer(
        computer_name: str,
        description: Optional[str] = None,
        ou: Optional[str] = None,
        dns_hostname: Optional[str] = None,
        additional_attributes: Optional[dict] = None,
    ) -> Any:
        return computers.create_computer(
            computer_name, description, ou, dns_hostname, additional_attributes
        )

    def modify_computer(computer_name: str, attributes: dict) -> Any:
        return computers.modify_computer(computer_name, attributes)

    def delete_computer(computer_name: str) -> Any:
        return computers.delete_computer(computer_name)

    def enable_computer(computer_name: str) -> Any:
        return computers.enable_computer(computer_name)

    def disable_computer(computer_name: str) -> Any:
        return computers.disable_computer(computer_name)

    def reset_computer_password(computer_name: str) -> Any:
        return computers.reset_computer_password(computer_name)

    def get_stale_computers(days: int = 90) -> Any:
        return computers.get_stale_computers(days)

    # Organizational Unit Tools
    def list_organizational_units(
        parent_ou: Optional[str] = None,
        filter_criteria: Optional[str] = None,
        attributes: Optional[list] = None,
        recursive: bool = True,
    ) -> Any:
        return ous.list_ous(parent_ou, filter_criteria, attributes, recursive)

    def get_organizational_unit(ou_dn: str, attributes: Optional[list] = None) -> Any:
        return ous.get_ou(ou_dn, attributes)

    def create_organizational_unit(
        name: str,
        parent_ou: Optional[str] = None,
        description: Optional[str] = None,
        managed_by: Optional[str] = None,
        additional_attributes: Optional[dict] = None,
    ) -> Any:
        return ous.create_ou(name, parent_ou, description, managed_by, additional_attributes)

    def modify_organizational_unit(ou_dn: str, attributes: dict) -> Any:
        return ous.modify_ou(ou_dn, attributes)

    def delete_organizational_unit(ou_dn: str, force: bool = False) -> Any:
        return ous.delete_ou(ou_dn, force)

    def move_organizational_unit(ou_dn: str, new_parent_dn: str) -> Any:
        return ous.move_ou(ou_dn, new_parent_dn)

    def get_organizational_unit_contents(ou_dn: str, object_types: Optional[list] = None) -> Any:
        return ous.get_ou_contents(ou_dn, object_types)

    # Security and Audit Tools
    def get_domain_info() -> Any:
        return security.get_domain_info()

    def get_privileged_groups() -> Any:
        return security.get_privileged_groups()

    def get_user_permissions(username: str) -> Any:
        return security.get_user_permissions(username)

    def get_inactive_users(days: int = 90, include_disabled: bool = False) -> Any:
        return security.get_inactive_users(days, include_disabled)

    def get_password_policy_violations() -> Any:
        return security.get_password_policy_violations()

    def audit_admin_accounts() -> Any:
        return security.audit_admin_accounts()

    # System Tools
    def test_connection() -> Any:
        return _test_connection(ctx)

    def health() -> Any:
        return _health(ctx)

    def get_schema_info() -> Any:
        return _get_schema_info(ctx)

    # Directory Tools (added after the original 42; keep at the end for stable ordering)
    def get_nested_group_members(group_name: str) -> Any:
        return directory.get_nested_group_members(group_name)

    def get_rootdse_info() -> Any:
        return directory.get_rootdse_info()

    def get_tls_posture() -> Any:
        return directory.get_tls_posture()

    ordered = (
        list_users,
        get_user,
        create_user,
        modify_user,
        delete_user,
        enable_user,
        disable_user,
        reset_user_password,
        get_user_groups,
        list_groups,
        get_group,
        create_group,
        modify_group,
        delete_group,
        add_group_member,
        remove_group_member,
        get_group_members,
        list_computers,
        get_computer,
        create_computer,
        modify_computer,
        delete_computer,
        enable_computer,
        disable_computer,
        reset_computer_password,
        get_stale_computers,
        list_organizational_units,
        get_organizational_unit,
        create_organizational_unit,
        modify_organizational_unit,
        delete_organizational_unit,
        move_organizational_unit,
        get_organizational_unit_contents,
        get_domain_info,
        get_privileged_groups,
        get_user_permissions,
        get_inactive_users,
        get_password_policy_violations,
        audit_admin_accounts,
        test_connection,
        health,
        get_schema_info,
        get_nested_group_members,
        get_rootdse_info,
        get_tls_posture,
    )
    return {fn.__name__: fn for fn in ordered}


def build_tool_specs(ctx: ToolContext) -> List[ToolSpec]:
    """Return the 45 tool specs in a stable order (KeyError if a definition is missing).

    Every handler is wrapped by the policy gate; a tool without a risk
    classification is a build-time error (fail closed).
    """
    policy = ctx.policy if ctx.policy is not None else ToolPolicy(False, False)
    handlers = _handlers(ctx)
    unclassified = [name for name in handlers if name not in RISK_CLASSIFICATION]
    if unclassified:
        raise RuntimeError(f"Tools without a risk classification: {', '.join(unclassified)}")
    return [
        ToolSpec(
            name=name,
            description=TOOL_DESCRIPTIONS[name],
            input_schema=TOOL_INPUT_SCHEMAS[name],
            handler=guard(name, handler, policy, ctx.audit),
        )
        for name, handler in handlers.items()
    ]


def register_tools(ctx: ToolContext, sink: ToolSink) -> None:
    """Register the full tool surface on any sink (the single call both servers make)."""
    for spec in build_tool_specs(ctx):
        sink.add(spec)


# --------------------------------------------------------------------------
# Sinks
# --------------------------------------------------------------------------


class FastMCPToolSink:
    """Registers tools on a FastMCP instance (HTTP transport)."""

    def __init__(self, mcp: Any) -> None:
        self._mcp = mcp

    def add(self, spec: ToolSpec) -> None:
        from fastmcp.tools import FunctionTool

        # output_schema=None keeps the advertised surface free of outputSchema.
        tool = FunctionTool.from_function(
            spec.handler,
            name=spec.name,
            description=spec.description,
            output_schema=None,
        )
        self._mcp.add_tool(tool)


class StdioToolSink:
    """Collects tools for the low-level stdio server and dispatches calls by name."""

    def __init__(self) -> None:
        self.tools: List[types.Tool] = []
        self.handlers: Dict[str, ToolSpec] = {}

    def add(self, spec: ToolSpec) -> None:
        self.tools.append(
            types.Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.input_schema,
            )
        )
        self.handlers[spec.name] = spec

    def dispatch(self, name: str, arguments: Optional[Dict[str, Any]]) -> List[Content]:
        """Call the registered handler; exceptions from the handler propagate to the caller."""
        spec = self.handlers.get(name)
        if spec is None:
            return [
                Content(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}, indent=2))
            ]
        provided = arguments or {}
        for required in spec.input_schema.get("required", []):
            if required not in provided:
                return [
                    Content(
                        type="text",
                        text=json.dumps(
                            {"error": f"Missing required argument: {required}"}, indent=2
                        ),
                    )
                ]
        kwargs = {key: value for key, value in provided.items() if key in spec.parameters}
        result = spec.handler(**kwargs)
        if isinstance(result, list):
            return result
        return [Content(type="text", text=json.dumps(result, indent=2, default=str))]
