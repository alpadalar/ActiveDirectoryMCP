"""
Main server implementation for Active Directory MCP.

This module implements the core MCP server for Active Directory integration, providing:
- Configuration loading and validation
- Logging setup
- LDAP connection management
- MCP tool registration and routing
- Signal handling for graceful shutdown

The server exposes a comprehensive set of tools for managing Active Directory resources including:
- User management (create, modify, delete, enable/disable, password reset)
- Group management (create, modify, delete, membership management)
- Computer management (create, modify, delete, enable/disable)
- Organizational Unit management (create, modify, delete, move)
- Security operations (audit, permissions analysis, policy compliance)
"""

import logging
import json
import os
import sys
import signal
import asyncio
from typing import Optional, List, Any, Dict

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from .config.loader import load_config, validate_config
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools


class ActiveDirectoryMCPServer:
    """Main server class for Active Directory MCP."""

    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the server.

        Args:
            config_path: Path to configuration file
        """
        # Configure root logger to use stderr before any logging happens
        # This prevents stdout pollution which interferes with MCP stdio protocol
        logging.basicConfig(
            level=logging.WARNING,
            format='%(levelname)s - %(message)s',
            stream=sys.stderr
        )

        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)

        # Setup logging (replaces basic config with full logging)
        self.logger = setup_logging(self.config.logging)

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance,
            self.config.organizational_units
        )

        # Test connection on startup
        self._test_initial_connection()

        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)

        # Initialize MCP server (using low-level API)
        self.mcp = Server("ActiveDirectoryMCP")
        self._tests_passed: Optional[bool] = None
        self._tools: List[types.Tool] = []
        self._tool_handlers: Dict[str, Any] = {}
        self._setup_handlers()

    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()
            
            if connection_info.get('connected'):
                self.logger.info(f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}")
                if connection_info.get('search_test'):
                    self.logger.info("LDAP search test passed")
                else:
                    self.logger.warning("LDAP search test failed")
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def _setup_handlers(self) -> None:
        """
        Register MCP handlers with the server using the low-level API.

        Initializes and registers all available tools with the MCP server:
        - User management tools
        - Group management tools
        - Computer management tools
        - Organizational Unit tools
        - Security and audit tools
        """
        # Define all tools with their schemas
        self._define_tools()

        # Register the list_tools handler
        @self.mcp.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return self._tools

        # Register the call_tool handler
        @self.mcp.call_tool()
        async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            if name not in self._tool_handlers:
                return [types.TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}, indent=2))]
            try:
                result = self._tool_handlers[name](arguments)
                if isinstance(result, list):
                    return result
                return [types.TextContent(type="text", text=json.dumps(result, indent=2, default=str))]
            except Exception as e:
                self.logger.error(f"Tool {name} error: {e}")
                return [types.TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]

    def _define_tools(self) -> None:
        """Define all tools and their handlers."""
        # User Management Tools
        self._add_tool(
            "list_users",
            "List users in Active Directory with optional filtering",
            {
                "type": "object",
                "properties": {
                    "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                    "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                }
            },
            lambda args: self.user_tools.list_users(args.get("ou"), args.get("filter_criteria"), args.get("attributes"))
        )

        self._add_tool(
            "get_user",
            "Get detailed information about a specific user",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username (sAMAccountName) to search for"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.get_user(args["username"], args.get("attributes"))
        )

        self._add_tool(
            "create_user",
            "Create a new user in Active Directory",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username (sAMAccountName)"},
                    "password": {"type": "string", "description": "User password"},
                    "first_name": {"type": "string", "description": "User's first name"},
                    "last_name": {"type": "string", "description": "User's last name"},
                    "email": {"type": "string", "description": "User's email address"},
                    "ou": {"type": "string", "description": "Organizational Unit DN to create user in"},
                    "additional_attributes": {"type": "object", "description": "Additional attributes to set"}
                },
                "required": ["username", "password", "first_name", "last_name"]
            },
            lambda args: self.user_tools.create_user(
                args["username"], args["password"], args["first_name"], args["last_name"],
                args.get("email"), args.get("ou"), args.get("additional_attributes")
            )
        )

        self._add_tool(
            "modify_user",
            "Modify user attributes",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to modify"},
                    "attributes": {"type": "object", "description": "Dictionary of attributes to modify"}
                },
                "required": ["username", "attributes"]
            },
            lambda args: self.user_tools.modify_user(args["username"], args["attributes"])
        )

        self._add_tool(
            "delete_user",
            "Delete a user from Active Directory",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to delete"}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.delete_user(args["username"])
        )

        self._add_tool(
            "enable_user",
            "Enable a user account",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to enable"}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.enable_user(args["username"])
        )

        self._add_tool(
            "disable_user",
            "Disable a user account",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to disable"}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.disable_user(args["username"])
        )

        self._add_tool(
            "reset_user_password",
            "Reset user password",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to reset password for"},
                    "new_password": {"type": "string", "description": "New password (auto-generated if not provided)"},
                    "force_change": {"type": "boolean", "description": "Force user to change password at next logon", "default": True}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.reset_password(args["username"], args.get("new_password"), args.get("force_change", True))
        )

        self._add_tool(
            "get_user_groups",
            "Get groups that a user is member of",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to get groups for"}
                },
                "required": ["username"]
            },
            lambda args: self.user_tools.get_user_groups(args["username"])
        )

        # Group Management Tools
        self._add_tool(
            "list_groups",
            "List groups in Active Directory with optional filtering",
            {
                "type": "object",
                "properties": {
                    "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                    "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                }
            },
            lambda args: self.group_tools.list_groups(args.get("ou"), args.get("filter_criteria"), args.get("attributes"))
        )

        self._add_tool(
            "get_group",
            "Get detailed information about a specific group",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name (sAMAccountName) to search for"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                },
                "required": ["group_name"]
            },
            lambda args: self.group_tools.get_group(args["group_name"], args.get("attributes"))
        )

        self._add_tool(
            "create_group",
            "Create a new group in Active Directory",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name (sAMAccountName)"},
                    "display_name": {"type": "string", "description": "Display name for the group"},
                    "description": {"type": "string", "description": "Group description"},
                    "ou": {"type": "string", "description": "Organizational Unit DN to create group in"},
                    "group_scope": {"type": "string", "description": "Group scope (Global, DomainLocal, Universal)", "default": "Global"},
                    "group_type": {"type": "string", "description": "Group type (Security, Distribution)", "default": "Security"},
                    "additional_attributes": {"type": "object", "description": "Additional attributes to set"}
                },
                "required": ["group_name"]
            },
            lambda args: self.group_tools.create_group(
                args["group_name"], args.get("display_name"), args.get("description"), args.get("ou"),
                args.get("group_scope", "Global"), args.get("group_type", "Security"), args.get("additional_attributes")
            )
        )

        self._add_tool(
            "modify_group",
            "Modify group attributes",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name to modify"},
                    "attributes": {"type": "object", "description": "Dictionary of attributes to modify"}
                },
                "required": ["group_name", "attributes"]
            },
            lambda args: self.group_tools.modify_group(args["group_name"], args["attributes"])
        )

        self._add_tool(
            "delete_group",
            "Delete a group from Active Directory",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name to delete"}
                },
                "required": ["group_name"]
            },
            lambda args: self.group_tools.delete_group(args["group_name"])
        )

        self._add_tool(
            "add_group_member",
            "Add a member to a group",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name to add member to"},
                    "member_dn": {"type": "string", "description": "Distinguished name of member to add"}
                },
                "required": ["group_name", "member_dn"]
            },
            lambda args: self.group_tools.add_member(args["group_name"], args["member_dn"])
        )

        self._add_tool(
            "remove_group_member",
            "Remove a member from a group",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name to remove member from"},
                    "member_dn": {"type": "string", "description": "Distinguished name of member to remove"}
                },
                "required": ["group_name", "member_dn"]
            },
            lambda args: self.group_tools.remove_member(args["group_name"], args["member_dn"])
        )

        self._add_tool(
            "get_group_members",
            "Get members of a group",
            {
                "type": "object",
                "properties": {
                    "group_name": {"type": "string", "description": "Group name to get members for"},
                    "recursive": {"type": "boolean", "description": "Include members of nested groups", "default": False}
                },
                "required": ["group_name"]
            },
            lambda args: self.group_tools.get_members(args["group_name"], args.get("recursive", False))
        )

        # Computer Management Tools
        self._add_tool(
            "list_computers",
            "List computer objects in Active Directory",
            {
                "type": "object",
                "properties": {
                    "ou": {"type": "string", "description": "Organizational Unit DN to search in"},
                    "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                }
            },
            lambda args: self.computer_tools.list_computers(args.get("ou"), args.get("filter_criteria"), args.get("attributes"))
        )

        self._add_tool(
            "get_computer",
            "Get detailed information about a specific computer",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name (sAMAccountName) to search for"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.get_computer(args["computer_name"], args.get("attributes"))
        )

        self._add_tool(
            "create_computer",
            "Create a new computer object in Active Directory",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name (without $ suffix)"},
                    "description": {"type": "string", "description": "Computer description"},
                    "ou": {"type": "string", "description": "Organizational Unit DN to create computer in"},
                    "dns_hostname": {"type": "string", "description": "DNS hostname"},
                    "additional_attributes": {"type": "object", "description": "Additional attributes to set"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.create_computer(
                args["computer_name"], args.get("description"), args.get("ou"),
                args.get("dns_hostname"), args.get("additional_attributes")
            )
        )

        self._add_tool(
            "modify_computer",
            "Modify computer attributes",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name to modify"},
                    "attributes": {"type": "object", "description": "Dictionary of attributes to modify"}
                },
                "required": ["computer_name", "attributes"]
            },
            lambda args: self.computer_tools.modify_computer(args["computer_name"], args["attributes"])
        )

        self._add_tool(
            "delete_computer",
            "Delete a computer from Active Directory",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name to delete"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.delete_computer(args["computer_name"])
        )

        self._add_tool(
            "enable_computer",
            "Enable a computer account",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name to enable"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.enable_computer(args["computer_name"])
        )

        self._add_tool(
            "disable_computer",
            "Disable a computer account",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name to disable"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.disable_computer(args["computer_name"])
        )

        self._add_tool(
            "reset_computer_password",
            "Reset computer account password",
            {
                "type": "object",
                "properties": {
                    "computer_name": {"type": "string", "description": "Computer name to reset password for"}
                },
                "required": ["computer_name"]
            },
            lambda args: self.computer_tools.reset_computer_password(args["computer_name"])
        )

        self._add_tool(
            "get_stale_computers",
            "Get computers that haven't logged in for specified number of days",
            {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Number of days to consider stale", "default": 90}
                }
            },
            lambda args: self.computer_tools.get_stale_computers(args.get("days", 90))
        )

        # Organizational Unit Tools
        self._add_tool(
            "list_organizational_units",
            "List Organizational Units in Active Directory",
            {
                "type": "object",
                "properties": {
                    "parent_ou": {"type": "string", "description": "Parent OU DN to search in"},
                    "filter_criteria": {"type": "string", "description": "Additional LDAP filter criteria"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"},
                    "recursive": {"type": "boolean", "description": "Search recursively in sub-OUs", "default": True}
                }
            },
            lambda args: self.ou_tools.list_ous(args.get("parent_ou"), args.get("filter_criteria"), args.get("attributes"), args.get("recursive", True))
        )

        self._add_tool(
            "get_organizational_unit",
            "Get detailed information about a specific Organizational Unit",
            {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string", "description": "Distinguished name of the OU"},
                    "attributes": {"type": "array", "items": {"type": "string"}, "description": "Specific attributes to retrieve"}
                },
                "required": ["ou_dn"]
            },
            lambda args: self.ou_tools.get_ou(args["ou_dn"], args.get("attributes"))
        )

        self._add_tool(
            "create_organizational_unit",
            "Create a new Organizational Unit",
            {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the OU"},
                    "parent_ou": {"type": "string", "description": "Parent OU DN"},
                    "description": {"type": "string", "description": "OU description"},
                    "managed_by": {"type": "string", "description": "DN of user/group managing this OU"},
                    "additional_attributes": {"type": "object", "description": "Additional attributes to set"}
                },
                "required": ["name"]
            },
            lambda args: self.ou_tools.create_ou(
                args["name"], args.get("parent_ou"), args.get("description"),
                args.get("managed_by"), args.get("additional_attributes")
            )
        )

        self._add_tool(
            "modify_organizational_unit",
            "Modify OU attributes",
            {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string", "description": "OU distinguished name to modify"},
                    "attributes": {"type": "object", "description": "Dictionary of attributes to modify"}
                },
                "required": ["ou_dn", "attributes"]
            },
            lambda args: self.ou_tools.modify_ou(args["ou_dn"], args["attributes"])
        )

        self._add_tool(
            "delete_organizational_unit",
            "Delete an Organizational Unit",
            {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string", "description": "OU distinguished name to delete"},
                    "force": {"type": "boolean", "description": "Force deletion even if OU contains objects", "default": False}
                },
                "required": ["ou_dn"]
            },
            lambda args: self.ou_tools.delete_ou(args["ou_dn"], args.get("force", False))
        )

        self._add_tool(
            "move_organizational_unit",
            "Move an OU to a new parent",
            {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string", "description": "OU distinguished name to move"},
                    "new_parent_dn": {"type": "string", "description": "New parent OU distinguished name"}
                },
                "required": ["ou_dn", "new_parent_dn"]
            },
            lambda args: self.ou_tools.move_ou(args["ou_dn"], args["new_parent_dn"])
        )

        self._add_tool(
            "get_organizational_unit_contents",
            "Get contents of an OU (users, groups, computers, sub-OUs)",
            {
                "type": "object",
                "properties": {
                    "ou_dn": {"type": "string", "description": "OU distinguished name"},
                    "object_types": {"type": "array", "items": {"type": "string"}, "description": "Types of objects to include"}
                },
                "required": ["ou_dn"]
            },
            lambda args: self.ou_tools.get_ou_contents(args["ou_dn"], args.get("object_types"))
        )

        # Security and Audit Tools
        self._add_tool(
            "get_domain_info",
            "Get domain information and security settings",
            {"type": "object", "properties": {}},
            lambda args: self.security_tools.get_domain_info()
        )

        self._add_tool(
            "get_privileged_groups",
            "Get information about privileged groups in the domain",
            {"type": "object", "properties": {}},
            lambda args: self.security_tools.get_privileged_groups()
        )

        self._add_tool(
            "get_user_permissions",
            "Get effective permissions for a user by analyzing group memberships",
            {
                "type": "object",
                "properties": {
                    "username": {"type": "string", "description": "Username to analyze permissions for"}
                },
                "required": ["username"]
            },
            lambda args: self.security_tools.get_user_permissions(args["username"])
        )

        self._add_tool(
            "get_inactive_users",
            "Get users who haven't logged in for specified number of days",
            {
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Number of days to consider inactive", "default": 90},
                    "include_disabled": {"type": "boolean", "description": "Include disabled accounts in results", "default": False}
                }
            },
            lambda args: self.security_tools.get_inactive_users(args.get("days", 90), args.get("include_disabled", False))
        )

        self._add_tool(
            "get_password_policy_violations",
            "Get users with password policy violations",
            {"type": "object", "properties": {}},
            lambda args: self.security_tools.get_password_policy_violations()
        )

        self._add_tool(
            "audit_admin_accounts",
            "Audit administrative accounts for security compliance",
            {"type": "object", "properties": {}},
            lambda args: self.security_tools.audit_admin_accounts()
        )

        # System Tools
        self._add_tool(
            "test_connection",
            "Test LDAP connection and get server information",
            {"type": "object", "properties": {}},
            lambda args: self._handle_test_connection()
        )

        self._add_tool(
            "health",
            "Health check for Active Directory MCP server",
            {"type": "object", "properties": {}},
            lambda args: self._handle_health()
        )

        self._add_tool(
            "get_schema_info",
            "Get schema information for all available tools",
            {"type": "object", "properties": {}},
            lambda args: self._handle_schema_info()
        )

    def _add_tool(self, name: str, description: str, input_schema: Dict[str, Any], handler: Any) -> None:
        """Helper to add a tool definition."""
        self._tools.append(types.Tool(
            name=name,
            description=description,
            inputSchema=input_schema
        ))
        self._tool_handlers[name] = handler

    def _handle_test_connection(self) -> Dict[str, Any]:
        """Handle test_connection tool."""
        try:
            return self.ldap_manager.test_connection()
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _handle_health(self) -> Dict[str, Any]:
        """Handle health tool."""
        status = "ok" if self._tests_passed is True else ("degraded" if self._tests_passed is False else "unknown")
        health_info = {
            "status": status,
            "server": "ActiveDirectoryMCP",
            "tests_passed": self._tests_passed,
            "ldap_connection": "unknown"
        }

        try:
            connection_info = self.ldap_manager.test_connection()
            health_info["ldap_connection"] = "connected" if connection_info.get('connected') else "disconnected"
            health_info["ldap_server"] = connection_info.get('server', 'unknown')
        except Exception as e:
            health_info["ldap_connection"] = "error"
            health_info["ldap_error"] = str(e)

        return health_info

    def _handle_schema_info(self) -> Dict[str, Any]:
        """Handle get_schema_info tool."""
        return {
            "server": "ActiveDirectoryMCP",
            "version": "0.1.0",
            "tools": {
                "user_tools": self.user_tools.get_schema_info(),
                "group_tools": self.group_tools.get_schema_info(),
                "computer_tools": self.computer_tools.get_schema_info(),
                "ou_tools": self.ou_tools.get_schema_info(),
                "security_tools": self.security_tools.get_schema_info()
            }
        }

    async def _run_server(self) -> None:
        """Run the MCP server with stdio transport."""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.mcp.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ActiveDirectoryMCP",
                    server_version="0.1.0",
                    capabilities=self.mcp.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    def start(self) -> None:
        """
        Start the MCP server.

        Initializes the server with:
        - Signal handlers for graceful shutdown (SIGINT, SIGTERM)
        - Async runtime for handling concurrent requests
        - Error handling and logging

        The server runs until terminated by a signal or fatal error.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                import subprocess
                self.logger.info("Running startup tests (pytest)...")
                env = os.environ.copy()
                # Ensure src on PYTHONPATH for tests
                env["PYTHONPATH"] = f"{os.getcwd()}/src" + (":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
                result = subprocess.run([sys.executable, "-m", "pytest", "-q"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
                self._tests_passed = (result.returncode == 0)
                if not self._tests_passed:
                    self.logger.error("Startup tests failed. Health will be 'degraded'. Output:\n" + result.stdout.decode())
                else:
                    self.logger.info("Startup tests passed.")

            self.logger.info("Starting Active Directory MCP server...")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")
            self.logger.info(f"Base DN: {self.config.active_directory.base_dn}")

            asyncio.run(self._run_server())

        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)


def main():
    """Main entry point for the server."""
    config_path = os.getenv("AD_MCP_CONFIG")
    if not config_path:
        print("AD_MCP_CONFIG environment variable must be set")
        sys.exit(1)
    
    try:
        server = ActiveDirectoryMCPServer(config_path)
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
