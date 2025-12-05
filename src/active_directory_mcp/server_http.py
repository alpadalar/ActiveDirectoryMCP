"""
HTTP-based MCP server implementation for Active Directory MCP.

This module provides an HTTP transport layer for the MCP server,
supporting both regular HTTP and streamable HTTP transports.
"""

import logging
import json
import os
import sys
import signal
from typing import Optional
from datetime import datetime

try:
    from fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        FASTMCP_AVAILABLE = True
    except ImportError:
        FASTMCP_AVAILABLE = False

from .config.loader import load_config, validate_config
from .core.logging import setup_logging
from .core.ldap_manager import LDAPManager
from .tools.user import UserTools
from .tools.group import GroupTools
from .tools.computer import ComputerTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools


logger = logging.getLogger("active-directory-mcp.http")


class ActiveDirectoryMCPHTTPServer:
    """
    HTTP-based MCP server for Active Directory management.
    
    This server supports:
    - HTTP transport via FastMCP
    - All Active Directory management operations
    - Health checks and monitoring
    """
    
    def __init__(self, 
                 config_path: Optional[str] = None,
                 host: str = "0.0.0.0",
                 port: int = 8813,
                 path: str = "/activedirectory-mcp"):
        """
        Initialize the HTTP MCP server.
        
        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        if not FASTMCP_AVAILABLE:
            raise RuntimeError("FastMCP is not available. Please install fastmcp package.")
            
        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)
        
        # Setup logging
        self.logger = setup_logging(self.config.logging)
        
        self.host = host
        self.port = port
        self.path = path
        
        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance
        )
        
        # Test connection on startup
        self._test_initial_connection()
        
        # Initialize tools
        self.user_tools = UserTools(self.ldap_manager)
        self.group_tools = GroupTools(self.ldap_manager)
        self.computer_tools = ComputerTools(self.ldap_manager)
        self.ou_tools = OrganizationalUnitTools(self.ldap_manager)
        self.security_tools = SecurityTools(self.ldap_manager)
        
        # Initialize FastMCP
        self.mcp = FastMCP("ActiveDirectoryMCP-HTTP")
        
        # Setup tools
        self._setup_tools()

    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()
            
            if connection_info.get('connected'):
                self.logger.info(f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}")
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def _setup_tools(self) -> None:
        """Register MCP tools with appropriate descriptions."""
        
        # User Management Tools
        @self.mcp.tool(description="List users in Active Directory")
        def list_users(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.user_tools.list_users(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific user")
        def get_user(username: str, attributes: Optional[list] = None):
            return self.user_tools.get_user(username, attributes)

        @self.mcp.tool(description="Create a new user in Active Directory")
        def create_user(username: str, password: str, first_name: str, last_name: str,
                       email: Optional[str] = None, ou: Optional[str] = None, additional_attributes: Optional[dict] = None):
            return self.user_tools.create_user(username, password, first_name, last_name, email, ou, additional_attributes)

        @self.mcp.tool(description="Modify user attributes")
        def modify_user(username: str, attributes: dict):
            return self.user_tools.modify_user(username, attributes)

        @self.mcp.tool(description="Delete a user from Active Directory")
        def delete_user(username: str):
            return self.user_tools.delete_user(username)

        @self.mcp.tool(description="Enable a user account")
        def enable_user(username: str):
            return self.user_tools.enable_user(username)

        @self.mcp.tool(description="Disable a user account")
        def disable_user(username: str):
            return self.user_tools.disable_user(username)

        @self.mcp.tool(description="Reset user password")
        def reset_user_password(username: str, new_password: Optional[str] = None, force_change: bool = True, password_never_expires: bool = False):
            return self.user_tools.reset_password(username, new_password, force_change, password_never_expires)

        @self.mcp.tool(description="Get groups that a user is member of")
        def get_user_groups(username: str):
            return self.user_tools.get_user_groups(username)

        # Group Management Tools
        @self.mcp.tool(description="List groups in Active Directory")
        def list_groups(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.group_tools.list_groups(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific group")
        def get_group(group_name: str, attributes: Optional[list] = None):
            return self.group_tools.get_group(group_name, attributes)

        @self.mcp.tool(description="Create a new group in Active Directory")
        def create_group(group_name: str, display_name: Optional[str] = None, description: Optional[str] = None,
                        ou: Optional[str] = None, group_scope: str = "Global", group_type: str = "Security",
                        additional_attributes: Optional[dict] = None):
            return self.group_tools.create_group(group_name, display_name, description, ou, group_scope, group_type, additional_attributes)

        @self.mcp.tool(description="Modify group attributes")
        def modify_group(group_name: str, attributes: dict):
            return self.group_tools.modify_group(group_name, attributes)

        @self.mcp.tool(description="Delete a group from Active Directory")
        def delete_group(group_name: str):
            return self.group_tools.delete_group(group_name)

        @self.mcp.tool(description="Add a member to a group")
        def add_group_member(group_name: str, member_dn: str):
            return self.group_tools.add_member(group_name, member_dn)

        @self.mcp.tool(description="Remove a member from a group")
        def remove_group_member(group_name: str, member_dn: str):
            return self.group_tools.remove_member(group_name, member_dn)

        @self.mcp.tool(description="Get members of a group")
        def get_group_members(group_name: str, recursive: bool = False):
            return self.group_tools.get_members(group_name, recursive)

        # Computer Management Tools
        @self.mcp.tool(description="List computer objects in Active Directory")
        def list_computers(ou: Optional[str] = None, filter_criteria: Optional[str] = None, attributes: Optional[list] = None):
            return self.computer_tools.list_computers(ou, filter_criteria, attributes)

        @self.mcp.tool(description="Get detailed information about a specific computer")
        def get_computer(computer_name: str, attributes: Optional[list] = None):
            return self.computer_tools.get_computer(computer_name, attributes)

        @self.mcp.tool(description="Create a new computer object in Active Directory")
        def create_computer(computer_name: str, description: Optional[str] = None, ou: Optional[str] = None,
                           dns_hostname: Optional[str] = None, additional_attributes: Optional[dict] = None):
            return self.computer_tools.create_computer(computer_name, description, ou, dns_hostname, additional_attributes)

        @self.mcp.tool(description="Modify computer attributes")
        def modify_computer(computer_name: str, attributes: dict):
            return self.computer_tools.modify_computer(computer_name, attributes)

        @self.mcp.tool(description="Delete a computer from Active Directory")
        def delete_computer(computer_name: str):
            return self.computer_tools.delete_computer(computer_name)

        @self.mcp.tool(description="Enable a computer account")
        def enable_computer(computer_name: str):
            return self.computer_tools.enable_computer(computer_name)

        @self.mcp.tool(description="Disable a computer account")
        def disable_computer(computer_name: str):
            return self.computer_tools.disable_computer(computer_name)

        @self.mcp.tool(description="Reset computer account password")
        def reset_computer_password(computer_name: str):
            return self.computer_tools.reset_computer_password(computer_name)

        @self.mcp.tool(description="Get stale computers (not logged in for specified days)")
        def get_stale_computers(days: int = 90):
            return self.computer_tools.get_stale_computers(days)

        # Organizational Unit Tools
        @self.mcp.tool(description="List Organizational Units in Active Directory")
        def list_organizational_units(parent_ou: Optional[str] = None, filter_criteria: Optional[str] = None,
                                     attributes: Optional[list] = None, recursive: bool = True):
            return self.ou_tools.list_ous(parent_ou, filter_criteria, attributes, recursive)

        @self.mcp.tool(description="Get detailed information about a specific Organizational Unit")
        def get_organizational_unit(ou_dn: str, attributes: Optional[list] = None):
            return self.ou_tools.get_ou(ou_dn, attributes)

        @self.mcp.tool(description="Create a new Organizational Unit")
        def create_organizational_unit(name: str, parent_ou: Optional[str] = None, description: Optional[str] = None,
                                      managed_by: Optional[str] = None, additional_attributes: Optional[dict] = None):
            return self.ou_tools.create_ou(name, parent_ou, description, managed_by, additional_attributes)

        @self.mcp.tool(description="Modify OU attributes")
        def modify_organizational_unit(ou_dn: str, attributes: dict):
            return self.ou_tools.modify_ou(ou_dn, attributes)

        @self.mcp.tool(description="Delete an Organizational Unit")
        def delete_organizational_unit(ou_dn: str, force: bool = False):
            return self.ou_tools.delete_ou(ou_dn, force)

        @self.mcp.tool(description="Move an OU to a new parent")
        def move_organizational_unit(ou_dn: str, new_parent_dn: str):
            return self.ou_tools.move_ou(ou_dn, new_parent_dn)

        @self.mcp.tool(description="Get contents of an OU")
        def get_organizational_unit_contents(ou_dn: str, object_types: Optional[list] = None):
            return self.ou_tools.get_ou_contents(ou_dn, object_types)

        # Security and Audit Tools
        @self.mcp.tool(description="Get domain information and security settings")
        def get_domain_info():
            return self.security_tools.get_domain_info()

        @self.mcp.tool(description="Get information about privileged groups")
        def get_privileged_groups():
            return self.security_tools.get_privileged_groups()

        @self.mcp.tool(description="Get effective permissions for a user")
        def get_user_permissions(username: str):
            return self.security_tools.get_user_permissions(username)

        @self.mcp.tool(description="Get inactive users")
        def get_inactive_users(days: int = 90, include_disabled: bool = False):
            return self.security_tools.get_inactive_users(days, include_disabled)

        @self.mcp.tool(description="Get users with password policy violations")
        def get_password_policy_violations():
            return self.security_tools.get_password_policy_violations()

        @self.mcp.tool(description="Audit administrative accounts")
        def audit_admin_accounts():
            return self.security_tools.audit_admin_accounts()

        # System Tools
        @self.mcp.tool(description="Test LDAP connection")
        def test_connection():
            try:
                connection_info = self.ldap_manager.test_connection()
                return self._format_response(connection_info, "test_connection")
            except Exception as e:
                return self._format_response({
                    "success": False,
                    "error": str(e)
                }, "test_connection")

        @self.mcp.tool(description="Health check for Active Directory MCP server")
        def health():
            health_info = {
                "status": "ok",
                "server": "ActiveDirectoryMCP-HTTP",
                "timestamp": datetime.now().isoformat(),
                "ldap_connection": "unknown"
            }
            
            # Test LDAP connection
            try:
                connection_info = self.ldap_manager.test_connection()
                health_info["ldap_connection"] = "connected" if connection_info.get('connected') else "disconnected"
                health_info["ldap_server"] = connection_info.get('server', 'unknown')
            except Exception as e:
                health_info["ldap_connection"] = "error"
                health_info["ldap_error"] = str(e)
                health_info["status"] = "degraded"
            
            return self._format_response(health_info, "health")

        @self.mcp.tool(description="Get schema information for all available tools")
        def get_schema_info():
            schema_info = {
                "server": "ActiveDirectoryMCP-HTTP",
                "version": "0.1.0",
                "endpoint": f"http://{self.host}:{self.port}{self.path}",
                "tools": {
                    "user_tools": self.user_tools.get_schema_info(),
                    "group_tools": self.group_tools.get_schema_info(),
                    "computer_tools": self.computer_tools.get_schema_info(),
                    "ou_tools": self.ou_tools.get_schema_info(),
                    "security_tools": self.security_tools.get_schema_info()
                }
            }
            return self._format_response(schema_info, "get_schema_info")

    def _format_response(self, data, operation: str = "operation"):
        """Format response data for MCP."""
        from mcp.types import TextContent as Content
        
        try:
            if isinstance(data, (dict, list)):
                formatted_data = json.dumps(data, indent=2, ensure_ascii=False)
            else:
                formatted_data = str(data)
            
            return [Content(type="text", text=formatted_data)]
            
        except Exception as e:
            self.logger.error(f"Error formatting response for {operation}: {e}")
            error_response = {
                "error": f"Failed to format response: {str(e)}",
                "operation": operation
            }
            return [Content(type="text", text=json.dumps(error_response, indent=2))]

    def run(self) -> None:
        """
        Start the HTTP MCP server.
        
        Runs the server with HTTP transport on the configured
        host and port.
        """
        def signal_handler(signum, frame):
            self.logger.info("Received signal to shutdown HTTP server...")
            self.ldap_manager.disconnect()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            self.logger.info(f"Starting Active Directory MCP HTTP server on {self.host}:{self.port}{self.path}")
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")
            
            # Run with FastMCP's built-in HTTP transport
            self.mcp.run(
                transport="http",
                host=self.host,
                port=self.port,
                path=self.path
            )
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            self.ldap_manager.disconnect()
            sys.exit(1)


class ActiveDirectoryMCPCommand:
    """
    Command runner for Active Directory MCP HTTP server.
    
    This class can be used as a standalone command runner.
    """
    
    help = "Active Directory MCP HTTP Server"
    
    def __init__(self):
        self.server = None
    
    def add_arguments(self, parser):
        """Add command line arguments."""
        parser.add_argument(
            '--host',
            type=str,
            default='0.0.0.0',
            help='Server host (default: 0.0.0.0)'
        )
        parser.add_argument(
            '--port',
            type=int,
            default=8813,
            help='Server port (default: 8813)'
        )
        parser.add_argument(
            '--path',
            type=str,
            default='/activedirectory-mcp',
            help='HTTP path (default: /activedirectory-mcp)'
        )
        parser.add_argument(
            '--config',
            type=str,
            help='Configuration file path'
        )
    
    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get('config') or os.getenv('AD_MCP_CONFIG')
        
        self.server = ActiveDirectoryMCPHTTPServer(
            config_path=config_path,
            host=options.get('host', '0.0.0.0'),
            port=options.get('port', 8813),
            path=options.get('path', '/activedirectory-mcp')
        )
        
        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Active Directory MCP HTTP Server')
    command = ActiveDirectoryMCPCommand()
    command.add_arguments(parser)
    
    args = parser.parse_args()
    options = vars(args)
    
    try:
        command.handle(**options)
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
