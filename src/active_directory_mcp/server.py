"""
Main server implementation for Active Directory MCP.

This module implements the core MCP server for Active Directory integration, providing:
- Configuration loading and validation
- Logging setup
- LDAP connection management
- MCP tool registration and routing (tools are declared once in registry.py)
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
from .registry import StdioToolSink, ToolContext, register_tools


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
        ctx = ToolContext(
            user_tools=self.user_tools,
            group_tools=self.group_tools,
            computer_tools=self.computer_tools,
            ou_tools=self.ou_tools,
            security_tools=self.security_tools,
            ldap_manager=self.ldap_manager,
            server_name="ActiveDirectoryMCP",
            endpoint=None,
            health_extras=self._health_extras,
        )
        sink = StdioToolSink()
        register_tools(ctx, sink)
        self._tools = sink.tools
        self._tool_handlers = sink.handlers

        # Register the list_tools handler
        @self.mcp.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            return self._tools

        # Register the call_tool handler
        @self.mcp.call_tool()
        async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            try:
                return sink.dispatch(name, arguments)
            except Exception as e:
                self.logger.error(f"Tool {name} error: {e}")
                return [types.TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]

    def _health_extras(self) -> Dict[str, Any]:
        """Stdio-specific fields merged into the shared ``health`` tool response."""
        if self._tests_passed is True:
            status = "ok"
        elif self._tests_passed is False:
            status = "degraded"
        else:
            status = "unknown"
        return {"tests_passed": self._tests_passed, "status": status}

    async def _run_server(self) -> None:
        """Run the MCP server with stdio transport."""
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            # Lazy: the package __init__ imports this module at import time.
            from . import __version__

            await self.mcp.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="ActiveDirectoryMCP",
                    server_version=__version__,
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
