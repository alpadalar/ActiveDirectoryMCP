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

import asyncio
import json
import logging
import os
import signal
import sys
from types import FrameType
from typing import Any, Dict, List, Optional

import mcp.server.stdio
import mcp.types as types
from mcp.server.lowlevel import NotificationOptions, Server
from mcp.server.models import InitializationOptions

from .audit import AuditLogger
from .config.loader import load_server_config, validate_config
from .core.ldap_manager import LDAPManager
from .core.logging import setup_logging
from .policy import ToolPolicy
from .registry import StdioToolSink, ToolContext, register_domain_tools
from .tools.computer import ComputerTools
from .tools.group import GroupTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools
from .tools.user import UserTools


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
            level=logging.WARNING, format="%(levelname)s - %(message)s", stream=sys.stderr
        )

        # Load and validate configuration (one or more domains)
        self.server_config = load_server_config(config_path)
        for name, domain_config in self.server_config.domains.items():
            try:
                validate_config(domain_config)
            except ValueError as exc:
                raise ValueError(f"domain '{name}': {exc}") from None

        # Setup logging (replaces basic config with full logging)
        self.logger = setup_logging(self.server_config.logging)

        # One LDAP manager and tool set per domain
        self.domains: Dict[str, ToolContext] = {}
        multi = self.server_config.multi
        for name, domain_config in self.server_config.domains.items():
            manager = LDAPManager(
                domain_config.active_directory,
                domain_config.security,
                domain_config.performance,
                domain_config.organizational_units,
            )
            self.domains[name] = ToolContext(
                user_tools=UserTools(manager),
                group_tools=GroupTools(manager),
                computer_tools=ComputerTools(manager),
                ou_tools=OrganizationalUnitTools(manager),
                security_tools=SecurityTools(manager),
                ldap_manager=manager,
                server_name="ActiveDirectoryMCP",
                endpoint=None,
                health_extras=self._health_extras,
                policy=ToolPolicy.from_security(domain_config.security),
                audit=AuditLogger.from_security(
                    domain_config.security, domain=name if multi else None
                ),
            )

        # The default domain keeps the single-domain attributes available
        self.config = self.server_config.default
        default = self.domains[self.server_config.default_domain]
        self.ldap_manager = default.ldap_manager
        self.user_tools = default.user_tools
        self.group_tools = default.group_tools
        self.computer_tools = default.computer_tools
        self.ou_tools = default.ou_tools
        self.security_tools = default.security_tools

        # Test connection on startup
        self._test_initial_connection()

        # Initialize MCP server (using low-level API)
        self.mcp = Server("ActiveDirectoryMCP")
        self._tests_passed: Optional[bool] = None
        self._tools: List[types.Tool] = []
        self._tool_handlers: Dict[str, Any] = {}
        self._setup_handlers()

    def _test_initial_connection(self) -> None:
        """Test the initial LDAP connection of every domain (failures are only logged)."""
        for name, ctx in self.domains.items():
            try:
                self.logger.info(f"Testing initial LDAP connection for domain '{name}'...")
                connection_info = ctx.ldap_manager.test_connection()

                if connection_info.get("connected"):
                    self.logger.info(
                        f"Successfully connected to {connection_info.get('server')}:"
                        f"{connection_info.get('port')}"
                    )
                    if connection_info.get("search_test"):
                        self.logger.info("LDAP search test passed")
                    else:
                        self.logger.warning("LDAP search test failed")
                else:
                    self.logger.error(
                        f"Initial connection failed for domain '{name}': "
                        f"{connection_info.get('error')}"
                    )

            except Exception as e:
                self.logger.error(f"Connection test error for domain '{name}': {e}")

    def _disconnect_all(self) -> None:
        for ctx in self.domains.values():
            ctx.ldap_manager.disconnect()

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
        sink = StdioToolSink()
        register_domain_tools(self.domains, self.server_config.default_domain, sink)
        self._tools = sink.tools
        self._tool_handlers = sink.handlers

        # Register the list_tools handler
        # mcp's lowlevel Server.list_tools()/call_tool() decorator factories are unannotated.
        @self.mcp.list_tools()  # type: ignore[untyped-decorator]
        async def handle_list_tools() -> list[types.Tool]:
            return self._tools

        # Register the call_tool handler
        @self.mcp.call_tool()  # type: ignore[untyped-decorator]
        async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:
            try:
                return sink.dispatch(name, arguments)
            except Exception as e:
                self.logger.error(f"Tool {name} error: {e}")
                return [
                    types.TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))
                ]

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

        def signal_handler(signum: int, frame: Optional[FrameType]) -> None:
            self.logger.info("Received signal to shutdown...")
            self._disconnect_all()
            sys.exit(0)

        # Set up signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            # Optionally run tests before serving
            run_tests = os.getenv("RUN_TESTS_ON_START", "0").lower() in ("1", "true", "yes", "on")
            if run_tests:
                # B404: fixed argv, opt-in via RUN_TESTS_ON_START
                import subprocess  # nosec B404

                self.logger.info("Running startup tests (pytest)...")
                env = os.environ.copy()
                # Ensure src on PYTHONPATH for tests
                env["PYTHONPATH"] = f"{os.getcwd()}/src" + (
                    ":" + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
                )
                # B603: argv is [sys.executable, -m, pytest]; no input
                result = subprocess.run(  # nosec B603
                    [sys.executable, "-m", "pytest", "-q"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                )
                self._tests_passed = result.returncode == 0
                if not self._tests_passed:
                    self.logger.error(
                        "Startup tests failed. Health will be 'degraded'. Output:\n"
                        + result.stdout.decode()
                    )
                else:
                    self.logger.info("Startup tests passed.")

            self.logger.info("Starting Active Directory MCP server...")
            for name, domain_config in self.server_config.domains.items():
                ad = domain_config.active_directory
                self.logger.info(
                    f"Domain '{name}': {ad.domain} at {ad.server} (base DN {ad.base_dn})"
                )

            asyncio.run(self._run_server())

        except Exception as e:
            self.logger.error(f"Server error: {e}")
            self._disconnect_all()
            sys.exit(1)


def main() -> None:
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
