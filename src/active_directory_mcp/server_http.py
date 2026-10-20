"""
HTTP-based MCP server implementation for Active Directory MCP.

This module provides an HTTP transport layer for the MCP server,
supporting both regular HTTP and streamable HTTP transports.
"""

import asyncio
import logging
import os
import socket
import sys
from typing import Any, Callable, List, Optional

import uvicorn
from fastmcp import FastMCP

from .audit import AuditLogger
from .auth import resolve_auth
from .config.loader import load_config, validate_config
from .core.ldap_manager import LDAPManager
from .core.logging import setup_logging
from .http_app import build_http_app
from .policy import ToolPolicy
from .registry import FastMCPToolSink, ToolContext, register_tools
from .tools.computer import ComputerTools
from .tools.group import GroupTools
from .tools.organizational_unit import OrganizationalUnitTools
from .tools.security import SecurityTools
from .tools.user import UserTools

logger = logging.getLogger("active-directory-mcp.http")


class _ShutdownHookServer(uvicorn.Server):
    """uvicorn server that runs a cleanup hook inside its graceful shutdown.

    uvicorn restores the previous signal handlers and re-raises a captured
    SIGTERM/SIGINT before ``serve()`` returns, which would kill the process
    (exit 143) before any cleanup placed after ``serve()`` could run. The hook
    runs in ``shutdown()`` instead, and the captured signals are discarded so
    a signal-initiated graceful stop ends with a normal return and exit code 0.
    """

    def __init__(self, config: uvicorn.Config, on_shutdown: Callable[[], None]) -> None:
        super().__init__(config)
        self._on_shutdown = on_shutdown

    async def shutdown(self, sockets: Optional[List[socket.socket]] = None) -> None:
        try:
            await super().shutdown(sockets=sockets)
        finally:
            try:
                self._on_shutdown()
            except Exception:
                logger.exception("Shutdown hook failed")
            captured = getattr(self, "_captured_signals", None)
            if isinstance(captured, list):
                captured.clear()


class ActiveDirectoryMCPHTTPServer:
    """
    HTTP-based MCP server for Active Directory management.

    This server supports:
    - HTTP transport via FastMCP
    - All Active Directory management operations
    - Health checks and monitoring
    - API-key authentication (required by default; /health is exempt)
    - Read-only-by-default tool policy
    """

    def __init__(
        self,
        config_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8813,
        path: str = "/activedirectory-mcp",
    ):
        """
        Initialize the HTTP MCP server.

        Args:
            config_path: Path to configuration file
            host: Server host address
            port: Server port
            path: HTTP path for MCP endpoint
        """
        # Load and validate configuration
        self.config = load_config(config_path)
        validate_config(self.config)

        # Fail fast (before any LDAP connection) when no credential is configured.
        self._verifier = resolve_auth(self.config.security, os.environ)

        # Setup logging
        self.logger = setup_logging(self.config.logging)

        self.host = host
        self.port = port
        self.path = path

        # Initialize LDAP manager
        self.ldap_manager = LDAPManager(
            self.config.active_directory,
            self.config.security,
            self.config.performance,
            self.config.organizational_units,
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

        # Register tools (declared once in registry.py)
        ctx = ToolContext(
            user_tools=self.user_tools,
            group_tools=self.group_tools,
            computer_tools=self.computer_tools,
            ou_tools=self.ou_tools,
            security_tools=self.security_tools,
            ldap_manager=self.ldap_manager,
            server_name="ActiveDirectoryMCP-HTTP",
            endpoint=f"http://{host}:{port}{path}",
            policy=ToolPolicy.from_security(self.config.security),
            audit=AuditLogger.from_security(self.config.security),
        )
        register_tools(ctx, FastMCPToolSink(self.mcp))
        self._uvicorn_server: Optional[uvicorn.Server] = None

    def _test_initial_connection(self) -> None:
        """Test initial LDAP connection."""
        try:
            self.logger.info("Testing initial LDAP connection...")
            connection_info = self.ldap_manager.test_connection()

            if connection_info.get("connected"):
                self.logger.info(
                    f"Successfully connected to {connection_info.get('server')}:{connection_info.get('port')}"
                )
            else:
                self.logger.error(f"Initial connection failed: {connection_info.get('error')}")

        except Exception as e:
            self.logger.error(f"Connection test error: {e}")

    def build_app(self) -> Any:
        """Build the ASGI app to serve (the only place the served app is created)."""
        return build_http_app(
            self.mcp,
            path=self.path,
            auth=self._verifier,
            allow_unauthenticated=(
                self._verifier is None and not self.config.security.http_auth.required
            ),
        )

    async def serve(self, sockets: Optional[List[socket.socket]] = None) -> None:
        """Serve the app from :meth:`build_app` with uvicorn until it exits.

        When ``sockets`` is given, uvicorn ignores host/port (used by the E2E
        harness to bind an ephemeral port).
        """
        app = self.build_app()
        config = uvicorn.Config(
            app,
            host=self.host,
            port=self.port,
            log_level="info",
            lifespan="on",
            timeout_graceful_shutdown=2,
        )
        server = _ShutdownHookServer(config, on_shutdown=self.ldap_manager.disconnect)
        self._uvicorn_server = server
        await server.serve(sockets=sockets)

    def stop(self) -> None:
        """Ask the running uvicorn server (if any) to exit."""
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True

    def run(self) -> None:
        """
        Start the HTTP MCP server.

        uvicorn installs its own SIGINT/SIGTERM handlers. LDAP is disconnected from
        inside the server's shutdown (see ``_ShutdownHookServer``) because uvicorn
        re-raises a captured SIGTERM before serve() returns; the ``finally`` below
        is a second, idempotent disconnect.
        """
        try:
            self.logger.info(
                f"Starting Active Directory MCP HTTP server on {self.host}:{self.port}{self.path}"
            )
            self.logger.info(f"Connected to: {self.config.active_directory.server}")
            self.logger.info(f"Domain: {self.config.active_directory.domain}")

            asyncio.run(self.serve())
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)
        finally:
            self.ldap_manager.disconnect()


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
            "--host", type=str, default="0.0.0.0", help="Server host (default: 0.0.0.0)"
        )
        parser.add_argument("--port", type=int, default=8813, help="Server port (default: 8813)")
        parser.add_argument(
            "--path",
            type=str,
            default="/activedirectory-mcp",
            help="HTTP path (default: /activedirectory-mcp)",
        )
        parser.add_argument("--config", type=str, help="Configuration file path")

    def handle(self, *args, **options):
        """Handle the command execution."""
        config_path = options.get("config") or os.getenv("AD_MCP_CONFIG")

        self.server = ActiveDirectoryMCPHTTPServer(
            config_path=config_path,
            host=options.get("host", "0.0.0.0"),
            port=options.get("port", 8813),
            path=options.get("path", "/activedirectory-mcp"),
        )

        self.server.run()


def main():
    """Main entry point for standalone execution."""
    import argparse

    parser = argparse.ArgumentParser(description="Active Directory MCP HTTP Server")
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
