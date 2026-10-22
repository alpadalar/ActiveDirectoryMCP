"""
HTTP-based MCP server implementation for Active Directory MCP.

This module provides an HTTP transport layer for the MCP server,
supporting both regular HTTP and streamable HTTP transports.
"""

import argparse
import asyncio
import logging
import os
import socket
import sys
from typing import Any, Callable, Dict, List, Optional

import uvicorn
from fastmcp import FastMCP

from .audit import AuditLogger
from .auth import resolve_auth
from .config.loader import load_server_config, validate_config
from .core.ldap_manager import LDAPManager
from .core.logging import setup_logging
from .http_app import build_http_app
from .policy import ToolPolicy
from .registry import FastMCPToolSink, ToolContext, register_domain_tools
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
        # B104: deliberate container bind; HTTP auth is required by default (Phase 4)
        host: str = "0.0.0.0",  # nosec B104
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
        # Load and validate configuration (one or more domains)
        self.server_config = load_server_config(config_path)
        for name, domain_config in self.server_config.domains.items():
            try:
                validate_config(domain_config)
            except ValueError as exc:
                raise ValueError(f"domain '{name}': {exc}") from None

        # Fail fast (before any LDAP connection) when no credential is configured.
        self._verifier = resolve_auth(self.server_config.security, os.environ)

        # Setup logging
        self.logger = setup_logging(self.server_config.logging)

        self.host = host
        self.port = port
        self.path = path

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
                server_name="ActiveDirectoryMCP-HTTP",
                endpoint=f"http://{host}:{port}{path}",
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

        # Initialize FastMCP and register tools (declared once in registry.py)
        self.mcp = FastMCP("ActiveDirectoryMCP-HTTP")
        register_domain_tools(
            self.domains, self.server_config.default_domain, FastMCPToolSink(self.mcp)
        )
        self._uvicorn_server: Optional[uvicorn.Server] = None

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

    def build_app(self) -> Any:
        """Build the ASGI app to serve (the only place the served app is created)."""
        return build_http_app(
            self.mcp,
            path=self.path,
            auth=self._verifier,
            allow_unauthenticated=(
                self._verifier is None and not self.server_config.security.http_auth.required
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
        server = _ShutdownHookServer(config, on_shutdown=self._disconnect_all)
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
            for name, domain_config in self.server_config.domains.items():
                ad = domain_config.active_directory
                self.logger.info(f"Domain '{name}': {ad.domain} at {ad.server}")

            asyncio.run(self.serve())
        except Exception as e:
            self.logger.error(f"HTTP server error: {e}")
            sys.exit(1)
        finally:
            self._disconnect_all()


class ActiveDirectoryMCPCommand:
    """
    Command runner for Active Directory MCP HTTP server.

    This class can be used as a standalone command runner.
    """

    help = "Active Directory MCP HTTP Server"

    def __init__(self) -> None:
        self.server: Optional[ActiveDirectoryMCPHTTPServer] = None

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command line arguments."""
        parser.add_argument(
            "--host",
            type=str,
            # B104: deliberate container bind; HTTP auth is required by default (Phase 4)
            default="0.0.0.0",  # nosec B104
            help="Server host (default: 0.0.0.0)",
        )
        parser.add_argument("--port", type=int, default=8813, help="Server port (default: 8813)")
        parser.add_argument(
            "--path",
            type=str,
            default="/activedirectory-mcp",
            help="HTTP path (default: /activedirectory-mcp)",
        )
        parser.add_argument("--config", type=str, help="Configuration file path")

    def handle(self, *args: Any, **options: Any) -> None:
        """Handle the command execution."""
        config_path = options.get("config") or os.getenv("AD_MCP_CONFIG")

        self.server = ActiveDirectoryMCPHTTPServer(
            config_path=config_path,
            # B104: deliberate container bind; HTTP auth is required by default (Phase 4)
            host=options.get("host", "0.0.0.0"),  # nosec B104
            port=options.get("port", 8813),
            path=options.get("path", "/activedirectory-mcp"),
        )

        self.server.run()


def main() -> None:
    """Main entry point for standalone execution."""

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
