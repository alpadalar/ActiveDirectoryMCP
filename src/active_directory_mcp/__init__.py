"""
ActiveDirectoryMCP - Model Context Protocol server for Active Directory management.

This package provides a comprehensive MCP server for interacting with Active Directory
through LDAP protocol, offering tools for user management, group operations,
organizational unit management, and security operations.
"""

__version__ = "1.0.0"
__author__ = "Alperen Adalar"
__email__ = "alp.adalar@gmail.com"

from .server import ActiveDirectoryMCPServer

__all__ = ["ActiveDirectoryMCPServer"]
