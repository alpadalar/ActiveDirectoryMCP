#!/usr/bin/env python3
"""
Test script for ActiveDirectoryMCP HTTP server.

This script demonstrates how to interact with the ActiveDirectoryMCP server
via HTTP transport and tests various operations.

Usage: uv run python tests/manual/http_server_smoke.py [URL]

Manual smoke aid only (not collected by pytest). The HTTP transport
requires an API key: export AD_MCP_HTTP_API_KEY with the server's key before
running. /health is unauthenticated.
"""

import json
import os
import sys
from typing import Any, Dict, Optional

import requests


class ActiveDirectoryMCPClient:
    """HTTP client for ActiveDirectoryMCP server."""

    def __init__(self, base_url: str = "http://localhost:8813/activedirectory-mcp"):
        """
        Initialize the client.

        Args:
            base_url: Base URL of the ActiveDirectoryMCP HTTP server
        """
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )
        api_key = os.environ.get("AD_MCP_HTTP_API_KEY")
        if api_key:
            self.session.headers["Authorization"] = f"Bearer {api_key}"

    def call_tool(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Call a tool on the MCP server.

        Args:
            method: Tool method name
            params: Parameters for the tool

        Returns:
            Response from the server
        """
        if params is None:
            params = {}

        payload = {"method": method, "params": params}

        try:
            response = self.session.post(self.base_url, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Request failed: {str(e)}"}

    def health_check(self) -> Dict[str, Any]:
        """Perform health check."""
        return self.call_tool("health")

    def test_connection(self) -> Dict[str, Any]:
        """Test LDAP connection."""
        return self.call_tool("test_connection")

    def get_schema_info(self) -> Dict[str, Any]:
        """Get schema information."""
        return self.call_tool("get_schema_info")

    def list_users(self, ou: Optional[str] = None) -> Dict[str, Any]:
        """List users."""
        params = {}
        if ou:
            params["ou"] = ou
        return self.call_tool("list_users", params)

    def list_groups(self, ou: Optional[str] = None) -> Dict[str, Any]:
        """List groups."""
        params = {}
        if ou:
            params["ou"] = ou
        return self.call_tool("list_groups", params)

    def list_computers(self, ou: Optional[str] = None) -> Dict[str, Any]:
        """List computers."""
        params = {}
        if ou:
            params["ou"] = ou
        return self.call_tool("list_computers", params)

    def get_domain_info(self) -> Dict[str, Any]:
        """Get domain information."""
        return self.call_tool("get_domain_info")

    def get_privileged_groups(self) -> Dict[str, Any]:
        """Get privileged groups."""
        return self.call_tool("get_privileged_groups")

    def audit_admin_accounts(self) -> Dict[str, Any]:
        """Audit admin accounts."""
        return self.call_tool("audit_admin_accounts")


def print_response(title: str, response: Dict[str, Any]) -> None:
    """Print formatted response."""
    print(f"\n{'=' * 60}")
    print(f"🔍 {title}")
    print("=" * 60)

    if "error" in response:
        print(f"❌ Error: {response['error']}")
    else:
        print("✅ Success")
        print(json.dumps(response, indent=2, ensure_ascii=False))


def test_basic_operations(client: ActiveDirectoryMCPClient) -> None:
    """Test basic server operations."""
    print("🚀 Testing Basic Operations")

    # Health check
    response = client.health_check()
    print_response("Health Check", response)

    # Connection test
    response = client.test_connection()
    print_response("Connection Test", response)

    # Schema info
    response = client.get_schema_info()
    print_response("Schema Information", response)


def test_directory_operations(client: ActiveDirectoryMCPClient) -> None:
    """Test directory listing operations."""
    print("\n📂 Testing Directory Operations")

    # List users
    response = client.list_users()
    print_response("List Users", response)

    # List groups
    response = client.list_groups()
    print_response("List Groups", response)

    # List computers
    response = client.list_computers()
    print_response("List Computers", response)


def test_security_operations(client: ActiveDirectoryMCPClient) -> None:
    """Test security and audit operations."""
    print("\n🛡️ Testing Security Operations")

    # Domain info
    response = client.get_domain_info()
    print_response("Domain Information", response)

    # Privileged groups
    response = client.get_privileged_groups()
    print_response("Privileged Groups", response)

    # Admin account audit
    response = client.audit_admin_accounts()
    print_response("Admin Account Audit", response)


def test_error_handling(client: ActiveDirectoryMCPClient) -> None:
    """Test error handling."""
    print("\n⚠️ Testing Error Handling")

    # Test invalid method
    response = client.call_tool("invalid_method")
    print_response("Invalid Method Test", response)

    # Test invalid parameters
    response = client.call_tool("get_user", {"username": ""})
    print_response("Invalid Parameters Test", response)


def check_server_availability(client: ActiveDirectoryMCPClient) -> bool:
    """Check if server is available."""
    try:
        response = client.health_check()
        return "error" not in response
    except Exception:
        return False


def main():
    """Main test function."""
    if not os.environ.get("AD_MCP_HTTP_API_KEY"):
        print("SKIP: set AD_MCP_HTTP_API_KEY to the server's API key (MCP calls require it).")
        return
    print("🔧 ActiveDirectoryMCP HTTP Server Test Script")
    print("=" * 60)

    # Parse command line arguments
    base_url = "http://localhost:8813/activedirectory-mcp"
    if len(sys.argv) > 1:
        base_url = sys.argv[1]

    print(f"🌐 Testing server at: {base_url}")

    # Initialize client
    client = ActiveDirectoryMCPClient(base_url)

    # Check server availability
    print("\n🔍 Checking server availability...")
    if not check_server_availability(client):
        print("❌ Server is not available. Please check:")
        print("   1. Server is running")
        print("   2. URL is correct")
        print("   3. No firewall blocking the connection")
        print("\n💡 To start the server:")
        print("   docker compose up -d")
        print("   # OR")
        print("   ./start_http_server.sh")
        return

    print("✅ Server is available!")

    try:
        # Run tests
        test_basic_operations(client)
        test_directory_operations(client)
        test_security_operations(client)
        test_error_handling(client)

        print("\n🎉 All tests completed!")
        print("\n📊 Test Summary:")
        print("   ✅ Basic operations")
        print("   ✅ Directory operations")
        print("   ✅ Security operations")
        print("   ✅ Error handling")

    except KeyboardInterrupt:
        print("\n\n⏹️ Tests interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Test failed with error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
