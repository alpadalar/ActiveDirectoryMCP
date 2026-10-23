"""MCP tool annotations (readOnlyHint / destructiveHint) follow RISK_CLASSIFICATION."""

import asyncio
from typing import Any, Dict

import pytest

from active_directory_mcp.policy import RISK_CLASSIFICATION, Risk
from active_directory_mcp.registry import MULTI_DOMAIN_TOOLS, tool_annotations
from tests.support.tool_surface import _offline_env

EXPECTED = {
    Risk.READ: (True, False),
    Risk.WRITE: (False, False),
    Risk.DESTRUCTIVE: (False, True),
}


def _stdio_annotations() -> Dict[str, Any]:
    with _offline_env("active_directory_mcp.server"):
        from active_directory_mcp.server import ActiveDirectoryMCPServer

        server = ActiveDirectoryMCPServer()
        return {tool.name: tool.annotations for tool in server._tools}


def _http_annotations() -> Dict[str, Any]:
    with _offline_env("active_directory_mcp.server_http"):
        from active_directory_mcp.server_http import ActiveDirectoryMCPHTTPServer

        server = ActiveDirectoryMCPHTTPServer()
        tools = asyncio.run(server.mcp.list_tools())
        return {tool.name: tool.annotations for tool in tools}


@pytest.mark.parametrize("collect", [_stdio_annotations, _http_annotations], ids=["stdio", "http"])
def test_every_tool_advertises_its_risk_class(collect: Any) -> None:
    annotations = collect()
    assert set(annotations) == set(RISK_CLASSIFICATION) - MULTI_DOMAIN_TOOLS
    for name, hints in annotations.items():
        assert hints is not None, name
        expected = EXPECTED[RISK_CLASSIFICATION[name]]
        assert (hints.readOnlyHint, hints.destructiveHint) == expected, name


def test_risk_class_counts() -> None:
    hints = [tool_annotations(name) for name in RISK_CLASSIFICATION]
    assert sum(h.readOnlyHint for h in hints) == 25  # 24 + list_domains
    assert sum(not h.readOnlyHint and not h.destructiveHint for h in hints) == 17
    assert sum(bool(h.destructiveHint) for h in hints) == 4


def test_unknown_tool_is_advertised_as_destructive() -> None:
    hints = tool_annotations("not_a_registered_tool")
    assert hints.readOnlyHint is False and hints.destructiveHint is True
