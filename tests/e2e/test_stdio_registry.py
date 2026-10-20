"""The stdio engine serves the shared registry (CONS-01, CONS-04)."""

import asyncio
import json
import os
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

from mcp.shared.memory import create_connected_server_and_client_session

from tests.support.mock_directory import MockDirectory
from tests.support.tool_surface import canonical_input_schema

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "tests" / "golden" / "tool_surface_stdio.json"


def _build_stdio_server(tmp_path: Path, directory: MockDirectory) -> Any:
    from active_directory_mcp.server import ActiveDirectoryMCPServer

    return ActiveDirectoryMCPServer()


def _run(tmp_path: Path, scenario: Any) -> None:
    directory = MockDirectory()
    directory.add_user("alice")
    with directory.patch(), patch.dict(os.environ, directory.env(tmp_path)):
        for var in ("AD_BIND_DN", "AZURE_KEYVAULT_URL"):
            os.environ.pop(var, None)
        server = _build_stdio_server(tmp_path, directory)

        async def main() -> None:
            async with create_connected_server_and_client_session(server.mcp) as session:
                await scenario(session)

        try:
            asyncio.run(main())
        finally:
            server.ldap_manager.disconnect()


def test_stdio_registry_over_in_memory_session(tmp_path: Path) -> None:
    golden = json.loads(GOLDEN.read_text(encoding="utf-8"))["tools"]

    async def scenario(session: Any) -> None:
        listed = (await session.list_tools()).tools
        assert len(listed) == 42
        actual: Dict[str, Any] = {t.name: canonical_input_schema(t.inputSchema) for t in listed}
        assert actual == golden

        health = await session.call_tool("health", {})
        info = json.loads(health.content[0].text)
        assert "tests_passed" in info and "status" in info

        conn = await session.call_tool("test_connection", {})
        assert not conn.isError
        assert json.loads(conn.content[0].text)

        users = await session.call_tool("list_users", {})
        assert "alice" in users.content[0].text

        unknown = await session.call_tool("no_such_tool", {})
        assert "Unknown tool" in json.loads(unknown.content[0].text)["error"]

    _run(tmp_path, scenario)


def test_compose_healthcheck_targets_health_route() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        match = re.search(r"healthcheck:\s*\n\s*test:\s*(.+)", text)
        assert match, "healthcheck test not found"
        test = match.group(1)
    else:
        data = yaml.safe_load(text)
        service = next(s for s in data["services"].values() if "healthcheck" in s)
        test = " ".join(service["healthcheck"]["test"])
    assert "/health" in test
    assert "-X POST" not in test and '"method"' not in test and "method" not in test
