"""Drift guard: README claims must match the registry, config models and example files."""

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterator, List, Set, Tuple
from unittest.mock import MagicMock

import pytest
from pydantic import TypeAdapter

from active_directory_mcp.config.models import Config, HttpAuthConfig, SecurityConfig
from active_directory_mcp.policy import RISK_CLASSIFICATION
from active_directory_mcp.registry import ToolContext, build_tool_specs

ROOT = Path(__file__).resolve().parent.parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
EXAMPLES = sorted((ROOT / "examples").glob("*.json"))

SECRET_KEY_RE = re.compile(r"KEY|PASSWORD|SECRET|TOKEN|AUTHORIZATION", re.IGNORECASE)
# Allowed secret values: obvious placeholders or environment references only.
PLACEHOLDER_RE = re.compile(r"^(?:Bearer )?(?:REPLACE_WITH_[A-Z0-9_]+|\$\{[^}]+\})$")
FORBIDDEN_PATH_FRAGMENTS = ("/media/workspace", "/home/", "C:\\Users")


def _registry_names() -> List[str]:
    ctx = ToolContext(
        user_tools=MagicMock(),
        group_tools=MagicMock(),
        computer_tools=MagicMock(),
        ou_tools=MagicMock(),
        security_tools=MagicMock(),
        ldap_manager=MagicMock(),
        server_name="readme-drift-test",
    )
    return [spec.name for spec in build_tool_specs(ctx)]


def _json_blocks(text: str) -> List[Dict[str, Any]]:
    blocks = []
    for raw in re.findall(r"```json\n(.*?)```", text, flags=re.DOTALL):
        blocks.append(json.loads(raw))
    return blocks


def _walk(node: Any, key: str = "") -> Iterator[Tuple[str, Any]]:
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, k)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, key)
    else:
        yield key, node


def _assert_placeholder_only(doc: Any, where: str) -> None:
    for key, value in _walk(doc):
        if not isinstance(value, str):
            continue
        for fragment in FORBIDDEN_PATH_FRAGMENTS:
            assert fragment not in value, f"{where}: personal path {fragment!r} in {key}"
        if SECRET_KEY_RE.search(key):
            assert PLACEHOLDER_RE.match(value), f"{where}: {key} must be a placeholder or env ref"


def test_tool_tables_match_registry() -> None:
    rows = re.findall(r"^\| `([a-z_]+)` \| (read|write|destructive) \|", README, re.MULTILINE)
    documented = [name for name, _ in rows]
    registry = _registry_names()
    assert len(documented) == len(set(documented)), "tool listed more than once in README"
    assert set(documented) == set(registry), (
        f"missing in README: {sorted(set(registry) - set(documented))}; "
        f"unknown in README: {sorted(set(documented) - set(registry))}"
    )
    for name, risk in rows:
        assert RISK_CLASSIFICATION[name].value == risk, f"{name}: README says {risk}"


def test_tool_count_in_prose_matches_registry() -> None:
    expected = len(_registry_names())
    counts = {int(n) for n in re.findall(r"\b(\d+) (?:MCP )?tools\b", README)}
    assert counts == {expected}, f"README tool counts {sorted(counts)} != registry {expected}"


def _code_env_corpus() -> str:
    parts = [(ROOT / "docker-compose.yml").read_text(encoding="utf-8")]
    for extra in (
        ".env.example",
        "docker-compose-openldap.yml",
        "start_server.sh",
        "start_http_server.sh",
    ):
        path = ROOT / extra
        if path.exists():
            parts.append(path.read_text(encoding="utf-8"))
    for path in (ROOT / "src").rglob("*.py"):
        parts.append(path.read_text(encoding="utf-8"))
    return "\n".join(parts)


def test_env_vars_named_in_readme_exist_in_code() -> None:
    named: Set[str] = set(re.findall(r"\b(?:AD_|HTTP_|AZURE_|LAB_)[A-Z0-9_]+\b", README))
    named -= {"AD_"}
    assert named, "README names no environment variables"
    corpus = _code_env_corpus()
    missing = sorted(var for var in named if var not in corpus)
    assert not missing, f"env vars in README not found in src/compose: {missing}"


def test_security_keys_named_in_readme_exist() -> None:
    top = set(SecurityConfig.model_fields)
    auth = set(HttpAuthConfig.model_fields)
    named = re.findall(r"`security\.([a-z_]+)(?:\.([a-z_0-9]+))?`", README)
    assert named, "README names no security.* keys"
    for first, second in named:
        assert first in top, f"security.{first} is not a SecurityConfig field"
        if second:
            assert first == "http_auth" and second in auth, f"security.{first}.{second} unknown"


def test_full_config_blocks_validate() -> None:
    validated = 0
    for block in _json_blocks(README):
        if "mcpServers" in block:
            continue
        if "active_directory" in block:
            Config.model_validate(block)
            validated += 1
            continue
        for section, value in block.items():
            assert section in Config.model_fields, f"unknown config section {section!r}"
            TypeAdapter(Config.model_fields[section].annotation).validate_python(value)
            validated += 1
    assert validated >= 3, "expected full and partial config blocks in README"


def test_readme_client_blocks_are_placeholder_only() -> None:
    clients = [b for b in _json_blocks(README) if "mcpServers" in b]
    assert len(clients) >= 4, "README should show Claude Desktop, Claude Code and Cursor configs"
    for block in clients:
        _assert_placeholder_only(block, "README")


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_files_parse_and_hold_no_secret(path: Path) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert "mcpServers" in doc
    _assert_placeholder_only(doc, path.name)


def test_examples_exist_and_lab_example_points_at_lab_config() -> None:
    names = {p.name for p in EXAMPLES}
    assert {
        "claude_desktop_config.json",
        "claude_code_mcp.json",
        "cursor_mcp_config.json",
        "cursor_openldap_config.json",
    } <= names
    lab = (ROOT / "examples" / "cursor_openldap_config.json").read_text(encoding="utf-8")
    assert "ad-config/openldap-lab.example.json" in lab


def test_readme_style() -> None:
    assert not re.search(r"[ığşçöüİĞŞÇÖÜ]", README), "README must be English only"
    for line in README.splitlines():
        if line.startswith("#"):
            assert all(ord(ch) < 0x2190 for ch in line), f"decorative symbol in heading: {line}"
    assert "shields.io" not in README and "badge" not in README.lower()
    for link in ("SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md"):
        assert f"]({link})" in README, f"README must link {link}"
    assert not re.search(r"(?m)^\s*(?:uv sync --all-extras|uv sync)\s*$", README), (
        "quickstart must use 'uv sync --locked'"
    )


def _src_corpus() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "src").rglob("*.py"))


def _assigned_env_names(text: str) -> Set[str]:
    """Names assigned as ``- NAME=`` / ``# - NAME=`` / ``NAME=`` (active or commented)."""
    return set(re.findall(r"^\s*(?:#\s*)?(?:-\s*)?([A-Z][A-Z0-9_]{2,})=", text, flags=re.MULTILINE))


def test_compose_env_overrides_are_read_by_the_server() -> None:
    """WR-05: no documented override may be a name the server never reads."""
    corpus = _src_corpus()
    named = _assigned_env_names((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    assert {"AD_MCP_CONFIG", "AD_BIND_DN", "AD_PASSWORD"} <= named
    missing = sorted(name for name in named if name not in corpus)
    assert not missing, f"docker-compose.yml names variables nothing in src/ reads: {missing}"


def test_env_example_names_are_read_by_the_server_or_launchers() -> None:
    corpus = _src_corpus() + "\n".join(
        (ROOT / n).read_text(encoding="utf-8")
        for n in ("start_server.sh", "start_http_server.sh")
    )
    named = _assigned_env_names((ROOT / ".env.example").read_text(encoding="utf-8"))
    missing = sorted(name for name in named if name not in corpus)
    assert not missing, f".env.example names variables nothing reads: {missing}"


def test_docker_quickstart_supplies_bind_credentials() -> None:
    """WR-06: the compose quickstart must pass a bind password or the container crash-loops."""
    section = README.split("\n## Docker\n", 1)[1].split("\n## ", 1)[0]
    block = re.search(r"```bash\nexport AD_MCP_HTTP_API_KEY.*?```", section, flags=re.DOTALL)
    assert block, "Docker quickstart block not found"
    assert "AD_BIND_DN" in block.group(0) and "AD_PASSWORD" in block.group(0)
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for name in ("AD_BIND_DN", "AD_PASSWORD"):
        assert re.search(rf"^\s*- {name}=\$\{{{name}:-\}}\s*$", compose, flags=re.MULTILINE), name


def test_readme_does_not_overstate_network_or_audit_guarantees() -> None:
    """WR-08 / IN-03: Key Vault contacts Azure; O_APPEND does not make a file tamper-proof."""
    assert "Nothing is sent anywhere" not in README
    assert "append-only" not in README.lower()
    assert "Azure Key Vault" in README.split("## Requirements", 1)[0]
