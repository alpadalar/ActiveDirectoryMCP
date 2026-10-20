"""Additive-only guard for the frozen tool surface.

``tests/golden/original_tools.sha256.json`` fingerprints the canonical entry of
each of the 42 pre-existing tools (both transports). Later phases may only ADD
tools: every original entry must keep its hash and the only new keys allowed are
the ones listed in ``ADDITIVE_TOOLS``.

Regenerate the fingerprint file (only ever from the unmodified original goldens):

    .venv/bin/python -c "from tests.unit.test_golden_additive import *; write_fingerprints()"
"""

import hashlib
import json
from pathlib import Path
from typing import Any, Dict

import pytest

from tests.support.tool_surface import serialize_surface

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "golden"
FINGERPRINTS = GOLDEN_DIR / "original_tools.sha256.json"
TRANSPORTS = ("http", "stdio")

# Tools added after the original 42 (plan 04.1-02; plan 04.1-03 adds the third).
ADDITIVE_TOOLS = {"get_nested_group_members", "get_rootdse_info"}


def _load_golden(transport: str) -> Dict[str, Any]:
    path = GOLDEN_DIR / f"tool_surface_{transport}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def entry_hash(entry: Dict[str, Any]) -> str:
    return hashlib.sha256(serialize_surface(entry)).hexdigest()


def compute_fingerprints() -> Dict[str, Dict[str, str]]:
    return {
        transport: {
            name: entry_hash(entry)
            for name, entry in sorted(_load_golden(transport)["tools"].items())
        }
        for transport in TRANSPORTS
    }


def write_fingerprints() -> None:
    FINGERPRINTS.write_text(
        json.dumps(compute_fingerprints(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


@pytest.fixture(scope="module")
def fingerprints() -> Dict[str, Dict[str, str]]:
    return json.loads(FINGERPRINTS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_fingerprint_lists_exactly_42_original_tools(fingerprints, transport):
    assert len(fingerprints[transport]) == 42


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_original_entries_unchanged(fingerprints, transport):
    tools = _load_golden(transport)["tools"]
    for name, digest in fingerprints[transport].items():
        assert name in tools, f"original tool {name} removed from {transport} golden"
        assert entry_hash(tools[name]) == digest, f"original tool {name} changed ({transport})"


@pytest.mark.parametrize("transport", TRANSPORTS)
def test_only_declared_tools_were_added(fingerprints, transport):
    new = set(_load_golden(transport)["tools"]) - set(fingerprints[transport])
    assert new <= ADDITIVE_TOOLS, f"unexpected new tools: {sorted(new - ADDITIVE_TOOLS)}"
