"""TOOL_DESCRIPTIONS / TOOL_INPUT_SCHEMAS are the single description and stdio schema source."""

import json
import re
from pathlib import Path

import pytest

from active_directory_mcp.tools import definitions
from active_directory_mcp.tools.definitions import TOOL_DESCRIPTIONS, TOOL_INPUT_SCHEMAS
from tests.support.tool_surface import canonical_input_schema

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "golden"
HTTP_GOLDEN = json.loads((GOLDEN_DIR / "tool_surface_http.json").read_text(encoding="utf-8"))
STDIO_GOLDEN = json.loads((GOLDEN_DIR / "tool_surface_stdio.json").read_text(encoding="utf-8"))
TOOL_NAMES = sorted(HTTP_GOLDEN["tools"])


def test_descriptions_cover_exactly_the_golden_tools() -> None:
    assert len(TOOL_DESCRIPTIONS) == 44
    assert sorted(TOOL_DESCRIPTIONS) == TOOL_NAMES


@pytest.mark.parametrize("name", TOOL_NAMES)
def test_description_is_non_empty_string(name: str) -> None:
    value = TOOL_DESCRIPTIONS[name]
    assert isinstance(value, str) and value.strip()


def test_every_desc_constant_is_used_once() -> None:
    constants = {
        key: value
        for key, value in vars(definitions).items()
        if key.endswith("_DESC") and isinstance(value, str)
    }
    assert sorted(constants.values()) == sorted(TOOL_DESCRIPTIONS.values())


def test_input_schemas_cover_exactly_the_golden_tools() -> None:
    assert len(TOOL_INPUT_SCHEMAS) == 44
    assert sorted(TOOL_INPUT_SCHEMAS) == TOOL_NAMES


@pytest.mark.parametrize("name", TOOL_NAMES)
def test_stdio_schema_matches_golden(name: str) -> None:
    assert canonical_input_schema(TOOL_INPUT_SCHEMAS[name]) == STDIO_GOLDEN["tools"][name]


def test_descriptions_only_reference_known_tools() -> None:
    known = set(TOOL_NAMES)
    call = re.compile(r"^\s*-\s+([a-z_]+)\(", re.M)
    for name, text in TOOL_DESCRIPTIONS.items():
        for called in call.findall(text):
            assert called in known, f"{name} description mentions unknown tool {called}"
