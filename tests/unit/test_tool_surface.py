"""Tool-surface contract tests (STAB-06).

The tool names, parameter names, canonical types, defaults and required sets of
both transports are frozen in tests/golden/tool_surface_{stdio,http}.json.
Tool descriptions are deliberately not part of the contract.

Intentional surface change: regenerate the golden files with

    UPDATE_GOLDEN=1 .venv/bin/pytest tests/unit/test_tool_surface.py -q

review the diff and record the change in CHANGELOG.md.
"""

import difflib
import json
import os
from pathlib import Path

import pytest

from tests.support.tool_surface import (
    build_http_surface,
    build_stdio_surface,
    canonical_input_schema,
    canonical_property,
    serialize_surface,
)

GOLDEN_DIR = Path(__file__).resolve().parent.parent / "golden"
STDIO_GOLDEN = GOLDEN_DIR / "tool_surface_stdio.json"
HTTP_GOLDEN = GOLDEN_DIR / "tool_surface_http.json"
UPDATE = os.environ.get("UPDATE_GOLDEN") == "1"


# --------------------------------------------------------------------------
# Canonicalization rules (pure functions)
# --------------------------------------------------------------------------


def test_canonical_optional_equals_plain_with_default():
    optional = {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None}
    assert canonical_property(optional) == {
        "type": "string",
        "nullable": True,
        "default": None,
    }


def test_canonical_nullable_only_when_explicit_null_member():
    assert "nullable" not in canonical_property({"type": "string", "default": None})
    assert "nullable" not in canonical_property({"type": "string"})


def test_canonical_nested_anyof_is_flattened():
    nested = {"anyOf": [{"anyOf": [{"type": "string"}, {"type": "null"}]}, {"type": "integer"}]}
    flat = {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]}
    assert canonical_property(nested) == canonical_property(flat)
    assert canonical_property(nested)["type"] == "integer|string"


def test_canonical_union_sorted_and_deduplicated():
    schema = {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "string"}]}
    assert canonical_property(schema) == {"type": "integer|string"}


def test_canonical_type_list_equals_anyof():
    assert canonical_property({"type": ["string", "null"]}) == canonical_property(
        {"anyOf": [{"type": "string"}, {"type": "null"}]}
    )


def test_canonical_arrays():
    assert canonical_property({"type": "array", "items": {"type": "string"}}) == {
        "type": "array<string>"
    }
    assert canonical_property({"type": "array", "items": {}}) == {"type": "array<any>"}
    assert canonical_property({"type": "array"}) == {"type": "array<any>"}


def test_canonical_object():
    schema = {"type": "object", "additionalProperties": True, "title": "X"}
    assert canonical_property(schema) == {"type": "object"}


def test_canonical_drops_noise_keys():
    schema = {
        "type": "boolean",
        "title": "T",
        "description": "d",
        "examples": [True],
        "$schema": "x",
        "additionalProperties": False,
        "default": True,
    }
    assert canonical_property(schema) == {"type": "boolean", "default": True}


@pytest.mark.parametrize(
    "schema", [{"$ref": "#/$defs/X"}, {"type": "array", "items": {"$ref": "#/$defs/X"}}]
)
def test_canonical_ref_raises(schema):
    with pytest.raises(ValueError, match=r"\$ref"):
        canonical_property(schema)


def test_canonical_defs_raise():
    with pytest.raises(ValueError, match=r"\$defs"):
        canonical_input_schema({"type": "object", "properties": {}, "$defs": {"X": {}}})


def test_canonical_input_schema_required_sorted():
    schema = {
        "type": "object",
        "properties": {"b": {"type": "string"}, "a": {"type": "integer", "default": 3}},
        "required": ["b", "a"],
    }
    assert canonical_input_schema(schema) == {
        "params": {"b": {"type": "string"}, "a": {"type": "integer", "default": 3}},
        "required": ["a", "b"],
    }


def test_canonical_input_schema_without_properties():
    assert canonical_input_schema({"type": "object"}) == {"params": {}, "required": []}


def test_serialize_is_deterministic_bytes():
    surface = {"tool_count": 1, "tools": {"t": {"params": {}, "required": []}}}
    data = serialize_surface(surface)
    assert isinstance(data, bytes)
    assert data.endswith(b"\n")
    assert data == serialize_surface(json.loads(data))
    assert data.decode("ascii") == json.dumps(surface, sort_keys=True, indent=2) + "\n"


# --------------------------------------------------------------------------
# Real servers (no directory server needed)
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def stdio_bytes() -> bytes:
    return serialize_surface(build_stdio_surface())


@pytest.fixture(scope="module")
def http_bytes() -> bytes:
    return serialize_surface(build_http_surface())


def _compare(actual: bytes, golden: Path) -> None:
    if UPDATE:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_bytes(actual)
        return
    expected = golden.read_bytes()
    if actual != expected:
        diff = "\n".join(
            list(
                difflib.unified_diff(
                    expected.decode().splitlines(),
                    actual.decode().splitlines(),
                    "golden",
                    "current",
                    lineterm="",
                )
            )[:60]
        )
        pytest.fail(
            f"Tool surface drifted from {golden.name}.\n{diff}\n"
            "An intentional surface change must be reviewed, regenerated with "
            "UPDATE_GOLDEN=1 and recorded in CHANGELOG.md."
        )


def test_stdio_surface_matches_golden(stdio_bytes):
    _compare(stdio_bytes, STDIO_GOLDEN)


def test_http_surface_matches_golden(http_bytes):
    _compare(http_bytes, HTTP_GOLDEN)


def test_transport_parity(stdio_bytes, http_bytes):
    stdio = json.loads(stdio_bytes)["tools"]
    http = json.loads(http_bytes)["tools"]
    problems = []
    for name in sorted(set(stdio) ^ set(http)):
        problems.append(f"{name}: only on {'stdio' if name in stdio else 'http'}")
    for name in sorted(set(stdio) & set(http)):
        if set(stdio[name]["params"]) != set(http[name]["params"]):
            problems.append(f"{name}: parameter names differ")
        if stdio[name]["required"] != http[name]["required"]:
            problems.append(f"{name}: required sets differ")
    assert not problems, "Transport drift in tools: " + "; ".join(problems)


@pytest.mark.parametrize("golden", [STDIO_GOLDEN, HTTP_GOLDEN], ids=lambda p: p.name)
def test_golden_files_are_canonical(golden, stdio_bytes, http_bytes):
    data = golden.read_bytes()
    assert serialize_surface(json.loads(data)) == data
    parsed = json.loads(data)
    assert parsed["tool_count"] == len(parsed["tools"])


def test_dump_for_matrix(stdio_bytes, http_bytes):
    dump_dir = os.environ.get("TOOL_SURFACE_DUMP_DIR")
    if not dump_dir:
        pytest.skip("TOOL_SURFACE_DUMP_DIR not set")
    out = Path(dump_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "tool_surface_stdio.json").write_bytes(stdio_bytes)
    (out / "tool_surface_http.json").write_bytes(http_bytes)
