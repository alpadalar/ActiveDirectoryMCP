"""Drift guards between SECURITY.md and the code."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

from active_directory_mcp.config.models import SecurityConfig
from active_directory_mcp.policy import RISK_CLASSIFICATION, Risk
from active_directory_mcp.registry import MULTI_DOMAIN_TOOLS, build_tool_specs
from tests.unit.test_registry import make_ctx

REPO_ROOT = Path(__file__).resolve().parents[2]
SECURITY_MD = REPO_ROOT / "SECURITY.md"


def _generator():
    path = REPO_ROOT / "scripts" / "gen_security_table.py"
    if not path.exists():
        pytest.skip("generator not present (sdist?)")
    spec = importlib.util.spec_from_file_location("gen_security_table", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_security_table"] = module
    spec.loader.exec_module(module)
    return module


def _committed_region() -> str:
    gen = _generator()
    text = SECURITY_MD.read_text(encoding="utf-8")
    region = gen.extract_region(text)
    assert region is not None, "generated region markers missing from SECURITY.md"
    return region


def _table_tools(region: str):
    return re.findall(r"^\| `([a-z_0-9]+)` \| (\w+) \|", region, flags=re.M)


def test_render_has_one_row_per_tool_sorted_by_risk_then_name():
    gen = _generator()
    rows = _table_tools(gen.render_risk_table())
    assert {n for n, _ in rows} == set(RISK_CLASSIFICATION)
    order = {"read": 0, "write": 1, "destructive": 2}
    assert rows == sorted(rows, key=lambda r: (order[r[1]], r[0]))


def test_generator_render_detects_a_new_tool():
    gen = _generator()
    patched = dict(RISK_CLASSIFICATION, fake_new_tool=Risk.WRITE)
    assert gen.render_risk_table(patched) != gen.render_risk_table()
    assert "`fake_new_tool`" in gen.render_risk_table(patched)


def test_check_mode_detects_drift(tmp_path):
    gen = _generator()
    good = tmp_path / "ok.md"
    good.write_text(f"{gen.BEGIN}\n{gen.render_risk_table()}\n{gen.END}\n", encoding="utf-8")
    assert gen.main(["--check", "--file", str(good)]) == 0
    bad = tmp_path / "bad.md"
    bad.write_text(f"{gen.BEGIN}\n| stale |\n{gen.END}\n", encoding="utf-8")
    assert gen.main(["--check", "--file", str(bad)]) == 1
    assert gen.main(["--write", "--file", str(bad)]) == 0
    assert gen.main(["--check", "--file", str(bad)]) == 0


def test_committed_table_matches_fresh_render():
    assert _committed_region() == _generator().render_risk_table()


def test_table_tool_set_equals_registry():
    registered = {spec.name for spec in build_tool_specs(make_ctx())}
    listed = {n for n, _ in _table_tools(_committed_region())}
    assert listed == registered | MULTI_DOMAIN_TOOLS


def test_table_risk_values_are_known():
    assert {r for _, r in _table_tools(_committed_region())} <= {"read", "write", "destructive"}


def test_security_config_keys_in_text_exist():
    text = SECURITY_MD.read_text(encoding="utf-8")
    fields = set(SecurityConfig.model_fields)
    nested = {"api_key_sha256", "required"}
    keys = set(re.findall(r"`security\.([a-z_]+)(?:\.([a-z_0-9]+))?`", text))
    assert keys, "SECURITY.md should reference security.* keys"
    for first, second in keys:
        assert first in fields, f"unknown config key security.{first}"
        if second:
            assert first == "http_auth" and second in nested


def test_cited_test_files_exist():
    text = SECURITY_MD.read_text(encoding="utf-8")
    cited = set(re.findall(r"tests/unit/test_[a-z_0-9]+\.py", text))
    assert cited, "controls table should cite test files"
    for rel in cited:
        assert (REPO_ROOT / rel).is_file(), rel


def test_credential_value_not_present():
    text = SECURITY_MD.read_text(encoding="utf-8")
    assert "BEGIN GENERATED" in text
    assert not re.search(r"(?i)password\s*[:=]\s*\"[^\"\s]{4,}\"", text)


def test_audited_column_is_conditional_on_audit_log_path():
    """WR-04: auditing is opt-in (security.audit_log_path defaults to unset)."""
    assert SecurityConfig().audit_log_path is None
    region = _generator().render_risk_table()
    assert "| yes |" not in region
    for line in region.splitlines()[2:]:
        if "| read |" in line:
            assert line.endswith("| no |")
        else:
            assert line.endswith("| only if `security.audit_log_path` is set |")


def test_security_md_says_audit_is_off_by_default():
    text = SECURITY_MD.read_text(encoding="utf-8")
    row = next(line for line in text.splitlines() if line.startswith("| No record of what"))
    assert "off by default" in row and "`security.audit_log_path`" in row
