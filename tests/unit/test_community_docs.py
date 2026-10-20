"""Guard tests for community documents and the release notes."""

import re
from pathlib import Path

from active_directory_mcp import auth
from active_directory_mcp.config.models import HttpAuthConfig, SecurityConfig

ROOT = Path(__file__).resolve().parents[2]
CONTACT = "alp.adalar@gmail.com"

REQUIRED = [
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_required_files_exist() -> None:
    for rel in REQUIRED:
        assert (ROOT / rel).is_file(), rel


def test_code_of_conduct_contact_and_no_placeholders() -> None:
    text = _read("CODE_OF_CONDUCT.md")
    assert CONTACT in text
    assert "Contributor Covenant" in text
    assert "[INSERT" not in text.upper()


def test_issue_config_disables_blank_issues_and_routes_security() -> None:
    text = _read(".github/ISSUE_TEMPLATE/config.yml")
    assert re.search(r"^blank_issues_enabled:\s*false\s*$", text, re.M)
    assert "/security/policy" in text


def test_issue_forms_have_valid_shape() -> None:
    for rel in (
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
    ):
        text = _read(rel)
        assert re.search(r"^name:\s*\S", text, re.M), rel
        assert re.search(r"^description:\s*\S", text, re.M), rel
        assert re.search(r"^body:\s*$", text, re.M), rel
        assert re.search(r"^\s+- type:\s*(input|textarea|dropdown|checkboxes|markdown)", text, re.M)
        assert "\t" not in text, rel
    bug = _read(".github/ISSUE_TEMPLATE/bug_report.yml").lower()
    assert "never paste" in bug
    assert "transport" in bug and "python" in bug and "version" in bug


def test_pr_template_mentions_frozen_surface() -> None:
    text = _read(".github/PULL_REQUEST_TEMPLATE.md")
    assert "golden" in text.lower()
    assert "RISK_CLASSIFICATION" in text


def _release_section() -> str:
    text = _read("CHANGELOG.md")
    unreleased = text.index("## [Unreleased]")
    release = text.index("## [1.0.0]")
    assert unreleased < release
    # the Unreleased block between the two headings is empty
    assert text[unreleased + len("## [Unreleased]") : release].strip() == ""
    return text[release:]


def test_changelog_breaking_summary_leads_release() -> None:
    section = _release_section()
    first_h3 = re.search(r"^### .*$", section, re.M)
    assert first_h3 is not None
    assert first_h3.group(0).startswith("### Breaking changes")
    summary = section[first_h3.start() : section.index("\n### ", first_h3.end())]
    for needle in (
        "AD_MCP_HTTP_API_KEY",
        "AD_MCP_HTTP_API_KEY_SHA256",
        "security.http_auth",
        "security.http_auth.required",
        "security.allow_writes",
        "security.allow_destructive",
        "base_dn",
        "security.require_secure_connection",
        "SECURITY.md",
    ):
        assert needle in summary, needle


def test_changelog_names_match_code() -> None:
    assert "allow_writes" in SecurityConfig.model_fields
    assert "allow_destructive" in SecurityConfig.model_fields
    assert "require_secure_connection" in SecurityConfig.model_fields
    assert "http_auth" in SecurityConfig.model_fields
    assert "audit_log_path" in SecurityConfig.model_fields
    assert "required" in HttpAuthConfig.model_fields
    assert auth.ENV_API_KEY == "AD_MCP_HTTP_API_KEY"
    assert auth.ENV_API_KEY_SHA256 == "AD_MCP_HTTP_API_KEY_SHA256"


def test_changelog_added_section_names_new_tools() -> None:
    section = _release_section()
    added = section[section.index("### Added") :]
    for name in ("get_nested_group_members", "get_rootdse_info", "get_tls_posture"):
        assert name in added, name
    assert "audit" in added.lower()
    assert "42 original tools" in section
    assert "tag" not in re.findall(r"^\[1\.0\.0\]:.*$", _read("CHANGELOG.md"), re.M)


def test_changelog_has_no_internal_process_language() -> None:
    text = _read("CHANGELOG.md")
    assert not re.search(r"\bWR-\d+\b", text)
    assert not re.search(r"\bPhase \d", text)
