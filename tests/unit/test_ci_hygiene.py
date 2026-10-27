"""Guards for CI workflows, pins, release safety, badge URLs and attribution residue.

Pure file inspection (no network). Marker strings are assembled from fragments so this
file never contains a contiguous marker and passes its own scan.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
WORKFLOW_FILES = ("test.yml", "lint.yml", "security.yml", "release.yml")

USES_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
VERSION_COMMENT = re.compile(r"#\s*v\d")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}")


def _load(name: str) -> dict[Any, Any]:
    data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict), f"{name} did not parse to a mapping"
    return data


def _triggers(wf: dict[Any, Any]) -> dict[str, Any]:
    # YAML 1.1: a bare `on:` key is parsed as boolean True.
    raw = wf.get("on", wf.get(True))
    assert raw is not None, "workflow has no `on` section"
    return (
        raw
        if isinstance(raw, dict)
        else {str(k): None for k in (raw if isinstance(raw, list) else [raw])}
    )


def _steps(wf: dict[Any, Any]):
    for job_name, job in wf["jobs"].items():
        for step in job.get("steps", []):
            yield job_name, step


def _text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


# 1. Existence and basic safety -------------------------------------------------------


def test_workflows_and_dependabot_exist():
    for name in WORKFLOW_FILES:
        assert (WORKFLOWS / name).is_file(), f"missing .github/workflows/{name}"
    assert (ROOT / ".github" / "dependabot.yml").is_file()


@pytest.mark.parametrize("name", WORKFLOW_FILES)
def test_workflow_has_permissions_and_job_timeouts(name):
    wf = _load(name)
    assert "permissions" in wf, f"{name}: top-level permissions missing"
    for job_name, job in wf["jobs"].items():
        if "uses" in job:  # reusable-workflow call: the timeout lives in the called workflow
            continue
        assert "timeout-minutes" in job, f"{name}: job {job_name} has no timeout-minutes"


# 2. Pin format -----------------------------------------------------------------------


def test_pin_matcher_has_positive_and_negative_controls():
    assert not USES_PIN.match("actions/checkout@v4")
    assert not USES_PIN.match("actions/checkout@main")
    assert USES_PIN.match("actions/checkout@" + "a" * 40)
    assert not USES_PIN.match("actions/checkout@" + "a" * 39)


@pytest.mark.parametrize("name", WORKFLOW_FILES)
def test_every_action_is_sha_pinned_with_version_comment(name):
    for line in _text(name).splitlines():
        stripped = line.strip().lstrip("- ").strip()
        if not stripped.startswith("uses:"):
            continue
        ref = stripped[len("uses:") :].split("#", 1)[0].strip()
        if ref.startswith("./"):
            continue
        assert USES_PIN.match(ref), f"{name}: not pinned to a 40-hex SHA: {line.strip()}"
        assert VERSION_COMMENT.search(line), f"{name}: no `# v<n>` comment: {line.strip()}"


@pytest.mark.parametrize("name", WORKFLOW_FILES)
def test_docker_run_images_are_digest_pinned(name):
    for job_name, step in _steps(_load(name)):
        run = step.get("run", "")
        if "docker run" in run:
            assert DIGEST.search(run), f"{name}/{job_name}: docker run without @sha256 digest"


def test_dockerfile_from_lines_are_digest_pinned():
    froms = [
        line
        for line in (ROOT / "Dockerfile").read_text(encoding="utf-8").splitlines()
        if line.startswith("FROM ")
    ]
    assert froms
    for line in froms:
        assert DIGEST.search(line), f"Dockerfile FROM not digest-pinned: {line}"


# 4. Release safety -------------------------------------------------------------------


def test_release_triggers_and_permissions():
    wf = _load("release.yml")
    triggers = _triggers(wf)
    assert "workflow_dispatch" in triggers
    tag_patterns = triggers["push"]["tags"]
    assert tag_patterns and all(p.startswith("v") for p in tag_patterns)
    assert not {"pull_request", "pull_request_target"} & set(triggers)
    dry_run = triggers["workflow_dispatch"]["inputs"]["dry_run"]
    assert dry_run["default"] is True
    assert "packages" not in wf["permissions"], "packages: write must be job-level only"
    assert any(j.get("permissions", {}).get("packages") == "write" for j in wf["jobs"].values())


def _release_steps() -> list[dict[str, Any]]:
    return [s for _, s in _steps(_load("release.yml"))]


def _step_named(fragment: str) -> dict[str, Any]:
    matches = [s for s in _release_steps() if fragment in str(s.get("name", ""))]
    assert len(matches) == 1, f"expected one release step named like {fragment!r}"
    return matches[0]


def test_release_metadata_cannot_roll_back_latest_or_emit_branch_tags():
    text = _text("release.yml")
    assert "flavor: latest=false" in text
    assert "{{branch}}" not in text
    meta = _step_named("Image metadata")
    tags = meta["with"]["tags"]
    assert "type=raw,value=latest,enable=${{ steps.latest.outputs.is_latest == 'true' }}" in tags
    highest = _step_named("highest release")
    assert highest["id"] == "latest"
    assert "sort -V" in highest["run"] and "tail -n 1" in highest["run"]
    assert 'GITHUB_REF_TYPE}" = "tag"' in highest["run"]


def test_release_version_check_covers_push_and_non_dry_run_dispatch():
    step = _step_named("Verify tag matches pyproject version")
    cond = step["if"]
    assert "github.event_name == 'push'" in cond and "inputs.dry_run == false" in cond
    assert "GITHUB_REF_NAME" in step["run"] and "pyproject.toml" in step["run"]
    assert "exit 1" in step["run"]


def test_release_requires_tagged_commit_on_main_with_full_history():
    wf = _load("release.yml")
    job = wf["jobs"]["build-and-push"]
    checkout = [s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout")]
    assert checkout and checkout[0]["with"]["fetch-depth"] == 0
    step = _step_named("Require the tagged commit to be on main")
    assert "merge-base --is-ancestor" in step["run"] and "origin/main" in step["run"]
    assert "github.event_name == 'push'" in step["if"] and "inputs.dry_run == false" in step["if"]


def test_release_publish_job_needs_reused_test_and_lint_workflows():
    wf = _load("release.yml")
    jobs = wf["jobs"]
    called = {
        name: job["uses"] for name, job in jobs.items() if str(job.get("uses", "")).startswith("./")
    }
    assert "./.github/workflows/test.yml" in called.values()
    assert "./.github/workflows/lint.yml" in called.values()
    needs = jobs["build-and-push"]["needs"]
    needs = [needs] if isinstance(needs, str) else needs
    assert set(called) <= set(needs), "build-and-push must need every reused gate job"
    for name in ("test.yml", "lint.yml"):
        assert "workflow_call" in _triggers(_load(name)), f"{name} must be reusable"


def test_release_never_publishes_without_gate_conditions():
    build = _step_named("Build and push")
    push = build["with"]["push"]
    assert "github.event_name == 'push'" in push and "inputs.dry_run == false" in push
    login = _step_named("Log in to GHCR")
    assert "github.event_name == 'push'" in login["if"] and "inputs.dry_run == false" in login["if"]


def test_release_image_is_lowercase_ghcr_and_multiarch():
    text = _text("release.yml")
    images = re.findall(r"^\s*images:\s*(\S+)\s*$", text, re.M)
    assert images, "no metadata images: value"
    for image in images:
        assert image.startswith("ghcr.io/"), image
        assert image == image.lower(), f"image reference must be lowercase: {image}"
    assert "linux/amd64" in text and "linux/arm64" in text


# 5. Security workflow ----------------------------------------------------------------


def test_security_workflow_gates():
    text = _text("security.yml")
    assert "bandit" in text
    assert "trivy-action" in text
    wf = _load("security.yml")
    audit = [
        s for _, s in _steps(wf) if "pip-audit" in str(s.get("uses", "")) + str(s.get("name", ""))
    ]
    assert audit, "no pip-audit step"
    assert all(s.get("continue-on-error") is True for s in audit)
    assert re.search(r"#.*\bPROMOTE\b", text, re.I), "pip-audit needs a promote-to-gate comment"
    gitleaks = [s for _, s in _steps(wf) if "gitleaks" in str(s.get("run", ""))]
    assert gitleaks and ".gitleaks.toml" in gitleaks[0]["run"]
    checkout_depths = [
        s.get("with", {}).get("fetch-depth")
        for job in wf["jobs"].values()
        if any("gitleaks" in str(st.get("run", "")) for st in job["steps"])
        for s in job["steps"]
        if str(s.get("uses", "")).startswith("actions/checkout")
    ]
    assert checkout_depths == [0], "gitleaks job must check out with fetch-depth: 0"


def test_image_builds_never_reuse_a_cached_runtime_stage():
    """OS packages come from the runtime stage; a cached one would hide security fixes."""
    stages = re.findall(r"(?m)^FROM \S+ AS (\w+)$", (ROOT / "Dockerfile").read_text("utf-8"))
    assert "runtime" in stages
    for name in ("security.yml", "release.yml"):
        builds = [
            s
            for _, s in _steps(_load(name))
            if str(s.get("uses", "")).startswith("docker/build-push-action")
        ]
        assert builds, f"{name}: no image build"
        for step in builds:
            assert "runtime" in str(step["with"].get("no-cache-filters", "")).split(","), name


# 6. Test and lint workflows ----------------------------------------------------------


def test_test_workflow_matrix_and_locked_sync():
    wf = _load("test.yml")
    versions = wf["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    assert [str(v) for v in versions] == ["3.11", "3.12", "3.13"]
    assert "uv sync --locked" in _text("test.yml")


def test_test_job_checks_out_full_history_for_hygiene_tests():
    steps = _load("test.yml")["jobs"]["test"]["steps"]
    checkout = [s for s in steps if str(s.get("uses", "")).startswith("actions/checkout")]
    assert checkout and checkout[0].get("with", {}).get("fetch-depth") == 0


def test_lint_workflow_runs_ruff_and_mypy():
    text = _text("lint.yml")
    for cmd in ("ruff check", "ruff format --check", "mypy"):
        assert cmd in text, f"lint.yml does not run {cmd}"


# 7. Badge URLs -----------------------------------------------------------------------

BADGE_URL = re.compile(
    r"https?://[^\s)\]\"']*(?:img\.shields\.io/|/actions/workflows/|codecov\.io/)[^\s)\]\"']*"
)
OWNER_REPO = re.compile(r"alpadalar|activedirectorymcp", re.I)


def badge_problems(readme: str, workflow_dir: Path | None = None) -> list[str]:
    problems = []
    for url in BADGE_URL.findall(readme):
        for seg in OWNER_REPO.findall(url):
            if seg != seg.lower():
                problems.append(f"mixed-case owner/repo {seg!r} in {url}")
        wf = re.search(r"/([\w.-]+\.ya?ml)(?:[?#]|$)", url)
        if wf and workflow_dir is not None and not (workflow_dir / wf.group(1)).is_file():
            problems.append(f"badge references missing workflow {wf.group(1)}")
    return problems


def test_badge_check_rejects_uppercase_and_accepts_lowercase():
    bad = "![x](https://img.shields.io/github/actions/workflow/status/alpadalar/ActiveDirectoryMCP/test.yml)"
    good = bad.replace("ActiveDirectoryMCP", "activedirectorymcp")
    assert badge_problems(bad)
    assert badge_problems(good) == []
    ghost = good.replace("test.yml", "nope.yml")
    assert any("missing workflow" in p for p in badge_problems(ghost, WORKFLOWS))


def test_readme_badges_are_lowercase_and_point_at_real_workflows():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert badge_problems(readme, WORKFLOWS) == []  # passes while the README has no badge


# 8. Attribution residue --------------------------------------------------------------

_AGENT = "Cl" + "aude"
_VENDOR = "Anthr" + "opic"
_NOREPLY = "noreply@" + _VENDOR.lower() + ".com"
MARKERS = {
    "noreply": _NOREPLY,
    "robot-emoji": chr(0x1F916),
    "generated-with": "Generated " + "with " + _AGENT,
    "generated-by": "Generated " + "by " + _AGENT,
    "session-link": _AGENT.lower() + ".ai/" + "code",
    "session-trailer": _AGENT + "-Sess" + "ion:",
}
TRAILER = "Co-authored" + "-by:"

TEXT_FILES = ("README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md")


def _scan_targets() -> list[Path]:
    paths = [ROOT / name for name in TEXT_FILES]
    paths += sorted((ROOT / "docs").rglob("*.md"))
    paths += sorted((ROOT / ".github").rglob("*.yml")) + sorted((ROOT / ".github").rglob("*.md"))
    paths.append(ROOT / "pyproject.toml")
    return [p for p in paths if p.is_file()]


def test_phase5_documents_exist():
    for name in TEXT_FILES:
        assert (ROOT / name).is_file(), f"missing {name}"


def test_no_attribution_markers_in_docs_and_ci_config():
    for path in _scan_targets():
        text = path.read_text(encoding="utf-8")
        for label, marker in MARKERS.items():
            assert marker.lower() not in text.lower(), f"{path.relative_to(ROOT)}: {label}"
        if path.name != "CONTRIBUTING.md":  # may state the rule as prohibition prose
            assert not re.search(
                re.escape(TRAILER) + r".*(?:" + _AGENT + "|" + _VENDOR + ")", text, re.I
            ), f"{path.relative_to(ROOT)}: agent co-author trailer"


def _allowlisted_shas() -> set[str]:
    path = ROOT / "scripts" / "ai_residue_allowlist.txt"
    entries = (line.split("#", 1)[0].strip() for line in path.read_text().splitlines())
    return {e.split()[0].lower() for e in entries if e}


@pytest.mark.skipif(
    not (ROOT / ".git").exists() or shutil.which("git") is None, reason="no git history"
)
def test_no_attribution_markers_in_commit_messages():
    shallow = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "--is-shallow-repository"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    if shallow == "true":
        # A shallow clone would silently scan only part of the history.
        if os.environ.get("CI"):
            pytest.fail("shallow checkout in CI: use fetch-depth: 0 so all commits are scanned")
        pytest.skip("shallow clone: commit history is incomplete")
    out = subprocess.run(
        ["git", "-C", str(ROOT), "log", "--format=%H%x00%B%x01"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    allowed = _allowlisted_shas()
    for record in filter(None, (r.strip("\n") for r in out.split("\x01"))):
        sha, _, body = record.partition("\x00")
        if any(sha.lower().startswith(a) for a in allowed):
            continue
        for label, marker in MARKERS.items():
            assert marker.lower() not in body.lower(), f"commit {sha[:12]}: {label}"
        assert not re.search(
            re.escape(TRAILER) + r".*(?:" + _AGENT + "|" + _VENDOR + ")", body, re.I
        ), f"commit {sha[:12]}: agent co-author trailer"


# 9. Self-exclusion -------------------------------------------------------------------


def test_this_file_contains_no_contiguous_marker():
    text = Path(__file__).read_text(encoding="utf-8").lower()
    for label, marker in MARKERS.items():
        assert marker.lower() not in text, f"self-scan: {label}"
    assert (TRAILER + " " + _AGENT).lower() not in text
