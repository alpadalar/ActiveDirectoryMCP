#!/usr/bin/env python3
"""Full-history and tree secret scan driven by ``.gitleaks.toml``.

Stdlib only. Output never contains a matched value: every finding is printed as
``<sha[:12]> <path> <rule-id> [REDACTED]``.

Exit codes: 0 nothing beyond the baseline, 1 new findings, 2 tooling error.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple

SCRIPT_REPO = Path(__file__).resolve().parent.parent
TREE_SHA = "HEAD"

Finding = Tuple[str, str, str]  # (sha, path, rule-id)


class ScanError(Exception):
    """Tooling failure (exit code 2)."""


@dataclass
class Rules:
    rules: List[Tuple[str, "re.Pattern[str]"]]
    allow_regexes: List["re.Pattern[str]"]
    allow_paths: List["re.Pattern[str]"]


def load_rules(config: Path) -> Rules:
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScanError(f"cannot read rules from {config}: {exc}") from exc
    rules: List[Tuple[str, "re.Pattern[str]"]] = []
    for rule in data.get("rules", []):
        # Only rules carrying their own regex are evaluated locally; the default
        # gitleaks ruleset (extend.useDefault) needs the real binary.
        if "regex" in rule:
            rules.append((rule["id"], re.compile(rule["regex"])))
    allow = data.get("allowlist", {})
    return Rules(
        rules=rules,
        allow_regexes=[re.compile(r) for r in allow.get("regexes", [])],
        allow_paths=[re.compile(r) for r in allow.get("paths", [])],
    )


def scan_line(rules: Rules, path: str, line: str) -> Iterator[str]:
    """Yield rule ids that fire on ``line`` after the allow-list is applied."""
    if any(p.search(path) for p in rules.allow_paths):
        return
    for rule_id, pattern in rules.rules:
        for match in pattern.finditer(line):
            text = match.group(0)
            if any(a.search(text) for a in rules.allow_regexes):
                continue
            yield rule_id
            break


def _git(repo: Path, *args: str) -> subprocess.Popen:  # type: ignore[type-arg]
    try:
        return subprocess.Popen(
            ["git", "-C", str(repo), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ScanError(f"cannot run git: {exc}") from exc


def history_findings(repo: Path, rules: Rules) -> Tuple[Set[Finding], int]:
    """Scan added lines of every commit on every ref. Returns (findings, commits)."""
    proc = _git(repo, "log", "--all", "-p", "--no-color", "--format=COMMIT%x00%H")
    assert proc.stdout is not None
    findings: Set[Finding] = set()
    commits = 0
    sha = ""
    path = ""
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n")
        if line.startswith("COMMIT\x00"):
            sha = line.split("\x00", 1)[1]
            path = ""
            commits += 1
        elif line.startswith("+++ "):
            path = line[4:]
            path = path[2:] if path.startswith("b/") else path
        elif line.startswith("+") and path and path != "/dev/null":
            for rule_id in scan_line(rules, path, line[1:]):
                findings.add((sha, path, rule_id))
    proc.stdout.close()
    if proc.wait() != 0:
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        raise ScanError(f"git log failed: {err.strip()}")
    return findings, commits


def tree_findings(repo: Path, rules: Rules) -> Tuple[Set[Finding], int]:
    """Scan every tracked file at the working tree."""
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=False
    )
    if out.returncode != 0:
        raise ScanError("git ls-files failed")
    findings: Set[Finding] = set()
    files = 0
    for rel in out.stdout.decode("utf-8", errors="replace").split("\x00"):
        if not rel:
            continue
        full = repo / rel
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        files += 1
        for line in text.splitlines():
            for rule_id in scan_line(rules, rel, line):
                findings.add((TREE_SHA, rel, rule_id))
    return findings, files


def load_baseline(path: Path) -> List[Finding]:
    entries: List[Finding] = []
    if not path.exists():
        return entries
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        parts = raw.split()
        if len(parts) != 3:
            raise ScanError(f"bad baseline line: {raw!r}")
        entries.append((parts[0], parts[1], parts[2]))
    return entries


def _baselined(finding: Finding, baseline: Iterable[Finding]) -> bool:
    sha, path, rule = finding
    return any(
        path == b_path and rule == b_rule and sha.startswith(b_sha)
        for b_sha, b_path, b_rule in baseline
    )


def compare(
    findings: Set[Finding], baseline: List[Finding]
) -> Tuple[List[Finding], List[Finding]]:
    """Return (new findings, stale baseline entries)."""
    new = sorted(f for f in findings if not _baselined(f, baseline))
    stale = [b for b in baseline if not any(_baselined(f, [b]) for f in findings)]
    return new, stale


def run_gitleaks(repo: Path, config: Path) -> Optional[Dict[str, object]]:
    """Run gitleaks if it is already available locally; never install or pull."""
    base = ["detect", "--redact", "--no-banner", "--report-format", "json",
            "--report-path", "/dev/stdout", "--exit-code", "0"]
    if shutil.which("gitleaks"):
        cmd = ["gitleaks", *base, "--source", str(repo), "--config", str(config)]
        tool = "gitleaks"
    elif shutil.which("docker"):
        images = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, check=False,
        ).stdout.split()
        image = next((i for i in images if "gitleaks" in i), None)
        if not image:
            return None
        cmd = ["docker", "run", "--rm", "--network", "none", "-v", f"{repo}:/repo:ro",
               image, *base, "--source", "/repo", "--config", "/repo/.gitleaks.toml"]
        tool = f"docker:{image}"
    else:
        return None
    res = subprocess.run(cmd, capture_output=True, check=False)
    try:
        items = json.loads(res.stdout.decode("utf-8", errors="replace") or "[]")
    except json.JSONDecodeError:
        return {"tool": tool, "count": -1, "fingerprints": []}
    return {
        "tool": tool,
        "count": len(items),
        "fingerprints": sorted(i.get("Fingerprint", "") for i in items),
    }


def fmt(finding: Finding) -> str:
    sha, path, rule = finding
    return f"{sha[:12]} {path} {rule} [REDACTED]"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="scan all commits")
    parser.add_argument("--tree", action="store_true", help="scan tracked files")
    parser.add_argument("--repo", type=Path, default=SCRIPT_REPO)
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--baseline", type=Path, default=None)
    parser.add_argument("--report", type=Path, default=None)
    parser.add_argument("--gitleaks", action="store_true")
    args = parser.parse_args(argv)
    if not (args.history or args.tree):
        args.history = args.tree = True
    repo = args.repo.resolve()
    config = args.config or (repo / ".gitleaks.toml")
    baseline_path = args.baseline or (SCRIPT_REPO / "scripts" / "secret_scan_baseline.txt")

    try:
        rules = load_rules(config)
        baseline = load_baseline(baseline_path)
        findings: Set[Finding] = set()
        if args.history:
            found, commits = history_findings(repo, rules)
            findings |= found
            print(f"history: {commits} commits scanned")
        if args.tree:
            found, files = tree_findings(repo, rules)
            findings |= found
            print(f"tree: {files} files scanned")
        gl = run_gitleaks(repo, config) if args.gitleaks else None
    except ScanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.gitleaks:
        if gl is None:
            print("gitleaks: not available, scripted scan is the scan of record")
        else:
            print(f"gitleaks: {gl['tool']} findings={gl['count']}")

    new, stale = compare(findings, baseline)
    print(f"findings: {len(findings)} total, {len(findings) - len(new)} baselined, {len(new)} new")
    for finding in new:
        print(fmt(finding))
    for b_sha, b_path, b_rule in stale:
        print(f"warning: stale baseline entry {b_sha[:12]} {b_path} {b_rule}")
    if args.report:
        with args.report.open("w", encoding="utf-8") as fh:
            for finding in sorted(findings):
                sha, path, rule = finding
                fh.write(json.dumps({"commit": sha, "path": path, "rule": rule,
                                     "baselined": finding not in new}) + "\n")
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
