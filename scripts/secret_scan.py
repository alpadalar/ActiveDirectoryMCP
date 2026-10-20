#!/usr/bin/env python3
"""Full-history and tree secret scan driven by ``.gitleaks.toml``.

Stdlib only. Output never contains a matched value: every finding is printed as
``<sha[:12]> <path> <rule-id> [REDACTED] fp=<fingerprint>``.

A finding's fingerprint is the first 16 hex digits of
``sha256(rule-id NUL path NUL credential-value)``. The baseline stores fingerprints, so a
baselined file does not hide a different credential added to it later, and the baseline file
never contains a credential value. Only already-public or throwaway values may be baselined.

Exit codes: 0 nothing beyond the baseline, 1 new findings, 2 tooling error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple

SCRIPT_REPO = Path(__file__).resolve().parent.parent
TREE_SHA = "HEAD"

Finding = Tuple[str, str, str, str]  # (sha, path, rule-id, fingerprint)
BaselineKey = Tuple[str, str, str]  # (fingerprint, path, rule-id)


class ScanError(Exception):
    """Tooling failure (exit code 2)."""


@dataclass
class Rule:
    rule_id: str
    pattern: "re.Pattern[str]"
    secret_group: int
    path: Optional["re.Pattern[str]"]


@dataclass
class Rules:
    rules: List[Rule]
    allow_regexes: List["re.Pattern[str]"]
    allow_paths: List["re.Pattern[str]"]


def load_rules(config: Path) -> Rules:
    try:
        data = tomllib.loads(config.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScanError(f"cannot read rules from {config}: {exc}") from exc
    rules: List[Rule] = []
    for rule in data.get("rules", []):
        # Only rules carrying their own regex are evaluated locally; the default
        # gitleaks ruleset (extend.useDefault) needs the real binary.
        if "regex" in rule:
            rules.append(
                Rule(
                    rule_id=rule["id"],
                    pattern=re.compile(rule["regex"]),
                    secret_group=int(rule.get("secretGroup", 0)),
                    path=re.compile(rule["path"]) if "path" in rule else None,
                )
            )
    allow = data.get("allowlist", {})
    target = allow.get("regexTarget", "match")
    if target not in ("secret", "match"):
        raise ScanError(f"unsupported allowlist regexTarget: {target!r}")
    return Rules(
        rules=rules,
        allow_regexes=[re.compile(r) for r in allow.get("regexes", [])],
        allow_paths=[re.compile(r) for r in allow.get("paths", [])],
    )


def fingerprint(rule_id: str, path: str, secret: str) -> str:
    digest = hashlib.sha256(f"{rule_id}\0{path}\0{secret}".encode("utf-8")).hexdigest()
    return digest[:16]


def scan_line_secrets(rules: Rules, path: str, line: str) -> Iterator[Tuple[str, str]]:
    """Yield ``(rule_id, secret)`` for each credential on ``line`` after the allow-list.

    The secret is yielded so callers can fingerprint it; it must never be printed.
    """
    if any(p.search(path) for p in rules.allow_paths):
        return
    seen: Set[str] = set()
    for rule in rules.rules:
        if rule.path is not None and not rule.path.search(path):
            continue
        for match in rule.pattern.finditer(line):
            secret = match.group(rule.secret_group)
            if not secret or secret in seen:
                continue
            if any(a.search(secret) for a in rules.allow_regexes):
                continue
            seen.add(secret)
            yield rule.rule_id, secret
            break


def scan_line(rules: Rules, path: str, line: str) -> Iterator[str]:
    """Yield rule ids that fire on ``line`` after the allow-list is applied."""
    for rule_id, _secret in scan_line_secrets(rules, path, line):
        yield rule_id


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
    """Scan added lines of every commit on every ref, including merge diffs.

    ``-m`` makes git show a diff against each parent of a merge commit, so a credential
    introduced only in a merge resolution is still seen. Returns (findings, commits).
    """
    proc = _git(repo, "log", "--all", "-p", "-m", "--no-color", "--format=COMMIT%x00%H")
    assert proc.stdout is not None
    findings: Set[Finding] = set()
    commits: Set[str] = set()
    sha = ""
    path = ""
    in_hunk = False
    for raw in proc.stdout:
        line = raw.decode("utf-8", errors="replace").rstrip("\n")
        if line.startswith("COMMIT\x00"):
            sha = line.split("\x00", 1)[1]
            path = ""
            in_hunk = False
            commits.add(sha)
        elif not in_hunk and line.startswith("+++ "):
            path = line[4:]
            path = path[2:] if path.startswith("b/") else path
        elif line.startswith("diff --git "):
            in_hunk = False
        elif line.startswith("@@"):
            in_hunk = True
        elif in_hunk and line.startswith("+") and path and path != "/dev/null":
            for rule_id, secret in scan_line_secrets(rules, path, line[1:]):
                findings.add((sha, path, rule_id, fingerprint(rule_id, path, secret)))
    proc.stdout.close()
    if proc.wait() != 0:
        err = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        raise ScanError(f"git log failed: {err.strip()}")
    return findings, len(commits)


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
            for rule_id, secret in scan_line_secrets(rules, rel, line):
                findings.add((TREE_SHA, rel, rule_id, fingerprint(rule_id, rel, secret)))
    return findings, files


def load_baseline(path: Path) -> List[BaselineKey]:
    """Read ``<fingerprint> <path> <rule-id> [# note]`` lines."""
    entries: List[BaselineKey] = []
    if not path.exists():
        return entries
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.split("#", 1)[0].strip()
        if not raw:
            continue
        parts = raw.split()
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{16}", parts[0]):
            raise ScanError(f"bad baseline line (want '<fingerprint16> <path> <rule>'): {raw!r}")
        entries.append((parts[0], parts[1], parts[2]))
    return entries


def _key(finding: Finding) -> BaselineKey:
    _sha, path, rule, fp = finding
    return (fp, path, rule)


def compare(
    findings: Set[Finding], baseline: List[BaselineKey]
) -> Tuple[List[Finding], List[BaselineKey]]:
    """Return (new findings, stale baseline entries)."""
    known = set(baseline)
    new = sorted(f for f in findings if _key(f) not in known)
    seen = {_key(f) for f in findings}
    stale = [b for b in baseline if b not in seen]
    return new, stale


def run_gitleaks(repo: Path, config: Path) -> Optional[Dict[str, object]]:
    """Run gitleaks if it is already available locally; never install or pull."""
    base = [
        "detect",
        "--redact",
        "--no-banner",
        "--report-format",
        "json",
        "--report-path",
        "/dev/stdout",
        "--exit-code",
        "0",
    ]
    if shutil.which("gitleaks"):
        cmd = ["gitleaks", *base, "--source", str(repo), "--config", str(config)]
        tool = "gitleaks"
    elif shutil.which("docker"):
        images = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        image = next((i for i in images if "gitleaks" in i), None)
        if not image:
            return None
        cmd = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{repo}:/repo:ro",
            image,
            *base,
            "--source",
            "/repo",
            "--config",
            "/repo/.gitleaks.toml",
        ]
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
    sha, path, rule, fp = finding
    return f"{sha[:12]} {path} {rule} [REDACTED] fp={fp}"


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
    for b_fp, b_path, b_rule in stale:
        print(f"warning: stale baseline entry {b_fp} {b_path} {b_rule}")
    if args.report:
        with args.report.open("w", encoding="utf-8") as fh:
            for finding in sorted(findings):
                sha, path, rule, fp = finding
                fh.write(
                    json.dumps(
                        {
                            "commit": sha,
                            "path": path,
                            "rule": rule,
                            "fingerprint": fp,
                            "baselined": finding not in new,
                        }
                    )
                    + "\n"
                )
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
