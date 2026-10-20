#!/usr/bin/env python3
"""Scan tracked files and commit metadata for AI-attribution and tooling residue.

Tree hits always fail. History hits fail unless the commit SHA is listed in
``scripts/ai_residue_allowlist.txt`` (format: ``<sha> # reason``, SHA of at least 12 hex
digits). Commit messages, author and committer names and e-mails, and annotated tag
messages are scanned. Exit codes: 0 clean, 1 findings, 2 tooling error.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple

SCRIPT_REPO = Path(__file__).resolve().parent.parent

_AGENTS = r"(?:claude|anthropic|copilot|chatgpt|openai|codex|gemini|cursor)"
PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ai-coauthor-trailer", re.compile(rf"co-authored-by:.*{_AGENTS}", re.I)),
    ("generated-with", re.compile(rf"generated (?:with|by) \[?{_AGENTS}", re.I)),
    ("anthropic-noreply", re.compile(r"noreply@anthropic\.com", re.I)),
    ("claude-session-trailer", re.compile(r"claude-session\s*:", re.I)),
    ("claude-code-link", re.compile(r"claude\.ai/code", re.I)),
    (
        "agent-email",
        re.compile(
            rf"[\w.+-]*{_AGENTS}[\w.+-]*@[\w.-]+|@[\w.-]*(?:anthropic|openai)\.[a-z]+", re.I
        ),
    ),
    ("copilot-app", re.compile(r"copilot app", re.I)),
    ("robot-emoji", re.compile("\U0001f916")),
    ("planning-tool", re.compile(r"\bGSD\b|\.planning/|REVIZYON|gsd-", re.I)),
]

# Files that legitimately contain the patterns.
TREE_EXCLUDE = {
    "scripts/ai_residue_scan.py",
    "scripts/ai_residue_allowlist.txt",
    "tests/unit/test_repo_hygiene.py",
}

Hit = Tuple[str, str, str]  # (where, location, rule)


def _match(text: str) -> List[str]:
    return [rule for rule, pat in PATTERNS if pat.search(text)]


def scan_tree(repo: Path) -> List[Hit]:
    out = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"], capture_output=True, check=False
    )
    if out.returncode != 0:
        raise RuntimeError("git ls-files failed")
    hits: List[Hit] = []
    for rel in out.stdout.decode("utf-8", errors="replace").split("\x00"):
        if not rel or rel in TREE_EXCLUDE:
            continue
        try:
            text = (repo / rel).read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # missing or binary
        for rule in _match(text):
            hits.append(("tree", rel, rule))
    return hits


MIN_SHA_LENGTH = 12


def load_allowlist(path: Path) -> Set[str]:
    """Read allowed commit SHAs; entries shorter than 12 hex digits are rejected."""
    shas: Set[str] = set()
    if path.exists():
        for raw in path.read_text(encoding="utf-8").splitlines():
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            sha = entry.split()[0].lower()
            if not re.fullmatch(rf"[0-9a-f]{{{MIN_SHA_LENGTH},40}}", sha):
                raise RuntimeError(
                    f"bad allowlist entry {sha!r}: need {MIN_SHA_LENGTH}-40 hex digits"
                )
            shas.add(sha)
    return shas


def scan_history(repo: Path, allowlist: Set[str]) -> Tuple[List[Hit], int]:
    out = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "log",
            "--all",
            "--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x01",
        ],
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError("git log failed")
    hits: List[Hit] = []
    commits = 0
    for record in out.stdout.decode("utf-8", errors="replace").split("\x01"):
        record = record.strip("\n")
        if not record:
            continue
        sha, author, author_mail, committer, committer_mail, body = record.split("\x00", 5)
        commits += 1
        if any(sha.lower().startswith(a) for a in allowlist):
            continue
        text = f"{author}\n{author_mail}\n{committer}\n{committer_mail}\n{body}"
        for rule in _match(text):
            hits.append(("history", sha, rule))
    return hits, commits


def scan_tags(repo: Path) -> List[Hit]:
    out = subprocess.run(
        ["git", "-C", str(repo), "tag", "-l", "--format=%(refname:short)%00%(contents)%01"],
        capture_output=True,
        check=False,
    )
    if out.returncode != 0:
        raise RuntimeError("git tag failed")
    hits: List[Hit] = []
    for record in out.stdout.decode("utf-8", errors="replace").split("\x01"):
        record = record.strip("\n")
        if not record:
            continue
        name, _, message = record.partition("\x00")
        for rule in _match(f"{name}\n{message}"):
            hits.append(("tag", name, rule))
    return hits


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree", action="store_true")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--repo", type=Path, default=SCRIPT_REPO)
    parser.add_argument("--allowlist", type=Path, default=None)
    args = parser.parse_args(argv)
    if not (args.tree or args.history):
        args.tree = args.history = True
    allow_path = args.allowlist or (SCRIPT_REPO / "scripts" / "ai_residue_allowlist.txt")
    hits: List[Hit] = []
    try:
        if args.tree:
            hits += scan_tree(args.repo)
        if args.history:
            found, commits = scan_history(args.repo, load_allowlist(allow_path))
            hits += found
            hits += scan_tags(args.repo)
            print(f"history: {commits} commits scanned")
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for where, loc, rule in hits:
        print(f"{where} {loc[:12] if where == 'history' else loc} {rule}")
    print(f"ai residue findings: {len(hits)}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
