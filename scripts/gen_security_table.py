#!/usr/bin/env python3
"""Render the tool-risk table of SECURITY.md from policy.RISK_CLASSIFICATION.

    python scripts/gen_security_table.py --check   # exit 1 when SECURITY.md is out of date
    python scripts/gen_security_table.py --write   # rewrite only the marked region
    python scripts/gen_security_table.py           # print the table
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping, Optional

from active_directory_mcp.policy import RISK_CLASSIFICATION, Risk

BEGIN = "<!-- BEGIN GENERATED: tool-risk-table -->"
END = "<!-- END GENERATED: tool-risk-table -->"
DEFAULT_FILE = Path(__file__).resolve().parents[1] / "SECURITY.md"

_ORDER = {Risk.READ: 0, Risk.WRITE: 1, Risk.DESTRUCTIVE: 2}
_ENABLED_BY = {
    Risk.READ: "always enabled",
    Risk.WRITE: "`security.allow_writes`",
    Risk.DESTRUCTIVE: "`security.allow_writes` and `security.allow_destructive`",
}


_AUDITED_WHEN_CONFIGURED = "only if `security.audit_log_path` is set"


def render_risk_table(classification: Optional[Mapping[str, Risk]] = None) -> str:
    """Markdown table, one row per tool, sorted by risk class then name."""
    source = RISK_CLASSIFICATION if classification is None else classification
    rows = sorted(source.items(), key=lambda item: (_ORDER[Risk(item[1])], item[0]))
    lines = [
        "| Tool | Risk | Enabled by | Audited |",
        "| --- | --- | --- | --- |",
    ]
    for name, risk in rows:
        risk = Risk(risk)
        # policy.guard records every non-read call, but only when security.audit_log_path
        # is set; the default is unset, so by default no call is audited.
        audited = "no" if risk is Risk.READ else _AUDITED_WHEN_CONFIGURED
        lines.append(f"| `{name}` | {risk.value} | {_ENABLED_BY[risk]} | {audited} |")
    return "\n".join(lines)


def extract_region(text: str) -> Optional[str]:
    """Return the text between the markers (without surrounding newlines) or None."""
    if BEGIN not in text or END not in text:
        return None
    start = text.index(BEGIN) + len(BEGIN)
    stop = text.index(END)
    if stop < start:
        return None
    return text[start:stop].strip("\n")


def replace_region(text: str, table: str) -> str:
    start = text.index(BEGIN) + len(BEGIN)
    stop = text.index(END)
    return text[:start] + "\n" + table + "\n" + text[stop:]


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="exit 1 on drift")
    group.add_argument("--write", action="store_true", help="rewrite the generated region")
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    args = parser.parse_args(argv)

    table = render_risk_table()
    if not (args.check or args.write):
        print(table)
        return 0
    text = args.file.read_text(encoding="utf-8")
    current = extract_region(text)
    if current is None:
        print(f"{args.file}: generated region markers not found", file=sys.stderr)
        return 1
    if args.check:
        if current != table:
            print(f"{args.file}: tool-risk table is out of date; run --write", file=sys.stderr)
            return 1
        return 0
    args.file.write_text(replace_region(text, table), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
