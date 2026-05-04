#!/usr/bin/env python3
"""Aggregate Semgrep alert JSONL files into a precision-tier summary.

Reads every `*.json` file in `corpus-eval/results/` produced by
`run-semgrep.sh`, counts alerts per (repo, rule, file), and prints a
table grouped by rule. Writes `corpus-eval/results/SUMMARY.md` with the
same content as a checked-in artifact.

Usage:
    corpus-eval/summary.py
"""
from __future__ import annotations

import collections
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
RESULTS = HERE / "results"


def main() -> int:
    if not RESULTS.is_dir():
        print(f"error: no results directory at {RESULTS}", file=sys.stderr)
        return 1

    by_rule: dict[str, dict[str, int]] = collections.defaultdict(
        lambda: collections.defaultdict(int)
    )
    by_rule_file: dict[str, dict[tuple[str, str], int]] = collections.defaultdict(
        lambda: collections.defaultdict(int)
    )

    for jsonl in sorted(RESULTS.glob("*.json")):
        if jsonl.suffix == ".json" and ".raw" in jsonl.stem:
            continue
        repo, _, rule = jsonl.stem.partition("-")
        with jsonl.open() as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                by_rule[rule][repo] += 1
                by_rule_file[rule][(repo, rec.get("path", ""))] += 1

    summary_lines: list[str] = []
    summary_lines.append("# Corpus evaluation summary")
    summary_lines.append("")
    summary_lines.append(
        "Counts come from running each rule against each target repository "
        "with `corpus-eval/run-semgrep.sh`. Numbers below are raw alert counts; "
        "manual triage (TP / FP / inconclusive) lives in `corpus-eval/results/triage/`."
    )
    summary_lines.append("")

    for rule, repos in sorted(by_rule.items()):
        summary_lines.append(f"## {rule}")
        summary_lines.append("")
        summary_lines.append("| Target repo | Alerts |")
        summary_lines.append("|---|---|")
        for repo, n in sorted(repos.items()):
            summary_lines.append(f"| {repo} | {n} |")
        summary_lines.append(f"| **total** | **{sum(repos.values())}** |")
        summary_lines.append("")

        # File-level breakdown when alerts are concentrated.
        files = by_rule_file[rule]
        top = sorted(files.items(), key=lambda kv: kv[1], reverse=True)[:10]
        if top and top[0][1] > 1:
            summary_lines.append("### Top alerting files")
            summary_lines.append("")
            summary_lines.append("| Repo | Path | Alerts |")
            summary_lines.append("|---|---|---|")
            for (repo, path), n in top:
                summary_lines.append(f"| {repo} | `{path}` | {n} |")
            summary_lines.append("")

    out = RESULTS / "SUMMARY.md"
    out.write_text("\n".join(summary_lines))
    print("\n".join(summary_lines))
    print(f"\nwrote {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
