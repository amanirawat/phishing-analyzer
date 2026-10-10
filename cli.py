"""Command-line interface.

    python -m phishing_analyzer samples/credential_phish.eml
    python -m phishing_analyzer email.txt --ai
    cat email.eml | python -m phishing_analyzer - --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import analyze, analyze_eml
from .ai import ai_available

COLORS = {"Critical": "\033[91m", "High": "\033[31m", "Medium": "\033[33m", "Low": "\033[32m"}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"


def _render(report, color: bool) -> str:
    c = (lambda code: code) if color else (lambda code: "")
    lvl = c(COLORS[report.level])
    bar = "█" * (report.score // 5) + "░" * (20 - report.score // 5)
    lines = [
        "",
        f"{c(BOLD)}PHISHING RISK: {lvl}{report.level.upper()}{c(RESET)}  {lvl}{bar}{c(RESET)} {report.score}/100",
        "",
        report.summary,
        "",
    ]
    if report.indicators:
        lines.append(f"{c(BOLD)}Red flags{c(RESET)}")
        for ind in report.indicators:
            lines.append(f"  • {ind.title} {c(DIM)}(+{ind.weight}, {ind.category}){c(RESET)}")
            lines.append(f"    {c(DIM)}{ind.evidence}{c(RESET)}")
        lines.append("")
    lines.append(f"{c(BOLD)}What to do{c(RESET)}")
    lines += [f"  {n}. {a}" for n, a in enumerate(report.actions, 1)]
    lines.append("")
    lines.append(f"{c(DIM)}Explanation: {'AI-generated' if report.ai_used else 'rule-based'}{c(RESET)}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="phishing-analyzer", description="Score an email for phishing risk.")
    p.add_argument("file", help="Path to a .eml or .txt file, or '-' to read stdin")
    p.add_argument("--ai", action="store_true", help="Add a plain-language AI explanation (needs ANTHROPIC_API_KEY)")
    p.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = p.parse_args(argv)

    raw = sys.stdin.buffer.read() if args.file == "-" else Path(args.file).read_bytes()
    if args.ai and not ai_available():
        print("Note: --ai needs ANTHROPIC_API_KEY and `pip install anthropic`. Using rule-based explanation.", file=sys.stderr)

    is_eml = args.file.lower().endswith(".eml") or raw[:200].lower().find(b"received:") != -1
    report = analyze_eml(raw, args.ai) if is_eml else analyze(raw.decode("utf-8", "replace"), args.ai)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render(report, color=sys.stdout.isatty()))
    return {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}[report.level]


if __name__ == "__main__":
    raise SystemExit(main())
