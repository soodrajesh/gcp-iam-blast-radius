"""CLI.  Exit codes for `analyze`: 0 healthy, 1 needs_attention, 2 critical, 3 error.

iamblast collect my-project > snapshot.json       # read-only, uses ADC
iamblast analyze snapshot.json --llm none
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .collector import CollectError, collect
from .llm import Budget, LLMError, make_llm
from .models import Analysis
from .orchestrator import analyze
from .snapshot import SnapshotError

EXIT = {"healthy": 0, "needs_attention": 1, "critical": 2}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}


def render(a: Analysis, color: bool) -> str:
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    out = [
        c(
            {"healthy": "32", "needs_attention": "33", "critical": "1;31"}[a.posture],
            f"POSTURE: {a.posture.upper()}",
        ),
        a.summary,
        "",
        "Blast radius (top 8):",
    ]
    for r in a.reaches[:8]:
        gained = (
            f"  (+{len(r.gained_caps)} via {len(r.reachable)} SA hop(s))" if r.gained_caps else ""
        )
        out.append(f"  {r.score:3}/100 {r.level:8} {r.principal}{gained}")
    out += ["", "Findings:"]
    for f in a.findings:
        out.append(f"  {c(COLOR[f.severity], f.severity.upper().ljust(8))} {f.id:10} {f.title}")
        for e in f.evidence[:2]:
            out.append(f"           {e}")
        if f.note:
            out.append(f"           note: {f.note}")
    if a.fixes:
        out += ["", "Verified fixes (each re-simulated):"]
        for v in a.fixes:
            out.append(f"  {v.finding_id:10} [{v.origin}] {v.reason}")
            out += [f"      {cmd}" for cmd in v.commands]
    for d in a.degraded:
        out.append(c("33", f"! {d}"))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="iamblast")
    sub = ap.add_subparsers(dest="cmd", required=True)
    co = sub.add_parser("collect", help="read a project's IAM (read-only) and print a snapshot")
    co.add_argument("project")
    co.add_argument("--internal-domain", action="append", default=[])
    an = sub.add_parser("analyze", help="analyze a snapshot file (or - for stdin)")
    an.add_argument("snapshot")
    an.add_argument("--llm", default="none", choices=["none", "mock", "vertex", "openai"])
    an.add_argument("--model")
    an.add_argument("--format", default="text", choices=["text", "json"])
    a = ap.parse_args(argv)
    try:
        if a.cmd == "collect":
            print(collect(a.project, a.internal_domain).model_dump_json(indent=1))
            return 0
        doc = (
            json.load(sys.stdin) if a.snapshot == "-" else json.loads(Path(a.snapshot).read_text())
        )
        res = asyncio.run(analyze(doc, make_llm(a.llm, a.model), budget=Budget()))
    except (OSError, ValueError, SnapshotError, LLMError, CollectError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    print(res.model_dump_json(indent=1) if a.format == "json" else render(res, sys.stdout.isatty()))
    return EXIT[res.posture]


if __name__ == "__main__":
    sys.exit(main())
