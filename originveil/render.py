from __future__ import annotations

import os
import sys

from .models import Report

COLORS = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[2m", "pass": "\033[32m",
}
RESET = "\033[0m"


def text(report: Report, verbose: bool = False, color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def c(sev: str, s: str) -> str:
        return f"{COLORS[sev]}{s}{RESET}" if color else s

    lines = [
        f"originveil {report.tool_version}  {report.generated_at}",
        f"scope: {', '.join(report.scope)}" + (f"   origin: {report.origin_mode}" if report.origin_mode else ""),
        f"verdict: {_verdict(report.verdict(), c)}   findings score: {report.score()}/100   worst: {c(report.worst(), report.worst())}",
        "checks: " + "  ".join(f"{k}={v}" for k, v in report.coverage().items()),
        "",
    ]
    if report.verdict() == "incomplete":
        lines.insert(-1, "note: no problem found in what ran, but some checks did not run fully (see below)")
    for f in report.sorted_findings():
        if f.severity in ("info", "pass") and not verbose:
            continue
        lines.append(c(f.severity, f"[{f.severity.upper():8}] ") + f"{f.check}/{f.id}: {f.title}")
        if f.detail:
            lines.append(f"           {f.detail}")
        if f.fix:
            lines.append(f"           fix: {f.fix}")
        if verbose and f.evidence:
            lines.append(f"           evidence: {f.evidence}")
    hidden = sum(1 for f in report.findings if f.severity in ("info", "pass"))
    if hidden and not verbose:
        lines.append(c("pass", f"{hidden} passing/info results hidden, use -v to show"))
    if report.skipped:
        lines.append("")
        lines.append("not checked:")
        for s in report.skipped:
            lines.append(f"  - {s.check}: {s.reason}")
    return "\n".join(lines)


def _verdict(v: str, c) -> str:
    return c({"fail": "high", "incomplete": "medium", "pass": "pass"}[v], v.upper())
