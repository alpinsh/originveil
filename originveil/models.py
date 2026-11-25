from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

SEVERITIES = ("critical", "high", "medium", "low", "info", "pass")
PENALTY = {"critical": 40, "high": 20, "medium": 10, "low": 3}
# Skip entries that only narrow another check instead of replacing it.
PARTIAL_OF = {
    "dns-api": "dns", "dns-partial": "dns",
    "discover-cap": "discover", "discover-partial": "discover",
    "webserver-partial": "webserver", "firewall-partial": "firewall",
}


@dataclass
class Finding:
    check: str
    id: str
    severity: str
    title: str
    detail: str = ""
    fix: str = ""
    evidence: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"unknown severity: {self.severity}")


@dataclass
class Skipped:
    check: str
    reason: str


@dataclass
class Report:
    tool_version: str
    scope: list[str]
    findings: list[Finding] = field(default_factory=list)
    skipped: list[Skipped] = field(default_factory=list)
    origin_mode: str = ""
    meta: dict = field(default_factory=dict)
    done: list[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def add(self, findings: list[Finding] | Finding) -> None:
        if isinstance(findings, Finding):
            findings = [findings]
        self.findings.extend(findings)

    def skip(self, check: str, reason: str) -> None:
        self.skipped.append(Skipped(check, reason))

    def complete(self, check: str) -> None:
        """A check reports that it ran to the end. Without this it is 'unknown', never 'pass'."""
        if check not in self.done:
            self.done.append(check)

    def score(self) -> int:
        total = 100 - sum(PENALTY.get(f.severity, 0) for f in self.findings)
        return max(total, 0)

    def worst(self) -> str:
        for sev in SEVERITIES:
            if any(f.severity == sev for f in self.findings):
                return sev
        return "pass"

    def coverage(self) -> dict[str, str]:
        """Result per check: pass, fail, partial, skipped, error or unknown.

        pass is only given to a check that explicitly reported completion."""
        names = list(self.scope) + (["discover"] if self.origin_mode == "discover" else [])
        out: dict[str, str] = {}
        for c in dict.fromkeys(names):
            fs = [f for f in self.findings if f.check == c]
            sk = [s for s in self.skipped if s.check == c]
            partial = [s for s in self.skipped if PARTIAL_OF.get(s.check) == c]
            if any(f.severity in PENALTY for f in fs):
                out[c] = "fail"
            elif any("failed" in s.reason for s in sk) or any(f.id.endswith("-unknown") for f in fs):
                out[c] = "error"
            elif sk:
                out[c] = "skipped"
            elif c not in self.done:
                out[c] = "unknown"
            elif partial:
                out[c] = "partial"
            else:
                out[c] = "pass"
        return out

    def verdict(self) -> str:
        """fail: something to fix. incomplete: no problem found, but not everything was
        checked. pass: every check ran fully and found nothing."""
        cov = self.coverage()
        if not cov:
            return "incomplete"  # nothing ran: never a pass
        if "fail" in cov.values():
            return "fail"
        if any(v != "pass" for v in cov.values()):
            return "incomplete"
        return "pass"

    def sorted_findings(self) -> list[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(self.findings, key=lambda f: (order[f.severity], f.check, f.id))

    def to_dict(self) -> dict:
        return {
            "tool": "originveil",
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "scope": self.scope,
            "origin_mode": self.origin_mode,
            "verdict": self.verdict(),
            "checks": self.coverage(),
            "score": self.score(),
            "score_note": "findings score over the checks that ran; read it together with verdict and checks",
            "worst": self.worst(),
            "meta": self.meta,
            "completed_checks": self.done,
            "findings": [asdict(f) for f in self.sorted_findings()],
            "skipped": [asdict(s) for s in self.skipped],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Report":
        r = cls(
            tool_version=data.get("tool_version", "?"),
            scope=list(data.get("scope", [])),
            generated_at=data.get("generated_at", ""),
            origin_mode=data.get("origin_mode", ""),
            meta=dict(data.get("meta", {})),
            done=list(data.get("completed_checks", [])),
        )
        r.findings = [Finding(**f) for f in data.get("findings", [])]
        r.skipped = [Skipped(**s) for s in data.get("skipped", [])]
        return r

    def merge(self, other: "Report") -> None:
        self.scope = sorted(set(self.scope) | set(other.scope))
        self.findings.extend(other.findings)
        self.skipped.extend(other.skipped)
