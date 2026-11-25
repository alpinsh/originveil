"""Firewall: are 80/443 open to the world, or only to Cloudflare?

Reading rules needs root. Parsing is heuristic on purpose: it looks for accept
rules on web ports and whether they carry a source restriction. Findings say
so when the answer is a guess.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess

from .. import net
from ..models import Finding

CHECK = "firewall"
WEB_PORTS = {"80", "443"}


def _run(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if res.returncode != 0:
        return None
    return res.stdout


def _ports_in(text: str) -> set[str]:
    ports: set[str] = set()
    for m in re.finditer(r"--dports?\s+([\d,:]+)", text):
        for part in m.group(1).split(","):
            if ":" in part:
                lo, hi = part.split(":")
                ports |= {p for p in WEB_PORTS if int(lo or 0) <= int(p) <= int(hi or 65535)}
            else:
                ports.add(part)
    for m in re.finditer(r"dport\s+(\{[^}]*\}|\S+)", text):
        for part in re.split(r"[\s,{}]+", m.group(1)):
            part = {"http": "80", "https": "443"}.get(part, part)
            if "-" in part and part.replace("-", "").isdigit():
                lo, hi = part.split("-")
                ports |= {p for p in WEB_PORTS if int(lo) <= int(p) <= int(hi)}
            elif part.isdigit():
                ports.add(part)
    return ports & WEB_PORTS


def parse_iptables_save(text: str) -> dict:
    """Return {'open': [...rules], 'restricted': {port: [sources]}, 'policy': str, 'docker': bool}."""
    result = {"open": [], "restricted": {}, "policy": None, "docker": False, "sets": [], "drop_ports": set()}
    table = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("*"):
            table = line[1:]
            continue
        if table == "nat" and line.startswith("-A DOCKER") and re.search(r"--dport (80|443)\b", line):
            result["docker"] = True
        if table != "filter":
            continue
        if line.startswith(":INPUT"):
            result["policy"] = line.split()[1]
        if line.startswith("-A ") and re.search(r"-j (DROP|REJECT)\b", line) and not re.search(r"\s-s\s", line):
            chain = line.split()[1]
            udp_only = re.search(r"-p udp\b", line) and not re.search(r"-p tcp\b", line)
            if (chain.startswith("INPUT") or chain.startswith("ufw")) and not udp_only and \
                    not re.search(r"-m (state|conntrack)", line) and " -i " not in line and " -d " not in line:
                if not re.search(r"--dports?\s|dport", line):
                    result["drop_ports"] |= WEB_PORTS  # catch-all drop
                else:
                    result["drop_ports"] |= _ports_in(line)
        if not line.startswith("-A ") or "-j ACCEPT" not in line:
            continue
        chain = line.split()[1]
        if chain.startswith(("OUTPUT", "FORWARD", "DOCKER")) or "-o " in line:
            continue
        ports = _ports_in(line)
        if not ports:
            continue
        src = re.search(r"\s-s\s+(\S+)", line)
        mset = re.search(r"--match-set\s+(\S+)\s+src", line)
        if src and src.group(1) not in ("0.0.0.0/0", "::/0"):
            for p in ports:
                result["restricted"].setdefault(p, []).append(src.group(1))
        elif mset:
            result["sets"].append(mset.group(1))
            for p in ports:
                result["restricted"].setdefault(p, []).append(f"@{mset.group(1)}")
        else:
            result["open"].append(line)
    return result


def parse_nft(text: str) -> dict:
    result = {"open": [], "restricted": {}, "sets": {}, "policy": None, "drop_ports": set()}
    # named sets with literal elements
    for m in re.finditer(r"set\s+(\S+)\s*\{(.*?)\n\s*\}", text, re.S):
        body = m.group(2)
        em = re.search(r"elements\s*=\s*\{([^}]*)\}", body, re.S)
        if em:
            result["sets"][m.group(1)] = [e.strip() for e in em.group(1).replace("\n", " ").split(",") if e.strip()]
    in_input = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("chain "):
            in_input = s.split()[1] in ("input", "INPUT") or "input" in s.lower()
            continue
        if in_input and s.startswith("type filter hook input") and "policy" in s:
            result["policy"] = s.rsplit("policy", 1)[1].strip(" ;")
        if in_input and s.split() and s.split()[-1] in ("drop", "reject") and "saddr" not in s \
                and "daddr" not in s and "udp" not in s.split() \
                and "ct state" not in s and "iifname" not in s:
            result["drop_ports"] |= WEB_PORTS if "dport" not in s else _ports_in(s)
        if not in_input or "accept" not in s.split() or "dport" not in s:
            continue
        ports = _ports_in(s)
        if not ports:
            continue
        sm = re.search(r"ip6?\s+saddr\s+(\{[^}]*\}|@\S+|\S+)", s)
        if sm:
            src = sm.group(1)
            for p in ports:
                result["restricted"].setdefault(p, []).append(src)
        else:
            result["open"].append(s)
    return result


def parse_ufw(text: str) -> dict:
    result = {"open": [], "restricted": {}, "active": "Status: active" in text, "policy": None}
    dm = re.search(r"Default:\s*(\w+)\s*\(incoming\)", text)
    if dm:
        result["policy"] = {"deny": "drop", "reject": "reject", "allow": "accept"}.get(dm.group(1).lower(), dm.group(1).lower())
    for line in text.splitlines():
        m = re.match(r"^\s*(.+?)\s{2,}(ALLOW(?: IN)?)\s+(.+?)\s*$", line)
        if not m:
            continue
        to, src = m.group(1).replace("(v6)", "").strip(), m.group(3)
        profiles = {
            "Nginx Full": "80,443", "Apache Full": "80,443", "Nginx HTTP": "80",
            "Nginx HTTPS": "443", "Apache": "80", "Apache Secure": "443",
            "WWW": "80", "WWW Secure": "443", "WWW Full": "80,443",
        }
        port = profiles.get(to, to.split("/")[0])
        port = {"http": "80", "https": "443"}.get(port, port)
        ports = {p for p in port.split(",") if p in WEB_PORTS}
        if not ports:
            continue
        if src.startswith("Anywhere"):
            result["open"].append(line.strip())
        else:
            for p in ports:
                result["restricted"].setdefault(p, []).append(src.split()[0])
    return result


def _expand_sources(sources: list[str], nft_sets: dict) -> list[str]:
    out = []
    for s in sources:
        if s.startswith("@"):
            out.extend(nft_sets.get(s[1:], [s]))
        elif s.startswith("{"):
            out.extend(x.strip() for x in s.strip("{}").split(",") if x.strip())
        else:
            out.append(s)
    return out


def _compare_with_cloudflare(sources: list[str], cf_nets: list) -> tuple[list[str], list[str]]:
    """Return (non_cloudflare_sources, missing_cloudflare_ranges)."""
    parsed = []
    non_cf = []
    for s in sources:
        try:
            n = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        parsed.append(n)
        if not any(n.version == c.version and n.subnet_of(c) for c in cf_nets):
            non_cf.append(s)
    missing = [
        str(c) for c in cf_nets
        if not any(c.version == p.version and (c.subnet_of(p) or c == p) for p in parsed)
    ]
    return non_cf, missing


def analyse(kind: str, parsed: dict, cf_nets: list) -> list[Finding]:
    findings: list[Finding] = []
    if kind == "ufw" and not parsed.get("active"):
        findings.append(Finding(
            CHECK, "ufw-inactive", "high", "ufw is installed but inactive",
            detail="No host firewall is filtering web ports (unless another tool does).",
            fix="Allow 80/443 only from Cloudflare ranges, then `ufw enable`.",
        ))
        return findings
    if parsed["open"]:
        findings.append(Finding(
            CHECK, "web-ports-open", "high",
            "Web ports accept connections from any address",
            detail=f"{kind}: accept rules for 80/443 without a source restriction (heuristic).",
            fix="Allow 80/443 only from https://www.cloudflare.com/ips/ ranges and drop the rest. Keep the list updated (cron or a timer).",
            evidence={"rules": parsed["open"][:10]},
        ))
    elif not parsed["restricted"]:
        policy = str(parsed.get("policy") or "").lower()
        sev = "high" if policy in ("accept", "") and not WEB_PORTS <= set(parsed.get("drop_ports", set())) else "info"
        findings.append(Finding(
            CHECK, "no-web-rules", sev,
            f"No explicit rule for 80/443 found ({kind}, policy {policy or '?'})",
            detail="With an accepting default policy, web ports are open to everyone.",
            fix="Add accept rules for Cloudflare ranges on 80/443 and a drop policy.",
        ))
    else:
        policy = str(parsed.get("policy") or "").lower()
        # Closed only if BOTH web ports are covered by a drop policy or their own drop rule.
        # A port with no rule at all under an accepting policy is open, restricted or not.
        closed = policy in ("drop", "reject", "deny") or WEB_PORTS <= set(parsed.get("drop_ports", set()))
        if not closed and policy == "accept":
            findings.append(Finding(
                CHECK, "web-ports-open-by-policy", "high",
                "Cloudflare-only rules exist, but the default policy accepts everything else",
                detail=f"{kind}: the input policy is ACCEPT and no rule drops other traffic to 80/443, so the source "
                       "restrictions do not keep anyone out (heuristic).",
                fix="Set the input policy to drop (or add a drop rule for 80/443 after the Cloudflare accepts).",
            ))
        elif not closed:
            findings.append(Finding(
                CHECK, "policy-unknown", "info",
                "Could not tell whether traffic outside the allowed sources is dropped",
                detail="The default policy was not found, so the Cloudflare-only rules cannot be confirmed as effective.",
            ))
        sources = [s for v in parsed["restricted"].values() for s in v]
        sources = _expand_sources(sources, parsed.get("sets", {}) if isinstance(parsed.get("sets"), dict) else {})
        sources = list(dict.fromkeys(sources))
        if cf_nets:
            non_cf, missing = _compare_with_cloudflare(sources, cf_nets)
            if non_cf:
                findings.append(Finding(
                    CHECK, "non-cf-sources", "medium",
                    "Web ports also allow sources outside Cloudflare",
                    detail="Could be your monitoring or office IP. Every extra source is another way around the WAF.",
                    fix="Check each source is intended. Prefer a VPN or tunnel for admin access.",
                    evidence={"sources": non_cf[:20]},
                ))
            if missing:
                findings.append(Finding(
                    CHECK, "cf-ranges-missing", "low",
                    "Some current Cloudflare ranges are not allowed",
                    detail="Requests from those Cloudflare edges will fail. Your allowlist may be stale.",
                    fix="Refresh the allowlist from https://api.cloudflare.com/client/v4/ips on a schedule.",
                    evidence={"missing": missing},
                ))
            if not non_cf and not missing and closed:
                findings.append(Finding(CHECK, "cf-only", "pass",
                                        "Web ports accept only Cloudflare ranges and drop the rest (from rules, heuristic)"))
        else:
            findings.append(Finding(
                CHECK, "restricted-unverified", "info",
                "Web ports have source restrictions (Cloudflare list unavailable to compare)",
                evidence={"sources": sources[:20]},
            ))
        findings.append(Finding(
            CHECK, "ip-allowlist-limit", "low",
            "IP allowlisting alone does not stop other Cloudflare tenants",
            detail="Cloudflare edge IPs are shared. Traffic routed through someone else's Cloudflare account passes an IP allowlist.",
            fix="Pair the allowlist with Authenticated Origin Pulls using your own certificate, or use Cloudflare Tunnel.",
        ))
    if parsed.get("docker"):
        findings.append(_docker_finding())
    return findings


def _docker_finding() -> Finding:
    return Finding(
        CHECK, "docker-bypass", "medium",
        "Docker publishes a web port",
        detail="Ports published by Docker go through the DOCKER chain and skip INPUT rules, including ufw.",
        fix="Bind containers to 127.0.0.1 and put nginx in front, or filter in the DOCKER-USER chain.",
    )


def check(cf_nets: list | None = None) -> tuple[list[Finding], str | None]:
    """Returns (findings, skip_reason)."""
    cf_nets = cf_nets if cf_nets is not None else net.cloudflare_ranges()
    ufw = _run(["ufw", "status", "verbose"])
    if ufw is not None and "Status: active" in ufw:
        findings = analyse("ufw", parse_ufw(ufw), cf_nets)
        ipt = _run(["iptables-save"])
        if ipt and parse_iptables_save(ipt)["docker"]:
            findings.append(_docker_finding())
        return findings, None
    nft = _run(["nft", "list", "ruleset"])
    if nft and "hook input" in nft:
        return analyse("nftables", parse_nft(nft), cf_nets), None
    ipt = _run(["iptables-save"])
    if ipt and "*filter" in ipt:
        return analyse("iptables", parse_iptables_save(ipt), cf_nets), None
    if ufw is not None:
        return analyse("ufw", parse_ufw(ufw), cf_nets), None
    return [], "no readable firewall (run as root, or no ufw/nft/iptables found)"
