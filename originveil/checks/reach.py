"""Direct reachability of the origin, run from a vantage host you control."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .. import net
from ..models import Finding
from . import probe

CHECK = "reach"
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


same_site = net.same_site


def reference_title(domain: str, timeout: float = 10.0) -> str | None:
    """Title of the page as served through Cloudflare."""
    try:
        status, _h, body = net.site_request(domain, "/", timeout=timeout, limit=65536)
    except (net.UnsafeTarget, OSError, ValueError):
        return None
    if status != 200:
        return None
    m = _TITLE_RE.search(body.decode(errors="replace"))
    return " ".join(m.group(1).split())[:200] if m else None


def parse_vantage(spec: str) -> list[str]:
    """ssh://user@host:port or user@host -> ssh argv prefix."""
    spec = spec.strip()
    port = None
    if spec.startswith("ssh://"):
        spec = spec[len("ssh://"):]
        if re.search(r":\d+$", spec):
            spec, port = spec.rsplit(":", 1)
    # Checked after stripping the scheme, so ssh://-F... cannot slip through as an option.
    if not re.fullmatch(r"(?:[A-Za-z0-9._][A-Za-z0-9._-]*@)?[A-Za-z0-9.][A-Za-z0-9.-]*|"
                        r"(?:[A-Za-z0-9._][A-Za-z0-9._-]*@)?\[[0-9A-Fa-f:.]+\]", spec):
        raise ValueError("invalid vantage spec")
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"]
    if port:
        argv += ["-p", port]
    return argv + [spec]


def run_remote(vantage: str, ip: str, domains: list[str], timeout: float) -> dict:
    src = Path(probe.__file__).read_text()
    remote = "python3 - " + " ".join(shlex.quote(x) for x in [ip, *domains, "--timeout", str(timeout)])
    res = subprocess.run(
        parse_vantage(vantage) + [remote],
        input=src, capture_output=True, text=True, timeout=60 + timeout * 6 * len(domains),
    )
    if res.returncode != 0:
        raise RuntimeError(f"vantage probe failed (exit {res.returncode})")
    return json.loads(res.stdout)


def _same(a: str | None, b: str | None) -> bool:
    return bool(a and b and a.strip().lower() == b.strip().lower())


def classify(obs: dict, references: dict[str, str | None]) -> list[Finding]:
    findings: list[Finding] = []
    ip = obs["ip"]
    for host, res in obs.get("hosts", {}).items():
        ref = references.get(host)
        h = res["https"]
        ev = {"ip": ip, "host": host}
        if h["tcp"] != "open":
            findings.append(Finding(CHECK, "https-closed", "pass",
                                    f"{host}: 443 on the origin is not reachable from the vantage ({h['tcp']})", evidence=ev))
        elif h.get("tls") in ("client_cert_required", "handshake_failure") or h.get("no_client_cert"):
            findings.append(Finding(CHECK, "https-aop-rejects", "pass",
                                    f"{host}: origin refuses TLS clients without the AOP certificate",
                                    detail="Port 443 is open but the origin demands a client certificate.",
                                    fix="Also restrict 443 to Cloudflare ranges so the port is not visible at all.",
                                    evidence=ev))
        elif h.get("tls") == "closed_without_response":
            linked = [n for n in h.get("cert_names", []) if n.endswith(host) or host.endswith(n.lstrip("*."))]
            findings.append(Finding(
                CHECK, "https-no-response", "low",
                f"{host}: 443 open on the origin, connection closed without a response",
                detail="Usually a client-certificate requirement (AOP working). The port is still visible"
                       + (", and the certificate names your domain." if linked else "."),
                fix="Restrict 443 to Cloudflare ranges so scanners cannot see the port or its certificate.",
                evidence={**ev, "cert_names": linked},
            ))
        elif h.get("status") and h["status"] < 400:
            follow = h.get("follow") or {}
            final = follow if follow.get("status") else h
            # Same page as via Cloudflare, or a 200 together with a certificate for the
            # domain. The title alone fails when Cloudflare challenges the reference fetch.
            confirmed = _same(final.get("title"), ref) or (
                200 <= (final.get("status") or 0) < 300 and _covers(h.get("cert_names", []), host)
            )
            findings.append(Finding(
                CHECK, "https-direct", "critical" if confirmed else "high",
                f"{host}: origin serves HTTPS directly" + (" (same page as via Cloudflare)" if confirmed else ""),
                detail=f"Direct request to the origin got HTTP {h['status']}"
                       + (f", redirect followed on the origin gave HTTP {follow['status']}" if follow.get("status") else "")
                       + ". These requests did not pass through Cloudflare, so its WAF, rate limiting and DDoS "
                         "protection did not apply to them.",
                fix="Allow 443 only from Cloudflare ranges and enforce Authenticated Origin Pulls with your own certificate.",
                evidence={**ev, "status": h["status"], "location": h.get("location"),
                          "final_status": follow.get("status"), "server": h.get("server"),
                          "cert_names": h.get("cert_names", [])},
            ))
        elif h.get("status"):
            findings.append(Finding(
                CHECK, "https-open-rejects", "medium",
                f"{host}: 443 open on the origin, request answered {h['status']}",
                detail="The app refused the request, but the port is open and the TLS certificate can tie the IP to your domain.",
                fix="Allow 443 only from Cloudflare ranges.",
                evidence={**ev, "status": h["status"], "cert_names": h.get("cert_names", [])},
            ))
        else:
            findings.append(Finding(CHECK, "https-unclear", "info",
                                    f"{host}: 443 open, outcome unclear ({h.get('tls')})", evidence=ev))

        p = res["http"]
        if p["tcp"] == "open" and p.get("status"):
            if p["status"] < 300:
                confirmed = _same(p.get("title"), ref)
                findings.append(Finding(
                    CHECK, "http-direct", "critical" if confirmed else "high",
                    f"{host}: origin serves plain HTTP directly",
                    fix="Close 80 to non-Cloudflare sources.",
                    evidence={**ev, "status": p["status"]},
                ))
            else:
                findings.append(Finding(
                    CHECK, "http-open", "medium",
                    f"{host}: port 80 open on the origin (HTTP {p['status']})",
                    fix="Close 80 to non-Cloudflare sources; let Cloudflare do the HTTPS redirect.",
                    evidence={**ev, "status": p["status"]},
                ))
        elif p["tcp"] != "open":
            findings.append(Finding(CHECK, "http-closed", "pass",
                                    f"{host}: port 80 on the origin is not reachable ({p['tcp']})", evidence=ev))

    bare = obs.get("bare_ip") or {}
    if bare.get("tcp") == "open" and bare.get("tls") == "ok" and bare.get("status") and bare["status"] < 400:
        linked = [n for n in bare.get("cert_names", []) if any(n.endswith(h) for h in obs.get("hosts", {}))]
        findings.append(Finding(
            CHECK, "bare-ip-serves", "high",
            "The bare IP answers HTTPS without SNI" + (" with your domain's certificate" if linked else ""),
            detail="Internet-wide scanners (Censys, Shodan) record what an IP serves. A cert or page for your domain links the IP to it.",
            fix="Add a default_server with `ssl_reject_handshake on;` so unknown SNI gets no certificate.",
            evidence={"ip": ip, "status": bare["status"], "cert_names": linked},
        ))
    return findings


def observe_all(ips: list[str], domains: list[str], vantage: str | None,
                timeout: float = 6.0, workers: int = 8) -> tuple[dict, dict, str | None]:
    """Probe each IP from the vantage, in parallel. Returns (obs by ip, reference titles, error)."""
    if not vantage:
        return {}, {}, "no vantage host set; direct reachability not tested (no third-party service is used)"
    if vantage == "local" and set(ips) & set(net.local_public_ips()):
        return {}, {}, "vantage 'local' is the origin itself; probing yourself proves nothing"
    refs = {d: reference_title(d, timeout) for d in domains}

    def one(ip: str):
        if vantage == "local":
            return probe.observe(ip, domains, timeout)
        return run_remote(vantage, ip, domains, timeout)

    out: dict = {}
    err = None
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(ips)))) as pool:
        futures = {pool.submit(one, ip): ip for ip in ips}
        for fut, ip in futures.items():
            try:
                out[ip] = fut.result()
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
                # keep the message generic: exception text can carry the ssh target
                detail = str(exc) if isinstance(exc, (RuntimeError, ValueError)) else type(exc).__name__
                err = f"vantage probe failed for some candidates: {detail}"
    return out, refs, err


def covers(names: list[str], domain: str) -> bool:
    return _covers(names, domain)


def _covers(names: list[str], domain: str) -> bool:
    for n in names:
        n = n.lower()
        if n == domain or n == "www." + domain or (n.startswith("*.") and domain.endswith(n[1:])):
            return True
    return False


def reachable(obs: dict) -> bool:
    for res in obs.get("hosts", {}).values():
        for scheme in ("https", "http"):
            if (res.get(scheme) or {}).get("tcp") == "open":
                return True
    return False


def describe(obs: dict) -> str:
    """Short, redaction-friendly account of what the probe saw, for elimination evidence."""
    parts = []
    for host, res in obs.get("hosts", {}).items():
        for scheme in ("https", "http"):
            r = res.get(scheme) or {}
            if r.get("tcp") != "open":
                parts.append(f"{scheme} {r.get('tcp') or 'not tried'}")
                continue
            bits = [str(r["status"])] if r.get("status") else [str(r.get("tls") or "no response")]
            if scheme == "https":
                names = r.get("cert_names", [])
                bits.append("cert names site" if _covers(names, host) else
                            ("cert for other names" if names else "no cert names"))
            final = r.get("follow") or {}
            if final.get("status"):
                bits.append(f"redirect -> {final['status']}")
            parts.append(f"{scheme} " + ", ".join(bits))
        break  # one host is enough for the summary
    return "; ".join(parts)


def confirms_site(obs: dict, refs: dict) -> list[str]:
    """Reasons this IP is the origin of the site, empty if it does not look like it."""
    reasons = []
    for host, res in obs.get("hosts", {}).items():
        for scheme in ("https", "http"):
            r = res.get(scheme) or {}
            final = r.get("follow") if (r.get("follow") or {}).get("status") else r
            if final and final.get("status") and final["status"] < 300 and _same(final.get("title"), refs.get(host)):
                reasons.append(f"{scheme} page matches {host}")
        if _covers((res.get("https") or {}).get("cert_names", []), host):
            reasons.append(f"TLS certificate names {host}")
    return sorted(set(reasons))


def check(origin_ips: list[str], domains: list[str], vantage: str | None,
          timeout: float = 6.0) -> tuple[list[Finding], str | None]:
    obs, refs, err = observe_all(origin_ips, domains, vantage, timeout)
    findings: list[Finding] = []
    for o in obs.values():
        findings.extend(classify(o, refs))
    return findings, err
