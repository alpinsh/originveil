from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__, net
from .checks import discover, dns, firewall, probe, reach, webserver, xmlrpc
from .config import Config
from .models import Finding, Report

ALL = ("dns", "webserver", "firewall", "reach", "wordpress")
# Checks that need nothing from the local box beyond network access.
REMOTE_SAFE = ("dns", "reach", "wordpress")


MAX_CANDIDATES = 24


def _quiet(_msg: str) -> None:
    pass


def run(cfg: Config, scopes: tuple[str, ...] = ALL, progress=_quiet) -> Report:
    report = Report(tool_version=__version__, scope=list(scopes))
    progress("fetching Cloudflare ranges")
    cf_nets = net.cloudflare_ranges(cfg.timeout)
    if not cf_nets:
        report.skip("cloudflare-ranges", "could not fetch Cloudflare IP ranges; range comparisons limited")

    report.meta["domain_hashes"] = [domain_hash(d) for d in cfg.domains]
    report.meta["probe"] = {
        "vantage": None if not cfg.vantage else ("local" if cfg.vantage == "local" else "ssh"),
        "ports": [443, 80],
    }
    origin_ips, mode = resolve_origin(cfg, report, cf_nets, scopes, progress)
    report.origin_mode = mode
    if "ip_families" not in report.meta["probe"]:
        report.meta["probe"]["ip_families"] = sorted({"ipv6" if ":" in ip else "ipv4" for ip in origin_ips})
    reach_done = mode == "discover"
    needs_ips = {"dns", "reach"} & set(scopes)
    if needs_ips and not origin_ips:
        if mode != "discover":
            for s in sorted(needs_ips):
                report.skip(s, "origin IP unknown: pass --origin-ip, use 'local' on the origin, or let discovery find it")
        else:
            if "dns" in needs_ips:
                report.skip("dns", "no origin confirmed, so per-record leak checks had nothing to compare against; pass --origin-ip for a full check")
            if "reach" in needs_ips and not any(s.check == "reach" for s in report.skipped):
                report.skip("reach", "no origin confirmed, so direct reachability of the real origin is unknown")
        scopes = tuple(s for s in scopes if s not in needs_ips)

    if "dns" in scopes:
        progress("checking DNS records")
        if not cfg.domains:
            report.skip("dns", "no domains configured")
        else:
            found, gaps = dns.check_public(cfg.domains, origin_ips, cf_nets, cfg.extra_labels, cfg.timeout)
            report.add(found)
            for g in gaps:
                report.skip("dns-partial", g)
            report.complete("dns")
            token = cfg.token()
            if token:
                found, errors = dns.check_cloudflare(cfg.domains, origin_ips, token, cfg.timeout)
                report.add(found)
                for e in errors:
                    report.skip("dns-api", e)
            else:
                report.skip("dns-api", f"no Cloudflare token in ${cfg.token_env}; only public DNS checked")

    if "webserver" in scopes:
        progress("reading web server config")
        ran = False
        try:
            found, gaps = webserver.check_nginx(cfg.nginx_conf)
            report.add(found)
            for g in gaps:
                report.skip("webserver-partial", g)
            ran = True
        except FileNotFoundError:
            pass
        except PermissionError:
            report.skip("webserver", "nginx config not readable by this user")
        found, gaps = webserver.check_apache(cfg.apache_dir)
        report.add(found)
        for g in gaps:
            report.skip("webserver-partial", g)
        if found or Path(cfg.apache_dir, "sites-enabled").is_dir():
            ran = True
        if ran:
            report.complete("webserver")
        elif not any(s.check == "webserver" for s in report.skipped):
            report.skip("webserver", "no nginx or Apache config found")

    if "firewall" in scopes:
        progress("reading firewall rules")
        found, reason = firewall.check(cf_nets)
        report.add(found)
        if any(f.id == "policy-unknown" for f in found):
            report.skip("firewall-partial", "default input policy unknown; Cloudflare-only rules not confirmed effective")
        if reason:
            report.skip("firewall", reason)
        else:
            report.complete("firewall")

    if "reach" in scopes and not reach_done:
        progress("probing the origin from the vantage")
        if not cfg.domains:
            report.skip("reach", "no domains configured")
        else:
            found, reason = reach.check(origin_ips, cfg.domains, cfg.vantage, cfg.timeout)
            report.add(found)
            if reason:
                report.skip("reach", reason)
            else:
                report.complete("reach")

    if "wordpress" in scopes and cfg.domains:
        progress("checking WordPress XML-RPC")
        found, complete = xmlrpc.check(cfg.domains, cfg.timeout)
        report.add(found)
        if complete:
            report.complete("wordpress")

    _dedupe(report)
    return report


def resolve_origin(cfg: Config, report: Report, cf_nets: list,
                   scopes: tuple[str, ...], progress=_quiet) -> tuple[list[str], str]:
    """Explicit IPs win; 'local' means this host; otherwise discover."""
    explicit = [ip for ip in cfg.origin_ips if ip != "local"]
    bad = [ip for ip in explicit if not net.routable_ip(ip)]
    if bad:
        report.skip("origin", f"{len(bad)} given origin IP(s) ignored: not a public unicast address")
        explicit = [ip for ip in explicit if ip not in bad]
    if "local" in cfg.origin_ips:
        return explicit + net.local_public_ips(), "local"
    if explicit and cfg.strict_given_ip:
        # IPs that came from a chat or a model: only accept those that present a
        # certificate for an audited domain, before any HTTP request is sent to them.
        kept = []
        for ip in explicit:
            names = next((n for d in cfg.domains if (n := probe.cert_names_only(ip, d, cfg.timeout))), None)
            if names and any(reach.covers(names, d) for d in cfg.domains):
                kept.append(ip)
        if len(kept) < len(explicit):
            report.skip("origin", f"{len(explicit) - len(kept)} given origin IP(s) ignored: no certificate for "
                                  "an audited domain, so they were not probed further")
        explicit = kept
        if not explicit:
            return [], "given"
    if explicit:
        return explicit, "given"
    if not cfg.domains or not ({"dns", "reach"} & set(scopes)):
        return [], "discover"

    dead = [d for d in cfg.domains if not net.resolve(d)]
    if dead:
        report.skip("discover", f"{len(dead)} domain(s) do not resolve from here; discovery would be meaningless")
        return [], "discover"
    progress("discovering origin candidates")
    cands, authoritative, gaps = discover.candidates(
        cfg.domains, cf_nets, cfg.token(), cfg.extra_labels, cfg.timeout
    )
    for g in gaps:
        report.skip("discover-partial", g)
    confirmed: dict[str, list[str]] = {ip: ["proxied record content"] for ip in authoritative}
    probed: set[str] = set()
    results: dict[str, str] = {}
    unreachable: set[str] = set()
    if len(cands) > MAX_CANDIDATES:
        report.skip("discover-cap", f"{len(cands)} candidates found, only the first {MAX_CANDIDATES} were probed")
    if cands and "reach" in scopes:
        to_probe = sorted(cands)[:MAX_CANDIDATES]
        report.meta["probe"]["ip_families"] = sorted({"ipv6" if ":" in ip else "ipv4" for ip in to_probe})
        if cfg.vantage:
            progress(f"probing {len(to_probe)} candidate(s) from the vantage")
        obs, refs, err = reach.observe_all(to_probe, cfg.domains, cfg.vantage, cfg.timeout)
        if err:
            report.skip("reach", err)
        for ip, o in obs.items():
            probed.add(ip)
            results[ip] = reach.describe(o)
            if not reach.reachable(o):
                unreachable.add(ip)
            reasons = reach.confirms_site(o, refs)
            if reasons:
                confirmed[ip] = sorted(set(confirmed.get(ip, [])) | set(reasons))
            if ip in confirmed:
                report.add(reach.classify(o, refs))
                report.complete("reach")
    report.add(discover.findings_for(cands, confirmed, probed, authoritative, results, unreachable))
    report.complete("discover")
    return sorted(confirmed), "discover"


def domain_hash(domain: str) -> str:
    """Lets a reader match a report to its domains without the report naming them."""
    return hashlib.sha256(domain.encode()).hexdigest()[:16]


def _dedupe(report: Report) -> None:
    seen, out = set(), []
    for f in report.findings:
        # evidence is part of the key: same title for different IPs is not a duplicate
        key = (f.check, f.id, f.title, json.dumps(f.evidence, sort_keys=True, default=str))
        if key not in seen:
            seen.add(key)
            out.append(f)
    report.findings = out


__all__ = ["run", "ALL", "REMOTE_SAFE", "Finding"]
