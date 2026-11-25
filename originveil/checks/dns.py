"""DNS leaks: records that hand out the origin IP even though the site is proxied."""

from __future__ import annotations

import ipaddress
import urllib.error
from typing import Callable

from .. import net
from ..models import Finding

CHECK = "dns"
API = "https://api.cloudflare.com/client/v4"

# Names that usually carry non-HTTP services. Cloudflare's proxy cannot carry them,
# so "turn on the proxy" is the wrong advice for these.
NON_HTTP_LABELS = {
    "mail", "smtp", "imap", "pop", "mx", "ftp", "sftp", "ns1", "ns2",
    "vpn", "autodiscover", "autoconfig",
}


def fix_for(host: str, domain: str) -> str:
    label = host[: -len(domain) - 1] if host.endswith("." + domain) else ""
    if label.split(".")[0] in NON_HTTP_LABELS:
        return ("This name usually serves a non-HTTP service that Cloudflare's proxy cannot carry. "
                "Delete it if unused; otherwise move that service to a host that is not the web origin.")
    return "Turn on the proxy for this name, or delete it if it is unused."


# Labels that commonly skip the proxy and end up on the origin.
COMMON_LABELS = [
    "", "www", "mail", "smtp", "imap", "pop", "webmail", "mx", "ftp", "sftp",
    "cpanel", "whm", "plesk", "direct", "direct-connect", "origin", "server",
    "dev", "staging", "test", "beta", "old", "api", "admin", "panel", "vpn",
    "ns1", "ns2", "autodiscover", "autoconfig", "cdn", "static", "img", "media",
]

ApiGet = Callable[[str], dict]


def _api_get_factory(token: str, timeout: float) -> ApiGet:
    def get(path: str) -> dict:
        return net.http_json(
            f"{API}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=timeout
        )

    return get


def find_zone(domain: str, api_get: ApiGet) -> dict | None:
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        data = api_get(f"/zones?name={name}")
        if data.get("success") and data.get("result"):
            return data["result"][0]
    return None


def zone_records(zone_id: str, api_get: ApiGet) -> list[dict]:
    records: list[dict] = []
    page = 1
    while True:
        data = api_get(f"/zones/{zone_id}/dns_records?page={page}&per_page=100")
        if not data.get("success"):
            # A logical failure must not look like "no records": raise so the caller records it.
            raise ValueError("Cloudflare API returned success=false")
        records.extend(data.get("result", []))
        info = data.get("result_info") or {}
        if page >= int(info.get("total_pages", 1) or 1):
            break
        page += 1
    return records


def spf_networks(txt: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for term in txt.strip('"').split():
        term = term.lstrip("+~?-")
        for prefix in ("ip4:", "ip6:"):
            if term.lower().startswith(prefix):
                try:
                    nets.append(ipaddress.ip_network(term[len(prefix):], strict=False))
                except ValueError:
                    pass
    return nets


def _origin_in(nets: list, origin_ips: list[str]) -> list[str]:
    return [ip for ip in origin_ips if net.in_networks(ip, nets)]


def check_records(records: list[dict], origin_ips: list[str]) -> list[Finding]:
    """Analyse Cloudflare DNS records of a zone against the origin IPs."""
    findings: list[Finding] = []
    origin = set(origin_ips)
    addr_by_name: dict[str, set[str]] = {}
    for r in records:
        if r.get("type") in ("A", "AAAA"):
            addr_by_name.setdefault(r["name"].lower(), set()).add(r["content"])

    for r in records:
        rtype, name, content = r.get("type"), r.get("name", ""), r.get("content", "")
        proxied = bool(r.get("proxied"))

        if rtype in ("A", "AAAA") and content in origin and not proxied:
            findings.append(Finding(
                CHECK, "dns-only-origin", "critical",
                f"{name} is DNS-only and points at the origin",
                detail=f"{rtype} {name} -> {content} is not proxied, so anyone can read the origin IP from it.",
                fix="Turn on the proxy (orange cloud) for this record, or move the service to another IP.",
                evidence={"record": name, "type": rtype, "content": content},
            ))
        elif rtype in ("A", "AAAA") and content in origin and proxied:
            findings.append(Finding(
                CHECK, "proxied-origin", "info",
                f"{name} is proxied",
                evidence={"record": name, "type": rtype},
            ))

        if rtype == "MX":
            target = content.lower().strip(".")
            target_ips = addr_by_name.get(target, set()) or net.resolve(target)
            hit = sorted(target_ips & origin)
            if hit:
                findings.append(Finding(
                    CHECK, "mx-on-origin", "high",
                    f"Mail for {name} is delivered to the origin host",
                    detail=f"MX {target} resolves to the origin. Mail cannot go through the HTTP proxy, so this publishes the IP.",
                    fix="Host mail elsewhere (separate server or provider) and keep the web origin's IP out of mail records.",
                    evidence={"record": name, "mx": target, "ips": hit},
                ))

        if rtype == "TXT" and content.strip('"').lower().startswith("v=spf1"):
            hit = _origin_in(spf_networks(content), origin_ips)
            if hit:
                findings.append(Finding(
                    CHECK, "spf-lists-origin", "high",
                    f"SPF record of {name} contains the origin IP",
                    detail="ip4:/ip6: terms in SPF are public and cover the origin address.",
                    fix="Send mail through a relay or provider that is not the web origin, then drop this ip4:/ip6: term.",
                    evidence={"record": name, "ips": hit},
                ))
    return findings


def check_public(domains: list[str], origin_ips: list[str], cf_nets: list,
                 extra_labels: list[str] = (), timeout: float = 5.0) -> tuple[list[Finding], list[str]]:
    """Resolve common names publicly. Works without any API token. Returns (findings, gaps)."""
    findings: list[Finding] = []
    gaps: list[str] = []
    origin = set(origin_ips)
    labels = list(dict.fromkeys(COMMON_LABELS + list(extra_labels)))
    for domain in domains:
        wild = net.wildcard_ips(domain)
        hosts = [f"{label}.{domain}" if label else domain for label in labels]
        resolved = net.resolve_many(hosts)
        for host in hosts:
            ips = resolved.get(host, set())
            if wild and ips == wild and host != domain:
                continue  # wildcard answer, not a real record
            leaked = sorted(ips & origin)
            if leaked:
                findings.append(Finding(
                    CHECK, "public-name-origin", "critical",
                    f"{host} resolves straight to the origin",
                    detail="Any resolver hands out the origin IP for this name.",
                    fix=fix_for(host, domain),
                    evidence={"host": host, "ips": leaked},
                ))
            elif cf_nets:
                other = sorted(ip for ip in ips if not net.in_networks(ip, cf_nets))
                if other:
                    findings.append(Finding(
                        CHECK, "public-name-unproxied", "low",
                        f"{host} is not behind Cloudflare",
                        detail="Not the origin, but it is a host of yours that is visible and unproxied.",
                        fix="Confirm this host is meant to be public.",
                        evidence={"host": host, "ips": other},
                    ))
        txt = net.dig(domain, "TXT", timeout=timeout)
        if txt is None:
            gaps.append(f"TXT/SPF of {domain} could not be queried (dig missing or DNS error)")
        for line in txt or []:
            if line.strip('"').lower().startswith("v=spf1"):
                hit = _origin_in(spf_networks(line), origin_ips)
                if hit:
                    findings.append(Finding(
                        CHECK, "spf-lists-origin", "high",
                        f"Public SPF of {domain} contains the origin IP",
                        fix="Move outbound mail off the web origin and drop the ip4:/ip6: term.",
                        evidence={"record": domain, "ips": hit},
                    ))
        mx = net.dig(domain, "MX", timeout=timeout)
        if mx is None:
            gaps.append(f"MX of {domain} could not be queried (dig missing or DNS error)")
        for line in mx or []:
            parts = line.split()
            target = parts[-1].strip(".") if parts else ""
            hit = sorted(net.resolve(target) & origin) if target else []
            if hit:
                findings.append(Finding(
                    CHECK, "mx-on-origin", "high",
                    f"Public MX of {domain} points at the origin host",
                    fix="Host mail elsewhere and keep the web origin's IP out of mail records.",
                    evidence={"record": domain, "mx": target, "ips": hit},
                ))
    return _dedupe(findings), gaps


def check_cloudflare(domains: list[str], origin_ips: list[str], token: str,
                     timeout: float = 10.0, api_get: ApiGet | None = None) -> tuple[list[Finding], list[str]]:
    """Returns (findings, errors)."""
    api_get = api_get or _api_get_factory(token, timeout)
    findings: list[Finding] = []
    errors: list[str] = []
    seen_zones: set[str] = set()
    for domain in domains:
        try:
            zone = find_zone(domain, api_get)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append(f"{domain}: API error ({type(exc).__name__})")
            continue
        if not zone:
            errors.append(f"{domain}: zone not found or token lacks Zone:Read")
            continue
        if zone["id"] in seen_zones:
            continue
        seen_zones.add(zone["id"])
        try:
            findings.extend(check_records(zone_records(zone["id"], api_get), origin_ips))
        except (urllib.error.URLError, OSError, ValueError) as exc:
            errors.append(f"{domain}: could not list DNS records ({type(exc).__name__})")
    return _dedupe(findings), errors


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.id, f.title)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
