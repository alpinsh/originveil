"""Find origin candidates the way an attacker would, from what the domain publishes.

Nothing here needs the origin IP. Candidates are only treated as the origin
after the vantage probe shows they serve the site (see reach.confirms_site),
or when the Cloudflare API itself names them as the content of a proxied
record.
"""

from __future__ import annotations

import urllib.error

from .. import net
from ..models import Finding
from . import dns

CHECK = "discover"
API_SOURCE = "Cloudflare API"


def _usable(ip: str, cf_nets: list) -> bool:
    """Routable and not Cloudflare."""
    return net.routable_ip(ip) and not net.in_networks(ip, cf_nets)


def candidates(domains: list[str], cf_nets: list, token: str | None = None,
               extra_labels: list[str] = (), timeout: float = 5.0,
               api_get=None) -> tuple[dict[str, list[str]], set[str], list[str]]:
    """Return ({ip: [sources]}, authoritative_ips, gaps)."""
    found: dict[str, list[str]] = {}
    authoritative: set[str] = set()
    gaps: list[str] = []

    def add(ip: str, source: str) -> None:
        if _usable(ip, cf_nets):
            found.setdefault(ip, [])
            if source not in found[ip]:
                found[ip].append(source)

    labels = list(dict.fromkeys(dns.COMMON_LABELS + list(extra_labels)))
    for domain in domains:
        wild = net.wildcard_ips(domain)
        hosts = [f"{label}.{domain}" if label else domain for label in labels]
        resolved = net.resolve_many(hosts)
        for host in hosts:
            ips = resolved.get(host, set())
            if wild and ips == wild and host != domain:
                continue
            for ip in ips:
                add(ip, f"{host} (public DNS)")
        if wild:
            for ip in wild:
                add(ip, f"*.{domain} wildcard (public DNS)")
        mx = net.dig(domain, "MX", timeout=timeout)
        if mx is None:
            gaps.append(f"MX of {domain} could not be queried")
        for line in mx or []:
            target = line.split()[-1].strip(".") if line.split() else ""
            for ip in net.resolve(target) if target else ():
                add(ip, f"MX {target}")
        txt = net.dig(domain, "TXT", timeout=timeout)
        if txt is None:
            gaps.append(f"TXT/SPF of {domain} could not be queried")
        for line in txt or []:
            if line.strip('"').lower().startswith("v=spf1"):
                for n in dns.spf_networks(line):
                    if n.num_addresses == 1:
                        add(str(n.network_address), f"SPF of {domain}")

    if token or api_get:
        api_get = api_get or dns._api_get_factory(token, timeout)
        for domain in domains:
            try:
                zone = dns.find_zone(domain, api_get)
                records = dns.zone_records(zone["id"], api_get) if zone else []
            except (urllib.error.URLError, OSError, ValueError) as exc:
                gaps.append(f"Cloudflare API records for {domain} unavailable ({type(exc).__name__})")
                continue
            for r in records:
                if r.get("type") not in ("A", "AAAA"):
                    continue
                name = str(r.get("name", "")).lower().rstrip(".")
                if name != domain and not name.endswith("." + domain):
                    continue  # the token may read a parent zone; stay inside the audited name
                if r.get("proxied"):
                    if _usable(r["content"], cf_nets):
                        add(r["content"], f"{r['name']} proxied ({API_SOURCE})")
                        authoritative.add(r["content"])
                else:
                    add(r["content"], f"{r['name']} DNS-only ({API_SOURCE})")
    return found, authoritative, gaps


def findings_for(cands: dict[str, list[str]], confirmed: dict[str, list[str]],
                 probed: set[str], authoritative: set[str],
                 results: dict[str, str] | None = None,
                 unreachable: set[str] | None = None) -> list[Finding]:
    results = results or {}
    unreachable = unreachable or set()
    out: list[Finding] = []
    if not cands:
        out.append(Finding(
            CHECK, "no-candidates", "pass",
            "No origin candidate found in public DNS, MX or SPF",
            detail="This does not prove the IP is unknown. Historical DNS and internet scan databases are not checked.",
        ))
        return out
    if probed and not confirmed:
        out.append(Finding(
            CHECK, "origin-not-found", "pass",
            f"No candidate from public records was confirmed as the origin ({len(cands)} checked)",
            detail="This does not prove the IP is unknown. Historical DNS and internet scan databases are not checked.",
        ))
    groups: dict[tuple[str, tuple[str, ...]], list[str]] = {}
    for ip, sources in sorted(cands.items()):
        public = [s for s in sources if API_SOURCE not in s]
        if ip in confirmed:
            if public:
                direct = [r for r in confirmed[ip] if r != "proxied record content"]
                out.append(Finding(
                    CHECK, "origin-discovered", "critical",
                    "Origin IP can be derived from public records",
                    detail=("Found without inside knowledge and confirmed by connecting to it directly."
                            if direct else
                            "Found in public records; the Cloudflare API names it as the origin. "
                            "No direct connection confirmed it."),
                    fix="Close every source listed here, restrict 80/443 to Cloudflare, then change the origin IP.",
                    evidence={"ip": ip, "found_via": public, "confirmed_by": confirmed[ip]},
                ))
            else:
                out.append(Finding(
                    CHECK, "origin-known", "info",
                    "Origin identified through the Cloudflare API only",
                    evidence={"ip": ip, "confirmed_by": confirmed[ip] or ["proxied record content"]},
                ))
        else:
            if ip not in probed:
                kind = "possible-origin"
            elif ip in unreachable:
                kind = "candidate-unreachable"
            else:
                kind = "candidate-not-origin"
            groups.setdefault((kind, tuple(sources)), []).append(ip)

    for (kind, sources), ips in sorted(groups.items()):
        n = len(ips)
        seen = {ip: results[ip] for ip in ips if ip in results}
        if kind == "candidate-not-origin":
            out.append(Finding(
                CHECK, kind, "info",
                f"{n} candidate IP(s) answered but did not serve the site",
                detail="Reachable from the vantage, but neither the page nor the certificate matched.",
                evidence={"ips": ips, "found_via": list(sources), "probe": seen},
            ))
        elif kind == "candidate-unreachable":
            out.append(Finding(
                CHECK, kind, "info",
                f"{n} candidate IP(s) were not reachable from the vantage",
                detail="No port answered. An origin firewalled to Cloudflare looks exactly like this, "
                       "so unreachable is not proof that an IP is not the origin.",
                evidence={"ips": ips, "found_via": list(sources), "probe": seen},
            ))
        else:
            out.append(Finding(
                CHECK, kind, "medium",
                f"{n} possible origin IP(s) in public records (not confirmed)",
                detail="Set a vantage host to confirm whether they serve the site.",
                evidence={"ips": ips, "found_via": list(sources)},
            ))
    return out
