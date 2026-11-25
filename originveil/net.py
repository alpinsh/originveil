from __future__ import annotations

import http.client
import ipaddress
import json
import re
import secrets
import shutil
import socket
import ssl
import urllib.parse
import subprocess
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

CF_IPS_URL = "https://api.cloudflare.com/client/v4/ips"
UA = "originveil-audit/0.1"

_cf_cache: list | None = None

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_INTERNAL = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7",
)]


def valid_domain(value: str) -> str | None:
    """Normalised hostname, or None. Rejects anything that could be read as an option or a path."""
    d = str(value or "").strip().lower().rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return d if _DOMAIN_RE.match(d) else None


def routable_ip(ip: str) -> bool:
    """Public unicast. Blocks loopback, link-local (cloud metadata), multicast and internal ranges.
    Spelled out instead of is_global so RFC 5737 documentation ranges still pass in tests."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return False
    if getattr(addr, "ipv4_mapped", None):
        return routable_ip(str(addr.ipv4_mapped))
    return not in_networks(str(addr), _INTERNAL)


def http_json(url: str, headers: dict | None = None, timeout: float = 10.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def cloudflare_ranges(timeout: float = 10.0) -> list[ipaddress._BaseNetwork]:
    """Current Cloudflare edge ranges from the public API. Empty list on failure."""
    global _cf_cache
    if _cf_cache is not None:
        return _cf_cache
    try:
        data = http_json(CF_IPS_URL, timeout=timeout)
        result = data.get("result", {})
        cidrs = result.get("ipv4_cidrs", []) + result.get("ipv6_cidrs", [])
        _cf_cache = [ipaddress.ip_network(c) for c in cidrs]
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError):
        _cf_cache = []
    return _cf_cache


def in_networks(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def resolve(host: str) -> set[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, UnicodeError, OSError):
        return set()
    return {i[4][0] for i in infos}


def dig(name: str, rtype: str, timeout: float = 5.0) -> list[str] | None:
    """Records of one type. [] means the query worked and there are none;
    None means the question could not be answered (no dig, timeout, SERVFAIL)."""
    if not valid_domain(name) or rtype not in ("A", "AAAA", "MX", "TXT", "NS"):
        return []
    if not shutil.which("dig"):
        return None
    try:
        res = subprocess.run(
            ["dig", "+noall", "+answer", "+comments", f"+time={int(timeout)}", "+tries=1", rtype, name],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
    except (subprocess.SubprocessError, OSError):
        return None
    if res.returncode != 0:
        return None
    status = re.search(r"status:\s*([A-Z]+)", res.stdout)
    if status and status.group(1) not in ("NOERROR", "NXDOMAIN"):
        return None
    out = []
    for line in res.stdout.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        parts = line.split(None, 4)
        if len(parts) == 5 and parts[3].upper() == rtype:
            out.append(parts[4].strip())
    return out


def local_public_ips() -> list[str]:
    """Globally routable addresses bound to this host's interfaces."""
    ips: set[str] = set()
    if shutil.which("ip"):
        try:
            out = subprocess.run(
                ["ip", "-j", "addr"], capture_output=True, text=True, timeout=5
            ).stdout
            for iface in json.loads(out or "[]"):
                for a in iface.get("addr_info", []):
                    ip = a.get("local")
                    if ip and ipaddress.ip_address(ip).is_global:
                        ips.add(ip)
        except (subprocess.SubprocessError, OSError, ValueError, json.JSONDecodeError):
            pass
    return sorted(ips)


def resolve_many(hosts: list[str], workers: int = 16) -> dict[str, set[str]]:
    """Resolve in parallel. getaddrinfo has no timeout, threads keep slow NXDOMAINs from adding up."""
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
        return dict(zip(hosts, pool.map(lambda h: resolve(h), hosts), strict=True))


def wildcard_ips(domain: str) -> set[str]:
    """Addresses a random label gets. Non-empty means the zone has a wildcard record."""
    return resolve(f"ov-{secrets.token_hex(6)}.{domain}")


# ---------------------------------------------------------------- pinned HTTPS

class UnsafeTarget(Exception):
    """The site resolved to an address we must not connect to."""


def same_site(host: str | None, domain: str) -> bool:
    host = (host or "").lower()
    bare = domain[4:] if domain.startswith("www.") else domain
    return host in (bare, "www." + bare)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS to a pre-validated IP, with SNI and certificate checks for the hostname."""

    def __init__(self, host: str, ip: str, **kw) -> None:
        super().__init__(host, **kw)
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def site_request(domain: str, path: str = "/", method: str = "GET", body: bytes | None = None,
                 headers: dict | None = None, timeout: float = 10.0, max_redirects: int = 3,
                 limit: int = 200000, context: ssl.SSLContext | None = None,
                 port: int = 443) -> tuple[int, dict, bytes]:
    """Request a page of the audited site itself.

    Every hop re-resolves the name and refuses to connect if any address is not public
    unicast, then connects to that exact address. Redirects are followed only within the
    same site and keep the method, so an XML-RPC POST stays a POST. This closes the
    DNS-rebinding gap that a plain urlopen with a hostname check leaves open.
    """
    url = f"https://{domain}{'' if port == 443 else f':{port}'}{path}"
    ctx = context or ssl.create_default_context()
    hdrs = {"User-Agent": UA, **(headers or {})}
    for _ in range(max_redirects + 1):
        u = urllib.parse.urlsplit(url)
        if u.scheme != "https" or not same_site(u.hostname, domain) or (u.port or 443) != port:
            raise UnsafeTarget("redirect leaves the site")
        ips = sorted(resolve(u.hostname))
        if not ips:
            raise OSError("does not resolve")
        if not all(routable_ip(ip) for ip in ips):
            raise UnsafeTarget("resolves to a non-public address")
        conn = _PinnedHTTPS(u.hostname, ips[0], port=u.port or 443, timeout=timeout, context=ctx)
        try:
            target = (u.path or "/") + (f"?{u.query}" if u.query else "")
            conn.request(method, target, body=body, headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            rh = {k.lower(): v for k, v in resp.getheaders()}
            data = resp.read(limit)
        finally:
            conn.close()
        loc = rh.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            nxt = urllib.parse.urljoin(url, loc)
            nu = urllib.parse.urlsplit(nxt)
            if not same_site(nu.hostname, domain) or nu.scheme != "https" or (nu.port or 443) != port:
                return status, rh, data
            url = nxt
            continue
        return status, rh, data
    raise OSError("too many redirects")
