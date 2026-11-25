"""Mask origin IPs, domains, paths and emails before a report leaves the box.

Tokens are stable inside one Redactor, so "<ip:1>" in two findings is the
same address. Addresses inside Cloudflare's published ranges are public and
are kept as-is.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Iterable

_V4 = r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])"
_V6 = r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?(?![0-9A-Fa-f:])"
_IP_RE = re.compile(f"{_V4}|{_V6}")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HOME_RE = re.compile(r"/(home|Users)/[^/\s\"']+")
_ROOT_HOME_RE = re.compile(r"(?<![\w/])/root(?=/|\b)")
# Hostnames in evidence (MX targets, providers). Not after "/" so file names in paths stay.
_HOST_RE = re.compile(r"(?<![\w/.<-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-]|\.[a-z0-9])", re.I)
_URL_HOST_RE = re.compile(r"([a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?)([^/:\s?#]+)", re.I)
_PUBLIC_HOSTS = ("cloudflare.com", "cloudflare.net", "example.com", "example.net", "example.org")
_FILE_EXT = ("conf", "json", "pem", "crt", "key", "toml", "yaml", "yml", "txt", "log", "py", "php", "html")


class Redactor:
    def __init__(
        self,
        domains: Iterable[str] = (),
        keep_ip: Callable[[ipaddress._BaseAddress], bool] | None = None,
    ) -> None:
        self._ips: dict[str, str] = {}
        self._hosts: dict[str, str] = {}
        self._domains: dict[str, str] = {}
        self._keep_ip = keep_ip or (lambda _ip: False)
        for d in sorted({d.lower().strip(".") for d in domains if d}, key=len, reverse=True):
            self._domains[d] = f"<domain:{len(self._domains) + 1}>"

    def _ip_token(self, match: re.Match) -> str:
        raw = match.group(0)
        addr_part, _, prefix = raw.partition("/")
        try:
            addr = ipaddress.ip_address(addr_part)
        except ValueError:
            return raw
        if self._keep_ip(addr):
            return raw
        key = str(addr)
        if key not in self._ips:
            self._ips[key] = f"<ip:{len(self._ips) + 1}>"
        return self._ips[key] + (f"/{prefix}" if prefix else "")

    def text(self, s: str) -> str:
        s = _EMAIL_RE.sub("<email>", s)
        s = _IP_RE.sub(self._ip_token, s)
        for domain, token in self._domains.items():
            s = re.sub(rf"(?<![\w-]){re.escape(domain)}(?![\w-])", token, s, flags=re.I)
        s = _HOME_RE.sub(r"/\1/<user>", s)
        s = _ROOT_HOME_RE.sub("/<root-home>", s)
        return s

    def _host_token(self, match: re.Match) -> str:
        host = match.group(0).lower()
        if host.rsplit(".", 1)[-1] in _FILE_EXT:
            return match.group(0)
        if any(host == h or host.endswith("." + h) for h in _PUBLIC_HOSTS):
            return match.group(0)
        if host not in self._hosts:
            self._hosts[host] = f"<host:{len(self._hosts) + 1}>"
        return self._hosts[host]

    def hosts(self, s: str) -> str:
        """Mask hostnames that are not ours. Run after text(), so our domains are tokens already.
        Hostnames inside URLs are handled first, since the general pattern skips text after '/'."""
        s = _URL_HOST_RE.sub(lambda m: m.group(1) + _HOST_RE.sub(self._host_token, m.group(2)), s)
        return _HOST_RE.sub(self._host_token, s)

    def data(self, obj: Any, _evidence: bool = False) -> Any:
        if isinstance(obj, str):
            s = self.text(obj)
            return self.hosts(s) if _evidence else s
        if isinstance(obj, dict):
            return {
                (self.text(k) if isinstance(k, str) else k): self.data(v, _evidence or k == "evidence")
                for k, v in obj.items()
            }
        if isinstance(obj, (list, tuple)):
            return [self.data(v, _evidence) for v in obj]
        return obj


def cloudflare_keeper(networks: Iterable[ipaddress._BaseNetwork]) -> Callable:
    nets = list(networks)

    def keep(addr: ipaddress._BaseAddress) -> bool:
        return any(addr.version == n.version and addr in n for n in nets)

    return keep
