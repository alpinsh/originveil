from __future__ import annotations

import os
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import net

DEFAULT_CONFIG_PATHS = (
    Path(os.environ.get("ORIGINVEIL_CONFIG", "")) if os.environ.get("ORIGINVEIL_CONFIG") else None,
    Path("/etc/originveil/config.toml"),
    Path.home() / ".config" / "originveil" / "config.toml",
)


@dataclass
class Config:
    domains: list[str] = field(default_factory=list)
    origin_ips: list[str] = field(default_factory=list)
    token_env: str = "CF_API_TOKEN"
    token_file: str | None = None
    vantage: str | None = None
    timeout: float = 6.0
    nginx_conf: str = "/etc/nginx/nginx.conf"
    apache_dir: str = "/etc/apache2"
    extra_labels: list[str] = field(default_factory=list)
    strict_given_ip: bool = False
    source: str | None = None

    def token(self) -> str | None:
        """Return the Cloudflare API token, or None. Never logged."""
        if self.token_file:
            p = Path(self.token_file)
            try:
                mode = p.stat().st_mode
                if mode & (stat.S_IRWXG | stat.S_IRWXO):
                    # Refuse rather than warn, and keep the path out of the message.
                    print("error: Cloudflare token file is accessible by group/others; chmod 600 it",
                          file=sys.stderr)
                    return None
                value = p.read_text().strip()
                return value or None
            except OSError:
                return None
        value = os.environ.get(self.token_env, "").strip()
        return value or None


def load(path: str | None = None) -> Config:
    candidates = [Path(path)] if path else [p for p in DEFAULT_CONFIG_PATHS if p]
    for p in candidates:
        if p.is_file():
            with p.open("rb") as fh:
                raw = tomllib.load(fh)
            domains = []
            for d in raw.get("domains", []):
                v = net.valid_domain(d)
                if not v:
                    raise ValueError(f"invalid domain in {p}")
                domains.append(v)
            cfg = Config(
                domains=domains,
                origin_ips=list(raw.get("origin_ips", [])),
                token_env=raw.get("cloudflare", {}).get("token_env", "CF_API_TOKEN"),
                token_file=raw.get("cloudflare", {}).get("token_file"),
                vantage=raw.get("probe", {}).get("vantage"),
                timeout=float(raw.get("probe", {}).get("timeout", 6.0)),
                nginx_conf=raw.get("paths", {}).get("nginx_conf", "/etc/nginx/nginx.conf"),
                apache_dir=raw.get("paths", {}).get("apache_dir", "/etc/apache2"),
                extra_labels=list(raw.get("dns", {}).get("extra_labels", [])),
                source=str(p),
            )
            return cfg
        if path:
            raise FileNotFoundError(path)
    return Config()
