"""Hermes tool handlers. They run the bundled CLI in a subprocess and only ever
return redacted output to the model.

Which domains may be audited is a security boundary: a prompt must not be able
to point the tool at someone else's site. Domains come from the config file
(written by an admin) or are added from chat after proving control of the
domain with a DNS TXT record, the way search consoles verify site ownership.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import tomllib
import urllib.parse
import urllib.request
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIGS = (Path("/etc/originveil/config.toml"), Path.home() / ".config" / "originveil" / "config.toml")
SECRET_ENV = "ORIGINVEIL_CF_TOKEN"  # declared as a `secret` in plugin.yaml config_schema
# What the CLI child process needs. Everything else in Hermes' environment, including
# other plugins' and providers' keys, stays out of it.
CHILD_ENV_KEEP = ("PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TMPDIR", "SSH_AUTH_SOCK")
CHALLENGE_LABEL = "_originveil-challenge"
CHALLENGE_PREFIX = "originveil-verify="
PENDING_TTL = 48 * 3600
STALE_HOURS = 8 * 24  # weekly timer plus a day of slack

_settings: dict = {"config_path": "", "report_dir": "/var/lib/originveil", "vantage": "local",
                   "allow_chat_origin_ip": False}
_state = None

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
# Last line of defence: anything that still looks like an IP literal is masked.
_IP_LITERAL = re.compile(
    r"(?<![\w.:<])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w.:])"
)


# ---------------------------------------------------------------- state

class _FileState:
    """Fallback when the host gives no ctx.state: a 0600 JSON file under HERMES_HOME."""

    def __init__(self) -> None:
        home = Path(os.environ.get("HERMES_HOME") or Path.home() / ".hermes")
        self.path = home / "originveil" / "state.json"

    def _load(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def get(self, key, default=None):
        return self._load().get(key, default)

    def set(self, key, value) -> None:
        data = self._load()
        data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)


def configure(settings: dict, state=None) -> None:
    global _state
    for k, v in settings.items():
        if v not in (None, ""):
            _settings[k] = v
    _settings["config_path"] = settings.get("config_path") or ""
    _state = state if state is not None else _FileState()


def _st():
    global _state
    if _state is None:
        _state = _FileState()
    return _state


# ---------------------------------------------------------------- helpers

def _valid_domain(value) -> str | None:
    d = str(value or "").strip().lower().rstrip(".")
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return d if _DOMAIN_RE.match(d) else None


def _routable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    if a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified or a.is_reserved:
        return False
    internal = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
    return not any(a.version == n.version and a in n for n in map(ipaddress.ip_network, internal))


def _config_path() -> Path | None:
    if _settings.get("config_path"):
        return Path(_settings["config_path"])
    return next((p for p in DEFAULT_CONFIGS if p.is_file()), None)


def _config_domains(path: Path | None) -> list[str]:
    if not path or not path.is_file():
        return []
    with path.open("rb") as fh:
        raw = tomllib.load(fh).get("domains", [])
    return [d for d in (_valid_domain(x) for x in raw) if d]


def _verified() -> list[str]:
    return [d for d in (_st().get("domains", []) or []) if _valid_domain(d)]


def _allowed() -> list[str]:
    return list(dict.fromkeys(_config_domains(_config_path()) + _verified()))


def _cf_token() -> str | None:
    """The optional Cloudflare token, read through Hermes' secret scope so a
    multi-profile gateway never hands one profile another profile's key."""
    try:
        from agent.secret_scope import get_secret
    except ImportError:  # running outside Hermes (tests, old builds)
        value = os.environ.get(SECRET_ENV)
    else:
        try:
            value = get_secret(SECRET_ENV)
        except Exception:  # no scope while multiplexing: fail closed, never fall back
            return None
    value = (value or "").strip()
    return value or None


def _token_env(path: Path | None) -> str:
    """The variable the CLI reads the token from (config `cloudflare.token_env`)."""
    name = "CF_API_TOKEN"
    if path and path.is_file():
        try:
            with path.open("rb") as fh:
                name = str(tomllib.load(fh).get("cloudflare", {}).get("token_env") or name)
        except (OSError, tomllib.TOMLDecodeError):
            pass
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) else "CF_API_TOKEN"


def _child_env(token: str | None, config: Path | None = None) -> dict:
    env = {k: os.environ[k] for k in CHILD_ENV_KEEP if k in os.environ}
    env["PYTHONPATH"] = str(PLUGIN_DIR)
    if token:
        env[_token_env(config)] = token
    return env


def _scrub(text: str) -> str:
    return _IP_LITERAL.sub("<ip>", text)


def _ok(**data) -> str:
    return json.dumps({"ok": True, **data})


def _err(msg: str) -> str:
    return json.dumps({"ok": False, "error": msg})


def _hash(domain: str) -> str:
    return hashlib.sha256(domain.encode()).hexdigest()[:16]


def _plugin_version() -> str:
    try:
        m = re.search(r"^version:\s*(\S+)", (PLUGIN_DIR / "plugin.yaml").read_text(), re.M)
        return m.group(1) if m else "?"
    except OSError:
        return "?"


def _last_report() -> dict | None:
    path = Path(_settings["report_dir"]) / "report.redacted.json"
    try:
        data = json.loads(_scrub(path.read_text()))
    except (OSError, json.JSONDecodeError):
        return None
    age = round((time.time() - path.stat().st_mtime) / 3600, 1)
    hashes = set((data.get("meta") or {}).get("domain_hashes", []))
    allowed = _allowed()
    data["freshness"] = {
        "age_hours": age,
        "stale": age > STALE_HOURS,
        "report_version": data.get("tool_version"),
        "plugin_version": _plugin_version(),
        "covers_allowed_domains": f"{sum(_hash(d) in hashes for d in allowed)} of {len(allowed)}",
    }
    return data


def _txt_records(name: str, timeout: float = 8.0) -> list[str]:
    """TXT values for name. dig if present, else DNS over HTTPS (no extra packages)."""
    if shutil.which("dig"):
        try:
            out = subprocess.run(["dig", "+short", "+time=5", "+tries=1", "TXT", name],
                                 capture_output=True, text=True, timeout=timeout).stdout
            return [line.strip().replace('" "', "").strip('"') for line in out.splitlines() if line.strip()]
        except (OSError, subprocess.SubprocessError):
            pass
    url = "https://cloudflare-dns.com/dns-query?" + urllib.parse.urlencode({"name": name, "type": "TXT"})
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            answers = json.loads(resp.read().decode()).get("Answer", [])
    except (OSError, ValueError):
        return []
    return [a.get("data", "").replace('" "', "").strip('"') for a in answers if a.get("type") == 16]


def _cloudflare_controls(domain: str) -> bool:
    """True if the configured Cloudflare token can read this domain's zone."""
    token = _cf_token()
    if not token:
        return False
    labels = domain.split(".")
    for i in range(len(labels) - 1):
        q = urllib.parse.urlencode({"name": ".".join(labels[i:])})
        req = urllib.request.Request(f"https://api.cloudflare.com/client/v4/zones?{q}",
                                     headers={"Authorization": f"Bearer {token}"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
        except (OSError, ValueError):
            return False
        if data.get("success") and data.get("result"):
            return True
    return False


# ---------------------------------------------------------------- domain tools

def add_domain(args: dict, **kwargs) -> str:
    try:
        d = _valid_domain(args.get("domain"))
        if not d:
            return _err("not a valid domain name")
        if d in _allowed():
            return _ok(status="already_allowed", domain=d)
        pending = _st().get("pending", {}) or {}
        token = secrets.token_hex(16)
        pending[d] = {"token": token, "created": int(time.time())}
        _st().set("pending", pending)
        return _ok(
            status="pending_verification",
            domain=d,
            dns_record={"type": "TXT", "name": f"{CHALLENGE_LABEL}.{d}", "value": f"{CHALLENGE_PREFIX}{token}"},
            instructions=(
                "Ask the user to add this TXT record in their DNS (for Cloudflare: DNS > Records > Add record), "
                "then call originveil_verify_domain. The code expires in 48 hours. "
                "If a Cloudflare token with access to this zone is configured, verify works without the record."
            ),
        )
    except Exception as exc:
        return _err(type(exc).__name__)


def verify_domain(args: dict, **kwargs) -> str:
    try:
        d = _valid_domain(args.get("domain"))
        if not d:
            return _err("not a valid domain name")
        if d in _allowed():
            return _ok(status="already_allowed", domain=d)
        pending = _st().get("pending", {}) or {}
        entry = pending.get(d)
        method = None
        if _cloudflare_controls(d):
            method = "cloudflare_api"
        elif entry and time.time() - entry.get("created", 0) <= PENDING_TTL:
            want = CHALLENGE_PREFIX + entry["token"]
            if want in _txt_records(f"{CHALLENGE_LABEL}.{d}"):
                method = "dns_txt"
        elif entry:
            pending.pop(d, None)
            _st().set("pending", pending)
            return _err("verification code expired; call originveil_add_domain again")
        else:
            return _err("no pending verification for this domain; call originveil_add_domain first")
        if not method:
            return _ok(status="not_verified_yet", domain=d,
                       hint="TXT record not visible yet. DNS changes can take a few minutes; try again shortly.")
        domains = _verified()
        domains.append(d)
        _st().set("domains", sorted(set(domains)))
        pending.pop(d, None)
        _st().set("pending", pending)
        return _ok(status="verified", domain=d, method=method,
                   note="The TXT record can be removed now.")
    except Exception as exc:
        return _err(type(exc).__name__)


def list_domains(args: dict, **kwargs) -> str:
    try:
        pending = _st().get("pending", {}) or {}
        return _ok(
            from_config=_config_domains(_config_path()),
            verified_in_chat=_verified(),
            pending=sorted(d for d, e in pending.items() if time.time() - e.get("created", 0) <= PENDING_TTL),
        )
    except Exception as exc:
        return _err(type(exc).__name__)


def remove_domain(args: dict, **kwargs) -> str:
    try:
        d = _valid_domain(args.get("domain"))
        if not d:
            return _err("not a valid domain name")
        if d in _config_domains(_config_path()) and d not in _verified():
            return _err("this domain comes from the config file; remove it there")
        _st().set("domains", [x for x in _verified() if x != d])
        pending = _st().get("pending", {}) or {}
        pending.pop(d, None)
        _st().set("pending", pending)
        return _ok(status="removed", domain=d)
    except Exception as exc:
        return _err(type(exc).__name__)


# ---------------------------------------------------------------- audit tools

def audit(args: dict, **kwargs) -> str:
    try:
        allowed = _allowed()
        if not allowed:
            return _err("no domains allowed yet. Add one with originveil_add_domain "
                        "(ownership is checked with a DNS TXT record), or list it in /etc/originveil/config.toml.")
        wanted = [_valid_domain(d) for d in (args.get("domains") or [])] or allowed
        if None in wanted or any(d not in allowed for d in wanted):
            return _err("only verified or configured domains can be audited; add the domain with originveil_add_domain first")

        cfg = _config_path()
        cli = [sys.executable, "-m", "originveil", "audit", "--remote-only", "--redact", "--json", "-q"]
        if cfg and cfg.is_file():
            cli += ["--config", str(cfg)]
        else:
            cli += ["--vantage", str(_settings.get("vantage") or "local")]
        for d in wanted:
            cli += ["--domain", d]
        if args.get("origin_ip") and _settings.get("allow_chat_origin_ip") is not True:
            return _err("origin_ip from chat is disabled. An admin can list the origin in origin_ips of "
                        "/etc/originveil/config.toml, or enable allow_chat_origin_ip in the plugin settings. "
                        "Without it, the tool discovers the origin itself.")
        for ip in args.get("origin_ip") or []:
            if not _routable(ip):
                return _err("origin_ip must be a public unicast IP address")
            cli += ["--origin-ip", str(ipaddress.ip_address(str(ip).strip()))]
        if args.get("origin_ip"):
            # Model-supplied IPs are not authorised targets by themselves.
            cli += ["--strict-given-ip"]
        if args.get("include_wordpress") is False:
            cli += ["--skip", "wordpress"]

        res = subprocess.run(cli, capture_output=True, text=True, timeout=600, cwd=PLUGIN_DIR,
                             env=_child_env(_cf_token(), cfg))
        if res.returncode not in (0, 1):
            return _err(f"originveil exited with {res.returncode}")
        report = json.loads(_scrub(res.stdout))
        out = {"ok": True, "live": report,
               "versions": {"plugin": _plugin_version(), "cli": report.get("tool_version")}}
        if out["versions"]["plugin"] != out["versions"]["cli"]:
            out["warning"] = "plugin and CLI versions differ; reinstall the plugin and restart Hermes"
        last = _last_report()
        if last:
            out["last_local_report"] = last
        else:
            out["note"] = ("no local timer report. Firewall and nginx/AOP checks run on the origin server itself "
                           "(the root timer described in the README), not on the host the agent runs on")
        return json.dumps(out)
    except subprocess.TimeoutExpired:
        return _err("audit timed out")
    except Exception as exc:  # never raise into the agent loop
        return _err(type(exc).__name__)


def last_report(args: dict, **kwargs) -> str:
    try:
        data = _last_report()
        if data is None:
            return _err("no readable report.redacted.json here; the timer is installed on the origin server")
        return _ok(report=data)
    except Exception as exc:
        return _err(type(exc).__name__)
