from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from pathlib import Path

from . import __version__, audit, config, net, render, systemd
from .checks import probe
from .models import Report
from .redact import Redactor, cloudflare_keeper


def _redactor(cfg: config.Config) -> Redactor:
    return Redactor(cfg.domains, keep_ip=cloudflare_keeper(net.cloudflare_ranges(cfg.timeout)))


def _write(path: Path, data: dict, mode: int) -> None:
    """Atomic write that cannot be redirected through a planted symlink or file."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def cmd_audit(args: argparse.Namespace) -> int:
    cfg = config.load(args.config)
    if args.domain:
        cfg.domains = [net.valid_domain(d) for d in args.domain]
        if not all(cfg.domains):
            print("error: invalid domain", file=sys.stderr)
            return 2
    if args.origin_ip:
        cfg.origin_ips = args.origin_ip
    if args.vantage:
        cfg.vantage = args.vantage
    if args.timeout:
        cfg.timeout = args.timeout
    if args.strict_given_ip:
        cfg.strict_given_ip = True

    scopes = audit.REMOTE_SAFE if args.remote_only else audit.ALL
    if args.only:
        wanted = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = [s for s in wanted if s not in audit.ALL]
        if unknown or not wanted:
            print(f"error: unknown check(s) in --only; valid: {','.join(audit.ALL)}", file=sys.stderr)
            return 2
        scopes = tuple(wanted)
    if args.skip:
        scopes = tuple(s for s in scopes if s not in args.skip.split(","))

    def progress(msg: str) -> None:
        if not args.quiet and (sys.stderr.isatty() or args.verbose):
            print(f"... {msg}", file=sys.stderr, flush=True)

    report = audit.run(cfg, scopes, progress)
    data = report.to_dict()

    if args.write_reports:
        out = Path(args.write_reports)
        out.mkdir(parents=True, exist_ok=True)
        _write(out / "report.json", data, 0o600)
        _write(out / "report.redacted.json", _redactor(cfg).data(data), 0o644)

    shown = _redactor(cfg).data(data) if args.redact else data
    if args.json:
        print(json.dumps(shown, indent=2))
    elif not args.write_reports or sys.stdout.isatty():
        print(render.text(Report.from_dict(shown), verbose=args.verbose))

    return 1 if report.worst() in ("critical", "high") else 0


def cmd_show(args: argparse.Namespace) -> int:
    name = "report.redacted.json" if args.redacted else "report.json"
    path = Path(args.dir) / name
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError:
        print(f"no report at {path} (has the timer run yet?)", file=sys.stderr)
        return 2
    except PermissionError:
        print(f"cannot read {path}; use --redacted or run as root", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(render.text(Report.from_dict(data), verbose=args.verbose))
    return 0


def cmd_probe(args: argparse.Namespace) -> int:
    print(json.dumps(probe.observe(args.origin_ip, args.domain, args.timeout), indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="originveil",
        description="Audit how a Cloudflare-proxied origin can be found or reached directly.",
    )
    p.add_argument("--version", action="version", version=f"originveil {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="run the checks")
    a.add_argument("--config", help="config file (default: /etc/originveil/config.toml, ~/.config/originveil/config.toml)")
    a.add_argument("-d", "--domain", action="append", help="domain to check (repeatable)")
    a.add_argument("--origin-ip", action="append", help="origin IP (repeatable), or 'local' for this host's own IPs; omit to discover it")
    a.add_argument("--vantage", help="ssh://user@host:port of a machine you control for the direct test, or 'local'")
    a.add_argument("--timeout", type=float)
    a.add_argument("--strict-given-ip", action="store_true",
                   help="probe a given --origin-ip only if it presents a certificate for an audited domain")
    a.add_argument("--only", help=f"comma list of checks: {','.join(audit.ALL)}")
    a.add_argument("--skip", help="comma list of checks to skip")
    a.add_argument("--remote-only", action="store_true", help="only checks that need no local privileges")
    a.add_argument("--redact", action="store_true", help="mask IPs, domains, paths and emails in output")
    a.add_argument("--json", action="store_true")
    a.add_argument("-v", "--verbose", action="store_true", help="show passing results and evidence")
    a.add_argument("-q", "--quiet", action="store_true", help="no progress messages on stderr")
    a.add_argument("--write-reports", metavar="DIR", help="write report.json (0600) and report.redacted.json (0644)")
    a.set_defaults(func=cmd_audit)

    s = sub.add_parser("show", help="print the last report written by the timer")
    s.add_argument("--dir", default=str(systemd.STATE_DIR))
    s.add_argument("--redacted", action="store_true")
    s.add_argument("--json", action="store_true")
    s.add_argument("-v", "--verbose", action="store_true")
    s.set_defaults(func=cmd_show)

    pr = sub.add_parser("probe", help="raw direct-connection probe (run this on the vantage host)")
    pr.add_argument("origin_ip")
    pr.add_argument("domain", nargs="+")
    pr.add_argument("--timeout", type=float, default=6.0)
    pr.set_defaults(func=cmd_probe)

    t = sub.add_parser("install-timer", help="install a root systemd timer")
    t.add_argument("--config", default="/etc/originveil/config.toml")
    t.add_argument("--calendar", default="weekly", help="systemd OnCalendar value")
    t.add_argument("--dry-run", action="store_true", help="print the units instead of installing")
    t.set_defaults(func=lambda a: systemd.install(a.config, a.calendar, a.dry_run))
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # A traceback can carry IPs, hostnames and paths. Keep it out of redacted/JSON output.
        if getattr(args, "redact", False) or getattr(args, "json", False):
            print(f"error: {type(exc).__name__}", file=sys.stderr)
            return 2
        raise
