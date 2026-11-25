"""Install a root systemd timer that writes a full and a redacted report.

The full report (with real IPs) is root-only. The redacted one is world
readable so an unprivileged agent can read it without ever seeing the IP.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

UNIT_DIR = Path("/etc/systemd/system")
STATE_DIR = Path("/var/lib/originveil")

SERVICE = """[Unit]
Description=originveil origin exposure audit
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
EnvironmentFile=-/etc/originveil/env
Environment=PYTHONPATH={pythonpath}
ExecStart={python} -m originveil audit --config {config} --write-reports {state}
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={state}
"""

TIMER = """[Unit]
Description=Run originveil audit {calendar}

[Timer]
OnCalendar={calendar}
Persistent=true
RandomizedDelaySec=1h

[Install]
WantedBy=timers.target
"""


def unsafe_path(path: Path) -> str | None:
    """First component of path (or a parent) that a non-root user could modify."""
    for part in [path, *path.parents]:
        try:
            st = part.lstat()
        except FileNotFoundError:
            continue
        if st.st_uid != 0 or st.st_mode & 0o022:
            return str(part)
    return None


def unsafe_tree(root: Path) -> str | None:
    """First file or directory under root (root itself included) that is not root-owned,
    is group/world-writable, or is a symlink. The timer imports every module here as root."""
    bad = unsafe_path(root)
    if bad:
        return bad
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath, name)
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                return str(p)
    return None


def _secret_file_unsafe(path: Path) -> str | None:
    """A file holding secrets must be root-owned and not readable by group or others."""
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o077:
        return str(path)
    return None


def install(config: str, calendar: str = "weekly", dry_run: bool = False) -> int:
    if os.geteuid() != 0 and not dry_run:
        print("install-timer needs root", file=sys.stderr)
        return 2
    pkg_parent = Path(__file__).resolve().parent.parent
    # The timer runs this code as root. If anyone else can write to it, that is a root escalation.
    checks = [
        unsafe_tree(Path(__file__).resolve().parent),
        unsafe_path(Path(config)),
        unsafe_path(Path(sys.executable).resolve()),
        _secret_file_unsafe(Path("/etc/originveil/env")),
        unsafe_path(STATE_DIR) if STATE_DIR.exists() else None,
    ]
    for bad in checks:
        if bad:
            msg = f"refusing: {bad} is writable by a non-root user or not owned by root"
            if dry_run:
                print(f"warning: {msg}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
                return 2
    service = SERVICE.format(
        pythonpath=pkg_parent, python=sys.executable, config=config, state=STATE_DIR
    )
    timer = TIMER.format(calendar=calendar)
    if dry_run:
        print("# originveil.service\n" + service + "\n# originveil.timer\n" + timer)
        return 0
    STATE_DIR.mkdir(mode=0o755, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o755)
    (UNIT_DIR / "originveil.service").write_text(service)
    (UNIT_DIR / "originveil.timer").write_text(timer)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", "originveil.timer"], check=True)
    print(f"installed. reports: {STATE_DIR}/report.json (root only), {STATE_DIR}/report.redacted.json")
    print("put CF_API_TOKEN=... in /etc/originveil/env (chmod 600) to enable the DNS API check")
    return 0
