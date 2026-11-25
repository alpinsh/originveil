import json
import subprocess
import sys
from pathlib import Path

from originveil import cli
from originveil.checks import probe

ROOT = Path(__file__).resolve().parent.parent


def test_audit_webserver_json_redacted(tmp_path, capsys):
    site = tmp_path / "site.conf"
    site.write_text("server { listen 443 ssl; server_name news.example.com; root /home/alice/www; }")
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"http {{ include {site}; }}")
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'domains = ["example.com"]\norigin_ips = ["192.0.2.10"]\n[paths]\nnginx_conf = "{conf}"\n')

    code = cli.main(["audit", "--config", str(cfg), "--only", "webserver", "--json", "--redact"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert code == 1  # high finding present
    assert "example.com" not in out and "alice" not in out
    assert any(f["id"] == "aop-off" for f in data["findings"])


def test_write_reports_permissions(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('domains = ["example.com"]\norigin_ips = ["192.0.2.10"]\n[paths]\nnginx_conf = "/nonexistent"\n')
    out = tmp_path / "state"
    cli.main(["audit", "--config", str(cfg), "--only", "webserver", "--write-reports", str(out)])
    assert (out / "report.json").stat().st_mode & 0o777 == 0o600
    assert (out / "report.redacted.json").stat().st_mode & 0o777 == 0o644
    assert cli.main(["show", "--dir", str(out), "--redacted", "--json"]) == 0
    assert '"tool": "originveil"' in capsys.readouterr().out


def test_probe_runs_standalone_over_stdin():
    # This is how the probe travels to a vantage host: `ssh host python3 - ARGS`.
    src = Path(probe.__file__).read_text()
    res = subprocess.run(
        [sys.executable, "-I", "-", "127.0.0.1", "example.com", "--timeout", "1"],
        input=src, capture_output=True, text=True, timeout=30, cwd="/",
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["ip"] == "127.0.0.1" and "example.com" in data["hosts"]


def test_timer_dry_run(capsys):
    assert cli.main(["install-timer", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "ProtectSystem=strict" in out and "OnCalendar=weekly" in out


def test_verdict_and_checks_in_output(tmp_path, capsys):
    cfg = tmp_path / "config.toml"
    cfg.write_text('domains = ["example.com"]\norigin_ips = ["192.0.2.10"]\n[paths]\nnginx_conf = "/nonexistent"\n')
    cli.main(["audit", "--config", str(cfg), "--only", "webserver", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "incomplete" and data["checks"] == {"webserver": "skipped"}
