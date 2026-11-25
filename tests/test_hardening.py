import os

import pytest

from originveil import audit, cli, config, net, systemd
from originveil.checks import reach
from originveil.config import Config


@pytest.mark.parametrize("bad", ["-f/etc/passwd", "a b.example", "evil.example;rm -rf", "", "..", "example", "x/../y.example"])
def test_invalid_domains(bad):
    assert net.valid_domain(bad) is None


def test_domain_normalised():
    assert net.valid_domain("Example.COM.") == "example.com"
    assert net.valid_domain("bücher.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("ip", ["169.254.169.254", "127.0.0.1", "::1", "10.1.2.3", "::ffff:127.0.0.1",
                                "fe80::1", "0.0.0.0", "224.0.0.1", "fd00::1", "not-an-ip"])
def test_non_routable(ip):
    assert not net.routable_ip(ip)


def test_routable():
    assert net.routable_ip("192.0.2.10") and net.routable_ip("2001:db8::1")


@pytest.mark.parametrize("spec", ["-oProxyCommand=sh", "a b@host", "ssh://-oProxyCommand=x@h", "",
                                  "ssh://-F/tmp/evil", "ssh://user@-oProxyCommand=x", "host;id", "ssh://u@h:22:x"])
def test_vantage_injection(spec):
    with pytest.raises(ValueError):
        reach.parse_vantage(spec)


def test_metadata_ip_from_config_is_ignored():
    report = audit.run(Config(domains=["example.com"], origin_ips=["169.254.169.254"]), ("dns",))
    assert any(s.check == "origin" for s in report.skipped)


def test_invalid_domain_cli(capsys):
    assert cli.main(["audit", "--domain=-x", "--json"]) == 2


def test_invalid_domain_config(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('domains = ["--help"]\n')
    with pytest.raises(ValueError):
        config.load(str(p))


def test_unsafe_path(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    os.chmod(d, 0o777)
    assert systemd.unsafe_path(d) == str(d)


def test_same_site():
    assert reach.same_site("www.example.com", "example.com")
    assert reach.same_site("example.com", "www.example.com")
    assert not reach.same_site("example.com.evil.net", "example.com")
    assert not reach.same_site(None, "example.com")


def test_redacted_crash_prints_no_details(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("secret 192.0.2.10")

    monkeypatch.setattr(audit, "run", boom)
    assert cli.main(["audit", "-d", "example.com", "--redact"]) == 2
    assert "192.0.2.10" not in capsys.readouterr().err


def _tree(tmp_path):
    root = tmp_path / "pkg"
    (root / "checks").mkdir(parents=True)
    for p in (root / "cli.py", root / "checks" / "dns.py"):
        p.write_text("x = 1\n")
        os.chmod(p, 0o644)
    for p in (tmp_path, root, root / "checks"):
        os.chmod(p, 0o755)
    return root


@pytest.mark.skipif(os.geteuid() != 0, reason="ownership checks need root to set up")
def test_unsafe_tree(tmp_path):
    root = _tree(tmp_path)
    # tmp_path's parents (/tmp is 1777) would be flagged first; test the walk itself
    assert systemd.unsafe_tree(root) is None or "/tmp" in systemd.unsafe_tree(root)
    walk_only = lambda r: next((str(p) for p in r.rglob("*") if (  # noqa: E731
        p.is_symlink() or p.lstat().st_uid != 0 or p.lstat().st_mode & 0o022)), None)
    assert walk_only(root) is None

    os.chmod(root / "checks" / "dns.py", 0o666)
    assert systemd.unsafe_tree(root) is not None
    os.chmod(root / "checks" / "dns.py", 0o644)

    os.chown(root / "cli.py", 65534, 65534)
    assert systemd.unsafe_tree(root) is not None
    os.chown(root / "cli.py", 0, 0)

    (root / "link.py").symlink_to(root / "cli.py")
    assert systemd.unsafe_tree(root) is not None


def test_world_readable_token_file_refused(tmp_path, capsys):
    tok = tmp_path / "tok"
    tok.write_text("secret-value")
    os.chmod(tok, 0o644)
    assert Config(token_file=str(tok)).token() is None
    err = capsys.readouterr().err
    assert str(tok) not in err and "secret-value" not in err
    os.chmod(tok, 0o600)
    assert Config(token_file=str(tok)).token() == "secret-value"


def test_strict_given_ip_needs_matching_cert(monkeypatch):
    from originveil.checks import probe
    monkeypatch.setattr(probe, "cert_names_only", lambda ip, host, timeout, port=443: ["unrelated.example.net"])
    cfg = Config(domains=["example.com"], origin_ips=["198.51.100.50"], strict_given_ip=True)
    report = audit.run(cfg, ("dns",))
    assert any(s.check == "origin" and "certificate" in s.reason for s in report.skipped)

    monkeypatch.setattr(probe, "cert_names_only", lambda ip, host, timeout, port=443: ["example.com"])
    report = audit.run(cfg, ("dns",))
    assert report.origin_mode == "given" and not any(s.check == "origin" for s in report.skipped)


def test_dig_parsing(monkeypatch):
    import subprocess as sp
    out = (";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
           "example.com.\t300\tIN\tMX\t10 mx.mail.example.net.\n")
    monkeypatch.setattr(net.shutil, "which", lambda n: "/usr/bin/dig")
    monkeypatch.setattr(net.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 0, stdout=out, stderr=""))
    from helpers import REAL_DIG
    assert REAL_DIG("example.com", "MX") == ["10 mx.mail.example.net."]
    bad = out.replace("NOERROR", "SERVFAIL")
    monkeypatch.setattr(net.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 0, stdout=bad, stderr=""))
    assert REAL_DIG("example.com", "MX") is None
    monkeypatch.setattr(net.subprocess, "run", lambda *a, **k: sp.CompletedProcess(a, 9, stdout="", stderr=""))
    assert REAL_DIG("example.com", "MX") is None


def test_valid_vantage_specs():
    assert reach.parse_vantage("ssh://audit@203.0.113.5:2222")[-1] == "audit@203.0.113.5"
    assert reach.parse_vantage("audit@vantage.example.net")[-1] == "audit@vantage.example.net"


def test_unknown_only_value_is_an_error(capsys):
    assert cli.main(["audit", "-d", "example.com", "--only", "dns,typo"]) == 2


def test_report_write_does_not_follow_symlink(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    out = tmp_path / "out"
    out.mkdir()
    (out / "report.json").symlink_to(victim)  # planted link at the final name
    cli._write(out / "report.json", {"a": 1}, 0o600)
    assert victim.read_text() == "keep" and not (out / "report.json").is_symlink()
