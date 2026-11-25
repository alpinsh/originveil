import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def plugin():
    spec = importlib.util.spec_from_file_location(
        "ov_plugin", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)]
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ov_plugin"] = mod
    spec.loader.exec_module(mod)
    yield mod
    for name in [n for n in sys.modules if n.startswith("ov_plugin")]:
        del sys.modules[name]


class State:
    def __init__(self):
        self.data = {}

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, key, value):
        self.data[key] = json.loads(json.dumps(value))  # must be JSON-serialisable


class Ctx:
    def __init__(self, settings):
        self.settings, self.tools, self.skills = settings, {}, {}
        self.state = State()

    def get_config(self, key, default=None):
        return self.settings.get(key, default)

    def register_tool(self, name, toolset, schema, handler):
        assert schema["name"] == name
        self.tools[name] = handler

    def register_skill(self, name, path):
        self.skills[name] = path


def test_register(plugin, tmp_path):
    ctx = Ctx({"config_path": str(tmp_path / "c.toml"), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    assert set(ctx.tools) == {
        "originveil_audit", "originveil_last_report", "originveil_add_domain",
        "originveil_verify_domain", "originveil_list_domains", "originveil_remove_domain",
    }
    assert "originveil-audit" in ctx.skills


def test_audit_rejects_unconfigured_domain(plugin, tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com"]\n')
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    out = json.loads(ctx.tools["originveil_audit"]({"domains": ["victim.example"]}))
    assert out["ok"] is False and "victim" not in out["error"]


def test_audit_output_is_scrubbed(plugin, tmp_path, monkeypatch):
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com"]\n')
    (tmp_path / "report.redacted.json").write_text(json.dumps({"findings": [], "note": "leak 198.51.100.1"}))
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 1, stdout=json.dumps({"findings": [{"evidence": "192.0.2.10"}]}), stderr="")

    monkeypatch.setattr(plugin.tools.subprocess, "run", fake_run)
    raw = ctx.tools["originveil_audit"]({})
    assert "192.0.2.10" not in raw and "198.51.100.1" not in raw
    assert "--redact" in seen["cmd"] and "--remote-only" in seen["cmd"]
    out = json.loads(raw)
    assert out["ok"] and "last_local_report" in out


def test_last_report_missing(plugin, tmp_path):
    ctx = Ctx({"config_path": "", "report_dir": str(tmp_path)})
    plugin.register(ctx)
    assert json.loads(ctx.tools["originveil_last_report"]({}))["ok"] is False


def test_chat_origin_ip_off_by_default(plugin, tmp_path, monkeypatch):
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com"]\n')
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    called = []
    monkeypatch.setattr(plugin.tools.subprocess, "run", lambda *a, **k: called.append(a))
    out = json.loads(ctx.tools["originveil_audit"]({"origin_ip": ["192.0.2.10"]}))
    assert out["ok"] is False and "disabled" in out["error"] and not called


def test_optional_origin_ip_is_validated_and_passed(plugin, tmp_path, monkeypatch):
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com"]\n')
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path), "allow_chat_origin_ip": True})
    plugin.register(ctx)
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

    monkeypatch.setattr(plugin.tools.subprocess, "run", fake_run)
    assert json.loads(ctx.tools["originveil_audit"]({"origin_ip": ["not-an-ip"]}))["ok"] is False
    ctx.tools["originveil_audit"]({"origin_ip": ["192.0.2.10"]})
    assert seen["cmd"][seen["cmd"].index("--origin-ip") + 1] == "192.0.2.10"
    assert "--strict-given-ip" in seen["cmd"]
    seen.clear()
    ctx.tools["originveil_audit"]({})
    assert "--origin-ip" not in seen["cmd"]


def call(ctx, name, **args):
    return json.loads(ctx.tools[name](args))


def test_add_and_verify_domain_with_txt(plugin, tmp_path, monkeypatch):
    ctx = Ctx({"config_path": str(tmp_path / "none.toml"), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    monkeypatch.setattr(plugin.tools, "_cloudflare_controls", lambda d: False)

    assert call(ctx, "originveil_audit")["ok"] is False  # nothing allowed yet
    added = call(ctx, "originveil_add_domain", domain="Example.COM")
    rec = added["dns_record"]
    assert rec["name"] == "_originveil-challenge.example.com" and rec["value"].startswith("originveil-verify=")

    monkeypatch.setattr(plugin.tools, "_txt_records", lambda name: [])
    assert call(ctx, "originveil_verify_domain", domain="example.com")["status"] == "not_verified_yet"

    monkeypatch.setattr(plugin.tools, "_txt_records", lambda name: ["unrelated", rec["value"]])
    v = call(ctx, "originveil_verify_domain", domain="example.com")
    assert v["status"] == "verified" and v["method"] == "dns_txt"
    assert call(ctx, "originveil_list_domains")["verified_in_chat"] == ["example.com"]

    seen = {}
    monkeypatch.setattr(plugin.tools.subprocess, "run", lambda cmd, **kw: seen.setdefault("cmd", cmd) and
                        subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr=""))
    call(ctx, "originveil_audit")
    assert "--vantage" in seen["cmd"] and "example.com" in seen["cmd"]

    assert call(ctx, "originveil_remove_domain", domain="example.com")["status"] == "removed"
    assert call(ctx, "originveil_audit")["ok"] is False


def test_wrong_token_and_unrequested_domain(plugin, tmp_path, monkeypatch):
    ctx = Ctx({"config_path": str(tmp_path / "none.toml"), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    monkeypatch.setattr(plugin.tools, "_cloudflare_controls", lambda d: False)
    # someone else's domain with no add step: refused, even if a TXT happens to exist
    monkeypatch.setattr(plugin.tools, "_txt_records", lambda name: ["originveil-verify=deadbeef"])
    assert call(ctx, "originveil_verify_domain", domain="victim.example")["ok"] is False
    call(ctx, "originveil_add_domain", domain="victim.example")
    assert call(ctx, "originveil_verify_domain", domain="victim.example")["status"] == "not_verified_yet"
    assert call(ctx, "originveil_add_domain", domain="-oProxyCommand=x")["ok"] is False


def test_expired_code(plugin, tmp_path, monkeypatch):
    ctx = Ctx({"config_path": "", "report_dir": str(tmp_path)})
    plugin.register(ctx)
    monkeypatch.setattr(plugin.tools, "_cloudflare_controls", lambda d: False)
    call(ctx, "originveil_add_domain", domain="example.com")
    ctx.state.data["pending"]["example.com"]["created"] -= 49 * 3600
    assert "expired" in call(ctx, "originveil_verify_domain", domain="example.com")["error"]


def test_cloudflare_token_verifies(plugin, tmp_path, monkeypatch):
    ctx = Ctx({"config_path": "", "report_dir": str(tmp_path)})
    plugin.register(ctx)
    monkeypatch.setattr(plugin.tools, "_cloudflare_controls", lambda d: d == "example.com")
    call(ctx, "originveil_add_domain", domain="example.com")
    assert call(ctx, "originveil_verify_domain", domain="example.com")["method"] == "cloudflare_api"


def test_metadata_origin_ip_rejected(plugin, tmp_path):
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com"]\n')
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path), "allow_chat_origin_ip": True})
    plugin.register(ctx)
    assert call(ctx, "originveil_audit", origin_ip=["169.254.169.254"])["ok"] is False


def test_last_report_freshness(plugin, tmp_path):
    import hashlib
    import os
    cfg = tmp_path / "c.toml"
    cfg.write_text('domains = ["example.com", "example.org"]\n')
    h = hashlib.sha256(b"example.com").hexdigest()[:16]
    rep = tmp_path / "report.redacted.json"
    rep.write_text(json.dumps({"tool_version": "0.1.0", "meta": {"domain_hashes": [h]}}))
    old = rep.stat().st_mtime - 10 * 24 * 3600
    os.utime(rep, (old, old))
    ctx = Ctx({"config_path": str(cfg), "report_dir": str(tmp_path)})
    plugin.register(ctx)
    fr = call(ctx, "originveil_last_report")["report"]["freshness"]
    assert fr["stale"] is True and fr["covers_allowed_domains"] == "1 of 2"
