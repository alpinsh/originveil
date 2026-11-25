from helpers import ORIGIN

from originveil import audit, net
from originveil.checks import discover, reach
from originveil.config import Config

OTHER = "198.51.100.20"
SPF = '"v=spf1 ip4:192.0.2.10 include:_spf.provider.example ~all"'


def fake_dns(monkeypatch):
    table = {
        "example.com": {"173.245.48.5"},
        "ns1.example.com": {ORIGIN},
        "autodiscover.example.com": {OTHER},
    }
    monkeypatch.setattr(net, "resolve", lambda h: table.get(h, set()))
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: [SPF] if rtype == "TXT" else [])


def serving(ip):
    page = {"tcp": "open", "tls": "ok", "status": 200, "title": "Example News", "cert_names": ["example.com"]}
    closed = {"tcp": "timeout"}
    https = page if ip == ORIGIN else closed
    return {"ip": ip, "hosts": {"example.com": {"https": https, "http": closed}}, "bare_ip": {}}


def test_candidates_from_public_records(monkeypatch, cf_nets):
    fake_dns(monkeypatch)
    cands, auth, _gaps = discover.candidates(["example.com"], cf_nets)
    assert set(cands) == {ORIGIN, OTHER}
    assert "ns1.example.com (public DNS)" in cands[ORIGIN]
    assert "SPF of example.com" in cands[ORIGIN]
    assert not auth


def test_api_proxied_record_is_authoritative(monkeypatch, cf_nets):
    def api_get(path):
        if path.startswith("/zones?"):
            return {"success": True, "result": [{"id": "z"}]}
        return {"success": True, "result": [
            {"type": "A", "name": "example.com", "content": ORIGIN, "proxied": True},
        ], "result_info": {"total_pages": 1}}

    cands, auth, _gaps = discover.candidates(["example.com"], cf_nets, api_get=api_get)
    assert auth == {ORIGIN}


def test_audit_discovers_and_confirms(monkeypatch):
    fake_dns(monkeypatch)

    def observe_all(ips, domains, vantage, timeout=6.0):
        return {ip: serving(ip) for ip in ips}, {"example.com": "Example News"}, None

    monkeypatch.setattr(reach, "observe_all", observe_all)
    cfg = Config(domains=["example.com"], vantage="local")
    report = audit.run(cfg, ("dns", "reach"))
    assert report.origin_mode == "discover"
    by_id = {}
    for f in report.findings:
        by_id.setdefault(f.id, []).append(f)

    disc = by_id["origin-discovered"][0]
    assert disc.severity == "critical" and disc.evidence["ip"] == ORIGIN
    assert "TLS certificate names example.com" in disc.evidence["confirmed_by"]
    unreach = by_id["candidate-unreachable"][0]
    assert unreach.evidence["ips"] == [OTHER]
    assert "timeout" in unreach.evidence["probe"][OTHER]
    assert report.verdict() == "fail"
    assert any(f.evidence.get("host") == "ns1.example.com" for f in by_id["public-name-origin"])
    assert "https-direct" in by_id


def test_without_vantage_candidates_stay_unconfirmed(monkeypatch):
    fake_dns(monkeypatch)
    report = audit.run(Config(domains=["example.com"]), ("dns", "reach"))
    ids = {f.id for f in report.findings}
    assert "possible-origin" in ids and "origin-discovered" not in ids
    assert any(s.check == "reach" for s in report.skipped)


def test_given_ip_skips_discovery(monkeypatch):
    fake_dns(monkeypatch)
    report = audit.run(Config(domains=["example.com"], origin_ips=[ORIGIN]), ("dns",))
    assert report.origin_mode == "given"
    assert not any(f.check == "discover" for f in report.findings)


def test_local_keyword(monkeypatch):
    monkeypatch.setattr(net, "local_public_ips", lambda: [ORIGIN])
    report = audit.run(Config(domains=["example.com"], origin_ips=["local"]), ("dns",))
    assert report.origin_mode == "local"


def test_nothing_found_is_pass_with_caveat(monkeypatch):
    monkeypatch.setattr(net, "resolve", lambda h: {"173.245.48.5"} if h == "example.com" else set())
    report = audit.run(Config(domains=["example.com"]), ("dns", "reach"))
    f = next(f for f in report.findings if f.id == "no-candidates")
    assert f.severity == "pass" and "does not prove" in f.detail


def test_unresolvable_domain_is_skipped_not_passed(monkeypatch):
    report = audit.run(Config(domains=["example.com"]), ("dns", "reach"))
    assert not report.findings
    assert any(s.check == "discover" for s in report.skipped)


def test_wildcard_zone_does_not_flood_candidates(monkeypatch, cf_nets):
    monkeypatch.setattr(net, "resolve", lambda h: {"173.245.48.5"} if h == "example.com" else {OTHER})
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: [])
    cands, _, _gaps = discover.candidates(["example.com"], cf_nets)
    assert cands == {OTHER: ["*.example.com wildcard (public DNS)"]}


def test_every_candidate_is_reported(monkeypatch):
    table = {"example.com": {"173.245.48.5"}, "mail.example.com": {"198.51.100.21"},
             "ftp.example.com": {"198.51.100.22"}, "dev.example.com": {"198.51.100.23"}}
    monkeypatch.setattr(net, "resolve", lambda h: table.get(h, set()))
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: [])
    monkeypatch.setattr(reach, "observe_all", lambda ips, d, v, timeout=6.0: (
        {ip: {"ip": ip, "hosts": {}} for ip in ips}, {}, None))
    report = audit.run(Config(domains=["example.com"], vantage="local"), ("dns", "reach"))
    others = [f for f in report.findings if f.id == "candidate-unreachable"]
    assert len(others) == 3  # different sources stay separate
    assert any(f.id == "origin-not-found" and f.severity == "pass" for f in report.findings)
    assert any(s.check == "dns" for s in report.skipped)
    # nothing wrong found, but the real origin was never confirmed: not a pass
    assert report.verdict() == "incomplete"
    assert report.coverage()["reach"] == "skipped"


def test_same_source_candidates_are_grouped():
    cands = {"198.51.100.31": ["MX mx.provider.example"], "198.51.100.32": ["MX mx.provider.example"]}
    out = discover.findings_for(cands, {}, set(cands), set())
    grouped = [f for f in out if f.id == "candidate-not-origin"]
    assert len(grouped) == 1 and grouped[0].evidence["ips"] == sorted(cands)


def test_reachable_other_site_is_not_origin(monkeypatch):
    table = {"example.com": {"173.245.48.5"}, "mail.example.com": {"198.51.100.21"}}
    monkeypatch.setattr(net, "resolve", lambda h: table.get(h, set()))
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: [])
    other = {"tcp": "open", "tls": "ok", "status": 200, "title": "Mail login", "cert_names": ["mail.provider.example"]}
    monkeypatch.setattr(reach, "observe_all", lambda ips, d, v, timeout=6.0: (
        {ip: {"ip": ip, "hosts": {"example.com": {"https": other, "http": {"tcp": "refused"}}}} for ip in ips},
        {"example.com": "Example News"}, None))
    report = audit.run(Config(domains=["example.com"], vantage="local"), ("dns", "reach"))
    f = next(f for f in report.findings if f.id == "candidate-not-origin")
    assert "cert for other names" in f.evidence["probe"]["198.51.100.21"]
    assert report.meta["probe"]["vantage"] == "local"


def test_parent_zone_records_are_filtered(monkeypatch, cf_nets):
    monkeypatch.setattr(net, "resolve", lambda h: set())

    def api_get(path):
        if path.startswith("/zones?"):
            return {"success": True, "result": [{"id": "z"}]}
        return {"success": True, "result_info": {"total_pages": 1}, "result": [
            {"type": "A", "name": "shop.example.com", "content": "198.51.100.40", "proxied": True},
            {"type": "A", "name": "other.example.com", "content": "198.51.100.41", "proxied": False},
        ]}

    cands, auth, _ = discover.candidates(["shop.example.com"], cf_nets, api_get=api_get)
    assert set(cands) == {"198.51.100.40"}
