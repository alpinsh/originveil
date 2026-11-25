from helpers import ORIGIN

from originveil import net
from originveil.checks import dns


def ids(findings):
    return {f.id for f in findings}


RECORDS = [
    {"type": "A", "name": "example.com", "content": ORIGIN, "proxied": True},
    {"type": "A", "name": "mail.example.com", "content": ORIGIN, "proxied": False},
    {"type": "MX", "name": "example.com", "content": "mail.example.com"},
    {"type": "TXT", "name": "example.com", "content": '"v=spf1 ip4:192.0.2.0/24 include:_spf.example.net ~all"'},
    {"type": "A", "name": "other.example.com", "content": "198.51.100.9", "proxied": False},
]


def test_records():
    found = dns.check_records(RECORDS, [ORIGIN])
    assert {"dns-only-origin", "mx-on-origin", "spf-lists-origin", "proxied-origin"} <= ids(found)
    crit = [f for f in found if f.severity == "critical"]
    assert len(crit) == 1 and crit[0].evidence["record"] == "mail.example.com"


def test_clean_zone():
    clean = [
        {"type": "A", "name": "example.com", "content": ORIGIN, "proxied": True},
        {"type": "MX", "name": "example.com", "content": "mx.provider.example"},
        {"type": "TXT", "name": "example.com", "content": "v=spf1 include:_spf.provider.example -all"},
    ]
    assert all(f.severity in ("info", "pass") for f in dns.check_records(clean, [ORIGIN]))


def test_spf_parsing():
    nets = dns.spf_networks("v=spf1 +ip4:192.0.2.10 ip6:2001:db8::/48 -all")
    assert [str(n) for n in nets] == ["192.0.2.10/32", "2001:db8::/48"]


def test_public_names(monkeypatch, cf_nets):
    table = {"example.com": {"173.245.48.5"}, "mail.example.com": {ORIGIN}, "dev.example.com": {"198.51.100.4"}}
    monkeypatch.setattr(net, "resolve", lambda h: table.get(h, set()))
    found, gaps = dns.check_public(["example.com"], [ORIGIN], cf_nets)
    by_id = {f.id: f for f in found}
    assert by_id["public-name-origin"].evidence["host"] == "mail.example.com"
    assert by_id["public-name-unproxied"].evidence["host"] == "dev.example.com"


def test_cloudflare_api_pagination():
    calls = []

    def api_get(path):
        calls.append(path)
        if path.startswith("/zones?name=sub.example.com"):
            return {"success": True, "result": []}
        if path.startswith("/zones?name=example.com"):
            return {"success": True, "result": [{"id": "z1"}]}
        page = int(path.split("page=")[1].split("&")[0])
        return {"success": True, "result": [RECORDS[page - 1]], "result_info": {"total_pages": 2}}

    found, errors = dns.check_cloudflare(["sub.example.com"], [ORIGIN], "t", api_get=api_get)
    assert not errors
    assert "proxied-origin" in ids(found) and "dns-only-origin" in ids(found)
    assert sum("dns_records" in c for c in calls) == 2


def test_cloudflare_api_zone_missing():
    found, errors = dns.check_cloudflare(["example.com"], [ORIGIN], "t",
                                         api_get=lambda p: {"success": True, "result": []})
    assert not found and errors


def test_fix_advice_depends_on_service():
    assert "non-HTTP" in dns.fix_for("ns1.example.com", "example.com")
    assert "non-HTTP" in dns.fix_for("mail.example.com", "example.com")
    assert dns.fix_for("dev.example.com", "example.com").startswith("Turn on the proxy")


def test_dig_failure_is_a_gap_not_empty(monkeypatch, cf_nets):
    monkeypatch.setattr(net, "dig", lambda name, rtype, timeout=5.0: None)
    _found, gaps = dns.check_public(["example.com"], [ORIGIN], cf_nets)
    assert any("MX" in g for g in gaps) and any("SPF" in g for g in gaps)


def test_api_success_false_is_an_error():
    def api_get(path):
        if path.startswith("/zones?"):
            return {"success": True, "result": [{"id": "z"}]}
        return {"success": False, "errors": [{"code": 10000}]}

    found, errors = dns.check_cloudflare(["example.com"], [ORIGIN], "t", api_get=api_get)
    assert errors and "could not list" in errors[0]
