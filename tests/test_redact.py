from helpers import CF

from originveil.redact import Redactor, cloudflare_keeper


def test_ips_get_stable_tokens():
    r = Redactor()
    out = r.data({"a": "origin 192.0.2.10 and 192.0.2.10", "b": ["198.51.100.7"]})
    assert out == {"a": "origin <ip:1> and <ip:1>", "b": ["<ip:2>"]}


def test_cloudflare_ranges_are_kept():
    r = Redactor(keep_ip=cloudflare_keeper(CF))
    assert r.text("allow 173.245.48.0/20 and 192.0.2.10") == "allow 173.245.48.0/20 and <ip:1>"


def test_ipv6_and_prefix():
    r = Redactor()
    assert r.text("2001:db8::1 2001:db8::/32") == "<ip:1> <ip:2>/32"


def test_domains_keep_subdomain_label():
    r = Redactor(["example.com"])
    assert r.text("mail.example.com and example.com") == "mail.<domain:1> and <domain:1>"


def test_longer_domain_wins():
    r = Redactor(["example.com", "news.example.com"])
    assert r.text("news.example.com example.com") == "<domain:1> <domain:2>"


def test_paths_and_emails():
    r = Redactor()
    s = r.text("/home/alice/.ssh/id /root/x admin@example.org")
    assert "alice" not in s and "/root/" not in s and "admin@" not in s


def test_timestamps_untouched():
    r = Redactor()
    assert r.text("2026-11-24T12:37:32+00:00") == "2026-11-24T12:37:32+00:00"


def test_third_party_hosts_in_evidence_are_masked():
    r = Redactor(["example.org"])
    out = r.data({"title": "x", "evidence": {
        "found_via": ["MX mx.mailprovider.example", "ns1.example.org (public DNS)"],
        "file": "/etc/nginx/sites/site.conf", "server": "LiteSpeed",
        "fix": "see https://www.cloudflare.com/ips/",
    }})
    ev = out["evidence"]
    assert ev["found_via"] == ["MX <host:1>", "ns1.<domain:1> (public DNS)"]
    assert ev["file"] == "/etc/nginx/sites/site.conf"
    assert "cloudflare.com" in ev["fix"] and ev["server"] == "LiteSpeed"


def test_hosts_outside_evidence_untouched():
    r = Redactor()
    assert r.data({"fix": "Refresh from api.cloudflare.com"})["fix"].endswith("api.cloudflare.com")


def test_hostname_inside_url_in_evidence_is_masked():
    r = Redactor(["example.com"])
    out = r.data({"evidence": {"location": "https://cdn.hoster.test:8443/x?y=1",
                               "own": "https://www.example.com/"}})
    assert out["evidence"]["location"] == "https://<host:1>:8443/x?y=1"
    assert out["evidence"]["own"] == "https://www.<domain:1>/"
