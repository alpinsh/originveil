from originveil.checks import firewall


def ids(findings):
    return {f.id for f in findings}


IPT_OPEN = """*filter
:INPUT DROP [0:0]
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 80,443 -j ACCEPT
COMMIT
"""

IPT_CF = """*nat
-A DOCKER ! -i docker0 -p tcp -m tcp --dport 443 -j DNAT --to-destination 172.17.0.2:443
COMMIT
*filter
:INPUT DROP [0:0]
-A INPUT -s 173.245.48.0/20 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 103.21.244.0/22 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -s 2400:cb00::/32 -p tcp -m tcp --dport 443 -j ACCEPT
COMMIT
"""

NFT = """table inet filter {
\tset cloudflare_v4 {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 173.245.48.0/20, 103.21.244.0/22,
\t\t\t     198.51.100.0/24 }
\t}
\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\ttcp dport 22 accept
\t\tip saddr @cloudflare_v4 tcp dport { 80, 443 } accept
\t}
}
"""

UFW = """Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
Nginx Full                 ALLOW       Anywhere
"""


def test_iptables_open(cf_nets):
    found = firewall.analyse("iptables", firewall.parse_iptables_save(IPT_OPEN), cf_nets)
    assert "web-ports-open" in ids(found)


def test_iptables_cloudflare_only_with_docker(cf_nets):
    found = firewall.analyse("iptables", firewall.parse_iptables_save(IPT_CF), cf_nets)
    assert {"cf-only", "ip-allowlist-limit", "docker-bypass"} <= ids(found)
    assert "web-ports-open" not in ids(found)


def test_nft_set_with_extra_source(cf_nets):
    parsed = firewall.parse_nft(NFT)
    assert parsed["policy"] == "drop"
    found = firewall.analyse("nftables", parsed, cf_nets)
    extra = next(f for f in found if f.id == "non-cf-sources")
    assert extra.evidence["sources"] == ["198.51.100.0/24"]
    missing = next(f for f in found if f.id == "cf-ranges-missing")
    assert missing.evidence["missing"] == ["2400:cb00::/32"]


def test_ufw_app_profile_open(cf_nets):
    found = firewall.analyse("ufw", firewall.parse_ufw(UFW), cf_nets)
    assert "web-ports-open" in ids(found)


def test_ufw_inactive(cf_nets):
    found = firewall.analyse("ufw", firewall.parse_ufw("Status: inactive\n"), cf_nets)
    assert ids(found) == {"ufw-inactive"}


def test_port_ranges():
    assert firewall._ports_in("--dports 1:1024") == {"80", "443"}
    assert firewall._ports_in("tcp dport 8000-9000 accept") == set()
    assert firewall._ports_in("tcp dport https accept") == {"443"}


IPT_CF_ACCEPT = IPT_CF.replace(":INPUT DROP [0:0]", ":INPUT ACCEPT [0:0]")


def test_accept_policy_defeats_cloudflare_rules(cf_nets):
    found = firewall.analyse("iptables", firewall.parse_iptables_save(IPT_CF_ACCEPT), cf_nets)
    assert "web-ports-open-by-policy" in ids(found) and "cf-only" not in ids(found)


def test_accept_policy_with_explicit_drop_is_closed(cf_nets):
    text = IPT_CF_ACCEPT.replace("COMMIT\n", "", 1)  # keep nat table intact
    text = IPT_CF_ACCEPT.replace("-A INPUT -s 2400:cb00::/32 -p tcp -m tcp --dport 443 -j ACCEPT",
                                 "-A INPUT -s 2400:cb00::/32 -p tcp -m tcp --dport 443 -j ACCEPT\n"
                                 "-A INPUT -p tcp -m multiport --dports 80,443 -j DROP")
    found = firewall.analyse("iptables", firewall.parse_iptables_save(text), cf_nets)
    assert "web-ports-open-by-policy" not in ids(found) and "cf-only" in ids(found)


def test_unknown_policy_is_not_a_pass(cf_nets):
    text = IPT_CF.replace(":INPUT DROP [0:0]\n", "")
    found = firewall.analyse("iptables", firewall.parse_iptables_save(text), cf_nets)
    assert "policy-unknown" in ids(found) and "cf-only" not in ids(found)


def test_ufw_verbose_default_policy():
    text = "Status: active\nDefault: allow (incoming), allow (outgoing)\n\n443/tcp   ALLOW IN   173.245.48.0/20\n"
    parsed = firewall.parse_ufw(text)
    assert parsed["policy"] == "accept"
    found = firewall.analyse("ufw", parsed, [])
    assert "web-ports-open-by-policy" in ids(found)


def test_drop_on_one_port_does_not_close_the_other(cf_nets):
    text = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 173.245.48.0/20 -p tcp -m multiport --dports 80,443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 80 -j DROP
COMMIT
"""
    found = firewall.analyse("iptables", firewall.parse_iptables_save(text), cf_nets)
    assert "web-ports-open-by-policy" in ids(found) and "cf-only" not in ids(found)


def test_unrestricted_port_80_under_accept_is_open(cf_nets):
    text = """*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 173.245.48.0/20 -p tcp -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 443 -j DROP
COMMIT
"""
    found = firewall.analyse("iptables", firewall.parse_iptables_save(text), cf_nets)
    assert "web-ports-open-by-policy" in ids(found) and "cf-only" not in ids(found)


def test_udp_or_destination_drop_does_not_count(cf_nets):
    for rule in ("-A INPUT -p udp -m multiport --dports 80,443 -j DROP",
                 "-A INPUT -d 192.0.2.99 -p tcp -m multiport --dports 80,443 -j DROP"):
        text = f"""*filter
:INPUT ACCEPT [0:0]
-A INPUT -s 173.245.48.0/20 -p tcp -m multiport --dports 80,443 -j ACCEPT
{rule}
COMMIT
"""
        found = firewall.analyse("iptables", firewall.parse_iptables_save(text), cf_nets)
        assert "cf-only" not in ids(found), rule
