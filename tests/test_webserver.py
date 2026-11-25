import os

from helpers import make_cert

from originveil.checks import webserver


def write(tmp_path, body, extra=None):
    (tmp_path / "sites").mkdir(exist_ok=True)
    for name, text in (extra or {}).items():
        (tmp_path / "sites" / name).write_text(text)
    conf = tmp_path / "nginx.conf"
    conf.write_text("events {}\nhttp {\n" + body + "\n include sites/*.conf;\n}\n")
    return str(conf)


def run(conf):
    findings, gaps = webserver.check_nginx(conf)
    return findings, gaps


def ids(findings):
    return {f.id for f in findings}


CATCHALL = "server { listen 443 ssl default_server; server_name _; ssl_reject_handshake on; }"


def test_aop_off_and_no_catchall(tmp_path):
    conf = write(tmp_path, "", {"a.conf": "server { listen 443 ssl; server_name example.com; }"})
    found, gaps = run(conf)
    assert {"aop-off", "no-catchall"} <= ids(found) and not gaps
    assert next(f for f in found if f.id == "aop-off").evidence["file"].endswith("a.conf")


def test_global_aop_cert_detected(tmp_path):
    ca, _ = make_cert(tmp_path, "/C=US/O=CloudFlare, Inc./OU=Origin Pull/CN=origin-pull.cloudflare.net")
    conf = write(tmp_path, f"ssl_client_certificate {ca};\nssl_verify_client on;", {
        "a.conf": "server { listen 443 ssl; server_name example.com; }",
        "default.conf": CATCHALL,
    })
    found, _ = run(conf)
    assert "aop-global-cert" in ids(found)
    assert not {"no-catchall", "aop-off"} & ids(found)


def test_bundle_with_global_cert_second_is_caught(tmp_path):
    own, _ = make_cert(tmp_path, "/O=Example/CN=own-ca", name="own")
    glob_ca, _ = make_cert(tmp_path, "/O=CloudFlare, Inc./OU=Origin Pull/CN=origin-pull.cloudflare.net", name="g")
    bundle = tmp_path / "bundle.pem"
    bundle.write_text(own.read_text() + glob_ca.read_text())
    conf = write(tmp_path, "", {"a.conf": (
        f"server {{ listen 443 ssl; server_name example.com; ssl_client_certificate {bundle}; ssl_verify_client on; }}"
    ), "d.conf": CATCHALL})
    assert "aop-global-cert" in ids(run(conf)[0])


def test_custom_cert_passes(tmp_path):
    ca, _ = make_cert(tmp_path, "/O=Example/CN=example-aop-ca")
    conf = write(tmp_path, "", {"a.conf": (
        "server { listen 443 ssl; server_name example.com;"
        f" ssl_client_certificate {ca}; ssl_verify_client on; }}"
    ), "d.conf": CATCHALL})
    found, gaps = run(conf)
    assert "aop-custom-cert" in ids(found) and not gaps


def _optional(tmp_path, inner):
    ca, _ = make_cert(tmp_path, "/CN=x")
    return write(tmp_path, "", {"a.conf": (
        "server { listen 443 ssl; server_name example.com;"
        f" ssl_client_certificate {ca}; ssl_verify_client optional; {inner} }}"
    ), "d.conf": CATCHALL})


def test_optional_without_if(tmp_path):
    assert "aop-optional" in ids(run(_optional(tmp_path, ""))[0])


def test_optional_with_server_level_reject(tmp_path):
    conf = _optional(tmp_path, "if ($ssl_client_verify != SUCCESS) { return 403; }")
    found = ids(run(conf)[0])
    assert "aop-optional" not in found and "aop-custom-cert" in found


def _not_credited(conf):
    found, gaps = run(conf)
    assert "aop-custom-cert" not in ids(found)
    assert "aop-unverified" in ids(found) and gaps


def test_optional_if_that_does_not_reject(tmp_path):
    _not_credited(_optional(tmp_path, "if ($ssl_client_verify = SUCCESS) { return 200; }"))


def test_optional_if_only_in_a_location(tmp_path):
    _not_credited(_optional(tmp_path, "location /admin { if ($ssl_client_verify != SUCCESS) { return 403; } }"))


def test_optional_condition_with_extra_text_not_credited(tmp_path):
    _not_credited(_optional(tmp_path, 'if ($ssl_client_verify != SUCCESS$http_x) { return 403; }'))


def test_optional_quoted_success_is_credited(tmp_path):
    conf = _optional(tmp_path, 'if ($ssl_client_verify != "SUCCESS") { return 403; }')
    assert "aop-custom-cert" in ids(run(conf)[0])


def test_optional_no_ca_is_not_aop(tmp_path):
    conf = write(tmp_path, "", {"a.conf": (
        "server { listen 443 ssl; server_name example.com; ssl_verify_client optional_no_ca; }"
    ), "d.conf": CATCHALL})
    assert "aop-no-ca-verify" in ids(run(conf)[0])


def test_http_catchall_does_not_cover_tls(tmp_path):
    ca, _ = make_cert(tmp_path, "/CN=x")
    conf = write(tmp_path, "", {
        "a.conf": f"server {{ listen 443 ssl; server_name example.com; ssl_client_certificate {ca}; ssl_verify_client on; }}",
        "d.conf": "server { listen 80 default_server; return 444; }",
    })
    assert "no-catchall" in ids(run(conf)[0])


def test_location_return_is_not_a_catchall(tmp_path):
    conf = write(tmp_path, "", {
        "a.conf": "server { listen 443 ssl default_server; server_name example.com; location /x { return 403; } }",
    })
    assert "no-catchall" in ids(run(conf)[0])


def test_unreadable_include_is_a_gap(tmp_path):
    conf = write(tmp_path, "", {"a.conf": "server { listen 443 ssl; server_name example.com; }"})
    secret = tmp_path / "sites" / "b.conf"
    secret.write_text("server { listen 443 ssl; server_name hidden.example.com; }")
    os.chmod(secret, 0)
    try:
        if os.geteuid() == 0:  # root reads anything; simulate with a dangling include instead
            os.chmod(secret, 0o644)
            secret.unlink()
            secret.symlink_to(tmp_path / "missing.conf")
        _found, gaps = run(conf)
    finally:
        if secret.exists():
            os.chmod(secret, 0o644)
    assert any("not readable" in g for g in gaps)


def test_no_tls_servers_is_a_gap(tmp_path):
    conf = write(tmp_path, "", {"a.conf": "server { listen 80; server_name example.com; }"})
    found, gaps = run(conf)
    assert found == [] and gaps


def test_real_ip_trust_all(tmp_path):
    conf = write(tmp_path, "set_real_ip_from 0.0.0.0/0;\nreal_ip_header CF-Connecting-IP;")
    assert "real-ip-trust-all" in ids(run(conf)[0])


def test_comments_and_quotes(tmp_path):
    conf = write(tmp_path, "", {"a.conf": (
        "server { # listen 443 ssl;\n listen 80; server_name \"example.com\"; # ssl_verify_client off;\n}"
    )})
    found, _gaps = run(conf)
    assert found == []


def test_cert_subject(tmp_path):
    ca, _ = make_cert(tmp_path, "/O=CloudFlare, Inc./OU=Origin Pull/CN=origin-pull.cloudflare.net")
    assert webserver.is_global_aop_ca(webserver.cert_subject(str(ca)))


def _apache(tmp_path, text):
    d = tmp_path / "apache"
    (d / "sites-enabled").mkdir(parents=True)
    (d / "sites-enabled" / "s.conf").write_text(text)
    return webserver.check_apache(str(d))


def test_apache_mixed_vhosts(tmp_path):
    found, _ = _apache(tmp_path, """
<VirtualHost *:443>
  ServerName a.example.com
  SSLVerifyClient require
</VirtualHost>
<VirtualHost *:443>
  ServerName b.example.com
  SSLVerifyClient none
</VirtualHost>
""")
    assert [f.evidence["vhost"] for f in found] == ["b.example.com"]


def test_apache_require_in_location_does_not_count(tmp_path):
    found, _ = _apache(tmp_path, """
<VirtualHost *:443>
  ServerName a.example.com
  <Location /admin>
    SSLVerifyClient require
  </Location>
</VirtualHost>
""")
    assert len(found) == 1


def test_apache_global_require_inherited(tmp_path):
    found, _ = _apache(tmp_path, """
SSLVerifyClient require
<VirtualHost *:443>
  ServerName a.example.com
</VirtualHost>
""")
    assert found == []


def test_missing_plain_include_is_a_gap(tmp_path):
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"http {{ include {tmp_path}/nope.conf; server {{ listen 443 ssl; server_name example.com; }} }}")
    _found, gaps = webserver.check_nginx(str(conf))
    assert any("not found" in g for g in gaps)


def test_catchall_is_per_listener(tmp_path):
    ca, _ = make_cert(tmp_path, "/CN=x")
    conf = write(tmp_path, "", {
        "a.conf": (f"server {{ listen 443 ssl; listen [::]:443 ssl; server_name example.com; "
                   f"ssl_client_certificate {ca}; ssl_verify_client on; }}"),
        "d.conf": "server { listen 443 ssl default_server; server_name _; ssl_reject_handshake on; }",
    })
    f = next(x for x in run(conf)[0] if x.id == "no-catchall")
    assert f.evidence["listeners"] == ["[::]:443"]


def test_http_default_flag_does_not_count_for_tls(tmp_path):
    conf = write(tmp_path, "", {
        "a.conf": ("server { listen 80 default_server; listen 443 ssl; server_name _; "
                   "ssl_reject_handshake on; }"),
    })
    assert "no-catchall" in ids(run(conf)[0])


def test_apache_require_in_ifmodule_not_credited(tmp_path):
    found, gaps = _apache(tmp_path, """
<IfModule mod_nonexistent.c>
  SSLVerifyClient require
</IfModule>
<VirtualHost *:443>
  ServerName a.example.com
</VirtualHost>
""")
    assert [f.id for f in found] == ["aop-off"] and any("IfModule" in g for g in gaps)


def test_apache_debian_style_ifmodule_wrapper(tmp_path):
    found, gaps = _apache(tmp_path, """
<IfModule mod_ssl.c>
<VirtualHost _default_:443>
  ServerName a.example.com
  SSLVerifyClient require
</VirtualHost>
</IfModule>
""")
    assert found == [] and gaps == []


def test_unreachable_deny_after_allow_not_credited(tmp_path):
    _not_credited(_optional(tmp_path, 'if ($ssl_client_verify != SUCCESS) { return 200 "public"; return 403; }'))


def test_http_return_catchall_still_presents_cert(tmp_path):
    ca, _ = make_cert(tmp_path, "/CN=x")
    conf = write(tmp_path, "", {
        "a.conf": f"server {{ listen 443 ssl; server_name example.com; ssl_client_certificate {ca}; ssl_verify_client on; }}",
        "d.conf": "server { listen 443 ssl default_server; server_name _; return 444; }",
    })
    found = ids(run(conf)[0])
    assert "catchall-presents-cert" in found and "no-catchall" not in found


def test_global_ca_in_trusted_certificate_is_caught(tmp_path):
    own, _ = make_cert(tmp_path, "/O=Example/CN=own-ca", name="own")
    g, _ = make_cert(tmp_path, "/O=CloudFlare, Inc./OU=Origin Pull/CN=origin-pull.cloudflare.net", name="g")
    conf = write(tmp_path, "", {"a.conf": (
        f"server {{ listen 443 ssl; server_name example.com; ssl_client_certificate {own}; "
        f"ssl_trusted_certificate {g}; ssl_verify_client on; }}"
    ), "d.conf": CATCHALL})
    assert "aop-global-cert" in ids(run(conf)[0])


def test_apache_nested_same_name_conditionals(tmp_path):
    found, gaps = _apache(tmp_path, """
<IfModule mod_a.c>
  <IfModule mod_b.c>
    Foo bar
  </IfModule>
  SSLVerifyClient require
</IfModule>
<VirtualHost *:443>
  ServerName a.example.com
</VirtualHost>
""")
    assert [f.id for f in found] == ["aop-off"] and gaps
