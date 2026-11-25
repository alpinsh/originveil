import http.server
import socket
import ssl
import threading

from helpers import make_cert

from originveil.checks import probe, reach


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Page(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>Example News</title></html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def serve(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server


def test_http_direct_and_closed_https():
    port = free_port()
    srv = serve(http.server.HTTPServer(("127.0.0.1", port), Page))
    try:
        res = probe.probe_http("127.0.0.1", "example.com", 3, port)
        assert res["status"] == 200 and res["title"] == "Example News"
        https = probe.probe_https("127.0.0.1", "example.com", 2, free_port())
        assert https["tcp"] == "refused"
    finally:
        srv.shutdown()

    obs = {"ip": "192.0.2.10", "hosts": {"example.com": {"https": https, "http": res}}, "bare_ip": {}}
    found = {f.id: f for f in reach.classify(obs, {"example.com": "Example News"})}
    assert found["http-direct"].severity == "critical"
    assert found["https-closed"].severity == "pass"


def test_tls_server_requiring_client_cert(tmp_path):
    crt, key = make_cert(tmp_path, "/CN=example.com")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(crt)
    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Page)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    serve(srv)
    try:
        res = probe.probe_https("127.0.0.1", "example.com", 3, port)
    finally:
        srv.shutdown()
    assert res["tcp"] == "open"
    assert res["tls"] in ("client_cert_required", "handshake_failure", "closed_without_response")
    obs = {"ip": "192.0.2.10", "hosts": {"example.com": {"https": res, "http": {"tcp": "refused"}}}}
    found = {f.id: f for f in reach.classify(obs, {})}
    assert "http-closed" in found
    assert {"https-aop-rejects", "https-no-response"} & set(found)
    assert all(f.severity in ("pass", "low") for f in found.values())


def test_tls_server_serving_site(tmp_path):
    crt, key = make_cert(tmp_path, "/CN=example.com")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    port = free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Page)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    serve(srv)
    try:
        res = probe.probe_https("127.0.0.1", "example.com", 3, port)
        bare = probe.probe_https("127.0.0.1", "127.0.0.1", 3, port, sni=False)
    finally:
        srv.shutdown()
    assert res["status"] == 200 and "example.com" in res["cert_names"]
    obs = {"ip": "192.0.2.10", "hosts": {"example.com": {"https": res, "http": {"tcp": "refused"}}}, "bare_ip": bare}
    found = {f.id: f for f in reach.classify(obs, {"example.com": "example news"})}
    assert found["https-direct"].severity == "critical"
    assert found["bare-ip-serves"].evidence["cert_names"] == ["example.com"]


def test_parse_vantage():
    assert reach.parse_vantage("ssh://audit@203.0.113.5:2222")[-3:] == ["-p", "2222", "audit@203.0.113.5"]
    assert reach.parse_vantage("audit@host")[-1] == "audit@host"


def test_no_vantage_is_skipped_not_passed():
    found, reason = reach.check(["192.0.2.10"], ["example.com"], None)
    assert found == [] and "no vantage" in reason


def test_redirect_is_followed_on_same_ip():
    final = {"tcp": "open", "tls": "ok", "status": 200, "title": "Example News"}
    https = {"tcp": "open", "tls": "ok", "status": 301, "location": "https://www.example.com/", "follow": final}
    obs = {"ip": "192.0.2.10", "hosts": {"example.com": {"https": https, "http": {"tcp": "refused"}}}}
    f = next(x for x in reach.classify(obs, {"example.com": "Example News"}) if x.id == "https-direct")
    assert f.severity == "critical" and f.evidence["final_status"] == 200


def test_follow_refuses_other_sites():
    res = {"status": 302, "location": "https://evil.example.net/"}
    assert probe._follow("127.0.0.1", "example.com", res, 1, 1, 1) == {"skipped": "redirect leaves the site"}


def test_cert_and_200_confirm_without_title():
    final = {"tcp": "open", "tls": "ok", "status": 200, "title": "Real Site"}
    https = {"tcp": "open", "tls": "ok", "status": 301, "location": "https://www.example.com/",
             "follow": final, "cert_names": ["example.com", "www.example.com"]}
    obs = {"ip": "192.0.2.10", "hosts": {"example.com": {"https": https, "http": {"tcp": "refused"}}}}
    f = next(x for x in reach.classify(obs, {"example.com": "Just a moment..."}) if x.id == "https-direct")
    assert f.severity == "critical"


def test_eof_variants_mean_closed_without_response():
    import ssl
    assert probe._ssl_reason(ssl.SSLEOFError()) == "closed_without_response"
    assert probe._ssl_reason(ssl.SSLZeroReturnError()) == "closed_without_response"
    assert probe._ssl_reason(ssl.SSLError(1, "[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED]")) == "client_cert_required"
