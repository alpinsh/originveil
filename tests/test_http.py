import http.server
import ssl
import threading

import pytest
from helpers import make_cert

from originveil import net
from originveil.checks import xmlrpc
from originveil.models import Report


def test_refuses_private_resolution(monkeypatch):
    monkeypatch.setattr(net, "resolve", lambda h: {"10.0.0.5"})
    with pytest.raises(net.UnsafeTarget):
        net.site_request("example.com")


def test_refuses_if_any_address_is_private(monkeypatch):
    monkeypatch.setattr(net, "resolve", lambda h: {"192.0.2.10", "169.254.169.254"})
    with pytest.raises(net.UnsafeTarget):
        net.site_request("example.com")


@pytest.fixture
def tls_site(tmp_path, monkeypatch):
    crt, key = make_cert(tmp_path, "/CN=example.com")
    seen = []

    class H(http.server.BaseHTTPRequestHandler):
        def _reply(self, code, body=b"", location=None):
            self.send_response(code)
            if location:
                self.send_header("Location", location)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            seen.append((self.command, self.headers["Host"].split(":")[0], self.path))
            port = self.server.server_address[1]
            if self.path == "/xmlrpc.php" and self.headers["Host"].startswith("example.com"):
                self._reply(301, location=f"https://www.example.com:{port}/xmlrpc.php")
            elif self.path == "/off":
                self._reply(302, location="https://evil.example.net/")
            else:
                self._reply(200, b"<methodResponse>pingback.ping</methodResponse>")

        def log_message(self, *a):
            pass

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(net, "resolve", lambda h: {"127.0.0.1"})
    monkeypatch.setattr(net, "routable_ip", lambda ip: True)  # loopback stands in for the site
    client = ssl.create_default_context()
    client.check_hostname = False
    client.verify_mode = ssl.CERT_NONE
    yield srv.server_address[1], client, seen
    srv.shutdown()


def test_same_site_redirect_keeps_post(tls_site):
    port, client, seen = tls_site
    status, _h, body = net.site_request("example.com", "/xmlrpc.php", method="POST", body=b"x",
                                        context=client, port=port)
    assert status == 200 and b"pingback.ping" in body
    assert seen == [("POST", "example.com", "/xmlrpc.php"), ("POST", "www.example.com", "/xmlrpc.php")]


def test_off_site_redirect_not_followed(tls_site):
    port, client, seen = tls_site
    status, headers, _b = net.site_request("example.com", "/off", method="POST", body=b"x",
                                           context=client, port=port)
    assert status == 302 and len(seen) == 1


def test_certificate_is_verified_by_default(tls_site):
    port, _client, _seen = tls_site
    with pytest.raises(ssl.SSLError):
        net.site_request("example.com", "/", port=port)  # self-signed: must fail


@pytest.mark.parametrize("status,complete,fid", [
    (404, True, "xmlrpc-closed"), (403, True, "xmlrpc-closed"),
    (429, False, "xmlrpc-unknown"), (503, False, "xmlrpc-unknown"), (302, False, "xmlrpc-unknown"),
])
def test_xmlrpc_status_classes(monkeypatch, status, complete, fid):
    monkeypatch.setattr(net, "site_request", lambda *a, **k: (status, {}, b""))
    found, done = xmlrpc.check(["example.com"])
    assert done is complete and found[0].id == fid


def test_xmlrpc_pingback(monkeypatch):
    monkeypatch.setattr(net, "site_request", lambda *a, **k: (200, {}, b"<methodResponse>pingback.ping"))
    found, done = xmlrpc.check(["example.com"])
    assert done and found[0].id == "pingback-enabled"


def test_unreported_check_is_unknown_not_pass():
    r = Report(tool_version="t", scope=["dns", "wordpress"])
    r.complete("wordpress")
    assert r.coverage() == {"dns": "unknown", "wordpress": "pass"}
    assert r.verdict() == "incomplete"


def test_xmlrpc_html_200_is_unknown(monkeypatch):
    monkeypatch.setattr(net, "site_request", lambda *a, **k: (200, {}, b"<html>Just a moment...</html>"))
    found, done = xmlrpc.check(["example.com"])
    assert done is False and found[0].id == "xmlrpc-unknown"


def test_redirect_to_other_port_not_followed(tls_site):
    port, client, seen = tls_site
    # first hop lands on the test port; a redirect that changes the port must stop there
    status, _h, _b = net.site_request("example.com", "/off", method="POST", body=b"x", context=client, port=port)
    assert status == 302
