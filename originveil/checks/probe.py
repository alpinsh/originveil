"""Raw reachability probe. Standalone on purpose: stdlib only, no package imports.

This file is piped over SSH to a vantage host (`python3 - ...`) so the
direct-to-origin test runs from a machine you control instead of a public
"check my site" service. It only observes; classification happens elsewhere.

usage: python3 probe.py ORIGIN_IP DOMAIN [DOMAIN...] [--timeout N]
"""

import json
import os
import re
import urllib.parse
import socket
import ssl
import sys
import tempfile

UA = "originveil-probe/0.1"
_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _connect(ip, port, timeout):
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        return sock, "open"
    except ConnectionRefusedError:
        return None, "refused"
    except socket.timeout:
        return None, "timeout"
    except OSError as exc:
        return None, f"error:{exc.__class__.__name__}"


def _http(sock, host, limit=65536, path="/"):
    req = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {UA}\r\n"
        "Accept: text/html\r\nConnection: close\r\n\r\n"
    ).encode()
    sock.sendall(req)
    data = b""
    while len(data) < limit:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data


def _parse(raw):
    out = {"status": None, "title": None, "server": None, "location": None, "no_client_cert": False}
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if lines and lines[0].startswith(b"HTTP/"):
        parts = lines[0].split()
        if len(parts) > 1 and parts[1].isdigit():
            out["status"] = int(parts[1])
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        k = k.strip().lower()
        if k == b"server":
            out["server"] = v.strip().decode(errors="replace")[:80]
        elif k == b"location":
            out["location"] = v.strip().decode(errors="replace")[:200]
    m = _TITLE_RE.search(body)
    if m:
        out["title"] = " ".join(m.group(1).decode(errors="replace").split())[:200]
    if b"No required SSL certificate was sent" in body or b"SSL certificate error" in body:
        out["no_client_cert"] = True
    return out


def _cert_names(der):
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
            path = fh.name
        try:
            info = ssl._ssl._test_decode_cert(path)
        finally:
            os.unlink(path)
        names = [v for k, v in info.get("subjectAltName", ()) if k == "DNS"]
        for rdn in info.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    names.append(v)
        return sorted(set(names))
    except Exception:
        return []


def probe_https(ip, host, timeout, port=443, sni=True, path="/"):
    res = {"tcp": None, "tls": None, "cert_names": []}
    sock, state = _connect(ip, port, timeout)
    res["tcp"] = state
    if not sock:
        return res
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        tls = ctx.wrap_socket(sock, server_hostname=host if sni else None)
    except ssl.SSLError as exc:
        sock.close()
        res["tls"] = _ssl_reason(exc)
        return res
    except OSError as exc:
        sock.close()
        res["tls"] = f"error:{exc.__class__.__name__}"
        return res
    try:
        der = tls.getpeercert(binary_form=True)
        if der:
            res["cert_names"] = _cert_names(der)
        res["tls"] = "ok"
        raw = _http(tls, host, path=path)
        if not raw:
            # typical when the server demands a client certificate under TLS 1.3
            res["tls"] = "closed_without_response"
        res.update(_parse(raw))
    except ssl.SSLError as exc:
        res["tls"] = _ssl_reason(exc)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        res["tls"] = "closed_without_response"
    except OSError as exc:
        res["tls"] = f"error:{exc.__class__.__name__}"
    finally:
        tls.close()
    return res


def _ssl_reason(exc):
    # The peer hung up mid-TLS. Depending on Python/OpenSSL this is SSLEOFError,
    # SSLZeroReturnError or a reset; servers that demand a client certificate do this.
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return "closed_without_response"
    text = str(exc).upper()
    if "CERTIFICATE_REQUIRED" in text or "CERTIFICATE REQUIRED" in text:
        return "client_cert_required"
    if "HANDSHAKE_FAILURE" in text:
        return "handshake_failure"
    if "UNRECOGNIZED_NAME" in text or "UNRECOGNIZED NAME" in text:
        return "rejected_sni"
    return "ssl_error:" + (getattr(exc, "reason", None) or exc.__class__.__name__)


def cert_names_only(ip, host, timeout, port=443):
    """TLS handshake with SNI, no HTTP request. Returns certificate names, or None."""
    sock, state = _connect(ip, port, timeout)
    if not sock:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            return _cert_names(der) if der else []
    except (ssl.SSLError, OSError):
        return None


def probe_http(ip, host, timeout, port=80, path="/"):
    res = {"tcp": None}
    sock, state = _connect(ip, port, timeout)
    res["tcp"] = state
    if not sock:
        return res
    try:
        res.update(_parse(_http(sock, host, path=path)))
    except OSError as exc:
        res["error"] = exc.__class__.__name__
    finally:
        sock.close()
    return res


def _follow(ip, domain, res, timeout, https_port, http_port):
    """Follow one redirect, but only to the same site and the same IP.

    A 301 from the origin to https://www.<domain>/ says little on its own; the
    page behind it says whether the origin really serves the site.
    """
    status, loc = res.get("status"), res.get("location")
    if not status or not 300 <= status < 400 or not loc:
        return None
    u = urllib.parse.urlsplit(loc)
    host = (u.hostname or domain).lower()
    if host not in (domain, "www." + domain) and not (domain.startswith("www.") and host == domain[4:]):
        return {"skipped": "redirect leaves the site"}
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    if u.scheme == "http":
        return probe_http(ip, host, timeout, http_port, path=path)
    return probe_https(ip, host, timeout, https_port, path=path)


def observe(ip, domains, timeout=6.0, https_port=443, http_port=80):
    out = {"ip": ip, "hosts": {}, "bare_ip": None}
    for d in domains:
        https = probe_https(ip, d, timeout, https_port)
        http = probe_http(ip, d, timeout, http_port)
        https["follow"] = _follow(ip, d, https, timeout, https_port, http_port)
        http["follow"] = _follow(ip, d, http, timeout, https_port, http_port)
        out["hosts"][d] = {"https": https, "http": http}
    out["bare_ip"] = probe_https(ip, ip, timeout, https_port, sni=False)
    return out


def main(argv):
    timeout = 6.0
    if "--timeout" in argv:
        i = argv.index("--timeout")
        timeout = float(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(observe(argv[0], argv[1:], timeout)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
