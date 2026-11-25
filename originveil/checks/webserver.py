"""Web server config: is the origin actually checking that requests come via Cloudflare?

Reads nginx config from disk (following include), so it usually works without
root. Certificates referenced by ssl_client_certificate are inspected to tell
the shared global Authenticated Origin Pulls CA from a zone-specific one.
"""

from __future__ import annotations

import glob
import os
import re
import ssl
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding

CHECK = "webserver"


@dataclass
class Node:
    name: str
    args: list[str]
    children: list["Node"] = field(default_factory=list)
    block: bool = False
    source: str = ""

    def find(self, name: str) -> list["Node"]:
        return [c for c in self.children if c.name == name]

    def first(self, name: str) -> "Node | None":
        found = self.find(name)
        return found[0] if found else None

    def walk(self):
        for c in self.children:
            yield c
            yield from c.walk()


_TOKEN_RE = re.compile(r"""\s*(?:("(?:\\.|[^"])*"|'(?:\\.|[^'])*')|([{};])|([^\s{};"']+))""")


def tokenize(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        out, quote = [], None
        for ch in line:
            if quote:
                out.append(ch)
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
                out.append(ch)
            elif ch == "#":
                break
            else:
                out.append(ch)
        lines.append("".join(out))
    text = "\n".join(lines)
    tokens, pos = [], 0
    while pos < len(text):
        m = _TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            pos += 1
            continue
        pos = m.end()
        tok = m.group(1) or m.group(2) or m.group(3)
        if tok:
            if m.group(1):
                tok = tok[1:-1]
            tokens.append(tok)
    return tokens


def _parse_tokens(tokens: list[str], i: int, parent: Node, base: Path, depth: int,
                 unreadable: list[str]) -> int:
    words: list[str] = []
    while i < len(tokens):
        tok = tokens[i]
        i += 1
        if tok == ";":
            if words:
                name, args = words[0], words[1:]
                if name == "include" and args:
                    if depth >= 20:
                        unreadable.append(f"{args[0]} (include depth limit)")
                    paths, problem = _expand_include(args[0], base) if depth < 20 else ([], None)
                    if problem:
                        unreadable.append(problem)
                    for path in paths:
                        try:
                            sub = tokenize(Path(path).read_text(errors="replace"))
                        except OSError as exc:
                            unreadable.append(f"{path} ({type(exc).__name__})")
                            continue
                        holder = Node("__include__", [path])
                        _parse_tokens(sub, 0, holder, base, depth + 1, unreadable)
                        for c in holder.children:
                            c.source = c.source or path
                        parent.children.extend(holder.children)
                else:
                    parent.children.append(Node(name, args, source=parent.source))
            words = []
        elif tok == "{":
            name, args = (words[0], words[1:]) if words else ("", [])
            node = Node(name, args, block=True, source=parent.source)
            i = _parse_tokens(tokens, i, node, base, depth, unreadable)
            parent.children.append(node)
            words = []
        elif tok == "}":
            return i
        else:
            words.append(tok)
    return i


def _expand_include(pattern: str, base: Path) -> tuple[list[str], str | None]:
    """Paths an include matches, plus a problem if the answer may be incomplete.

    An empty wildcard match is normal. A directory that cannot be listed, or a plain
    include that does not exist, is not: glob would silently return nothing."""
    p = pattern if os.path.isabs(pattern) else str(base / pattern)
    if glob.has_magic(p):
        d = os.path.dirname(p)
        while glob.has_magic(d):
            d = os.path.dirname(d)
        if os.path.isdir(d) and not os.access(d, os.R_OK | os.X_OK):
            return [], f"{d} (directory not listable)"
        # Wildcards in directory parts (tenants/*/conf.d/*.conf): every matched
        # intermediate directory must be listable too, or glob skips it silently.
        parent = os.path.dirname(p)
        if glob.has_magic(parent):
            for sub in glob.glob(parent):
                if os.path.isdir(sub) and not os.access(sub, os.R_OK | os.X_OK):
                    return sorted(glob.glob(p)), f"{sub} (directory not listable)"
        return sorted(glob.glob(p)), None
    if not os.path.lexists(p):
        return [], f"{p} (include not found)"
    return [p], None


def parse_nginx(conf_path: str) -> tuple[Node, list[str]]:
    """Parse with includes. Returns (tree, files that could not be read)."""
    path = Path(conf_path)
    root = Node("__root__", [], block=True, source=str(path))
    unreadable: list[str] = []
    _parse_tokens(tokenize(path.read_text(errors="replace")), 0, root, path.parent, 0, unreadable)
    return root, unreadable


def cert_subject(path: str) -> str:
    """Flattened subject of the first certificate in a PEM file, or ''."""
    try:
        decoded = ssl._ssl._test_decode_cert(path)  # stdlib, no extra deps
        parts = []
        for rdn in decoded.get("subject", ()):
            for k, v in rdn:
                parts.append(f"{k}={v}")
        return ", ".join(parts)
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-in", path],
            capture_output=True, text=True, timeout=5,
        ).stdout
        return out.strip().removeprefix("subject=").strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def ca_subjects(path: str) -> list[str]:
    """Subjects of every certificate in a PEM bundle. A bundle can mix the global
    Cloudflare CA with a custom one, so checking only the first is not enough."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return []
    blocks = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", text, re.S)
    if len(blocks) <= 1:
        s = cert_subject(path)
        return [s] if s else []
    out = []
    import tempfile
    for b in blocks:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
            fh.write(b + "\n")
            tmp = fh.name
        try:
            s = cert_subject(tmp)
        finally:
            os.unlink(tmp)
        if s:
            out.append(s)
    return out


def is_global_aop_ca(subject: str) -> bool:
    s = subject.lower()
    return "origin-pull.cloudflare.net" in s or ("cloudflare" in s and "origin pull" in s)


def _listens_tls(server: Node) -> bool:
    for listen in server.find("listen"):
        if "ssl" in listen.args or any(a.endswith(":443") or a == "443" for a in listen.args):
            return True
    return False


def _is_default(server: Node) -> bool:
    return any("default_server" in n.args or "default" in n.args for n in server.find("listen"))


def _listen_key(listen: Node) -> tuple[str, str] | None:
    """(address, port) of a listen line, as nginx groups sockets. None for unix sockets."""
    if not listen.args:
        return None
    spec = listen.args[0]
    if spec.startswith("unix:"):
        return None
    if spec.startswith("["):
        addr, _, port = spec.rpartition(":")
        addr = addr if port.isdigit() else spec
        port = port if port.isdigit() else "80"
    elif spec.isdigit():
        addr, port = "*", spec
    elif ":" in spec:
        addr, port = spec.rsplit(":", 1)
    else:
        addr, port = spec, "80"
    if addr in ("0.0.0.0", "*"):
        addr = "*"
    return addr, port


def _tls_listens(server: Node) -> list[Node]:
    out = []
    for listen in server.find("listen"):
        key = _listen_key(listen)
        if key and ("ssl" in listen.args or key[1] == "443"):
            out.append(listen)
    return out


def _inherited(server: Node, http: Node, name: str) -> Node | None:
    return server.first(name) or http.first(name)


def _server_level_reject(server: Node, codes: set[str]) -> bool:
    """A return with one of codes directly in the server block, not inside a location or if."""
    return any(n.name == "return" and n.args and n.args[0] in codes for n in server.children)


def _rejects_handshake(server: Node) -> bool:
    return any(n.name == "ssl_reject_handshake" and n.args[:1] == ["on"] for n in server.children)


_DENY_CODES = {"400", "401", "403", "404", "421", "444", "495", "496"}


_VERIFY_COND = re.compile(r"\(\s*\$ssl_client_verify\s*!=\s*([\"']?)SUCCESS\1\s*\)")


def _verify_state(server: Node) -> str:
    """'enforced', 'absent' or 'unclear' for ssl_verify_client optional.

    Enforced only for exactly `if ($ssl_client_verify != SUCCESS) { return 4xx; }` at
    server level. Any other condition that mentions the variable is not interpreted:
    it is reported as unclear, never as protection."""
    mentions = False
    for n in server.walk():
        if n.name == "if" and any("$ssl_client_verify" in a for a in n.args):
            mentions = True
    for n in server.children:
        if n.name != "if" or not n.block:
            continue
        if not _VERIFY_COND.fullmatch(" ".join(n.args)):
            continue
        # nginx stops at the first return: only that one counts.
        first = next((c for c in n.children if c.name == "return"), None)
        if first is not None and first.args and first.args[0] in _DENY_CODES:
            return "enforced"
    return "unclear" if mentions else "absent"


def check_nginx(conf_path: str) -> tuple[list[Finding], list[str]]:
    """Returns (findings, gaps). Any gap means the result cannot count as complete."""
    root, unreadable = parse_nginx(conf_path)
    findings: list[Finding] = []
    gaps = [f"nginx include not readable: {u}" for u in unreadable]
    http = root.first("http") or root
    servers = [n for n in http.walk() if n.name == "server" and n.block]
    tls_servers = [s for s in servers if _listens_tls(s)]
    if not tls_servers:
        gaps.append("no TLS server blocks found in the nginx config that was read")

    for s in tls_servers:
        names = [a for n in s.find("server_name") for a in n.args] or ["_"]
        label = names[0]
        if label in ("_", "") and _is_default(s) and (
            _server_level_reject(s, {"444"}) or _rejects_handshake(s)
        ):
            continue
        verify = _inherited(s, http, "ssl_verify_client")
        mode = verify.args[0] if verify and verify.args else "off"
        ev = {"server_name": label, "file": s.source}
        if mode == "off":
            findings.append(Finding(
                CHECK, "aop-off", "high",
                f"{label}: Authenticated Origin Pulls not enforced",
                detail="nginx accepts TLS from any client. If the origin IP is reached directly, the site answers without Cloudflare in front.",
                fix="Enable AOP in Cloudflare and add `ssl_client_certificate <ca.pem>; ssl_verify_client on;` to this server block.",
                evidence=ev,
            ))
            continue
        if mode == "optional_no_ca":
            findings.append(Finding(
                CHECK, "aop-no-ca-verify", "high",
                f"{label}: ssl_verify_client optional_no_ca does not verify the client certificate",
                detail="Any certificate, or none, is accepted. This is not Authenticated Origin Pulls.",
                fix="Use `ssl_verify_client on;` with your AOP CA.",
                evidence=ev,
            ))
            continue
        state = _verify_state(s) if mode == "optional" else "enforced"
        if state == "absent":
            findings.append(Finding(
                CHECK, "aop-optional", "high",
                f"{label}: ssl_verify_client is optional and not enforced",
                detail="Clients without a valid certificate still get the site.",
                fix="Use `ssl_verify_client on;` or put `if ($ssl_client_verify != SUCCESS) { return 403; }` directly in the server block.",
                evidence=ev,
            ))
            continue
        if state == "unclear":
            gaps.append(f"{label}: client-certificate check in a form originveil does not interpret")
            findings.append(Finding(
                CHECK, "aop-unverified", "info",
                f"{label}: ssl_verify_client optional with a check originveil cannot confirm",
                detail="The only form counted as enforcement is a server-level "
                       "`if ($ssl_client_verify != SUCCESS) { return 403; }`. Anything else is not credited.",
                fix="Prefer `ssl_verify_client on;`.",
                evidence=ev,
            ))
            continue
        if mode not in ("on", "optional"):
            gaps.append(f"{label}: unrecognised ssl_verify_client value")
            continue
        ca = _inherited(s, http, "ssl_client_certificate") or _inherited(s, http, "ssl_trusted_certificate")
        trusted = _inherited(s, http, "ssl_trusted_certificate")
        if not ca or not ca.args:
            findings.append(Finding(
                CHECK, "aop-no-ca", "medium",
                f"{label}: client verification on but no CA file found",
                evidence=ev,
            ))
            continue
        subjects = ca_subjects(ca.args[0])
        if trusted and trusted.args and trusted is not ca:
            subjects += ca_subjects(trusted.args[0])  # both can be trusted for client verification
        ev = {**ev, "ca_file": ca.args[0], "ca_subjects": subjects}
        if not subjects:
            gaps.append(f"{label}: client CA certificate could not be read")
            findings.append(Finding(
                CHECK, "aop-ca-unreadable", "info",
                f"{label}: could not read the client CA certificate",
                detail="Run as a user that can read the CA file to classify it.",
                evidence=ev,
            ))
        elif any(is_global_aop_ca(x) for x in subjects):
            findings.append(Finding(
                CHECK, "aop-global-cert", "high",
                f"{label}: trusts Cloudflare's shared global AOP certificate",
                detail="The global AOP certificate is the same for every Cloudflare customer. Someone who learns the origin IP can add it to their own Cloudflare account, switch off WAF there, and still pass this check.",
                fix="Upload your own client certificate for zone-level or per-hostname AOP in Cloudflare and trust only its CA in ssl_client_certificate.",
                evidence=ev,
            ))
        else:
            findings.append(Finding(
                CHECK, "aop-custom-cert", "pass",
                f"{label}: client certificate required, custom CA (from config, not tested live)",
                evidence=ev,
            ))

    # Spoofable client IP.
    for n in [http, *http.walk()]:
        if n.name == "set_real_ip_from" and n.args and n.args[0] in ("0.0.0.0/0", "::/0", "all"):
            findings.append(Finding(
                CHECK, "real-ip-trust-all", "high",
                "set_real_ip_from trusts every address",
                detail="Any client can forge CF-Connecting-IP / X-Forwarded-For and pick the IP your logs, rate limits and bans see.",
                fix="List only Cloudflare ranges in set_real_ip_from.",
                evidence={"file": n.source, "value": n.args[0]},
            ))
            break

    # Default server for unknown Host / SNI, per TLS listening socket (address, port).
    keys: set[tuple[str, str]] = set()
    covered: set[tuple[str, str]] = set()
    http_only: set[tuple[str, str]] = set()
    for s in tls_servers:
        handshake = _rejects_handshake(s)
        http_reject = _server_level_reject(s, {"444", "400", "403", "421"})
        for listen in _tls_listens(s):
            key = _listen_key(listen)
            keys.add(key)
            if "default_server" in listen.args or "default" in listen.args:
                if handshake:
                    covered.add(key)
                elif http_reject:
                    http_only.add(key)
    for key in sorted(http_only - covered):
        findings.append(Finding(
            CHECK, "catchall-presents-cert", "low",
            f"TLS catch-all on {key[0]}:{key[1]} rejects with HTTP, after presenting a certificate",
            detail="A `return 444` happens after the TLS handshake, so the bare IP still hands out a certificate.",
            fix="Use `ssl_reject_handshake on;` in the default server.",
            evidence={"listener": f"{key[0]}:{key[1]}"},
        ))
    missing = sorted(keys - covered - http_only)
    if missing:
        findings.append(Finding(
            CHECK, "no-catchall", "medium",
            "TLS listener(s) without a catch-all server that rejects unknown hosts",
            detail="On these sockets a TLS request to the bare IP or an unknown SNI falls through to a real vhost. Scanners that hit the IP get your certificate, which links the IP to your domain.",
            fix="For each listed address:port add: server { listen <addr:port> ssl default_server; ssl_reject_handshake on; }",
            evidence={"listeners": [f"{a}:{p}" for a, p in missing]},
        ))
    return findings, gaps


_VHOST_RE = re.compile(r"<VirtualHost([^>]*)>(.*?)</VirtualHost>", re.I | re.S)


def _apache_verify(text: str) -> str | None:
    """Last SSLVerifyClient value in text (Apache: the last one wins)."""
    found = re.findall(r"^\s*SSLVerifyClient\s+(\S+)", text, re.I | re.M)
    return found[-1].lower() if found else None


def check_apache(apache_dir: str) -> tuple[list[Finding], list[str]]:
    """Each TLS VirtualHost is judged on its own setting, falling back to the global one."""
    findings: list[Finding] = []
    gaps: list[str] = []
    files = sorted(glob.glob(os.path.join(apache_dir, "sites-enabled", "*")) + glob.glob(
        os.path.join(apache_dir, "conf-enabled", "*")
    ) + glob.glob(os.path.join(apache_dir, "conf.d", "*.conf")))
    text = ""
    for f in files:
        try:
            text += Path(f).read_text(errors="replace") + "\n"
        except OSError as exc:
            gaps.append(f"apache file not readable: {f} ({type(exc).__name__})")
    if not text:
        return findings, gaps
    global_text = _VHOST_RE.sub("", text)
    # Directives inside <Location>/<Directory> do not protect the whole vhost.
    scoped = re.compile(r"<(Location|LocationMatch|Directory|DirectoryMatch|Files|FilesMatch|If)\b.*?</\1>", re.I | re.S)
    # Conditional sections may or may not be active; their directives are never credited.
    conditional = re.compile(r"<(IfModule|IfDefine|IfVersion|IfFile|IfDirective|IfSection|ElseIf|Else)\b[^>]*>(.*?)</\1>", re.I | re.S)

    cond_open = re.compile(r"<(IfModule|IfDefine|IfVersion|IfFile|IfDirective|IfSection|ElseIf|Else)\b", re.I)
    cond_close = re.compile(r"</(IfModule|IfDefine|IfVersion|IfFile|IfDirective|IfSection|ElseIf|Else)\s*>", re.I)

    def effective(block: str, where: str) -> str | None:
        for cm in conditional.finditer(block):
            if re.search(r"^\s*SSLVerifyClient\b", cm.group(2), re.I | re.M):
                gaps.append(f"{where}: SSLVerifyClient inside <{cm.group(1)}>; whether it applies is unknown")
        rest = conditional.sub("", block)
        if cond_open.search(rest) or cond_close.search(rest):
            # Nested sections the simple pass could not peel; credit nothing from this block.
            if re.search(r"^\s*SSLVerifyClient\b", rest, re.I | re.M):
                gaps.append(f"{where}: nested conditional sections around SSLVerifyClient; not interpreted")
            return None
        return _apache_verify(scoped.sub("", rest))

    global_mode = effective(global_text, "global config")
    for m in _VHOST_RE.finditer(text):
        addr, body = m.group(1), m.group(2)
        if ":443" not in addr and not re.search(r"^\s*SSLEngine\s+on", body, re.I | re.M):
            continue
        name = re.search(r"^\s*ServerName\s+(\S+)", body, re.I | re.M)
        label = name.group(1) if name else addr.strip()
        mode = effective(body, f"vhost {label}") or global_mode
        if mode != "require":
            findings.append(Finding(
                CHECK, "aop-off", "high",
                f"Apache {label}: Authenticated Origin Pulls not enforced",
                detail="SSLVerifyClient is not `require` for this vhost (directives inside Location/Directory blocks are not counted).",
                fix="Add `SSLVerifyClient require` and `SSLCACertificateFile <ca.pem>` to this VirtualHost.",
                evidence={"vhost": label, "mode": mode or "none"},
            ))
    return findings, gaps
