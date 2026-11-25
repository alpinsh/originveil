"""WordPress pingback: makes the origin open an outbound request, which shows its IP."""

from __future__ import annotations

from .. import net
from ..models import Finding

CHECK = "wordpress"
BODY = (
    b"<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName>"
    b"<params></params></methodCall>"
)
# Answers that mean the endpoint is not usable from outside.
CLOSED = {401, 403, 404, 405, 410, 444}


def check(domains: list[str], timeout: float = 10.0) -> tuple[list[Finding], bool]:
    """Only asks for system.listMethods. pingback.ping is never called, so no third
    party is contacted and nothing is written on the site.

    Returns (findings, complete). Rate limits, server errors and network failures do
    not count as "closed": the check is then reported as not concluded.
    """
    findings: list[Finding] = []
    complete = True
    for d in domains:
        try:
            status, _h, body = net.site_request(
                d, "/xmlrpc.php", method="POST", body=BODY,
                headers={"Content-Type": "text/xml"}, timeout=timeout,
            )
        except (net.UnsafeTarget, OSError, ValueError) as exc:
            complete = False
            findings.append(Finding(CHECK, "xmlrpc-unknown", "info",
                                    f"{d}: /xmlrpc.php could not be checked ({type(exc).__name__})",
                                    evidence={"host": d}))
            continue
        if status in CLOSED:
            findings.append(Finding(CHECK, "xmlrpc-closed", "pass",
                                    f"{d}: /xmlrpc.php refused (HTTP {status})", evidence={"host": d}))
        elif status == 429 or status >= 500 or 300 <= status < 400:
            complete = False
            findings.append(Finding(CHECK, "xmlrpc-unknown", "info",
                                    f"{d}: /xmlrpc.php gave HTTP {status}, result not conclusive",
                                    detail="Rate limiting, a server error or an off-site redirect hides whether XML-RPC is enabled.",
                                    evidence={"host": d, "status": status}))
        elif b"pingback.ping" in body:
            findings.append(Finding(
                CHECK, "pingback-enabled", "medium",
                f"{d}: XML-RPC pingback is enabled",
                detail="Anyone can ask WordPress to fetch a URL they control. The fetch comes from the origin, not Cloudflare, and logs its real IP.",
                fix="Block /xmlrpc.php at Cloudflare or in nginx, or remove the pingback methods with the xmlrpc_methods filter.",
                evidence={"host": d},
            ))
        elif b"<methodResponse" in body:
            findings.append(Finding(CHECK, "xmlrpc-open", "low", f"{d}: XML-RPC is reachable",
                                    fix="Block /xmlrpc.php unless an app needs it.", evidence={"host": d}))
        else:
            # A 200 HTML page (challenge, maintenance, custom error) says nothing about XML-RPC.
            complete = False
            findings.append(Finding(CHECK, "xmlrpc-unknown", "info",
                                    f"{d}: /xmlrpc.php answered {status} without an XML-RPC response",
                                    detail="Could be a bot challenge or a custom page in front of WordPress; not proof that XML-RPC is off.",
                                    evidence={"host": d, "status": status}))
    return findings, complete
