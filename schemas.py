AUDIT = {
    "name": "originveil_audit",
    "description": (
        "Check whether the origin server behind Cloudflare can be found or reached directly. "
        "Without origin_ip it discovers the origin like an attacker would and confirms it. Checks: "
        "DNS records that leak the origin IP, SPF/MX on the origin, direct HTTPS/HTTP from the "
        "configured vantage host, and WordPress pingback. Runs only against domains in the "
        "originveil config. Output is redacted: IPs, domains and paths are tokens like <ip:1>. "
        "Also attaches the last privileged local report (firewall, nginx/AOP) if the timer is installed."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "domains": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Subset of configured domains to check. Omit to check all configured domains.",
            },
            "origin_ip": {
                "type": "array",
                "items": {"type": "string"},
                "description": (
                    "Optional origin IP(s) if the user explicitly gave them. Disabled unless the admin "
                    "enabled allow_chat_origin_ip; if refused, do not retry. Omit to let the tool "
                    "discover the origin from public records and confirm it from the vantage host. "
                    "Never guess or look up an IP to fill this."
                ),
            },
            "include_wordpress": {
                "type": "boolean",
                "description": "Also check /xmlrpc.php pingback. Default true.",
            },
        },
        "required": [],
    },
}

LAST_REPORT = {
    "name": "originveil_last_report",
    "description": (
        "Read the last redacted report written by the originveil root timer "
        "(firewall, nginx/Authenticated Origin Pulls, DNS). Read-only, no network."
    ),
    "parameters": {"type": "object", "properties": {}, "required": []},
}


_DOMAIN_ARG = {
    "type": "object",
    "properties": {"domain": {"type": "string", "description": "Domain name, e.g. example.com"}},
    "required": ["domain"],
}

ADD_DOMAIN = {
    "name": "originveil_add_domain",
    "description": (
        "Start adding a domain to the audit allowlist. Returns a DNS TXT record the user must create to "
        "prove they control the domain. Only call this when the user asks to add their own domain."
    ),
    "parameters": _DOMAIN_ARG,
}

VERIFY_DOMAIN = {
    "name": "originveil_verify_domain",
    "description": (
        "Check the TXT record from originveil_add_domain (or Cloudflare API access to the zone) and, if it is "
        "there, add the domain to the allowlist. Call after the user says they created the record."
    ),
    "parameters": _DOMAIN_ARG,
}

LIST_DOMAINS = {
    "name": "originveil_list_domains",
    "description": "List domains that can be audited: from the config file, verified in chat, and pending.",
    "parameters": {"type": "object", "properties": {}, "required": []},
}

REMOVE_DOMAIN = {
    "name": "originveil_remove_domain",
    "description": "Remove a chat-verified domain from the audit allowlist.",
    "parameters": _DOMAIN_ARG,
}
