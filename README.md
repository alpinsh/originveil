# originveil

Is your origin still hidden behind Cloudflare, and if someone finds it, does it matter?

Tools in this space look from the outside, the way an attacker would (CloudFail,
cdn-proxy, recon scripts). originveil runs on your side. It can read your nginx and
firewall config, look for the origin the way an attacker would, and test whether the
origin answers without Cloudflare in front. Each finding comes with a fix.

It covers the common leak and bypass paths listed below. It is a set of checks and
heuristics, not a proof that the origin is safe; the report says which checks ran
fully and which did not.

No Python packages beyond the 3.11 standard library. Some checks use system tools:
`dig` for MX/SPF, `ssh` and a remote `python3` for a remote vantage, `ip` to find local
addresses, `ufw`/`nft`/`iptables-save` for the firewall and `openssl` as a fallback for
certificates. When a tool is missing the affected check is reported as partial.
Ships as a CLI and as a [Hermes Agent](https://github.com/NousResearch/hermes-agent) plugin.

## How it knows the origin

You do not have to tell it. By default originveil does what an attacker does: it
collects candidate IPs from public DNS names, MX, SPF and (with a token) the
Cloudflare API, connects to each one from your vantage host, and treats a candidate
as the origin only if it serves the same page or a certificate for your domain. This
is a strong signal, not cryptographic proof. If it can find your origin this way, so
can anyone, and that is reported as critical. A proxied record read through the
Cloudflare API is also treated as the origin, and the report says when no direct
connection confirmed it.

You can also pass the IP (`--origin-ip 192.0.2.10`), or use `--origin-ip local` when
running on the origin itself. Finding nothing is not proof that the IP is unknown:
historical DNS and internet scan databases are not checked.

## What it checks

| Check | Needs | Looks for |
|---|---|---|
| `discover` | network, vantage host to confirm | origin candidates in public DNS, MX, SPF and the Cloudflare API, confirmed by direct connection |
| `dns` | network, optional CF token | DNS-only records pointing at the origin, MX hosts and SPF `ip4:`/`ip6:` on the origin IP, common names (`mail`, `ftp`, `cpanel`, `dev`, ...) that resolve straight to it |
| `webserver` | read access to nginx/Apache config | Authenticated Origin Pulls off, `optional` without a server-level reject, `optional_no_ca`, the shared global AOP certificate anywhere in the CA bundle, `set_real_ip_from 0.0.0.0/0`, no TLS catch-all for unknown SNI. Apache: `SSLVerifyClient require` per TLS vhost |
| `firewall` | root | 80/443 open to the world, Cloudflare-only rules undone by an accepting default policy, non-Cloudflare sources, stale Cloudflare ranges, Docker-published ports that skip ufw |
| `reach` | a vantage host you control | whether the origin serves the site when connected to directly, whether the bare IP hands out your certificate |
| `wordpress` | network | XML-RPC pingback, which makes the origin fetch a URL and reveal its IP. Rate limits, errors and HTML challenge pages are reported as not concluded |

Two things people often miss, and that originveil reports explicitly:

- A Cloudflare IP allowlist does not stop traffic routed through someone else's
  Cloudflare account. Edge IPs are shared.
- The global AOP certificate is the same for every Cloudflare customer. AOP "on" with
  that certificate has the same gap. Use your own certificate (zone-level or
  per-hostname) or Cloudflare Tunnel.

## Install

```
git clone https://github.com/alpinsh/originveil
cd originveil
pip install .
```

or run it in place with `python3 -m originveil`.

## Use

```
originveil audit -d example.com --vantage ssh://audit@203.0.113.5:22 -v
originveil audit -d example.com --origin-ip 192.0.2.10 --vantage local
sudo originveil audit -d example.com --origin-ip local --only webserver,firewall
originveil audit --json --redact > report.json
```

Every report has a `verdict` and a result per check:

- `fail`: there is something to fix
- `incomplete`: nothing wrong in what ran, but some checks were skipped, partial or
  errored, or the real origin was never confirmed
- `pass`: every check ran fully and found nothing

The score (100 minus penalties) only covers the checks that ran. Read it together
with the verdict; a 100 with `incomplete` is not a clean bill of health.

Exit codes: 1 when there is a high or critical finding, 2 on errors (including an
unknown name in `--only`), otherwise 0. An `incomplete` verdict exits 0, so automation
that needs full coverage should read `verdict` from `--json` output.

Config lives in `$ORIGINVEIL_CONFIG`, `/etc/originveil/config.toml` or
`~/.config/originveil/config.toml`, first match wins.
Start from [examples/config.toml](examples/config.toml).

The Cloudflare token is optional and should only have Zone:Read and DNS:Read
(originveil cannot enforce that; scope it when you create it). Pass it in
`CF_API_TOKEN` or a `token_file`; a token file readable by group or others is refused.
Without a token, only public DNS is checked.

### The direct test needs a vantage host

You cannot test "is the origin reachable from the internet" from the origin itself.
originveil does not use public "check host" services, because that would hand your
origin IP to a third party. Point `vantage` at any machine you control with SSH and
python3. The probe script is piped over SSH and nothing is installed there. Without a
vantage host the check is listed as not checked, never as passed.

### Root timer

Run this on the origin server. The firewall and web server checks describe the machine
they run on, so a timer on your monitoring host would audit the wrong box.

```
sudo originveil install-timer --calendar weekly
```

Running from a clone without `pip install`, use `sudo python3 -m originveil install-timer`.

This writes a hardened systemd service and timer. Each run writes two files to
`/var/lib/originveil`:

- `report.json`, mode 600, real values
- `report.redacted.json`, mode 644, with IP addresses, your domains, home directory
  paths and emails replaced by tokens, plus third-party hostnames inside evidence

`originveil show` prints the last report.

## Hermes Agent plugin

```
hermes plugins install alpinsh/originveil
hermes plugins enable originveil
```

originveil is not in the Hermes plugin catalog yet, so Hermes scans it at install
time and may block it as a community source. The findings come from what the tool
has to do: `subprocess` calls for `dig`, `ssh` and `systemctl` (always argument
lists, never a shell), and `sudo`, `pip install` and SSH examples in this README and
the tests. Read the code first; if you are satisfied, answer `y` at the prompt or
install with `--force`.

Tools:

- `originveil_audit`: discovery, DNS, reach and WordPress checks, plus the last timer report
- `originveil_last_report`: the last redacted timer report, with its age and coverage
- `originveil_add_domain`, `originveil_verify_domain`, `originveil_list_domains`,
  `originveil_remove_domain`: manage the audit allowlist from chat

A bundled skill (`originveil:originveil-audit`) tells the agent how to read the
results and what not to do.

Plugin settings (in Hermes' plugin settings screen):
`config_path`, `vantage`, `report_dir`, `allow_chat_origin_ip` (off by default) and
an optional `cloudflare_token`. The token is stored as a secret in Hermes' `.env` as
`ORIGINVEIL_CF_TOKEN` and read through Hermes' secret scope, so a general
`CF_API_TOKEN` you may have for other tools is not picked up. Give it Zone:Read and
DNS:Read only. The audit runs the CLI with a minimal environment (`PATH`, `HOME`,
locale, `SSH_AUTH_SOCK` and this token); other keys in Hermes' environment are not
passed to it.

### Adding domains without touching a config file

Ask the agent to add your domain. It returns a TXT record, for example:

```
_originveil-challenge.example.com  TXT  "originveil-verify=3f0c..."
```

Add it in your DNS (Cloudflare: DNS > Records), tell the agent, and it checks the
record and adds the domain. You can delete the record afterwards. If the plugin's
Cloudflare token can read the zone, that counts as proof and no record is needed. Codes expire after
48 hours. Verified domains are stored in the plugin's own Hermes state, not in a file
you have to edit. `/etc/originveil/config.toml` still works for admins who prefer it.

This stops a prompt, a web page or an email from pointing the tool at someone else's
site, because whoever sent it cannot add records to that site's DNS.

### Trust boundary

The allowlist and DNS ownership check enforce target restrictions at originveil's
tool interface. They are not an independent security boundary against an agent that
has terminal access as the same OS user and can modify the verification state.
Such an agent could also send requests to a target without using originveil at all.
The skill's rules are behavioural safeguards and do not replace OS-level access
control. For stronger isolation, keep the allowlist and the audit runner in a separate
privilege domain the agent cannot modify, and limit the agent's direct network access
and other ways to execute code.

The plugin is built so the agent does not need privileges and the model never sees the
origin IP:

- Firewall and nginx checks run in the root timer. The agent only reads the redacted
  report. Do not give the agent user sudo for this.
- Audit results returned to the model are redacted (IPs, your domains, home paths,
  emails, third-party hostnames in evidence), and a final pass masks any IP literal
  that is left. Other paths, such as `/etc/nginx/...`, are kept because they are needed
  to act on a finding.
- The agent cannot pass an origin IP by default (`allow_chat_origin_ip` is off). A
  model-supplied IP is not an authorised target, so the origin is either discovered or
  listed by an admin in `origin_ips`. If you turn the setting on, a given IP is only
  probed after it presents a certificate naming an audited domain. That check costs
  one TLS handshake to the address and is not authorisation: any server can present a
  self-signed certificate with your name. Turn it on only if you accept that.
- The agent can only audit domains in the config file or verified through DNS, not
  whatever a prompt asks for.
- Domain names are visible to the model in the domain management tools, since the
  user types them in chat. Audit reports still mask them.

Redaction protects what the tool sends to the model. An agent with an unrestricted
shell on the origin can still find its own IP in other ways. Restrict the agent's
toolsets if that matters to you.

## What leaves the machine

- Cloudflare API calls (`/ips`, and zone/DNS reads if a token is set)
- DNS lookups for your own names
- HTTPS requests to your own domains through Cloudflare (`/` and `/xmlrpc.php`)
- Direct TCP connections on ports 80 and 443 to the public IPs your own records point
  at (discovery), plus one TLS handshake per candidate
- SSH to your vantage host, if configured
- One TXT lookup when verifying a domain (over Cloudflare DNS-over-HTTPS if `dig` is
  not installed)

No telemetry and no external scanning services. The only third-party services
contacted are Cloudflare's API and DNS-over-HTTPS (for the TXT fallback) and your
system's DNS resolver. MX lookups can resolve your mail provider's hostnames. The
WordPress check only calls `system.listMethods`; it never calls `pingback.ping`, so no
third party is contacted on its behalf (the request still shows up in your site's
access log).

What the plugin touches on the Hermes host: it runs the originveil CLI, which calls
`dig` and, if a vantage is set, `ssh`; it reads the config file and `report.redacted.json` in `report_dir`; it keeps
verified domains and pending TXT codes in its own plugin state. It installs nothing,
registers no hooks and never writes outside its state. The root timer is something
you install yourself with the CLI on the origin server.

## Security design

- Discovery connects to every public IP that the audited domain's own records point
  to (ports 80 and 443 only, plus one TLS handshake without SNI). Records can point at
  any address, so audit only domains whose DNS you control. With a token that can read
  a parent zone, only records at or below the audited name are used.

- Candidate and given IPs must be public unicast. Loopback, link-local (cloud
  metadata), multicast and RFC 1918/CGNAT/ULA ranges are refused.
- Redirects are only followed within the audited site, over HTTPS and on the same
  port, and the direct probe never leaves the IP it is testing.
- Domains are validated as hostnames before they reach `dig`, `ssh` or a URL. All
  subprocesses get argument lists, and the remote probe command is shell-quoted.
  A vantage spec must be a plain `[user@]host[:port]`; anything that could be read as
  an ssh option is refused.
- `install-timer` refuses to run if any file or directory of the package (walked
  recursively, symlinks rejected), the config, the Python binary, the state directory
  or the secrets file `/etc/originveil/env` is not root-owned or is writable (for the
  env file: readable) by others. It does not audit the Python standard library or the
  interpreter's own import path. Reports are written atomically into the root-owned
  state directory.
- With `--redact` or `--json`, a crash prints only the exception type, not a traceback
  that could carry addresses or paths.

## Limits

- Firewall parsing is heuristic (ufw, nftables, iptables-save). It reads accept rules
  on 80/443 and their source restrictions. Unusual rulesets can confuse it.
- nginx config is parsed structurally with includes; unreadable includes,
  unlistable include directories and missing include files make the check partial.
  Only `ssl_verify_client on`, or `optional` with exactly
  `if ($ssl_client_verify != SUCCESS) { return 4xx; }` at server level, counts as
  enforcement; other forms are reported as not confirmed. Enforcement is read from the
  config, not tested live (the `reach` check is the live test).
- Apache support covers `SSLVerifyClient` per TLS vhost. Directives inside
  `<IfModule>`, `<IfDefine>` and other conditional sections are never credited.
- Firewall drops are matched per web port, not per IP family or chain path. When the
  default policy is unknown, the check is partial.
- It cannot see historical DNS. If the origin IP was ever public, assume it is known:
  close the leaks, then change the IP.

## Development

```
pip install pytest
python3 -m pytest
```

Use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and
`example.com` in tests, issues and examples.

## License

MIT
