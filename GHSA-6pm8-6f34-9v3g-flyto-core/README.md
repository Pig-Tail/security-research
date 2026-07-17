# GHSA-6pm8-6f34-9v3g — flyto-core SSRF via DNS rebinding

- **Advisory:** [GHSA-6pm8-6f34-9v3g](https://github.com/flytohub/flyto-core/security/advisories/GHSA-6pm8-6f34-9v3g)
- **Severity:** Medium · **CWE-918** (SSRF)
- **Impact:** reach internal/loopback services the SSRF guard was meant to block.

## Root cause

`validate_url_ssrf()` resolves the hostname, checks the resolved IP against the private/loopback
blocklist, and then the HTTP client **re-resolves and connects** separately. Because the guard does
not pin the validated IP for the actual connection, an attacker DNS with `TTL=0` can return a
public address for the validation lookup and a private/loopback address for the connect lookup
(classic DNS rebinding) — the check passes, the connection hits the internal target.

## PoC

`poc/poc_dns_rebinding.py` stands up a loopback TCP **sentinel** (an "internal service") and
monkeypatches `socket.getaddrinfo` to flip public→private across successive lookups exactly as a
`TTL=0` attacker DNS would. It shows the guard validating the first (public) resolution while the
connect reaches the private sentinel. Local and benign.

```sh
cd /path/to/flyto-core && python3 /path/to/poc/poc_dns_rebinding.py
```

## Fix

Pin the validated IP for the connection (resolve once, connect to that exact IP), or re-validate
the address the socket actually connects to.
