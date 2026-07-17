# GHSA-96fx-pqc3-28xv — Linuxfabrik monitoring-plugins Redfish SSRF + auth-token disclosure

- **Advisory:** [GHSA-96fx-pqc3-28xv](https://github.com/Linuxfabrik/monitoring-plugins/security/advisories/GHSA-96fx-pqc3-28xv)
- **Severity:** Medium · **CWE-918** (SSRF) / **CWE-200** (info exposure) / **CWE-20**
- **Impact:** a malicious/compromised monitored Redfish BMC coerces the plugin into an
  authenticated request to an attacker-chosen host, leaking the BMC `Authorization` token.

## Root cause

The `redfish-*` plugins follow the `@odata.id` link field returned by the monitored BMC. A value
that does **not** begin with `/` — e.g. `@evil-host/pivot` — is concatenated as
`f'{args.URL}{odata_id}'`, so the URL's *authority* becomes the attacker's host
(`http://<bmc-creds>@evil-host/pivot`). The plugin then re-fetches that URL **with the Redfish
`Authorization` header attached**, sending the credentials to the attacker.

## PoC

`poc/redfish_ssrf_poc.py` and `redfish_ssrf_token_poc.py` run a benign "evil" HTTP **sentinel** that
records the request (and its `Authorization` header) the plugin sends after being handed a crafted
`@odata.id`. Local, no destructive action.

```sh
python3 poc/redfish_ssrf_token_poc.py
```

## Fix

Reject `@odata.id` values that alter the authority (require a leading `/`, resolve against the
validated base URL), and never attach the Redfish auth header to a host other than the configured
BMC.
