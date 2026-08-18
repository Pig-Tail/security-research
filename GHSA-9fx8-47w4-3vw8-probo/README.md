# GHSA-9fx8-47w4-3vw8 — Probo stored XSS via unsanitized Markdown (`<iframe srcdoc>`)

- **Advisory:** [GHSA-9fx8-47w4-3vw8](https://github.com/getprobo/probo/security/advisories/GHSA-9fx8-47w4-3vw8) · no CVE assigned
- **Affected:** go.probo.inc/probo `< 0.257.0` · **Fixed:** `0.257.0`
- **Severity:** Moderate (CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N = 4.8) · **CWE-79**, with **CWE-693** contributing
- **Impact:** stored XSS running in the authenticated console session of any member who views the
  Organization Context page — including an OWNER or an external AUDITOR.

## Root cause

Two gaps that are only exploitable together.

**1 — the Markdown sink opts out of sanitization** (`packages/ui/src/Atoms/Markdown/Markdown.tsx:29-31`):

```tsx
<ReactMarkdown
  remarkPlugins={[remarkGfm]}
  rehypePlugins={[rehypeRaw]}   // raw HTML passed through; NO rehype-sanitize
>
```

react-markdown v10 strips `on*` handlers and neutralises `javascript:`/`data:` URLs, but passes
`<iframe srcdoc="…">` through intact. Scripts inside `srcdoc` execute **same-origin** at the console
origin.

The write path (`updateOrganizationContext` in
`pkg/server/api/console/v1/organization_resolvers.go`) stores the value verbatim and authorizes
`ActionOrganizationContextUpdate` (OWNER/ADMIN). The read path
(`apps/console/src/pages/organizations/context/ContextPage.tsx`) renders it, and
`ActionOrganizationContextGet` extends to **VIEWER and AUDITOR**
(`pkg/probo/policies.go:109,134`).

**2 — no CSP on the console app**, which is what made it exploitable. The
`Content-Security-Policy: default-src 'self'` header is set only inside the API server's handler
(`pkg/server/api/api.go`, mounted at `/api`). The console SPA is mounted at `/`
(`pkg/server/server.go:80`) and served by `pkg/server/web/web.go` → `statichandler`, which sets only
`Content-Type`, `Cache-Control` and `ETag` (`statichandler.go:145-216`) — no CSP, no
`X-Frame-Options`. The console `index.html` carries no `<meta http-equiv>` CSP either. An
`<iframe srcdoc>` inherits the embedding document's CSP; with none, the inline script runs.

## Payload

```html
<iframe srcdoc="<script>/* exfiltrate session / CSRF token */</script>"></iframe>
```

Set as the Organization Context by an OWNER/ADMIN; fires when any member with read access opens
the page.

## Why it crosses a privilege boundary

The injector must already be OWNER/ADMIN (hence `PR:H`), so this is not a privilege escalation on
its own. Its value is the direction it travels: an ADMIN runs script in the session of an **OWNER**
(session/CSRF theft → act as OWNER), or of an **AUDITOR** — typically an external party whose
session may span several audited organizations.

The vendor kept the score at 4.8 rather than adopting the session-theft `C:H/I:H` (~8) framing,
reasoning that injection already requires OWNER/ADMIN plus victim interaction. Recorded here as
the vendor's call.

## Fix

`0.257.0` serves a restrictive CSP with `script-src 'self'` (no `'unsafe-inline'`) on the console,
which blocks the inline `srcdoc` script. The sink itself is still worth hardening — adding
`rehype-sanitize` after `rehype-raw`, or dropping `rehype-raw`, also closes `<style>`-based CSS
injection through the same component.

## Credit

Reported by [@Pig-Tail](https://github.com/Pig-Tail). Fixed by the Probo team (@gearnode).
