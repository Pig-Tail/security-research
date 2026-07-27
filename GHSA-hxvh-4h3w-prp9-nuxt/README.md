# GHSA-hxvh-4h3w-prp9 — Nuxt route rules silently dropped for mixed-case paths (incomplete fix for CVE-2026-53721)

- **Advisory:** [GHSA-hxvh-4h3w-prp9](https://github.com/nuxt/nuxt/security/advisories/GHSA-hxvh-4h3w-prp9)
- **Severity:** High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (8.2) · CWE-178, CWE-863
- **Affected:** `>= 4.4.7, < 4.5.1` and `>= 3.21.7, < 3.21.10` · **Patched:** `4.5.1`, `3.21.10`
- **Prior advisory (regressed fix):** [GHSA-mm7m-92g8-7m47](https://github.com/nuxt/nuxt/security/advisories/GHSA-mm7m-92g8-7m47) / CVE-2026-53721
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure (incomplete-fix follow-up).

## Summary

Nuxt matches route rules **case-insensitively** by default (mirroring vue-router's `sensitive: false`).
The fix for **CVE-2026-53721** lower-cased the *lookup path* before matching route rules, but left the
compiled route-rule **keys verbatim**. Because the radix3 matcher compares path segments
case-sensitively, any route rule whose key contains an upper-case character — e.g. `/Admin`,
`/Dashboard/**`, or the rules Nuxt derives from PascalCase/camelCase page files like `pages/Admin.vue` —
**never matches**, since every lookup is folded to lowercase while the key stays mixed-case.

vue-router still serves the page for every casing, so the page renders with **none of its Nuxt
route-rule protections applied**. The most serious consequence is an **authorization bypass**: an
`appMiddleware` auth gate (`routeRules: { '/Admin/dashboard': { appMiddleware: 'auth' } }`) is dropped,
and `/Admin/dashboard`, `/admin/dashboard`, and `/ADMIN/dashboard` all render the protected page (and
its SSR-fetched data) to an unauthenticated visitor instead of redirecting to login. The same gap drops
the app-side `ssr: false` decision, the client redirect middleware, `appLayout`, prerender and payload
handling for mixed-case keys.

## Root cause

The fix normalises only the *input* path at each matcher call site, while the rule keys baked into the
matcher retain their original case:

- `packages/nitro-server/src/index.ts` — the compiled matcher lowercases only the runtime `path`
  argument (`matcher('', path.toLowerCase())`); the radix3 tree is built from route-rule keys verbatim.
- `packages/nuxt/src/app/composables/manifest.ts` — `routeRulesMatcher(path.toLowerCase())`, keys unchanged.
- `packages/nuxt/src/pages/route-rules.ts` / `utils.ts` — page-derived globs keep their case
  (`/Admin` → `/Admin/**`).

radix3 compares segments with strict equality, so `'admin' !== 'Admin'` and the lowercased lookup never
reaches the node. (The normalisation is also applied inconsistently: `nuxt-layout.ts` calls the matcher
*without* `.toLowerCase()`, diverging from every other consumer.)

## Proof of Concept

`poc/poc.mjs` reproduces the core defect with the exact matcher library Nuxt ships (`radix3@1.1.2`),
replicating the post-fix compiled-matcher logic (lowercased lookup, verbatim keys). No network, no
secrets, read-only.

```
$ cd poc && npm install && node poc.mjs

=== protected mixed-case rule  /Admin { appMiddleware: "auth", ssr:false, X-Frame-Options } ===
  request /Admin   -> rules applied: {}    auth gate: DROPPED (bypass)
  request /admin   -> rules applied: {}    auth gate: DROPPED (bypass)
  request /ADMIN   -> rules applied: {}    auth gate: DROPPED (bypass)
  request /aDmIn   -> rules applied: {}    auth gate: DROPPED (bypass)

=== control lowercase rule  /public ===
  request /public  -> rules applied: {"headers":{"Cache-Control":"public"}} (matches, as expected)

[VULNERABLE] /Admin route rules DROPPED for every casing while /public (lowercase key) still matches.
```

The `/Admin` rule (auth gate + `ssr: false` + `X-Frame-Options`) resolves to `{}` for **every** casing,
while the lowercase-keyed `/public` control still matches — proving the drop is caused by key casing, not
by the lookup. vue-router serves `/Admin` for all casings (its documented default), so the unauthenticated
visitor reaches the protected page.

## Fix

`4.5.1` / `3.21.10`: the matcher now case-folds the compiled **keys** the same way it folds the lookup
path, so key and lookup normalisation are symmetric. Both sides are gated on `router.options.sensitive`
— with `sensitive: true` casing is preserved on both sides.

**Workarounds** (pre-upgrade): key all `routeRules` (and page filenames) in lowercase; or set
`router: { options: { sensitive: true } }`; or enforce the protections server-side (e.g. a server
middleware auth check) independently of app-level route rules.
