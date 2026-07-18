# security-research

Proof-of-concept code and technical write-ups for vulnerabilities I discovered and reported
through coordinated disclosure. **Every entry here is already public: the vendor advisory is
published and a fixed release is available.** Nothing under embargo or in draft is included.

The PoCs are *verification harnesses*, not weaponized exploits: each runs against a **local,
self-owned instance** and proves the defect with a benign sentinel (a marker file, a seeded
"secret" record, a policy-evaluation assertion). None of them target third-party systems, and
none perform any destructive or persistent action.

— **Pig-Tail** · Offensive Security Engineer & Vulnerability Researcher · <jorge@jmilla.es>

## Index

| CVE / Advisory | Project | Class (CWE) | Severity | PoC |
|:--|:--|:--|:--|:--|
| [GHSA-f5m5-jfmq-ghpx](GHSA-f5m5-jfmq-ghpx-NetCoreToolService/) | SteeltoeOSS/NetCoreToolService | Unauthenticated RCE via argument injection into 'dotnet new' (CWE-88) | Critical | ✅ runnable |
| [GHSA-p34x-fmph-9fjx](GHSA-p34x-fmph-9fjx-flyto-core/) | flyto-core | Arbitrary file write via unguarded data.*/file.* modules (in (CWE-22) | Critical | ✅ runnable |
| [GHSA-9vx2-j98c-p72w](GHSA-9vx2-j98c-p72w-kirby/) | kirby | Access to image files and limited access to JSON files outsi (CWE-22) | High | 📄 write-up |
| [CVE-2026-61699](CVE-2026-61699-nebula-mesh/) | nebula-mesh | Certificate revocation is never enforced at the mesh: nebula (CWE-299/CWE-672) | High | 📄 write-up |
| [CVE-2026-63202](CVE-2026-63202-netty-incubator-codec-ohttp/) | netty-incubator-codec-ohttp | BinaryHttpParser: Unauthenticated CPU-exhaustion DoS via inf (CWE-400/CWE-835) | High | ✅ runnable |
| [GHSA-p6gq-j5cr-w38f](GHSA-p6gq-j5cr-w38f-nodemailer/) | nodemailer | Message-level raw option bypasses disableFileAccess/disableU (CWE-73/CWE-918) | High | ✅ runnable |
| [GHSA-cppp-g98f-gfpp](GHSA-cppp-g98f-gfpp-probo/) | probo | Vertical privilege escalation: an organization ADMIN can min (CWE-269/CWE-863) | High | ✅ runnable |
| [CVE-2026-62989](CVE-2026-62989-shopper/) | shopper | Missing authorization on product variant DeleteAction/Delete (CWE-285/CWE-862) | High | 📄 write-up |
| [CVE-2026-54697](CVE-2026-54697-cbssh/) | cbssh | Excessive allocation and integer overflow in DER private-key (CWE-190/CWE-789) | Medium | 📄 write-up |
| [CVE-2026-55422](CVE-2026-55422-conda-forge/) | conda-forge | Stored DOM XSS on conda-forge.org via unsanitized dangerousl (CWE-79) | Medium | 📄 write-up |
| [GHSA-6pm8-6f34-9v3g](GHSA-6pm8-6f34-9v3g-flyto-core/) | flyto-core | SSRF guard bypass via DNS rebinding (validate_url_ssrf resol (CWE-918) | Medium | ✅ runnable |
| [CVE-2026-48728](CVE-2026-48728-glpi-inventory-plugin/) | glpi-inventory-plugin | Job enumeration and status manipulation on Deploy, Collect,  (CWE-306) | Medium | 📄 write-up |
| [CVE-2026-63432](CVE-2026-63432-horilla-hr/) | horilla-hr | Server-Side Template Injection (SSTI) in Mail Preview Endpoi (CWE-94/CWE-200) | Medium | 📄 write-up |
| [CVE-2026-59249](CVE-2026-59249-mint/) | mint | HTTP/1 chunk-size desync in Mint via Integer.parse/2 sign to (CWE-444) | Medium | 📄 write-up |
| [GHSA-4jc5-g844-4x33](GHSA-4jc5-g844-4x33-monitoring-plugins/) | monitoring-plugins | fetch() forwards credential headers across a cross-origin re (CWE-200/CWE-918) | Medium | 📄 write-up |
| [GHSA-96fx-pqc3-28xv](GHSA-96fx-pqc3-28xv-monitoring-plugins/) | monitoring-plugins | SSRF and auth-token disclosure via unvalidated @odata.id lin (CWE-20/CWE-200/CWE-918) | Medium | ✅ runnable |
| [CVE-2026-63505](CVE-2026-63505-probo/) | probo | Cross-tenant IDOR via unvalidated FK references (CWE-639) | Medium | ✅ runnable |
| [GHSA-qh8c-7588-qfrv](GHSA-qh8c-7588-qfrv-statamic/) | statamic | Missing authorization on navigation endpoint allows disclosu (CWE-639/CWE-862) | Medium | 📄 write-up |
| [GHSA-h5rg-8p7f-47g2](GHSA-h5rg-8p7f-47g2-surrealdb/) | surrealdb | SSRF via JWKS URL — Redirect Following in JWT Key Fetch (CWE-918) | Medium | 📄 write-up |
| [CVE-2026-54764](CVE-2026-54764-traefik/) | traefik | ForwardAuth middleware leaks X-Forwarded-Port spoofing via u (CWE-345) | Medium | 📄 write-up |
| [CVE-2026-14620](CVE-2026-14620-webpack-dev-server/) | webpack-dev-server | webpack-dev-server vulnerable to cross-site request forgery  (CWE-352/CWE-749) | Medium | ✅ runnable |
| [CVE-2026-55780](CVE-2026-55780-NanaZip/) | NanaZip | Uncaught exception / unbounded allocation in NanaZip .NET si (CWE-248/CWE-400) | Low | 📄 write-up |
| [CVE-2026-55781](CVE-2026-55781-NanaZip/) | NanaZip | Unbounded memory allocation (DoS) in NanaZip UFS parser via  (CWE-400/CWE-789) | Low | 📄 write-up |
| [CVE-2026-55782](CVE-2026-55782-NanaZip/) | NanaZip | Unbounded memory allocation (DoS) in NanaZip WebAssembly par (CWE-400/CWE-789) | Low | 📄 write-up |
| [CVE-2026-55783](CVE-2026-55783-NanaZip/) | NanaZip | NULL pointer dereference in Extract() of all seven NanaZip c (CWE-476) | Low | 📄 write-up |
| [GHSA-vwv6-85p7-mjvc](GHSA-vwv6-85p7-mjvc-glpi-agent/) | glpi-agent | Oracle inventory module uses unvalidated process username in (CWE-78) | Low | 📄 write-up |
| [GHSA-mgcf-xgv7-5w4x](GHSA-mgcf-xgv7-5w4x-glpi-agent/) | glpi-agent | Collect task compiles server-controlled regular expression w (CWE-1333) | Low | 📄 write-up |
| [GHSA-cwg9-jj5m-pq4q](GHSA-cwg9-jj5m-pq4q-glpi-agent/) | glpi-agent | Stored XSS via SNMP community/authprotocol credential fields (CWE-79) | Low | 📄 write-up |
| [GHSA-w2gg-hx6w-24w3](GHSA-w2gg-hx6w-24w3-monitoring-plugins/) | monitoring-plugins | Symlink following in logfile legacy database migration (CWE-59/CWE-367) | Low | ✅ runnable |
| [GHSA-m5p8-h274-f7w8](GHSA-m5p8-h274-f7w8-openproject/) | openproject | Content Security Policy img-src wildcard enables cross-origi (CWE-200) | Low | 📄 write-up |
| [GHSA-22xj-f767-ppw6](GHSA-22xj-f767-ppw6-probo/) | probo | Broken access control in public e-signature API: any trust-c (CWE-639/CWE-862) | Low | 📄 write-up |
| [GHSA-w23w-f7v2-625w](GHSA-w23w-f7v2-625w-probo/) | probo | Unauthenticated cross-tenant and hidden-item disclosure via  (CWE-284/CWE-639) | Low | 📄 write-up |

More entries are added here as their advisories are published by each vendor. Findings still under
coordinated-disclosure embargo (advisory in draft, CVE reserved but not yet public) are deliberately
**not** included until the vendor publishes.

## Disclosure ethics

All findings were reported privately to the maintainer first (GitHub Private Vulnerability
Report or the vendor's security contact), triaged, fixed, and only then published. PoCs are
released after the fix so defenders can verify their own patching — not to arm attackers.
