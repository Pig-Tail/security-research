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
| [GHSA-f5m5-jfmq-ghpx](GHSA-f5m5-jfmq-ghpx-NetCoreToolService/) | SteeltoeOSS/NetCoreToolService | Unauth RCE via `dotnet new` arg injection (CWE-88) | Critical | ✅ runnable |
| [GHSA-p34x-fmph-9fjx](GHSA-p34x-fmph-9fjx-flyto-core/) | flytohub/flyto-core | Arbitrary file write, incomplete fix (CWE-22) | Critical | ✅ runnable |
| [CVE-2026-14620](CVE-2026-14620-webpack-dev-server/) | webpack-dev-server | Cross-origin CSRF → arbitrary file open (CWE-352/CWE-749) | Medium | ✅ runnable |
| [CVE-2026-63505](CVE-2026-63505-probo/) | getprobo/probo | Cross-tenant IDOR via unvalidated FK (CWE-639) | Moderate | ✅ runnable |
| [GHSA-cppp-g98f-gfpp](GHSA-cppp-g98f-gfpp-probo/) | getprobo/probo | ADMIN→OWNER privilege escalation (CWE-269/CWE-863) | High | ✅ runnable |
| [GHSA-p6gq-j5cr-w38f](GHSA-p6gq-j5cr-w38f-nodemailer/) | nodemailer | `raw` bypasses disableFileAccess/UrlAccess (CWE-73/CWE-918) | High | ✅ runnable |
| [GHSA-96fx-pqc3-28xv](GHSA-96fx-pqc3-28xv-monitoring-plugins/) | Linuxfabrik/monitoring-plugins | Redfish SSRF + auth-token disclosure (CWE-918/CWE-200) | Medium | ✅ runnable |
| [GHSA-6pm8-6f34-9v3g](GHSA-6pm8-6f34-9v3g-flyto-core/) | flytohub/flyto-core | SSRF via DNS rebinding (CWE-918) | Medium | ✅ runnable |
| [GHSA-w2gg-hx6w-24w3](GHSA-w2gg-hx6w-24w3-monitoring-plugins/) | Linuxfabrik/monitoring-plugins | logfile symlink-following, incomplete fix (CWE-59/CWE-367) | Low | ✅ runnable |

More entries are added here as their advisories are published by each vendor. Findings still under
coordinated-disclosure embargo (advisory in draft, CVE reserved but not yet public) are deliberately
**not** included until the vendor publishes.

## Disclosure ethics

All findings were reported privately to the maintainer first (GitHub Private Vulnerability
Report or the vendor's security contact), triaged, fixed, and only then published. PoCs are
released after the fix so defenders can verify their own patching — not to arm attackers.
