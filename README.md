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

| CVE / Advisory | Project | Class (CWE) | Fixed in | PoC |
|:--|:--|:--|:--|:--|
| [CVE-2026-14620](CVE-2026-14620-webpack-dev-server/) | webpack-dev-server | Cross-origin CSRF → arbitrary file open (CWE-352/CWE-749) | 5.2.6 | ✅ runnable |
| [CVE-2026-63505](CVE-2026-63505-probo/) | getprobo/probo | Cross-tenant IDOR via unvalidated FK (CWE-639) | 0.223.1 | ✅ runnable |
| [GHSA-cppp-g98f-gfpp](GHSA-cppp-g98f-gfpp-probo/) | getprobo/probo | ADMIN→OWNER privilege escalation (CWE-269/CWE-863) | 0.223.1 | ✅ runnable |

More entries are added here as their advisories are published by each vendor.

## Disclosure ethics

All findings were reported privately to the maintainer first (GitHub Private Vulnerability
Report or the vendor's security contact), triaged, fixed, and only then published. PoCs are
released after the fix so defenders can verify their own patching — not to arm attackers.
