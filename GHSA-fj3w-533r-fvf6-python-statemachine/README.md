# GHSA-fj3w-533r-fvf6 — SCXML `<data src="file://…">` reads arbitrary local files when loading an untrusted document (secure-by-default bypass)

- **Advisory:** [GHSA-fj3w-533r-fvf6](https://github.com/fgmacedo/python-statemachine/security/advisories/GHSA-fj3w-533r-fvf6)
- **Severity:** High — CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L` (7.1) · CWE-22, CWE-200
- **Affected:** `>= 3.2.0, < 3.2.1` · **Patched:** `3.2.1`
- **Related:** distinct from GHSA-v4jc-pm6r-3vj8 / CVE-2026-47103 (SCXML `<data expr>` eval injection, fixed in 3.2.0 by a restricted AST-allowlist evaluator) — this is a separate file-disclosure path in the same "secure by default" IO layer.
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

`statemachine.io.load(..., trusted=False)` — the documented safe default, meant to mirror
`yaml.safe_load` and be usable on semi-trusted documents — opens and reads an arbitrary local file
named in an SCXML `<data src="file://…">` attribute **during parsing**, before any expression
evaluation happens and with **no `trusted` gate at all**. The file content is loaded into a
datamodel variable that the same attacker-authored document can then exfiltrate via
`<log expr>`/`<send>`.

This breaks confidentiality against the exact threat model the project's own security policy
describes (`docs/io/security.md`: "a document can come from an untrusted source").

## Root cause

`statemachine/io/scxml/reader.py`, `parse_datamodel()` (lines 117–121, v3.2.0) opens
`urlparse(src).path` unconditionally for any `<data src="file://...">` entry — no `trusted` check,
no base-directory confinement (an absolute path defeats path-join confinement entirely). A weaker
same-class vector exists in `statemachine/io/invoke.py`, `_resolve_content()` (lines 179–189).

## Proof of Concept

`poc/poc_scxml_fileread.py` writes a benign sentinel file, then loads an attacker-authored SCXML
document via `statemachine.io.load(scxml, format="scxml")` in the **default** `trusted=False` mode.
The document's `<data src="file://...">` reads the sentinel file's content into a datamodel
variable, which the document's own `<onentry><log>` immediately exfiltrates.

```sh
pip install "python-statemachine==3.2.0"
python3 poc/poc_scxml_fileread.py
```

Expected (benign) output — the sentinel content is printed via the state machine's own logging,
proving the untrusted document read a file it should never have been able to reach:

```
[*] secret file: /tmp/xxxxxxxx.secret
[*] loading SCXML with trusted=False (secure default)...
EXFIL: TOP-SECRET-SENTINEL-12345
```

No network access; only a local temp file is created and immediately unlinked.

## Fix

`3.2.1`: the SCXML `<data src>` / `<invoke src>` file-loading paths are now gated on `trusted=True`,
consistent with the eval-injection fix's threat model — an untrusted document can no longer read
arbitrary local files via the default `trusted=False` loader.
