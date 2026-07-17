# GHSA-f5m5-jfmq-ghpx — NetCoreToolService unauthenticated RCE via `dotnet new` argument injection

- **Advisory:** [GHSA-f5m5-jfmq-ghpx](https://github.com/SteeltoeOSS/NetCoreToolService/security/advisories/GHSA-f5m5-jfmq-ghpx) (SteeltoeOSS; filed via the org's central `security-advisories` repo — no CVE, Git ecosystem)
- **Severity:** Critical · **CWE-88** (argument injection)
- **Impact:** unauthenticated remote code execution on the service host.

## Root cause

`NewController.GetTemplateProject` builds a `dotnet new` command line from the attacker-controlled
`{template}` route parameter with no validation. A crafted value injects extra arguments that reach
an ungated `dotnet new install`, and a malicious template's **post-action** (`RunScript`) executes
attacker code during instantiation. The production image ships the full `dotnet/sdk` runtime, so
the SDK needed to install/run templates is present.

## PoC

`poc/poc_ncts_rce.sh` reproduces the exact command strings the controller assembles from HTTP
input, using a local template whose only post-action writes a benign **sentinel** file
(`RCE_PROOF.txt`) in a `mktemp` dir. 100% local, no network, no persistence. Requires a .NET 10 SDK
on PATH (as in the target image).

```sh
cd poc && bash poc_ncts_rce.sh   # prints the sentinel path on success
```

## Fix

Validate/allow-list the `{template}` parameter, never pass user input as raw `dotnet new`
arguments, and disable template post-actions for untrusted sources. Fixed by SteeltoeOSS.
