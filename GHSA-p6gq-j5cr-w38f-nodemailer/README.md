# GHSA-p6gq-j5cr-w38f — Nodemailer `raw` bypasses disableFileAccess / disableUrlAccess

- **Advisory:** [GHSA-p6gq-j5cr-w38f](https://github.com/nodemailer/nodemailer/security/advisories/GHSA-p6gq-j5cr-w38f)
- **Severity:** High · **CWE-73** (external control of file path) / **CWE-918** (SSRF)
- **Impact:** an app that passes untrusted message data with `disableFileAccess`/`disableUrlAccess`
  set (to stop that input reading local files or fetching URLs) is still exposed: a message-level
  `raw` option reads the file / fetches the URL anyway → local file read + SSRF.

## Root cause

`MailComposer.compile()` builds the `message/rfc822` root node for a `raw: { path }` /
`raw: { href }` message **without threading the `disableFileAccess` / `disableUrlAccess` flags**
(`lib/mail-composer/index.js:34-35`) — unlike every attachment/alternative node, which *is* created
with those flags. So the protection that covers attachments simply doesn't apply to `raw`.

## PoC

`poc/poc-raw-fileaccess-bypass.js` sets `disableFileAccess: true`, sends a `raw: { path: <sentinel> }`
message with a unique nonce, and shows the sentinel file's contents appear in the generated message
— proving the flag was bypassed. Local, benign, no network.

```sh
# from a checkout with nodemailer installed as a sibling (see the require path in the PoC)
node poc/poc-raw-fileaccess-bypass.js
```

## Fix

Thread `disableFileAccess` / `disableUrlAccess` into the `raw` root node in
`MailComposer.compile()`, same as attachment nodes.
