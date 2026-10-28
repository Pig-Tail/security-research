# GHSA-wc2f-fvpv-c32r — OpenEMR: leftover debug code in `fax_view.php` prints the web server's Unix groups

- **Advisory:** [GHSA-wc2f-fvpv-c32r](https://github.com/openemr/openemr/security/advisories/GHSA-wc2f-fvpv-c32r)
- **Severity:** Low — CVSS 3.1 `AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N` (3.1) · CWE-200 / CWE-489 — no CVE assigned
- **Affected:** `openemr/openemr` `< 8.5.0` · **Patched:** `8.5.0`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

`interface/fax/fax_view.php` shows HylaFAX fax jobs. When the job file for the requested
`jid` cannot be opened, the script runs the shell command `groups` with `passthru()` and
sends its output to the browser before stopping. Any logged-in user who can reach the fax
viewer can trigger it and learn which Unix groups the web server process belongs to.

## Root cause

`interface/fax/fax_view.php` (8.4.1):

```php
$jobid = $_GET['jid'];
if ($jobid) {
    $jfname = OEGlobalsBag::getInstance()->getString('hylafax_basedir') . "/sendq/q" . check_file_dir_name($jobid);
    if (!file_exists($jfname)) {
        $jfname = OEGlobalsBag::getInstance()->getString('hylafax_basedir') . "/doneq/q" . check_file_dir_name($jobid);
    }

    $jfhandle = fopen($jfname, 'r');
    if (!$jfhandle) {
        echo "I am in these groups: ";
        passthru("groups");
        echo "<br />";
        die(xlt("Cannot open ") . text($jfname));
    }
```

The three lines before `die()` are debug code from when the fax module was written. They were
never removed. The page only checks for a session (`globals.php`) and a CSRF token, so any user
with a session and a valid token reaches this branch just by asking for a job that doesn't
exist. `check_file_dir_name()` limits `jid` to a safe file name, so there is no command
injection here: the command is fixed. The only problem is what it prints.

## Impact

The response shows the web server's groups, for example:

```
I am in these groups: www-data adm fax
Cannot open /var/spool/hylafax/sendq/qNOTEXIST
```

On its own this doesn't give access to anything. It helps an attacker plan the next step.
Membership in groups like `shadow`, `adm`, `disk` or `docker` tells them which files or
devices the web process can reach, and so how much a later code-execution or file-read bug
in OpenEMR would be worth. The `Cannot open` line also shows the HylaFAX spool path.

The attacker needs a valid session, and the fax viewer only has a use when HylaFAX is
configured. That is why the rating is Low.

## Proof of concept

As a logged-in user, with a CSRF token from your own session:

```
GET /openemr/interface/fax/fax_view.php?csrf_token_form=<valid_token>&jid=NOTEXIST HTTP/1.1
Host: <target>
Cookie: <authenticated session>
```

The response body begins with `I am in these groups:` followed by the groups of the PHP
process user. Any `jid` made of letters and digits with no matching file in `sendq/` or
`doneq/` works.

## Fix

Upgrade to `8.5.0` or later. Commit
[`1d8ef2d344`](https://github.com/openemr/openemr/commit/1d8ef2d344) (#14679) removes the
`echo` / `passthru("groups")` / `echo` lines. The page still stops with `Cannot open <path>`,
so the spool path is still shown, but the group list is gone. The same commit lowers the
PHPStan `forbiddenShellExecution` baseline for `fax_view.php` from 3 to 2. The file still makes
two other shell calls, which the baseline keeps allowing.

If you can't upgrade yet, delete those three lines by hand. Nothing else depends on them.

## Timeline

- 2026-10-21 — fix merged (#14679)
- 2026-10-27 — OpenEMR 8.5.0 released
- 2026-10-28 — advisory published
