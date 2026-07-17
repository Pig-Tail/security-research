# GHSA-w2gg-hx6w-24w3 — Linuxfabrik monitoring-plugins logfile symlink-following (incomplete fix of CVE-2026-53759)

- **Advisory:** [GHSA-w2gg-hx6w-24w3](https://github.com/Linuxfabrik/monitoring-plugins/security/advisories/GHSA-w2gg-hx6w-24w3)
- **Severity:** Low · **CWE-59** (link following) / **CWE-367** (TOCTOU)
- **Impact:** an unprivileged local user (`nagios`) plants a symlink that the root-run plugin's
  legacy-DB migration follows on `os.rename()`, overwriting an arbitrary root-owned file.

## Root cause

Incomplete fix of CVE-2026-53759. The `logfile` plugin's legacy-database migration renames a
predictable path without ensuring it is not a symlink. An unprivileged user who wins the race and
plants a symlink at that path redirects the root `os.rename()` to a target of their choosing.

## PoC

`poc/logfile_symlink_poc.sh` runs the **real** plugin as root with an unprivileged `nagios`
attacker planting the symlink, and tests **both** `fs.protected_symlinks` states — showing the
overwrite succeeds when the sysctl mitigation is off. (On the default hardened Linux
`fs.protected_symlinks=1` the OS blocks it — hence the Low rating; the code defect remains.)

```sh
# run in a throwaway root container/VM (it creates a 'nagios' user and writes as root)
sh poc/logfile_symlink_poc.sh
```

## Fix

Open with `O_NOFOLLOW` / verify the path is not a symlink before `os.rename()`, and drop privileges
for the migration. Don't rely on `fs.protected_symlinks`.
