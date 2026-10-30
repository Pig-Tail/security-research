# GHSA-q2j6-54g3-jhcj — GLPI Agent: MySQL option-file injection through server-supplied credentials

- **Advisory:** [GHSA-q2j6-54g3-jhcj](https://github.com/glpi-project/glpi-agent/security/advisories/GHSA-q2j6-54g3-jhcj)
- **Severity:** High · CVSS 4.0 7.3 (`AV:A/AC:L/AT:P/PR:H/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N`) · CWE-74 / CWE-94 — no CVE assigned yet
- **Affected:** GLPI Agent `< 1.20` · **Patched:** `1.20`
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

For database inventory, the GLPI server sends the agent the credentials to use
(host, port, user, socket, password). For MySQL/MariaDB the agent writes them into a
temporary option file and runs `mysql --defaults-extra-file=<file>`. The values were written
into the file as they came, so a value containing a newline added extra lines to the
`[client]` section. Whoever controls what the GLPI server sends (a compromised server, or a
GLPI admin) can then set any option of the `mysql` client on every agent that runs the
database inventory.

## Root cause

`lib/GLPI/Agent/Task/Inventory/Generic/Databases/MySQL.pm` (1.19):

```perl
sub _mysqlOptionsFile {
    my ($credential) = @_;
    ...
        print $fh "[client]\n";
        print $fh "host = $credential->{host}\n" if $credential->{host};
        print $fh "port = $credential->{port}\n" if $credential->{port};
        print $fh "user = $credential->{login}\n" if $credential->{login};
        print $fh "socket = $credential->{socket}\n" if $credential->{socket};
        if ($credential->{password}) {
            my $password = $credential->{password};
            if ($password =~ /[#'"]/) {
                $password =~ s/"/\\"/g;
                $password = '"'.$password.'"'
            }
            print $fh "password = $password\n";
        }
```

`host`, `port`, `login` and `socket` are written as they arrive. The password only gets
quotes when it contains `#`, `'` or `"`; a newline is never handled. The credentials come
from the server's answer in `Databases.pm::_credentials()`, which passed them on without any
check.

## Impact

A value like `login = "inventory\nplugin-dir = /some/dir\ndefault-auth = name"` turns into
three lines in the option file, and the `mysql` client reads all three. The server already
decides the host, user and password; with this it can also:

- set any other option allowed in `[client]` and change how the client behaves;
- make the client load a shared library through `plugin-dir` and `default-auth`. This means
  running code on the inventoried machine, as the user the agent runs as (usually root or
  SYSTEM). It needs a library the attacker can place, or one already on disk.

The attacker needs control of the GLPI server or of the credentials configured in it, and
only machines with the `mysql` client installed and database inventory enabled are affected.
That is why the rating is `PR:H`. What it gives in return is a way from the GLPI server onto
every agent it manages.

## Proof of concept

Not published. It is enough to configure a database credential in GLPI whose login or host
contains a newline followed by any `[client]` option, run database inventory on an agent, and
look at the temporary `my-XXXXXX.cnf` it creates.

## Fix

GLPI Agent 1.20, commit [`5c832116ad`](https://github.com/glpi-project/glpi-agent/commit/5c832116ad):

- `Databases.pm` checks every credential field received from the server with
  `getSanitizedString()` and discards any credential that contains control characters, so the
  newline never reaches the option file. This applies to every database module, not only
  MySQL.
- `MySQL.pm` now builds the `mysql` command as a list (`--defaults-extra-file`, `-q`, `-sN`,
  `-e`) instead of a single string.

If you can't upgrade yet, set `no-category = database` in the agent configuration to turn off
database inventory. Machines without the `mysql` client are not affected
(`mysql --version` tells you whether it is installed).

## Timeline

- 2026-09-24 — fix merged and GLPI Agent 1.20 released
- 2026-10-30 — advisory published
