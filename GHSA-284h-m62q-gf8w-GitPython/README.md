# GHSA-284h-m62q-gf8w — GitPython config read→corrupt-on-rewrite RCE via `core.hooksPath`

- **Advisory:** [GHSA-284h-m62q-gf8w](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-284h-m62q-gf8w)
- **Severity:** High · **CWE-88 / CWE-94** (argument/code injection)
- **Affected:** GitPython `<= 3.1.58` · **Fixed:** `>= 3.1.59`
- **Impact:** arbitrary code execution via an injected `core.hooksPath`, requiring no unsafe
  caller argument at all.

## Root cause

`GitConfigParser`'s injection guards (`UNSAFE_CONFIG_CHARS_RE` / `_value_to_string_safe()`)
only cover the write-**argument** surface (`set()`, `set_value()`, ...). A legitimately-encoded
multi-line config value (standard quoted + backslash-continuation syntax, containing an escaped
`\n` that decodes to a real embedded newline in memory — 100% valid git-config syntax, no raw
control byte on disk) is corrupted into a **new, live config key** the moment `write_section()`
re-serializes it during any unrelated write, because that serializer uses the *unsafe*
`_value_to_string()` path and a bogus continuation scheme real git doesn't recognize. If the
smuggled second "line" reads `hooksPath = <attacker path>`, it becomes a real `core.hooksPath`
after one unrelated `config_writer()` write, firing on the next hook-triggering git operation.

## PoC

`poc/poc_config_hookspath.py` plants a dormant, spec-compliant multi-line value in `.git/config`,
performs one totally unrelated benign write (`set_value("user", "name", ...)`), confirms
`core.hookspath` is now live per real `git config --get`, then runs a normal `git commit` and
shows the injected hook fires (writes a benign marker file). Fully local and benign.

```sh
PYTHONPATH="<GitPython checkout>:<checkout>/gitdb:<checkout>/smmap" \
  python3 poc/poc_config_hookspath.py /tmp/gitpython-002-poc
```

## Fix

Make `write_section()`/`_write()` re-quote/escape **every** resident value (including those that
originated from `_read()`) using the safe value-to-string path, so an embedded newline is always
re-emitted as a properly quoted + backslash-continued value instead of a bare new line.
