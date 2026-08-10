# GHSA-7833-fr7j-v32q — GitPython local file disclosure via `[include]` in untrusted `.gitmodules`

- **Advisory:** [GHSA-7833-fr7j-v32q](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-7833-fr7j-v32q)
- **Severity:** High · **CWE-200 / CWE-73** (exposure of sensitive information / path control)
- **Affected:** GitPython `<= 3.1.58` · **Fixed:** `>= 3.1.59`
- **Impact:** non-blind first-line disclosure of any locally-readable file, triggered by a
  routine, read-only `repo.submodules` call.

## Root cause

`GitConfigParser` defaults `merge_includes=True`. `Repo.config_writer()` was hardened against
this in 2023 (`41ecc6a4`, "Disable merge_includes in config writers"), but
`Submodule._config_parser()` — which parses `.gitmodules`, content that is **always**
attacker-controlled the moment a repo is cloned — never got the same treatment. A `.gitmodules`
with `[include] path = /etc/passwd` (or any local path) makes `GitConfigParser._read()` open the
target file; if it isn't valid git-config syntax (true of almost any non-config file), Python's
own `configparser.MissingSectionHeaderError` embeds the target file's **first line verbatim** in
its message, which propagates straight out of `repo.submodules` — no `update()`/`init()`/checkout
required.

## PoC

`poc/poc_gitmodules_include_lfi.py` clones a repo whose `.gitmodules` targets a throwaway secret
file (or `/etc/passwd` if you pass a path), then shows `list(repo.submodules)` raising
`MissingSectionHeaderError` with the target's first line embedded verbatim. Fully local, only
reads the given file, never exfiltrates it anywhere but the local terminal.

```sh
PYTHONPATH="<GitPython checkout>:<checkout>/gitdb:<checkout>/smmap" \
  python3 poc/poc_gitmodules_include_lfi.py /tmp/gitpython-003-poc
```

## Fix

Pass `merge_includes=False` when constructing `SubmoduleConfigParser` in
`Submodule._config_parser()` (`git/objects/submodule/base.py`), mirroring the existing
`Repo.config_writer()` fix.
