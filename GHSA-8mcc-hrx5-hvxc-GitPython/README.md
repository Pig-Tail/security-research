# GHSA-8mcc-hrx5-hvxc — GitPython arbitrary git-directory creation via `--separate-git-dir`

- **Advisory:** [GHSA-8mcc-hrx5-hvxc](https://github.com/gitpython-developers/GitPython/security/advisories/GHSA-8mcc-hrx5-hvxc)
- **Severity:** High · **CWE-22 / CWE-73** (external control of file name/path)
- **Affected:** GitPython `<= 3.1.58` · **Fixed:** `>= 3.1.59`
- **Impact:** `Repo.clone_from()`/`Repo.clone()` write a full git directory (`config`, `hooks/`,
  `objects/`, `refs/`, ...) to an attacker-controlled path outside the intended clone
  destination.

## Root cause

`Repo.unsafe_git_clone_options` (the denylist `clone_from()`/`clone()` check kwargs against by
default) omits `--separate-git-dir`, even though the *sibling* `unsafe_git_init_options` list
blocks the exact same option for `Repo.init()`, and the `clone_from`/`clone` docstring itself
documents `--separate-git-dir` as one of the options `allow_unsafe_options` is supposed to gate.
A parity gap between two denylists guarding the same primitive — same class as the project's
other "denylist missing an equally-dangerous sibling option" advisories.

## PoC

`poc/poc_separate_git_dir.py` clones a local throwaway repo with `separate_git_dir=<outside
path>` and default `allow_unsafe_options=False`, then confirms the full git directory (including
`hooks/`) was created outside the clone destination. Fully local and benign.

```sh
PYTHONPATH="<GitPython checkout>:<checkout>/gitdb:<checkout>/smmap" \
  python3 poc/poc_separate_git_dir.py /tmp/gitpython-001-poc
```

## Fix

Add `"--separate-git-dir"` to `Repo.unsafe_git_clone_options` in `git/repo/base.py`, matching
`unsafe_git_init_options`.
