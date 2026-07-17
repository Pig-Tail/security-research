# GHSA-p34x-fmph-9fjx — flyto-core arbitrary file write (incomplete fix of GHSA-2956)

- **Advisory:** [GHSA-p34x-fmph-9fjx](https://github.com/flytohub/flyto-core/security/advisories/GHSA-p34x-fmph-9fjx)
- **Severity:** Critical · **CWE-22** (path traversal → arbitrary write)
- **Impact:** write files outside the intended sandbox → code execution / config overwrite.

## Root cause

Incomplete fix of GHSA-2956. That advisory added `validate_path_with_env_config()` to confine
writes to `FLYTO_SANDBOX_DIR`, but the guard was only wired into some write paths. The sibling
atomic modules `data.csv_write` and `data.json_to_csv` write their `file_path` / `output_path`
directly, **without** calling the guard — so an attacker-supplied absolute path escapes the
sandbox even though the "fixed" central validator would reject it.

## PoC

`poc/poc_arbitrary_write.py` first shows `validate_path_with_env_config()` correctly **rejects** an
out-of-sandbox path (proving the guard exists and the modules simply bypass it), then drives the two
unguarded modules to write **sentinel** CSV/JSON files outside the sandbox (into a sibling temp
dir). Fully local and benign.

```sh
# point FLYTO_SRC at a local flyto-core checkout's src/ dir
FLYTO_SRC=/path/to/flyto-core/src python3 poc/poc_arbitrary_write.py
```

## Fix

Route every module that writes a caller-supplied path through
`validate_path_with_env_config()` (not just the ones patched in GHSA-2956).
