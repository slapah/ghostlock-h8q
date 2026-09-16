#!/system/bin/sh
# KernelSU runs this in PID 1's mount namespace, before Android userspace is
# stopped for an emulated soft reboot. ReZygisk's daemon/ptrace monitor and
# LSPosed's lspd otherwise survive the transition; KernelSU then re-runs the
# module service stage and starts a second set, so two lspd (and two zygiskd)
# race for the same control socket and LSPosed misbehaves. Terminate the old
# daemons here so the service stage brings up exactly one of each.

MODDIR=${0%/*}
RESULT_FILE="$MODDIR/last-result.txt"

terminated=
killed=
failures=

# The exact daemon comm/first-arg values to match. zygiskd / zygiskd64 =
# ReZygisk daemon; zygisk-ptrace* = its zygote monitor; lspd = LSPosed daemon.
DAEMONS="zygiskd zygiskd64 zygisk-ptrace32 zygisk-ptrace64 lspd"

matches_daemon() {
    _md_pid=$1
    case "$_md_pid" in ''|*[!0-9]*) return 1 ;; esac
    [ -r "/proc/$_md_pid/cmdline" ] || return 1
    _md_arg0=$(tr '\000' '\n' < "/proc/$_md_pid/cmdline" 2>/dev/null | sed -n '1p')
    # Compare on the basename so a full path (/data/adb/.../lspd) still matches.
    _md_base=${_md_arg0##*/}
    for _md_want in $DAEMONS; do
        [ "$_md_base" = "$_md_want" ] && return 0
    done
    return 1
}

wait_exit() {
    _we_pid=$1 _we_n=0
    while matches_daemon "$_we_pid"; do
        [ "$_we_n" -ge 10 ] && return 1
        sleep 0.1
        _we_n=$((_we_n + 1))
    done
    return 0
}

for name in $DAEMONS; do
    for pid in $(pgrep -x "$name" 2>/dev/null; pgrep -f "/$name\$" 2>/dev/null); do
        matches_daemon "$pid" || { failures="$failures reused:$pid"; continue; }
        if kill "$pid" 2>/dev/null && wait_exit "$pid"; then
            terminated="$terminated $name:$pid"
            continue
        fi
        # Revalidate immediately before SIGKILL so a recycled PID is never hit.
        if matches_daemon "$pid" && kill -9 "$pid" 2>/dev/null && wait_exit "$pid"; then
            killed="$killed $name:$pid"
        elif matches_daemon "$pid"; then
            failures="$failures alive:$name:$pid"
        fi
    done
done

status=ok
[ -z "$failures" ] || status=degraded
{
    printf 'status=%s\n' "$status"
    printf 'terminated:%s\n' "${terminated:- none}"
    printf 'sigkilled:%s\n' "${killed:- none}"
    printf 'failures:%s\n' "${failures:- none}"
} > "$RESULT_FILE"
chmod 0600 "$RESULT_FILE" 2>/dev/null

if [ "$status" = ok ]; then
    log -p i -t ReZygiskLSPosedGuard "stale zygisk/lspd daemons stopped"
else
    log -p w -t ReZygiskLSPosedGuard "cleanup incomplete; see $RESULT_FILE"
fi
exit 0
