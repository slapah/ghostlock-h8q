#!/system/bin/sh
set -eu

DEVICE_TMP=/data/local/tmp
MODULE_DIR=/data/adb/modules/rezygisk
PREPARER="$DEVICE_TMP/prepare-rezygisk-on-device.sh"
ZIP_FILE="$DEVICE_TMP/rezygisk-h8q.zip"
RESTART_ZYGOTE=0
FORCE_RESCUE_LEVEL=0
VERIFY_ONLY=0
INSTALL_ZIP=0

usage() {
  echo "Usage: $0 [--install-zip] [--restart-zygote] [--force-rescue-level] [--verify]" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --restart-zygote) RESTART_ZYGOTE=1 ;;
    --force-rescue-level) FORCE_RESCUE_LEVEL=1 ;;
    --verify) VERIFY_ONLY=1 ;;
    --install-zip) INSTALL_ZIP=1 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

fail() {
  echo "deploy-rezygisk: $*" >&2
  exit 1
}

find_ksud() {
  as_root '
    for candidate in /data/adb/ksud /data/adb/ksu/bin/ksud; do
      [ -x "$candidate" ] && { printf "%s\n" "$candidate"; exit 0; }
    done
    command -v ksud && exit 0
    exit 1
  ' | tail -n 1
}

find_su() {
  for candidate in /system/bin/su /debug_ramdisk/su; do
    [ -x "$candidate" ] && { printf '%s\n' "$candidate"; return 0; }
  done
  command -v su
}

as_root() {
  printf '%s\n' "$1" >"$DEVICE_TMP/rezygisk-rootcmd.sh"
  chmod 700 "$DEVICE_TMP/rezygisk-rootcmd.sh"
  if [ "$(id -u)" = 0 ]; then
    /system/bin/sh "$DEVICE_TMP/rezygisk-rootcmd.sh"
  else
    "$(find_su)" -c "/system/bin/sh $DEVICE_TMP/rezygisk-rootcmd.sh"
  fi
}

root_uid() {
  as_root 'id -u' | tail -n 1
}

single_pid() {
  process_pids="$(pidof "$1" 2>/dev/null || true)"
  [ -n "$process_pids" ] && [ "${process_pids#* }" = "$process_pids" ]
}

stack_is_ready() {
  single_pid zygisk-ptrace64 || return 1
  single_pid zygiskd64 || return 1
  as_root "cmp -s \
    $DEVICE_TMP/rezygisk-libzygisk.so \
    $MODULE_DIR/lib64/libzygisk.so" || return 1
  as_root "cmp -s \
    $DEVICE_TMP/rezygisk-zygisk-ptrace64 \
    $MODULE_DIR/bin/zygisk-ptrace64" || return 1
  as_root "cmp -s \
    $DEVICE_TMP/rezygisk-zygiskd64 \
    $MODULE_DIR/bin/zygiskd64" || return 1
  compact_state="$(as_root "cat /data/adb/rezygisk/state.json" | tr -d '[:space:]')"
  case "$compact_state" in
    *'"root":"KernelSU"'*'"rezygiskd":{"64":{"state":1'*'"zygote":{"64":1'*) ;;
    *) return 1 ;;
  esac
  service check activity 2>/dev/null | grep -q 'found' || return 1
  return 0
}

device="$(getprop ro.product.device)"
case "$device" in
  h8q|q8q) ;;
  *) fail "unexpected device $device (want h8q or q8q)" ;;
esac

[ "$(id -u)" = 0 ] || [ "$(id -u)" = 2000 ] ||
  fail "run from an ADB shell or as root"
[ "$(root_uid)" = 0 ] || fail "YukiSU su is not granting uid 0"
[ -x "$PREPARER" ] || fail "ReZygisk preparer is not staged"

for artifact in \
  "$DEVICE_TMP/rezygisk-libzygisk.so" \
  "$DEVICE_TMP/rezygisk-zygisk-ptrace64" \
  "$DEVICE_TMP/rezygisk-zygiskd64"; do
  [ -f "$artifact" ] || fail "missing staged artifact: $artifact"
done

if [ "$VERIFY_ONLY" = 1 ]; then
  stack_is_ready || fail "ReZygisk is not attached to zygote64"
  as_root "cat /data/adb/rezygisk/state.json"
  echo "ZYGISK_READY=1"
  exit 0
fi

if [ "$INSTALL_ZIP" = 1 ]; then
  [ -f "$ZIP_FILE" ] || fail "missing $ZIP_FILE"
  ksud="$(find_ksud)"
  [ -n "$ksud" ] || fail "ksud not found under /data/adb"
  as_root "$ksud module install $ZIP_FILE"
fi

if [ "$RESTART_ZYGOTE" = 1 ] && stack_is_ready; then
  echo "ReZygisk is already attached to zygote64."
  cat /data/adb/rezygisk/state.json
  exit 0
fi

as_root "/system/bin/sh $PREPARER"
if as_root "test -f $MODULE_DIR/sepolicy.rule"; then
  as_root "ksud sepolicy apply $MODULE_DIR/sepolicy.rule" ||
    fail "failed to apply ReZygisk sepolicy.rule"
fi

attempt=0
while [ "$attempt" -lt 50 ]; do
  pidof zygisk-ptrace64 >/dev/null 2>&1 && break
  sleep 0.1
  attempt=$((attempt + 1))
done
pidof zygisk-ptrace64 >/dev/null 2>&1 || {
  echo "monitor log:" >&2
  cat "$DEVICE_TMP/rezygisk-monitor.log" >&2 || true
  fail "monitor did not start"
}

echo "ReZygisk monitor started. Installed hashes:"
as_root "sha256sum \
  $MODULE_DIR/lib64/libzygisk.so \
  $MODULE_DIR/bin/zygisk-ptrace64 \
  $MODULE_DIR/bin/zygiskd64"

if [ "$RESTART_ZYGOTE" != 1 ]; then
  echo "Monitor is ready; zygote was not restarted."
  echo "Pass --restart-zygote to attach this boot."
  exit 0
fi

rescue_level="$(getprop persist.sys.rescue_level)"
case "$rescue_level" in
  ""|*[!0-9]*) rescue_level=0 ;;
esac
if [ "$rescue_level" -ge 4 ] && [ "$FORCE_RESCUE_LEVEL" != 1 ]; then
  fail "Android RescueParty level is $rescue_level; refusing a framework restart"
fi

zygote_pid="$(ps -A -o PID,NAME | awk '$2 == "zygote64" { print $1; exit }')"
[ -n "$zygote_pid" ] || fail "zygote64 was not found"
as_root "kill -KILL $zygote_pid"

attempt=0
while [ "$attempt" -lt 200 ]; do
  new_pid="$(ps -A -o PID,NAME | awk '$2 == "zygote64" { print $1; exit }')"
  if [ -n "$new_pid" ] && [ "$new_pid" != "$zygote_pid" ] &&
      grep -q '"state": 1' /data/adb/rezygisk/state.json 2>/dev/null; then
    break
  fi
  sleep 0.1
  attempt=$((attempt + 1))
done

[ "$attempt" -lt 200 ] || {
  echo "monitor log:" >&2
  cat "$DEVICE_TMP/rezygisk-monitor.log" >&2 || true
  echo "state.json:" >&2
  cat /data/adb/rezygisk/state.json >&2 || true
  fail "ReZygisk did not attach to the new zygote"
}
service check activity | grep -q 'found' || fail "ActivityManager is unavailable"
echo "ReZygisk attached to zygote64 PID $new_pid."
cat /data/adb/rezygisk/state.json
echo "ZYGISK_READY=1"
