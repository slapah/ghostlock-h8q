#!/system/bin/sh
set -eu

DEVICE_TMP=/data/local/tmp
MODULE_DIR=/data/adb/modules/rezygisk
UPDATE_DIR=/data/adb/modules_update/rezygisk

fail() {
  echo "prepare-rezygisk: $*" >&2
  exit 1
}

uid="$(id -u)"
[ "$uid" = 0 ] || [ "$uid" = 2000 ] || fail "need uid 0 (YukiSU su) or uid 2000"

rezygisk_named() {
  want="$1"
  ps -A -o PID,NAME 2>/dev/null |
    while read proc_pid proc_name; do
      [ "$proc_name" = "$want" ] || continue
      printf '%s\n' "$proc_pid"
    done
}

rezygisk_workers() {
  rezygisk_named zygiskd64
  ps -A -o PID,NAME 2>/dev/null |
    while read proc_pid proc_name; do
      case "$proc_name" in
        zygiskd64-*) printf '%s\n' "$proc_pid" ;;
      esac
    done
}

rezygisk_monitors() {
  rezygisk_named zygisk-ptrace64
}

stop_named() {
  pids="$1"
  [ -n "$pids" ] || return 0
  kill -TERM $pids 2>/dev/null || true
  attempt=0
  while [ "$attempt" -lt 20 ]; do
    remaining="$($2)"
    [ -z "$remaining" ] && return 0
    sleep 0.1
    attempt=$((attempt + 1))
  done
  remaining="$($2)"
  [ -z "$remaining" ] && return 0
  kill -KILL $remaining 2>/dev/null || true
  sleep 0.1
  remaining="$($2)"
  [ -z "$remaining" ] || fail "old processes did not exit: $remaining"
}

[ -d "$MODULE_DIR" ] || [ -d "$UPDATE_DIR" ] || fail "ReZygisk module is not installed"
for artifact in \
  "$DEVICE_TMP/rezygisk-libzygisk.so" \
  "$DEVICE_TMP/rezygisk-zygisk-ptrace64" \
  "$DEVICE_TMP/rezygisk-zygiskd64"; do
  [ -f "$artifact" ] || fail "missing staged artifact: $artifact"
done

mkdir -p "$MODULE_DIR/bin" "$MODULE_DIR/lib64"
if [ -x "$MODULE_DIR/bin/zygisk-ptrace64" ]; then
  "$MODULE_DIR/bin/zygisk-ptrace64" ctl exit >/dev/null 2>&1 || true
fi
stop_named "$(rezygisk_monitors)" rezygisk_monitors
stop_named "$(rezygisk_workers)" rezygisk_workers

if [ -d "$UPDATE_DIR" ]; then
  cp -a "$UPDATE_DIR/." "$MODULE_DIR/"
  rm -f "$MODULE_DIR/update"
fi

[ -f "$MODULE_DIR/module.prop" ] || printf '%s\n' \
  "id=rezygisk" \
  "name=ReZygisk" \
  "version=h8q-fileless" \
  "versionCode=1" \
  "author=PerformanC" \
  "description=Samsung DEFEX fileless ReZygisk for h8q/q8q" \
  >"$MODULE_DIR/module.prop"
cp "$MODULE_DIR/module.prop" "$MODULE_DIR/module.prop.bak"

cd "$MODULE_DIR"

cp "$DEVICE_TMP/rezygisk-libzygisk.so" lib64/.libzygisk.so.new
cp "$DEVICE_TMP/rezygisk-zygisk-ptrace64" bin/.zygisk-ptrace64.new
cp "$DEVICE_TMP/rezygisk-zygiskd64" bin/.zygiskd64.new
chmod 755 \
  lib64/.libzygisk.so.new \
  bin/.zygisk-ptrace64.new \
  bin/.zygiskd64.new
chcon u:object_r:system_file:s0 \
  lib64/.libzygisk.so.new \
  bin/.zygisk-ptrace64.new \
  bin/.zygiskd64.new 2>/dev/null || true
mv -f lib64/.libzygisk.so.new lib64/libzygisk.so
mv -f bin/.zygisk-ptrace64.new bin/zygisk-ptrace64
mv -f bin/.zygiskd64.new bin/zygiskd64

if [ -x /data/adb/ksud ] && [ ! -e /data/adb/ksu/bin/ksud ]; then
  mkdir -p /data/adb/ksu/bin
  ln -sf /data/adb/ksud /data/adb/ksu/bin/ksud
fi

chmod 711 /data/adb
rm -rf /data/adb/rezygisk
mkdir -p /data/adb/rezygisk
chmod 555 /data/adb/rezygisk
chcon u:object_r:system_file:s0 /data/adb/rezygisk 2>/dev/null || true
: >"$DEVICE_TMP/rezygisk-monitor.log"
nohup ./bin/zygisk-ptrace64 monitor </dev/null \
  >"$DEVICE_TMP/rezygisk-monitor.log" 2>&1 &
