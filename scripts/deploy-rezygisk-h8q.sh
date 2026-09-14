#!/usr/bin/env bash
set -euo pipefail

readonly DEVICE_TMP="/data/local/tmp"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOCAL_DIR="${GHOSTLOCK_LOCAL_DIR:-$REPO_DIR/local}"
OUTPUT_DIR="${REZYGISK_OUTPUT_DIR:-$LOCAL_DIR/build/rezygisk-h8q}"
ADB_BIN="${ADB:-adb}"
ADB_ARGS=()
DEVICE_ARGS=()

usage() {
  echo "Usage: $0 [--install-zip] [--restart-zygote] [--force-rescue-level] [--verify] [ADB_SERIAL]" >&2
}

while (( $# > 0 )); do
  case "$1" in
    --restart-zygote|--force-rescue-level|--verify|--install-zip)
      DEVICE_ARGS+=("$1")
      ;;
    -*) usage; exit 2 ;;
    *)
      (( ${#ADB_ARGS[@]} == 0 )) || { usage; exit 2; }
      ADB_ARGS=(-s "$1")
      ;;
  esac
  shift
done

adb_cmd() {
  "$ADB_BIN" "${ADB_ARGS[@]}" "$@"
}

for artifact in libzygisk.so zygisk-ptrace64 zygiskd64; do
  [[ -f "$OUTPUT_DIR/$artifact" ]] || {
    echo "Missing $OUTPUT_DIR/$artifact; run scripts/build-rezygisk-h8q.sh" >&2
    exit 1
  }
done

adb_cmd wait-for-device
adb_cmd push \
  "$OUTPUT_DIR/libzygisk.so" \
  "$DEVICE_TMP/rezygisk-libzygisk.so" >/dev/null
adb_cmd push \
  "$OUTPUT_DIR/zygisk-ptrace64" \
  "$DEVICE_TMP/rezygisk-zygisk-ptrace64" >/dev/null
adb_cmd push \
  "$OUTPUT_DIR/zygiskd64" \
  "$DEVICE_TMP/rezygisk-zygiskd64" >/dev/null
adb_cmd push \
  "$SCRIPT_DIR/deploy-rezygisk-on-device.sh" \
  "$DEVICE_TMP/deploy-rezygisk-on-device.sh" >/dev/null
adb_cmd push \
  "$SCRIPT_DIR/prepare-rezygisk-on-device.sh" \
  "$DEVICE_TMP/prepare-rezygisk-on-device.sh" >/dev/null

if [[ -f "$OUTPUT_DIR/rezygisk-h8q.zip" ]]; then
  adb_cmd push \
    "$OUTPUT_DIR/rezygisk-h8q.zip" \
    "$DEVICE_TMP/rezygisk-h8q.zip" >/dev/null
fi

adb_cmd shell "chmod 755 \
  $DEVICE_TMP/rezygisk-libzygisk.so \
  $DEVICE_TMP/rezygisk-zygisk-ptrace64 \
  $DEVICE_TMP/rezygisk-zygiskd64 \
  $DEVICE_TMP/deploy-rezygisk-on-device.sh \
  $DEVICE_TMP/prepare-rezygisk-on-device.sh"

quoted_args=""
for argument in "${DEVICE_ARGS[@]}"; do
  quoted_args+=" $argument"
done
adb_cmd shell "$DEVICE_TMP/deploy-rezygisk-on-device.sh$quoted_args"
