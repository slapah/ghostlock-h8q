#!/usr/bin/env bash
set -euo pipefail

readonly REZYGISK_REPOSITORY="https://github.com/PerformanC/ReZygisk.git"
readonly REZYGISK_COMMIT="333d423cde1a959958d9fce380bd017cf6c1cf64"
readonly CSOLOADER_COMMIT="4cf67b87a8d39e765073a63fea148e6d409e4554"
readonly PLTI_COMMIT="bc9319d1ca91fb9ca01f9e741e6a89cbf55115f7"
readonly ARCH="arm64-v8a"
readonly API_LEVEL=25

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
INVOCATION_DIR="$(pwd -P)"
LOCAL_DIR="${GHOSTLOCK_LOCAL_DIR:-$REPO_DIR/local}"
SOURCE_DIR="${REZYGISK_SOURCE_DIR:-$LOCAL_DIR/third_party/rezygisk-src}"
BUILD_DIR="${REZYGISK_BUILD_DIR:-$LOCAL_DIR/build/rezygisk-fileless}"
OUTPUT_DIR="${REZYGISK_OUTPUT_DIR:-$LOCAL_DIR/build/rezygisk-h8q}"
NDK_PATH="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-$HOME/android-ndk-cache/android-ndk-r29}}"
BUILD_TYPE="${REZYGISK_BUILD_TYPE:-debug}"

make_absolute() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *) printf '%s/%s\n' "$INVOCATION_DIR" "$1" ;;
  esac
}

LOCAL_DIR="$(make_absolute "$LOCAL_DIR")"
SOURCE_DIR="$(make_absolute "$SOURCE_DIR")"
BUILD_DIR="$(make_absolute "$BUILD_DIR")"
OUTPUT_DIR="$(make_absolute "$OUTPUT_DIR")"
NDK_PATH="$(make_absolute "$NDK_PATH")"

readonly FILELESS_PATCH="$REPO_DIR/patches/rezygisk-samsung-defex-fileless.patch"
readonly CSOLOADER_PATCH="$REPO_DIR/patches/csoloader-samsung-defex-fd.patch"
readonly KSUD_PATCH="$REPO_DIR/patches/rezygisk-h8q-ksud-path.patch"

fail() {
  echo "build-rezygisk-h8q: $*" >&2
  exit 1
}

apply_once() {
  local source_dir="$1"
  local patch_file="$2"

  if git -C "$source_dir" apply --check "$patch_file" 2>/dev/null; then
    git -C "$source_dir" apply "$patch_file"
  elif git -C "$source_dir" apply --reverse --check "$patch_file" 2>/dev/null; then
    echo "Already applied: ${patch_file##*/}"
  else
    fail "checkout does not match ${patch_file##*/}"
  fi
}

for command in git make sha256sum python3; do
  command -v "$command" >/dev/null || fail "missing host command: $command"
done

# ReZygisk's Makefile shells out to `zip`. Provide a Python fallback when
# Info-ZIP is not installed (this host has no package-install rights).
if ! command -v zip >/dev/null; then
  mkdir -p "$LOCAL_DIR/tools"
  cat >"$LOCAL_DIR/tools/zip" <<'PY'
#!/usr/bin/env python3
import fnmatch
import os
import sys
import zipfile
from pathlib import Path

args = sys.argv[1:]
excludes = []
outfile = None
inputs = []
i = 0
while i < len(args):
    arg = args[i]
    if arg == "-x":
        i += 1
        excludes.append(args[i])
    elif arg.startswith("-"):
        pass
    elif outfile is None:
        outfile = arg
    else:
        inputs.append(arg)
    i += 1
if not outfile:
    sys.exit("zip: missing output archive")

def excluded(name: str) -> bool:
    base = os.path.basename(name)
    return any(fnmatch.fnmatch(name, pat) or fnmatch.fnmatch(base, pat) for pat in excludes)

with zipfile.ZipFile(outfile, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for item in inputs or ["."]:
        path = Path(item)
        if path.is_dir():
            for file in path.rglob("*"):
                if not file.is_file():
                    continue
                arcname = str(file.relative_to(path if item != "." else "."))
                if item == ".":
                    arcname = str(file.relative_to("."))
                if not excluded(arcname):
                    archive.write(file, arcname)
        elif path.is_file() and not excluded(path.name):
            archive.write(path, path.name)
PY
  chmod +x "$LOCAL_DIR/tools/zip"
  export PATH="$LOCAL_DIR/tools:$PATH"
fi
[[ -x "$NDK_PATH/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ]] ||
  fail "Android NDK not found at $NDK_PATH"
[[ -f "$FILELESS_PATCH" && -f "$CSOLOADER_PATCH" && -f "$KSUD_PATCH" ]] ||
  fail "tracked ReZygisk patch files are missing"

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  mkdir -p "$(dirname -- "$SOURCE_DIR")"
  git clone --filter=blob:none "$REZYGISK_REPOSITORY" "$SOURCE_DIR"
fi

current_commit="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$current_commit" != "$REZYGISK_COMMIT" ]]; then
  [[ -z "$(git -C "$SOURCE_DIR" status --porcelain)" ]] ||
    fail "refusing to replace a dirty ReZygisk checkout at $current_commit"
  git -C "$SOURCE_DIR" fetch origin "$REZYGISK_COMMIT"
  git -C "$SOURCE_DIR" checkout --detach "$REZYGISK_COMMIT"
fi

git -C "$SOURCE_DIR" submodule update --init --recursive

csoloader_dir="$SOURCE_DIR/loader/src/external/csoloader"
plti_dir="$SOURCE_DIR/loader/src/external/plti"
[[ "$(git -C "$csoloader_dir" rev-parse HEAD)" == "$CSOLOADER_COMMIT" ]] ||
  fail "unexpected CSOLoader submodule commit"
[[ "$(git -C "$plti_dir" rev-parse HEAD)" == "$PLTI_COMMIT" ]] ||
  fail "unexpected PLT hook submodule commit"

apply_once "$SOURCE_DIR" "$KSUD_PATCH"
apply_once "$SOURCE_DIR" "$FILELESS_PATCH"
apply_once "$csoloader_dir" "$CSOLOADER_PATCH"

version="v1.0.0-h8q-333d423-$BUILD_TYPE"

# Build CSOLoader first. ReZygisk's recursive Makefile otherwise allows its
# archive to race the arm64 injector link when a checkout has no build cache.
make -B -C "$csoloader_dir" \
  BUILD_TYPE="$BUILD_TYPE" \
  ARCH="$ARCH" \
  NDK_PATH="$NDK_PATH" \
  API_LEVEL="$API_LEVEL" \
  out="$BUILD_DIR/obj/$BUILD_TYPE/csoloader/$ARCH"

# YukiSU reports a git-count VERSION_CODE far below ReZygisk's stock
# MIN_KSUD_VERSION=11425. Relax the zip installer so `ksud module
# install` works after late-load on h8q.
rm -f "$BUILD_DIR/module-$BUILD_TYPE.done"
make -C "$SOURCE_DIR" \
  BUILD_TYPE="$BUILD_TYPE" \
  BUILD_DIR="$BUILD_DIR" \
  ZKSU_VERSION="$version" \
  NDK_PATH="$NDK_PATH" \
  ARCHS="$ARCH" \
  MIN_KSU_VERSION=1 \
  MIN_KSUD_VERSION=1

mkdir -p "$OUTPUT_DIR"
cp "$BUILD_DIR/obj/$BUILD_TYPE/loader/$ARCH/stripped/libzygisk.so" \
  "$OUTPUT_DIR/libzygisk.so"
cp "$BUILD_DIR/obj/$BUILD_TYPE/loader/$ARCH/stripped/libzygisk_ptrace.so" \
  "$OUTPUT_DIR/zygisk-ptrace64"
cp "$BUILD_DIR/obj/$BUILD_TYPE/zygiskd/$ARCH/zygiskd" \
  "$OUTPUT_DIR/zygiskd64"
chmod 755 \
  "$OUTPUT_DIR/libzygisk.so" \
  "$OUTPUT_DIR/zygisk-ptrace64" \
  "$OUTPUT_DIR/zygiskd64"

zip_file="$(find "$BUILD_DIR/out" -maxdepth 1 -name 'ReZygisk-*.zip' -print -quit)"
[[ -n "$zip_file" ]] || fail "ReZygisk module zip was not produced"
cp "$zip_file" "$OUTPUT_DIR/rezygisk-h8q.zip"

echo "ReZygisk h8q artifacts:"
sha256sum \
  "$OUTPUT_DIR/libzygisk.so" \
  "$OUTPUT_DIR/zygisk-ptrace64" \
  "$OUTPUT_DIR/zygiskd64" \
  "$OUTPUT_DIR/rezygisk-h8q.zip"
