#!/usr/bin/env bash
#
# build-yukisu-h8q.sh — finish the KernelSU -> YukiSU switch for the GhostLock
# (CVE-2026-43499) h8q/q8q chain end to end.
#
# Stages (each can be skipped with a flag):
#   1. env      set up NDK / SDK / Java / gradle from ~/android-toolchain
#   2. clone    fetch YukiSU (github.com/Anatdx/YukiSU) pinned to --yukisu-ref
#   3. lkm      obtain the android16-6.12 kernelsu.ko (the LKM ksud embeds):
#                 --ko PATH        use a prebuilt Samsung-patched .ko  (Fold 8: REQUIRED)
#                 --build-lkm      build it in the YukiSU DDK docker image, optionally
#                                  after applying --samsung-patch PATH to kernel/
#                 --stock-lkm      download the stock released .ko (TEST ONLY — panics
#                                  on a real KDP/RKP/DEFEX Samsung kernel)
#   3b. vermagic rewrite the staged .ko's vermagic to the h8q stock kernel release
#                 (scripts/patch-ko-vermagic.sh) — without this init_module() is
#                 rejected ENOEXEC: the DDK image builds 6.12.76-4k vermagic, the
#                 Fold 8 runs 6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k,
#                 and YukiSU's ksud loader does no runtime vermagic patching.
#   4. ksud     build YukiSU's C++ ksud (embeds the .ko) via YukiSU scripts/build.sh
#   5. package  drop ksud into the GhostLock APK assets, rebuild preload.so + ReZygisk
#               + the GhostLock APK
#   6. manager  download the signed YukiSU manager APK (com.anatdx.yukisu)
#   7. deploy   (--deploy) adb-install the manager + GhostLock APK to a device
#
# The kernel LKM is the only artifact this script cannot conjure for you: a
# Samsung Fold 8 needs the BuSung-dev KDP/RKP/DEFEX patch ported onto the YukiSU
# 6.12 kernel sources. Supply the built .ko with --ko, or drive the DDK build
# with --build-lkm (needs docker + a patch that applies to YukiSU's kernel/).
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Defaults / config
# --------------------------------------------------------------------------- #
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

KMI="android16-6.12"                       # h8q kernel is 6.12.58-android16-6
YUKISU_REPO="https://github.com/Anatdx/YukiSU.git"
YUKISU_REF="v1.6.0"                        # clone tag AND manager release tag (same signing key)
WORKDIR="$REPO_DIR/local/yukisu-build"
NDK_R29="${ANDROID_NDK_ROOT:-$HOME/android-ndk-cache/android-ndk-r29}"
TOOLCHAIN_ENV="$HOME/android-toolchain/env.sh"

KO_PATH=""                                 # --ko: prebuilt Samsung-patched .ko
SAMSUNG_PATCH=""                           # --samsung-patch: applied to YukiSU kernel/ before --build-lkm
# Applied to the ndk-busybox submodule after clone (bionic lacks glibc SYSLOG_NAMES).
BUSYBOX_PATCH="$REPO_DIR/patches/ndk-busybox-syslogd-bionic.patch"
LKM_MODE=""                                # one of: prebuilt | build | stock
DO_DEPLOY=0
DO_REZYGISK=1
DO_KSUD=1
DO_APK=1
DO_VERMAGIC_PATCH=1                        # rewrite .ko vermagic to the h8q kernel release

usage() {
  # Print the leading comment header (skip the shebang, stop at the first code line).
  awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 && !/^#/ {exit}' "${BASH_SOURCE[0]}"
  cat <<EOF

Usage: $0 (--ko PATH | --build-lkm [--samsung-patch PATH] | --stock-lkm) [options]

LKM source (choose exactly one):
  --ko PATH            use a prebuilt ${KMI}_kernelsu.ko (recommended for Fold 8)
  --build-lkm          build the LKM via the YukiSU DDK docker image
  --samsung-patch P    (with --build-lkm) git-apply P to kernel/ first
  --stock-lkm          download the stock released .ko (TEST ONLY; panics on Samsung)

Options:
  --yukisu-ref REF     YukiSU tag/branch/commit to build + manager release to fetch (default $YUKISU_REF)
  --workdir DIR        scratch/checkout dir (default $WORKDIR)
  --ndk PATH           NDK for the exploit build (default $NDK_R29)
  --kmi KMI            kernel module interface (default $KMI)
  --skip-ksud          reuse an already-built ksud in the workdir (skip stages 2-4)
  --skip-vermagic-patch  do not rewrite the staged .ko's vermagic (DANGEROUS:
                         the DDK vermagic never matches the stock Fold 8 kernel)
  --no-rezygisk        do not rebuild ReZygisk
  --no-apk             do not rebuild the GhostLock APK (only swap the asset + preload.so)
  --deploy             adb-install the YukiSU manager + GhostLock APK to a connected device
  -h, --help           this help
EOF
}

log()  { printf '\033[1;36m[yukisu-h8q]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[yukisu-h8q] WARN:\033[0m %s\n' "$*" >&2; }
fail() { printf '\033[1;31m[yukisu-h8q] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

set_lkm_mode() { [ -z "$LKM_MODE" ] || fail "pick only one LKM source (--ko/--build-lkm/--stock-lkm)"; LKM_MODE="$1"; }

# --------------------------------------------------------------------------- #
# Args
# --------------------------------------------------------------------------- #
while [ "$#" -gt 0 ]; do
  case "$1" in
    --ko)            set_lkm_mode prebuilt; KO_PATH="${2:?--ko needs a path}"; shift 2 ;;
    --build-lkm)     set_lkm_mode build; shift ;;
    --samsung-patch) SAMSUNG_PATCH="${2:?--samsung-patch needs a path}"; shift 2 ;;
    --stock-lkm)     set_lkm_mode stock; shift ;;
    --yukisu-ref)    YUKISU_REF="${2:?}"; shift 2 ;;
    --workdir)       WORKDIR="${2:?}"; shift 2 ;;
    --ndk)           NDK_R29="${2:?}"; shift 2 ;;
    --kmi)           KMI="${2:?}"; shift 2 ;;
    --skip-ksud)     DO_KSUD=0; shift ;;
    --skip-vermagic-patch) DO_VERMAGIC_PATCH=0; shift ;;
    --no-rezygisk)   DO_REZYGISK=0; shift ;;
    --no-apk)        DO_APK=0; shift ;;
    --deploy)        DO_DEPLOY=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               usage; fail "unknown option: $1" ;;
  esac
done

# Fast-fail: an LKM source is required whenever we build ksud.
if [ "$DO_KSUD" = 1 ] && [ -z "$LKM_MODE" ]; then
  usage
  fail "no LKM source chosen — pass --ko PATH (Fold 8), --build-lkm, or --stock-lkm"
fi

YUKISU_SRC="$WORKDIR/YukiSU"
KSUD_OUT="$YUKISU_SRC/userspace/ksud/build/ksud"
ASSET_KSUD="$REPO_DIR/apk/app/src/main/assets/ksud"
MANAGER_APK="$WORKDIR/YukiSU-manager-${YUKISU_REF}.apk"

# --------------------------------------------------------------------------- #
# 1. env
# --------------------------------------------------------------------------- #
stage_env() {
  log "stage 1: environment"
  [ -f "$TOOLCHAIN_ENV" ] && { log "sourcing $TOOLCHAIN_ENV"; # shellcheck disable=SC1090
    . "$TOOLCHAIN_ENV"; } || warn "no $TOOLCHAIN_ENV; relying on the current environment"
  : "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME unset (source your Android toolchain env first)}"
  # The Android SDK ships cmake + ninja; put the newest on PATH if the host has none.
  if ! command -v cmake >/dev/null || ! command -v ninja >/dev/null; then
    local sdk_cmake_bin
    sdk_cmake_bin="$(ls -d "${ANDROID_SDK_ROOT:-$HOME/android-toolchain/sdk}"/cmake/*/bin 2>/dev/null | sort -V | tail -n1)"
    [ -n "$sdk_cmake_bin" ] && { export PATH="$sdk_cmake_bin:$PATH"; log "using SDK cmake/ninja: $sdk_cmake_bin"; }
  fi
  export ANDROID_NDK_ROOT="$NDK_R29"
  [ -x "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" ] \
    || fail "exploit NDK r29 not found at $ANDROID_NDK_ROOT (pass --ndk)"
  for c in git cmake ninja python3 make; do command -v "$c" >/dev/null || fail "missing host command: $c"; done
  command -v curl >/dev/null || command -v wget >/dev/null || fail "need curl or wget to fetch the manager APK"
  mkdir -p "$WORKDIR"
  log "NDK(ksud)=$ANDROID_NDK_HOME  NDK(exploit)=$ANDROID_NDK_ROOT"
}

# --------------------------------------------------------------------------- #
# 2. clone YukiSU
# --------------------------------------------------------------------------- #
stage_clone() {
  log "stage 2: YukiSU @ $YUKISU_REF"
  if [ -d "$YUKISU_SRC/.git" ]; then
    git -C "$YUKISU_SRC" fetch --tags --force origin
  else
    git clone "$YUKISU_REPO" "$YUKISU_SRC"
  fi
  git -C "$YUKISU_SRC" checkout --force "$YUKISU_REF"
  # --force: reset pinned submodules (e.g. ndk-busybox) to their exact commits.
  git -C "$YUKISU_SRC" submodule update --init --recursive --force
  # Drop untracked AND ignored files in kernel/ (the ported compat/*.c and
  # include/ksu_samsung_kdp.h are recreated by the Samsung patch; leaving them
  # would make `git apply` fail with "already exists in working directory";
  # -x also clears stale kbuild .o/.ko artifacts for a reproducible build).
  git -C "$YUKISU_SRC" clean -fdx -- kernel/

  # ndk-busybox (pinned submodule) cannot compile its syslogd applet on
  # Android/NDK: bionic's <syslog.h> omits the glibc SYSLOG_NAMES feature
  # (CODE/prioritynames/facilitynames). submodule update resets it each run,
  # so re-apply the fix here before any ksud build.
  local busybox_dir="$YUKISU_SRC/userspace/ksud/third_party/ndk-busybox"
  # NOTE: .git is a FILE for git submodules, so test the dir + patch, not .git.
  if [ -f "$BUSYBOX_PATCH" ] && [ -d "$busybox_dir" ]; then
    local abs_patch; abs_patch="$(realpath "$BUSYBOX_PATCH")"
    if git -C "$busybox_dir" apply --check "$abs_patch" 2>/dev/null; then
      git -C "$busybox_dir" apply "$abs_patch"
      log "applied busybox syslogd/bionic fix to $busybox_dir"
    elif git -C "$busybox_dir" apply --reverse --check "$abs_patch" 2>/dev/null; then
      log "busybox fix already applied"
    else
      warn "busybox fix does not apply to ndk-busybox submodule (ksud build may fail on syslogd)"
    fi
  fi
}

# --------------------------------------------------------------------------- #
# 3. obtain the LKM (.ko) into YukiSU out/  (build.sh --skip-lkm reads it there)
# --------------------------------------------------------------------------- #
stage_lkm() {
  log "stage 3: LKM ($KMI)"
  local out_dir="$YUKISU_SRC/out" dest
  dest="$out_dir/${KMI}_kernelsu.ko"
  mkdir -p "$out_dir"
  case "$LKM_MODE" in
    prebuilt)
      [ -f "$KO_PATH" ] || fail "--ko file not found: $KO_PATH"
      # cp errors out on identical src/dst (re-running with the already-staged .ko)
      [ "$(realpath "$KO_PATH")" = "$(realpath "$dest")" ] || cp -f "$KO_PATH" "$dest"
      log "staged prebuilt Samsung .ko -> $dest"
      ;;
    stock)
      warn "downloading the STOCK released ${KMI}_kernelsu.ko."
      warn "it has NO Samsung KDP/RKP/DEFEX bypass and will PANIC a real Fold 8."
      warn "use --ko with a BuSung-dev-patched build for on-device use."
      fetch_release_asset "${KMI}_kernelsu.ko" "$dest"
      ;;
    build)
      command -v docker >/dev/null || fail "--build-lkm needs docker"
      if [ -n "$SAMSUNG_PATCH" ]; then
        [ -f "$SAMSUNG_PATCH" ] || fail "--samsung-patch not found: $SAMSUNG_PATCH"
        # git -C changes dir before resolving the patch arg, so a relative
        # path would be looked up inside YukiSU/. Canonicalize to absolute.
        SAMSUNG_PATCH="$(realpath "$SAMSUNG_PATCH")"
        log "applying Samsung patch to YukiSU kernel/: $SAMSUNG_PATCH"
        if git -C "$YUKISU_SRC" apply --directory=kernel --check "$SAMSUNG_PATCH" 2>/dev/null; then
          git -C "$YUKISU_SRC" apply --directory=kernel "$SAMSUNG_PATCH"
        elif git -C "$YUKISU_SRC" apply --directory=kernel --reverse --check "$SAMSUNG_PATCH" 2>/dev/null; then
          warn "Samsung patch already applied"
        else
          fail "Samsung patch does not apply to YukiSU kernel/ — it must be ported to YukiSU's 6.12 tree first (see BuSung-dev/Root-My-Galaxy-Payloads)"
        fi
      else
        warn "no --samsung-patch given: building a STOCK LKM that will panic a real Fold 8"
      fi
      log "running YukiSU DDK build for $KMI (docker) ..."
      # build.sh (no --skip-lkm) builds LKM -> ksud -> manager. Tolerate a manager
      # sub-build failure: we only need the .ko and ksud, both made before it.
      # --skip-kasumi: YukiSU build.sh otherwise tries to build the Kasumi LKM
      # from a host path that does not exist on this box.
      ( cd "$YUKISU_SRC" && bash scripts/build.sh -k "$KMI" --skip-kasumi ) || \
        warn "YukiSU build.sh exited nonzero (often just the manager sub-build) — checking outputs"
      [ -f "$dest" ]      || fail "DDK build did not produce $dest"
      [ -x "$KSUD_OUT" ]  || fail "DDK build did not produce ksud at $KSUD_OUT"
      # build.sh already built ksud in this mode; skip the standalone ksud stage.
      DO_KSUD=0
      ;;
    *) fail "no LKM source chosen — pass --ko, --build-lkm, or --stock-lkm" ;;
  esac
}

# --------------------------------------------------------------------------- #
# 3b. rewrite the staged .ko's vermagic to the h8q stock kernel release.
#     YukiSU's ksud loader self-relocates every undefined symbol via
#     /proc/kallsyms, so CONFIG_MODVERSIONS CRCs are never consulted — the
#     vermagic string in .modinfo is the ONLY module-load gate left, and the
#     DDK's 6.12.76-4k string fatally ENOEXECs on the Fold 8's
#     6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k kernel.
# --------------------------------------------------------------------------- #
stage_vermagic() {
  log "stage 3b: vermagic patch"
  local dest="$YUKISU_SRC/out/${KMI}_kernelsu.ko"
  [ -f "$dest" ] || fail "no staged .ko at $dest (stage 3 did not run?)"
  "$SCRIPT_DIR/patch-ko-vermagic.sh" "$dest"
}

# --------------------------------------------------------------------------- #
# 4. build ksud (embeds the staged .ko). Uses YukiSU's own pipeline with the LKM
#    step skipped, then salvages the ksud binary even if the manager sub-build
#    (which we do not need — we download the signed manager) stumbles.
# --------------------------------------------------------------------------- #
stage_ksud() {
  log "stage 4: build ksud"
  ( cd "$YUKISU_SRC" && bash scripts/build.sh -k "$KMI" --skip-lkm --skip-kasumi ) || \
    warn "YukiSU build.sh exited nonzero (often just the manager sub-build) — checking for ksud"
  [ -x "$KSUD_OUT" ] || fail "ksud not produced at $KSUD_OUT"
  file "$KSUD_OUT" | grep -q aarch64 || fail "ksud is not an aarch64 binary"
  log "ksud: $(sha256sum "$KSUD_OUT" | cut -d' ' -f1)"
}

# --------------------------------------------------------------------------- #
# 5. package: swap the asset, rebuild preload.so + ReZygisk + the GhostLock APK
# --------------------------------------------------------------------------- #
stage_package() {
  log "stage 5: package into the GhostLock chain"
  [ -x "$KSUD_OUT" ] || fail "no ksud at $KSUD_OUT (run without --skip-ksud, or build it first)"
  cp -f "$KSUD_OUT" "$ASSET_KSUD"
  chmod 755 "$ASSET_KSUD"
  log "asset ksud <- YukiSU  ($(sha256sum "$ASSET_KSUD" | cut -d' ' -f1))"

  log "rebuilding exploit preload.so (make all)"
  make -C "$REPO_DIR" all
  cp -f "$REPO_DIR/build/preload.so" "$REPO_DIR/apk/app/src/main/assets/preload.so"

  if [ "$DO_REZYGISK" = 1 ]; then
    log "rebuilding ReZygisk (make rezygisk)"
    make -C "$REPO_DIR" rezygisk
  fi

  if [ "$DO_APK" = 1 ]; then
    log "rebuilding the GhostLock APK (gradlew assembleDebug)"
    ( cd "$REPO_DIR/apk" && ./gradlew --no-daemon assembleDebug )
    local built; built="$(find "$REPO_DIR/apk/app/build/outputs/apk/debug" -name '*.apk' -print -quit)"
    [ -n "$built" ] || fail "APK build produced no apk"
    mkdir -p "$REPO_DIR/apk/release"
    cp -f "$built" "$REPO_DIR/apk/release/GhostLock-h8q.apk"
    log "GhostLock APK: $REPO_DIR/apk/release/GhostLock-h8q.apk"
  fi
}

# --------------------------------------------------------------------------- #
# 6. manager APK (signed release — matches the kernel's trusted signature)
# --------------------------------------------------------------------------- #
fetch_release_asset() {           # $1=asset-name-substring  $2=dest
  local want="$1" dest="$2" api url
  api="https://api.github.com/repos/Anatdx/YukiSU/releases/tags/${YUKISU_REF}"
  local json
  if command -v curl >/dev/null; then json="$(curl -fsSL "$api")"; else json="$(wget -qO- "$api")"; fi
  url="$(printf '%s' "$json" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/' \
        | grep -F "$want" | grep -v '\.\(asc\|sig\|sha256\)$' | head -n1)"
  [ -n "$url" ] || fail "could not find release asset matching '$want' in $YUKISU_REF"
  log "downloading $(basename "$url")"
  if command -v curl >/dev/null; then curl -fsSL -o "$dest" "$url"; else wget -qO "$dest" "$url"; fi
}

stage_manager() {
  log "stage 6: signed YukiSU manager APK"
  if [ -f "$MANAGER_APK" ]; then
    log "already downloaded: $MANAGER_APK (delete to re-fetch)"
  else
    fetch_release_asset "arm64-v8a-release.apk" "$MANAGER_APK"
  fi
  log "manager (com.anatdx.yukisu): $MANAGER_APK"
}

# --------------------------------------------------------------------------- #
# 7. deploy
# --------------------------------------------------------------------------- #
stage_deploy() {
  log "stage 7: deploy to device"
  command -v adb >/dev/null || fail "adb not on PATH (source ~/android-toolchain/env.sh)"
  adb get-state >/dev/null 2>&1 || fail "no device in 'adb devices'"
  local dev; dev="$(adb shell getprop ro.product.device | tr -d '\r')"
  case "$dev" in h8q|q8q) ;; *) warn "device reports '$dev' (expected h8q/q8q) — continuing" ;; esac

  log "installing YukiSU manager"
  adb install -r -g "$MANAGER_APK" || adb install -r "$MANAGER_APK"

  if [ -f "$REPO_DIR/apk/release/GhostLock-h8q.apk" ]; then
    log "installing GhostLock APK"
    adb install -r -g "$REPO_DIR/apk/release/GhostLock-h8q.apk" || adb install -r "$REPO_DIR/apk/release/GhostLock-h8q.apk"
  fi

  cat <<EOF

Next, on the device:
  1. Start Shizuku (wireless debugging or root) and grant the GhostLock app its permission.
  2. Open GhostLock and tap "Run exploit + install YukiSU" (or run the adb one-liner:
       adb push $REPO_DIR/build/preload.so /data/local/tmp/
       adb push $ASSET_KSUD /data/local/tmp/ksud
       adb shell env LD_PRELOAD=/data/local/tmp/preload.so sh -c 'echo PWND'   ).
     A logcat line 'uid=0(root)' under tag GHOSTLOCK = success.
  3. Open the YukiSU manager — it should show the kernel as rooted.
EOF

  if [ "$DO_REZYGISK" = 1 ]; then
    cat <<EOF
  4. After YukiSU is live, deploy ReZygisk:
       scripts/deploy-rezygisk-h8q.sh --install-zip --restart-zygote
EOF
  fi
}

# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
stage_env
if [ "$DO_KSUD" = 1 ]; then
  stage_clone
  stage_lkm
  [ "$DO_VERMAGIC_PATCH" = 1 ] && stage_vermagic
  [ "$DO_KSUD" = 1 ] && stage_ksud   # stage_lkm may clear DO_KSUD in --build-lkm mode
else
  log "stage 2-4: skipped (--skip-ksud); reusing $KSUD_OUT"
fi
stage_package
stage_manager
[ "$DO_DEPLOY" = 1 ] && stage_deploy

log "done."
log "  GhostLock APK : $REPO_DIR/apk/release/GhostLock-h8q.apk"
log "  YukiSU manager: $MANAGER_APK"
[ "$DO_DEPLOY" = 1 ] || log "  (re-run with --deploy to adb-install both to a connected device)"
