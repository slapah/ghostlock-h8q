#!/usr/bin/env bash
#
# patch-ko-vermagic.sh — rewrite the vermagic= string in a kernelsu.ko .modinfo
# section so the module passes check_modinfo() on the h8q (SM-F971U) stock kernel.
#
# Why this exists: YukiSU's ksud loader resolves every undefined module symbol
# itself against /proc/kallsyms (SHN_ABS), so CONFIG_MODVERSIONS CRCs are never
# consulted. The ONLY remaining module-load gate is the vermagic string match.
# The YukiSU DDK docker image builds against a 6.12.76 tree, producing
#   vermagic=6.12.76-4k-gae4e2f4f997e-dirty SMP preempt mod_unload modversions aarch64
# which init_module() rejects with ENOEXEC on the Fold 8's
#   6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k
# kernel. The replacement string is longer than the original, so this script
# rebuilds the whole .modinfo section with llvm-objcopy --update-section.
#
# Usage: patch-ko-vermagic.sh <in.ko> [out.ko] [release-string]
#   out.ko defaults to in-place. release-string defaults to the full vermagic
#   banner extracted from $REPO_DIR/kernel (the unpacked stock Image), with a
#   hardcoded h8q-F971USQU1AZFW fallback.
#
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"

IN_KO="${1:?usage: patch-ko-vermagic.sh <in.ko> [out.ko] [release]}"
OUT_KO="${2:-$IN_KO}"
REL_OVERRIDE="${3:-}"

FALLBACK_VERMAGIC="6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k SMP preempt mod_unload modversions aarch64"
LLVM_OBJCOPY="${LLVM_OBJCOPY:-$HOME/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy}"

log()  { printf '\033[1;36m[vermagic]\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m[vermagic] FATAL:\033[0m %s\n' "$*" >&2; exit 1; }

[ -f "$IN_KO" ] || fail "module not found: $IN_KO"
[ -x "$LLVM_OBJCOPY" ] || fail "llvm-objcopy not found at $LLVM_OBJCOPY (set LLVM_OBJCOPY)"

# --------------------------------------------------------------------------- #
# Resolve the target vermagic string
# --------------------------------------------------------------------------- #
TARGET="$REL_OVERRIDE"
if [ -z "$TARGET" ] && [ -f "$REPO_DIR/kernel" ]; then
  # The stock kernel Image embeds its own vermagic-format string; grab it.
  TARGET="$(strings "$REPO_DIR/kernel" \
      | grep -m1 -E '^[0-9]+\.[0-9]+\.[0-9]+[^ ]* SMP preempt mod_unload modversions aarch64$' || true)"
  [ -n "$TARGET" ] && log "target vermagic extracted from stock kernel image"
fi
[ -n "$TARGET" ] || { TARGET="$FALLBACK_VERMAGIC"; log "using hardcoded h8q fallback vermagic"; }
log "target: $TARGET"

# --------------------------------------------------------------------------- #
# Rebuild .modinfo with the new vermagic entry
# --------------------------------------------------------------------------- #
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

"$LLVM_OBJCOPY" -O binary --only-section=.modinfo "$IN_KO" "$WORK/modinfo.orig"
[ -s "$WORK/modinfo.orig" ] || fail "no .modinfo section in $IN_KO"

python3 - "$WORK/modinfo.orig" "$WORK/modinfo.new" "$TARGET" <<'PY'
import sys
orig_path, new_path, target = sys.argv[1], sys.argv[2], sys.argv[3]
blob = open(orig_path, 'rb').read()
entries = blob.split(b'\0')
out, done = [], False
for e in entries:
    if e.startswith(b'vermagic='):
        e = b'vermagic=' + target.encode()
        done = True
    out.append(e)
if not done:
    sys.exit("FATAL: no vermagic= entry in .modinfo")
open(new_path, 'wb').write(b'\0'.join(out))
print(f"[vermagic] .modinfo {len(blob)} -> {sum(len(x)+1 for x in out)-1} bytes")
PY

# --------------------------------------------------------------------------- #
# Swap the section and verify
# --------------------------------------------------------------------------- #
cp -f "$IN_KO" "$WORK/in.ko"
"$LLVM_OBJCOPY" --update-section .modinfo="$WORK/modinfo.new" "$WORK/in.ko" "$WORK/out.ko"

"$LLVM_OBJCOPY" -O binary --only-section=.modinfo "$WORK/out.ko" "$WORK/modinfo.check"
python3 - "$WORK/modinfo.check" "$TARGET" <<'PY'
import sys
blob = open(sys.argv[1], 'rb').read()
want = ('vermagic=' + sys.argv[2]).encode()
entry = next((e for e in blob.split(b'\0') if e.startswith(b'vermagic=')), None)
if entry != want:
    sys.exit(f"FATAL: verify failed, got {entry!r}")
print("[vermagic] verify OK:", entry.decode())
PY

cp -f "$WORK/out.ko" "$OUT_KO"
log "wrote $OUT_KO"
