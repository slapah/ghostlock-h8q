# GhostLock (CVE-2026-43499) for Galaxy Z Fold 8 (h8q) / Fold 8 Ultra (q8q)
Most of this code is based on [@polygraphene's](https://github.com/polygraphene/CyberMeowfia) fork of the [original](https://github.com/NebuSec/CyberMeowfia). 
Heavy modifications were required because the main primer used (`select()`) for most published variants of the exploit does not properly align with the `rt_mutex_waiter` struct on these 6.12 Samsung targets. `io_submit()` is used instead.

This chain roots with [YukiSU](https://github.com/Anatdx/YukiSU) (a SukiSU-Ultra / KernelSU fork with a C++ `ksud`), not stock KernelSU.

**Working:** `h8q-F971USQU1AZFW` (SM-F971U, P0=`0xc7800000`). Build with `make PROJECT=h8q-F971USQU1AZFW`. 

# Build
```sh
git clone (this repo)
cd (this repo)
export ANDROID_NDK_ROOT=(your ndk path)
make
```

Build YukiSU's `ksud` + `<kmi>_kernelsu.ko` from the [YukiSU tree](https://github.com/Anatdx/YukiSU) (`userspace/ksud` is C++ and `kernel/` is the LKM). Port the Samsung KDP/RKP/DEFEX + 6.12 adaptation from [BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/61a543e206bf503b54ffb2ac8329c2cd1b99a695/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch) onto the YukiSU kernel sources (the same KDP/RKP/DEFEX bypasses apply; the module still exports the `kernelsu` name and ioctl ABI). YukiSU embeds the `.ko` inside `ksud`, so the daemon you drop into the APK assets is the only artifact the exploit needs.

**The .ko's vermagic must be rewritten to the stock kernel release before embedding.** YukiSU's loader self-relocates all undefined symbols via `/proc/kallsyms` (so CONFIG_MODVERSIONS CRCs are never consulted), but it does *not* patch vermagic at load time — and the DDK docker image builds `6.12.76-4k-...` vermagic, which `init_module()` rejects (ENOEXEC) on the Fold 8's `6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k` kernel. `scripts/patch-ko-vermagic.sh` rebuilds the `.modinfo` section with the correct string (extracted from the unpacked stock `kernel` image in this repo); `scripts/build-yukisu-h8q.sh` runs it automatically as stage 3b.

Drop the built `ksud` into `apk/app/src/main/assets/ksud` (the app stages it to `/data/local/tmp/ksud`).

# Run
```sh
$ adb install /path/to/YukiSU_Manager.apk        # applicationId com.anatdx.yukisu
$ adb push build/preload.so /data/local/tmp/
$ adb push /path/to/yukisu/ksud /data/local/tmp/
$ adb shell env LD_PRELOAD=/data/local/tmp/preload.so sh -c 'echo PWND'
```

The exploit runs `ksud late-load --allow-shell`. Unlike stock KernelSU, YukiSU's `late-load` has **no** `--package-name`: the kernel authorizes the manager by matching an installed APK against YukiSU's trusted release signature (throne tracker / dynamic-manager), so just install the signed `com.anatdx.yukisu` manager. `--allow-shell` loads the LKM with `allow_shell=1`, which grants this shell uid 0 before the manager is registered. Override the flag with `GHOSTLOCK_LATE_LOAD_ARGS` if you need `--magica`/`--post-magica`.

# Zygisk (ReZygisk, Samsung DEFEX fileless)

YukiSU ships its own YukiZygisk, but this chain keeps ReZygisk. Because YukiSU keeps the `kernelsu` module name and KernelSU ioctl ABI, ReZygisk's KernelSU `root_impl` detects it and reports `"root":"KernelSU"` in `state.json`.

Vanilla ReZygisk fails on these Fold 8 kernels because zygote is not allowed to open files under `/data`. This tree uses the same fileless injector as [saltcute/ghostlock-samsung-s25](https://github.com/saltcute/ghostlock-samsung-s25): the tracer copies `libzygisk.so` into anonymous remote memory, and zygiskd passes already-open module FDs over `SCM_RIGHTS` so CSOLoader never uses `/proc/self/fd`.

An extra patch accepts YukiSU's daemon path `/data/adb/ksud` (its `defs.hpp` `DAEMON_PATH`) in addition to `/data/adb/ksu/bin/ksud`.

```sh
make rezygisk
# after YukiSU is live on the phone:
scripts/deploy-rezygisk-h8q.sh --install-zip --restart-zygote
```

Artifacts land in `local/build/rezygisk-h8q/` (`libzygisk.so`, `zygisk-ptrace64`, `zygiskd64`, `rezygisk-h8q.zip`). `--restart-zygote` kills `zygote64` so ReZygisk can attach this boot; skip it if Android RescueParty is already angry (`persist.sys.rescue_level` >= 4) unless you also pass `--force-rescue-level`. Success looks like `ZYGISK_READY=1` and `"zygote":{"64":1}` in `/data/adb/rezygisk/state.json`.

# Acknowledgments
- [@polygraphene](https://github.com/polygraphene/CyberMeowfia): Most of this code is based on his fork of the original for compatibility with Samsung devices running kernel 6.12
- [Nebula Security](https://github.com/NebuSec/CyberMeowfia): Vulnerability and original exploit
- [@lukasmaar](https://github.com/lukasmaar/kernelsnitch): This exploit is heavily dependent on kernelsnitch
- [@diabl0w](https://github.com/diabl0w/ghostlock-q8q): q8q `io_submit` primer
- [BuSung-dev](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads): Samsung KDP/RKP/DEFEX KernelSU patch
- [YukiSU / @Anatdx](https://github.com/Anatdx/YukiSU): SukiSU-Ultra / KernelSU fork with the C++ `ksud` used as the root manager here
