# GhostLock (CVE-2026-43499) for Galaxy Z Fold 8 (h8q) / Fold 8 Ultra (q8q)
Most of this code is based on [@polygraphene's](https://github.com/polygraphene/CyberMeowfia) fork of the [original](https://github.com/NebuSec/CyberMeowfia). 
Heavy modifications were required because the main primer used (`select()`) for most published variants of the exploit does not properly align with the `rt_mutex_waiter` struct on these 6.12 Samsung targets. `io_submit()` is used instead.

**Working:** `h8q-F971USQU1AZFW` (SM-F971U, P0=`0xc7800000`). Build with `make PROJECT=h8q-F971USQU1AZFW`. 

# Build
```sh
git clone (this repo)
cd (this repo)
export ANDROID_NDK_ROOT=(your ndk path)
make
```

Build ksud + kernelsu.ko using [this tree](https://github.com/polygraphene/KernelSU/tree/a5531763971cf034e3f630d31654189a148e5f81) by polygraphene
and following [this instruction](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/61a543e206bf503b54ffb2ac8329c2cd1b99a695/kernelsu/README.md).
This tree contains [a patch from BuSung-dev/Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/61a543e206bf503b54ffb2ac8329c2cd1b99a695/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch) and 6.12 adaptation.

# Run
```sh
$ adb install /path/to/KernelSu_Manager.apk
$ adb push build/preload.so /data/local/tmp/
$ adb push $KERNELSU/target/aarch64-linux-android/release/ksud /data/local/tmp/
$ adb shell env LD_PRELOAD=/data/local/tmp/preload.so sh -c 'echo PWND'
```

# Acknowledgments
- [@polygraphene](https://github.com/polygraphene/CyberMeowfia): Most of this code is based on his fork of the original for compatibility with Samsung devices running kernel 6.12
- [Nebula Security](https://github.com/NebuSec/CyberMeowfia): Vulnerability and original exploit
- [@lukasmaar](https://github.com/lukasmaar/kernelsnitch): This exploit is heavily dependent on kernelsnitch
- [@diabl0w](https://github.com/diabl0w/ghostlock-q8q): q8q `io_submit` primer
- [BuSung-dev](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads): Samsung KDP/RKP/DEFEX KernelSU patch

