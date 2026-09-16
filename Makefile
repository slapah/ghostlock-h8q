PROJECT ?= h8q-F971USQU1AZFW
OUTDIR  := build

TARGET_HEADER := src/targets/$(PROJECT)/target.h
ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif

SRCS := src/main.c src/slide.c src/threads.c src/util.c src/primer.c src/preload.c src/pipe.c src/root.c src/mark.c src/koload.c src/tempsu.c src/su_blob.S

NDK_BIN := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin
CC := $(NDK_BIN)/aarch64-linux-android35-clang

# Embedded su_daemon binary (temp_su.sock ephemeral root), incbin'd by su_blob.S.
EMBED_SU := $(OUTDIR)/embed/su_daemon_aarch64_pie

CFLAGS := -O2 -g0 -fPIC -Wall -Wextra \
  -Wno-sign-compare \
  -mno-outline-atomics -Isrc \
  -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\" \
  -DANDROID_TARGET -llog

OUT := $(OUTDIR)/preload.so
ROOTHELPER := $(OUTDIR)/cve-2026-43499-root

.PHONY: all clean rezygisk roothelper app

rezygisk:
	chmod +x scripts/build-rezygisk-h8q.sh scripts/deploy-rezygisk-h8q.sh \
	  scripts/prepare-rezygisk-on-device.sh scripts/deploy-rezygisk-on-device.sh
	scripts/build-rezygisk-h8q.sh

all: $(OUT)

$(OUTDIR):
	mkdir -p $@

$(EMBED_SU): src/su_daemon.c | $(OUTDIR)
	mkdir -p $(OUTDIR)/embed
	$(CC) -O2 -g0 -fPIE -pie -mno-outline-atomics -o $@ $< -llog
	$(NDK_BIN)/llvm-strip -s $@

$(OUT): $(SRCS) $(EMBED_SU) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(CC) $(CFLAGS) $(SRCS) -shared -o $@ -pthread
	sha256sum $@

# Root-My-Galaxy dual-role root helper (payload launcher + KSU auto-late-load).
$(ROOTHELPER): src/roothelper.c | $(OUTDIR)
	$(CC) -O2 -g0 -Wall -Wextra -static -fPIE -pie -o $@ $<
	$(NDK_BIN)/llvm-strip -s $@
	sha256sum $@

roothelper: $(ROOTHELPER)

# Everything the Root-My-Galaxy feed needs for this target.
app: $(OUT) $(ROOTHELPER)

clean:
	rm -rf build
