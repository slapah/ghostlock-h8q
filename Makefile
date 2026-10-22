PROJECT ?= h8q-F971USQU1AZFW
OUTDIR  := build

# $(OUT) does not encode PROJECT in its path, so `make PROJECT=B` after
# `make PROJECT=A` would otherwise see an up-to-date preload.so and silently
# keep A's binary -- i.e. ship the wrong kernel offsets to a device. The stamp
# is PROJECT-specific, so switching PROJECT always forces a relink.
PROJECT_STAMP := $(OUTDIR)/.project-$(PROJECT)

TARGET_HEADER := src/targets/$(PROJECT)/target.h
ifeq ($(wildcard $(TARGET_HEADER)),)
$(error unknown PROJECT=$(PROJECT), missing $(TARGET_HEADER))
endif

SRCS := src/main.c src/slide.c src/threads.c src/util.c src/primer.c src/preload.c src/pipe.c src/root.c

NDK_BIN := $(ANDROID_NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin
CC := $(NDK_BIN)/aarch64-linux-android35-clang

CFLAGS := -O2 -g0 -fPIC -Wall -Wextra \
  -Wno-sign-compare \
  -mno-outline-atomics -Isrc \
  -DTARGET_CONFIG_H=\"targets/$(PROJECT)/target.h\" \
  -DANDROID_TARGET -llog

OUT := $(OUTDIR)/preload.so

.PHONY: all clean

all: $(OUT)

$(OUTDIR):
	mkdir -p $@

$(PROJECT_STAMP): | $(OUTDIR)
	rm -f $(OUTDIR)/.project-*
	touch $@

$(OUT): $(SRCS) $(TARGET_HEADER) $(PROJECT_STAMP) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(CC) $(CFLAGS) $(SRCS) -shared -o $@
	sha256sum $@

clean:
	rm -rf build
