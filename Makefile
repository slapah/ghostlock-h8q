PROJECT ?= h8q-F971USQU1AZFW
OUTDIR  := build

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

$(OUT): $(SRCS) $(TARGET_HEADER) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(CC) $(CFLAGS) $(SRCS) -shared -o $@
	sha256sum $@

clean:
	rm -rf build
