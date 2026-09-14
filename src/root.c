#include "common.h"

#ifdef ANDROID_TARGET

#include <sys/mount.h>
#include <stdarg.h>
#define LOG_TAG "GHOSTLOCK"
#define KSU_LOADER_PATH "/data/local/tmp/ksud"
#define LOGCAT_PATH "/system/bin/logcat"

#include <android/log.h>
void android_log(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);

  va_end(args);
}

static int wait_status(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

const char *get_env_default(const char *name, const char *default_val) {
  const char *val = getenv(name);
  return val ? val : default_val;
}

int do_root_stage() {
  android_log("[*] Am I root? uid=%d\n", getuid());
  system("/system/bin/load_policy /sys/fs/selinux/policy");
  sleep(3);
  //system("/data/local/tmp/magiskpolicy --live"
  //     " \"allow isolated_app knoxzt_service service_manager find\""
  //     " \"allow isolated_app network_management_service service_manager find\""
  //     " \"allow isolated_app connectivity_service service_manager find\""
  //     " \"allow isolated_app vpn_management_service service_manager find\""
  //     " \"allow isolated_app content_capture_service service_manager find\"");
  int ret = system(get_env_default("ROOT_STAGE_CMD", "cp /data/local/tmp/ksud /data/local/tmp/.ksud-stage"));
  android_log("[*] cp result=%d\n", ret);

  // DEFEX prohibits execution of binary from /data/local/tmp.
  // Execute ksud via /system/bin/logcat by bind mount.
  // Privately bind-mount to avoid system-wide effect.
  if (unshare(CLONE_NEWNS) != 0 ||
      mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    android_log("late-load: private mount namespace: %s\n",
        strerror(errno));
    _exit(10);
  }
  if (mount(get_env_default("KSU_LOADER_PATH", KSU_LOADER_PATH), LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
    android_log("late-load: bind mount: %s\n", strerror(errno));
    _exit(11);
  }

  pid_t loader = fork();
  if (loader < 0) {
    android_log("late-load: fork: %s\n", strerror(errno));
    _exit(12);
  }
  if (loader == 0) {
    /* YukiSU's ksud selects its embedded <kmi>_kernelsu.ko for the running
     * kernel; hard-coding a KMI made the shared loader path unusable for
     * exact payloads such as E2S.  YukiSU's late-load takes no --package-name
     * (the kernel matches the manager by trusted APK signature via the throne
     * tracker); --allow-shell loads the LKM with allow_shell=1 so this shell
     * receives uid 0 before a signed YukiSU manager (com.anatdx.yukisu) is
     * installed.  Override the single flag with GHOSTLOCK_LATE_LOAD_ARGS. */
    const char *late_args = get_env_default("GHOSTLOCK_LATE_LOAD_ARGS",
        "--allow-shell");
    /* YukiSU's ksud dispatches by argv[0] basename (main.cpp): a base other
     * than ksud/magiskboot/bootctl/resetprop/su is delegated to the embedded
     * busybox, which exits 127 on "late-load". Pass argv[0]="ksud" so the
     * bind-mounted /system/bin/logcat path still bypasses DEFEX but routes to
     * ksud's own cli_run -> late-load command. */
    execl(LOGCAT_PATH, "ksud", "late-load", late_args, (char *)NULL);
    android_log("late-load: exec: %s\n", strerror(errno));
    _exit(12);
  }

  int loader_status = wait_status(loader);
  android_log("[*] ksud result=%d\n", loader_status);

  return loader_status;
}
#endif
