#include "common.h"

#include <stdarg.h>

/*
 * Persistent step markers for panic post-mortem. The Fold 8 kernel is
 * CONFIG_PANIC_ON_OOPS=1, so a fault anywhere past the exploit instantly
 * reboots the device and logcat is lost with it. Every marker is appended
 * to /data/local/tmp/ghostlock-markers.log and fsync'd so the trail
 * survives the panic; after the reboot, `adb pull` the file and the last
 * line names the phase that killed the kernel.
 */

#define GHOST_MARK_PATH "/data/local/tmp/ghostlock-markers.log"

void ghost_mark(const char *fmt, ...) {
  char buf[512];
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  int off = snprintf(buf, sizeof(buf), "[%lld.%03ld uid=%d] ",
      (long long)ts.tv_sec, ts.tv_nsec / 1000000, getuid());
  if (off < 0 || (size_t)off >= sizeof(buf))
    return;

  va_list args;
  va_start(args, fmt);
  vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, args);
  va_end(args);

  size_t len = strlen(buf);
  if (len + 1 < sizeof(buf)) {
    buf[len] = '\n';
    buf[len + 1] = '\0';
  }

  int fd = open(GHOST_MARK_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd < 0)
    return;
  if (write(fd, buf, strlen(buf)) > 0)
    fsync(fd);
  close(fd);
}
