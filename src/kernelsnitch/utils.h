#pragma once

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sched.h>
#include <time.h>
#include <string.h>
#include <sys/resource.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>

#ifndef HIDEMINMAX
#define MAX(X,Y) (((X) > (Y)) ? (X) : (Y))
#define MIN(X,Y) (((X) < (Y)) ? (X) : (Y))
#endif

#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_DEFAULT "\033[0m"

#define SYSCHK(x) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error("SYSCHK(" #x "): %m\n"); \
        __res; \
    })
#define SYSCHK_pr(x, fmt) ({ \
        typeof(x) __res = (x); \
        if (__res == (typeof(x))-1) \
            pr_error(fmt); \
        __res; \
    })

static inline void timelog(const char *format, ...) {
    struct timespec ts;
    struct tm tm_info;
    char time_buf[26];
    va_list args;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", &tm_info);

    dprintf(STDOUT_FILENO, "[%s.%06ld] ", time_buf, ts.tv_nsec / 1000);

    va_start(args, format);
    vdprintf(STDOUT_FILENO, format, args);
    va_end(args);
}

#define ASSERT(cond) do { \
        if (!!(cond) == 0) \
            pr_warning("[detected] assert(" #cond ")\n"); \
    } while (0)
#define ASSERT_pr(cond, fmt, ...) do { \
        if (!!(cond) == 0) \
            pr_warning("[detected] assert(%s): " fmt, #cond, ##__VA_ARGS__); \
    } while (0)

#define pr_error(fmt, ...) do { \
        timelog(COLOR_RED "[!] " COLOR_DEFAULT fmt, ##__VA_ARGS__); \
        exit(-1); \
    } while (0)
#define pr_warning(fmt, ...) \
        timelog(COLOR_RED "[-] " COLOR_DEFAULT fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...) \
        timelog(COLOR_YELLOW "[*] " COLOR_DEFAULT fmt, ##__VA_ARGS__)
#define pr_success(fmt, ...) \
        timelog(COLOR_GREEN "[+] " COLOR_DEFAULT fmt, ##__VA_ARGS__)

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static inline void pin_to_core(size_t core)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void reset_cpu_pin(void)
{
    cpu_set_t cpuset;
    memset(&cpuset, 0xff, sizeof(cpu_set_t));
    SYSCHK(sched_setaffinity(0, sizeof(cpu_set_t), &cpuset));
}

static inline void set_limit(void)
{
    struct rlimit r;
    SYSCHK(getrlimit(RLIMIT_NOFILE, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NOFILE, &r));
    SYSCHK(getrlimit(RLIMIT_NPROC, &r));
    r.rlim_cur = r.rlim_max;
    SYSCHK(setrlimit(RLIMIT_NPROC, &r));
}

static inline void set_unbuffer(void)
{
    SYSCHK(setvbuf(stdin,  NULL, _IONBF, 0));
    SYSCHK(setvbuf(stdout, NULL, _IONBF, 0));
    SYSCHK(setvbuf(stderr, NULL, _IONBF, 0));
}

