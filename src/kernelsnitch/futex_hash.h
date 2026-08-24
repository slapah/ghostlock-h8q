#pragma once

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>

typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint8_t u8;

static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

#define fallthrough __attribute__((fallthrough));

#define jhash_size(n)   ((u32)1<<(n))

#define jhash_mask(n)   (jhash_size(n)-1)

#define __jhash_mix(a, b, c)            \
{                        \
    a -= c;  a ^= rol32(c, 4);  c += b;    \
    b -= a;  b ^= rol32(a, 6);  a += c;    \
    c -= b;  c ^= rol32(b, 8);  b += a;    \
    a -= c;  a ^= rol32(c, 16); c += b;    \
    b -= a;  b ^= rol32(a, 19); a += c;    \
    c -= b;  c ^= rol32(b, 4);  b += a;    \
}

#define __jhash_final(a, b, c)            \
{                        \
    c ^= b; c -= rol32(b, 14);        \
    a ^= c; a -= rol32(c, 11);        \
    b ^= a; b -= rol32(a, 25);        \
    c ^= b; c -= rol32(b, 16);        \
    a ^= c; a -= rol32(c, 4);        \
    b ^= a; b -= rol32(a, 14);        \
    c ^= b; c -= rol32(b, 24);        \
}

#define JHASH_INITVAL        0xdeadbeef

static inline u32 jhash2(const u32 *k, u32 length, u32 initval)
{

    u32 a, b, c;


    a = b = c = JHASH_INITVAL + (length<<2) + initval;


    while (length > 3) {
        a += k[0];
        b += k[1];
        c += k[2];
        __jhash_mix(a, b, c);
        length -= 3;
        k += 3;
    }


    switch (length) {
    case 3: c += k[2];    fallthrough;
    case 2: b += k[1];    fallthrough;
    case 1: a += k[0];
        __jhash_final(a, b, c);
    case 0:
        break;
    }

    return c;
}

static inline u32 __jhash_nwords(u32 a, u32 b, u32 c, u32 initval)
{
    a += initval;
    b += initval;
    c += initval;

    __jhash_final(a, b, c);

    return c;
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
    return __jhash_nwords(a, b, c, initval + JHASH_INITVAL + (3 << 2));
}

static inline u32 jhash_2words(u32 a, u32 b, u32 initval)
{
    return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
    return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#define OFFSET_OF(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#ifndef KS_PAGE_MASK
#define KS_PAGE_MASK 0xfffULL
#endif

#define FUTEX_KEY_INIT (union futex_key) { .both = { .ptr = 0ULL } }

typedef union {
    struct {
        uint64_t i_seq;
        unsigned long pgoff;
        unsigned int offset;
    } shared;
    struct {
        union {

            void *mm;
            uint64_t __tmp;
        };
        unsigned long address;
        unsigned int offset;
    } private;
    struct {
        uint64_t ptr;
        unsigned long word;
        unsigned int offset;
    } both;
} futex_key_t;

uint32_t futex_hash_no_trunc(futex_key_t *key)
{
    uint32_t hash = jhash2((uint32_t *)key, OFFSET_OF(typeof(*key), both.offset) / 4,
              key->both.offset);

    return hash;
}

uint32_t __futex_hash(futex_key_t *key, uint32_t futex_hashsize)
{
    uint32_t hash = futex_hash_no_trunc(key);

    return hash & (futex_hashsize-1);
}

unsigned long futex_hashsize = (unsigned long)-1;
void futex_init(void)
{
    futex_hashsize = SYSCHK(sysconf(_SC_NPROCESSORS_ONLN) * 256);
}
uint32_t futex_hash(size_t addr, size_t mm)
{
    ASSERT_pr((futex_hashsize != (unsigned long)-1), "need to call futex_init() first\n");
    futex_key_t key;
    key.private.mm = (void *)mm;
    key.private.address = addr & ~KS_PAGE_MASK;
    key.private.offset = addr & KS_PAGE_MASK;
    return __futex_hash(&key, futex_hashsize);
}
