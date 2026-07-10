/* fulcrum memtrace — LD_PRELOAD copy/alloc counter, works on ANY binary (gz AND rapidgzip).
 * Counts calls + total bytes for memcpy/memmove/memset and malloc/calloc/realloc/free.
 * Dumps a JSON line to $FULCRUM_MEMTRACE_OUT (append) or stderr on exit.
 * The KEY cross-tool number: copy_bytes / output_bytes — a per-element decoder shows LOW
 * libc-copy bytes; a bulk-memmove decoder shows copy_bytes >= output_bytes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static _Atomic uint64_t memcpy_calls, memcpy_bytes;
static _Atomic uint64_t memmove_calls, memmove_bytes;
static _Atomic uint64_t memset_calls, memset_bytes;
static _Atomic uint64_t malloc_calls, malloc_bytes;
static _Atomic uint64_t calloc_calls, calloc_bytes;
static _Atomic uint64_t realloc_calls, realloc_bytes;
static _Atomic uint64_t free_calls;

typedef void *(*memcpy_t)(void *, const void *, size_t);
typedef void *(*memmove_t)(void *, const void *, size_t);
typedef void *(*memset_t)(void *, int, size_t);
typedef void *(*malloc_t)(size_t);
typedef void *(*calloc_t)(size_t, size_t);
typedef void *(*realloc_t)(void *, size_t);
typedef void (*free_t)(void *);

static memcpy_t real_memcpy;
static memmove_t real_memmove;
static memset_t real_memset;
static malloc_t real_malloc;
static calloc_t real_calloc;
static realloc_t real_realloc;
static free_t real_free;

static void init(void) {
    if (!real_memmove) {
        real_memcpy = (memcpy_t)dlsym(RTLD_NEXT, "memcpy");
        real_memmove = (memmove_t)dlsym(RTLD_NEXT, "memmove");
        real_memset = (memset_t)dlsym(RTLD_NEXT, "memset");
        real_malloc = (malloc_t)dlsym(RTLD_NEXT, "malloc");
        real_calloc = (calloc_t)dlsym(RTLD_NEXT, "calloc");
        real_realloc = (realloc_t)dlsym(RTLD_NEXT, "realloc");
        real_free = (free_t)dlsym(RTLD_NEXT, "free");
    }
}

void *memcpy(void *d, const void *s, size_t n) {
    init(); memcpy_calls++; memcpy_bytes += n; return real_memcpy(d, s, n);
}
void *memmove(void *d, const void *s, size_t n) {
    init(); memmove_calls++; memmove_bytes += n; return real_memmove(d, s, n);
}
void *memset(void *d, int c, size_t n) {
    init(); memset_calls++; memset_bytes += n; return real_memset(d, c, n);
}
void *malloc(size_t n) {
    init(); malloc_calls++; malloc_bytes += n; return real_malloc(n);
}
void *calloc(size_t a, size_t b) {
    init(); calloc_calls++; calloc_bytes += a * b; return real_calloc(a, b);
}
void *realloc(void *p, size_t n) {
    init(); realloc_calls++; realloc_bytes += n; return real_realloc(p, n);
}
void free(void *p) {
    init(); if (p) free_calls++; real_free(p);
}

static _Atomic int g_dumped = 0;
static void dump(void) {
    int expected = 0;
    if (!__atomic_compare_exchange_n(&g_dumped, &expected, 1, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST))
        return; /* dump exactly once (destructor + exit interceptors may both fire) */
    const char *out = getenv("FULCRUM_MEMTRACE_OUT");
    const char *label = getenv("FULCRUM_MEMTRACE_LABEL");
    char buf[1024];
    int len = snprintf(buf, sizeof(buf),
        "{\"kind\":\"memtrace\",\"label\":\"%s\","
        "\"memcpy_calls\":%lu,\"memcpy_bytes\":%lu,"
        "\"memmove_calls\":%lu,\"memmove_bytes\":%lu,"
        "\"memset_calls\":%lu,\"memset_bytes\":%lu,"
        "\"malloc_calls\":%lu,\"malloc_bytes\":%lu,"
        "\"calloc_calls\":%lu,\"calloc_bytes\":%lu,"
        "\"realloc_calls\":%lu,\"realloc_bytes\":%lu,"
        "\"free_calls\":%lu}\n",
        label ? label : "?",
        (unsigned long)memcpy_calls, (unsigned long)memcpy_bytes,
        (unsigned long)memmove_calls, (unsigned long)memmove_bytes,
        (unsigned long)memset_calls, (unsigned long)memset_bytes,
        (unsigned long)malloc_calls, (unsigned long)malloc_bytes,
        (unsigned long)calloc_calls, (unsigned long)calloc_bytes,
        (unsigned long)realloc_calls, (unsigned long)realloc_bytes,
        (unsigned long)free_calls);
    if (out) {
        FILE *f = fopen(out, "a");
        if (f) { fwrite(buf, 1, len, f); fclose(f); return; }
    }
    if (write(2, buf, len) < 0) { /* ignore */ }
}

__attribute__((destructor)) static void dtor(void) { dump(); }

/* gzippy fast-exits via _exit(), skipping destructors — intercept the exit family
 * so the counters are dumped for BOTH tools regardless of exit path. */
typedef void (*exit_t)(int);
void _exit(int c)  { dump(); ((exit_t)dlsym(RTLD_NEXT, "_exit"))(c);  __builtin_unreachable(); }
void _Exit(int c)  { dump(); ((exit_t)dlsym(RTLD_NEXT, "_Exit"))(c);  __builtin_unreachable(); }
void exit(int c)   { dump(); ((exit_t)dlsym(RTLD_NEXT, "exit"))(c);   __builtin_unreachable(); }
