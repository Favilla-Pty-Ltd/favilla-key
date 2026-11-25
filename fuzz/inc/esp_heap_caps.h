// Host shim for the fuzzers (9u): ESP-IDF's capability allocator as plain malloc.
#pragma once
#include <stdlib.h>
#define MALLOC_CAP_SPIRAM 0
#define MALLOC_CAP_8BIT 0
#define MALLOC_CAP_INTERNAL 0
static inline void* heap_caps_malloc(size_t n, unsigned c){ (void)c; return malloc(n); }
static inline void* heap_caps_calloc(size_t a, size_t n, unsigned c){ (void)c; return calloc(a, n); }
static inline void heap_caps_free(void* p){ free(p); }
