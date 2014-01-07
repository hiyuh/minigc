#ifndef _MINI_GC
#define _MINI_GC

void minigc_free(void *ptr);
void *minigc_malloc(size_t req_size);
void *minigc_realloc(void *ptr, size_t req_size);

void garbage_collect(void);
void gc_init(void);
void add_roots(void *start, void *end);

#endif
