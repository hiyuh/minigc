#if defined(HAVE_CONFIG_H)
#include "config.h"
#endif

#if defined(DO_DEBUG)
#define DEBUG(exp) (exp)
#else
#define NDEBUG
#define DEBUG(exp)
#endif

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <setjmp.h>
#include <string.h>
#include "minigc.h"

typedef struct header {
	size_t flags;
	size_t size;
	struct header *next_free;
} header_t;

typedef struct heap {
	header_t *slot;
	size_t size;
} heap_t;

// FIXME: Set default on configure.
// FIXME: Enable runtime tuning on init.
#define TINY_HEAP_SIZE 0x4000
#define HEAP_LIMIT 10000

#define PTRSIZE (sizeof(void *))
#define HEADER_SIZE (sizeof(header_t))
#define ALIGN(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define NEXT_HEADER(x) ((header_t *)((size_t)(x + 1) + x->size))

#define FL_ALLOC ((size_t)0b01)
#define FL_MARK  ((size_t)0b10)

#define FL_SET(x, f)   (((header_t *)x)->flags |=  (f))
#define FL_UNSET(x, f) (((header_t *)x)->flags &= ~(f))
#define FL_TEST(x, f)  (((header_t *)x)->flags &   (f))

static header_t *free_list = NULL;
static heap_t heaps[HEAP_LIMIT];
static size_t heaps_used = 0;

static void join_freelist(header_t * target);
static heap_t *is_pointer_to_heap(void *ptr);

static header_t *add_heap(size_t req_size)
{
	void *p;
	header_t *align_p;

	if (heaps_used >= HEAP_LIMIT) {
		fputs("OutOfMemory Error", stderr);
		abort();
	}

	if (req_size < TINY_HEAP_SIZE) {
		req_size = TINY_HEAP_SIZE;
	} else {
		req_size += HEADER_SIZE;
	}

#if defined(HAVE_SBRK)
	if ((p = sbrk(req_size + PTRSIZE + HEADER_SIZE)) == (void *)-1) {
		return NULL;
	}
#else
	// FIXME: Emulate sbrk() by VirtualAlloc() and VirtualFree() is better on windows?
	//        http://www.genesys-e.org/jwalter//mix4win.htm
	if ((p = (void *)malloc(req_size + PTRSIZE + HEADER_SIZE)) == NULL) {
		return NULL;
	}
#endif

	memset(p, 0, req_size + PTRSIZE + HEADER_SIZE);
	align_p = heaps[heaps_used].slot =
	    (header_t *) ALIGN((size_t) p, PTRSIZE);
	req_size = heaps[heaps_used].size = req_size;
	align_p->size = req_size - HEADER_SIZE;
	align_p->next_free = align_p;
	align_p->flags = 0;
	heaps_used++;

	return align_p;
}

static header_t *grow(size_t req_size)
{
	header_t *p;

	if (!(p = add_heap(req_size))) {
		return NULL;
	}
	join_freelist(p);

	return free_list;
}

void *minigc_malloc(size_t req_size)
{
	header_t *p, *prevp;
	bool do_gcollect = false;

	req_size = ALIGN(req_size, PTRSIZE);

	if ((prevp = free_list) == NULL) {
		if (!(p = add_heap(TINY_HEAP_SIZE))) {
			return NULL;
		}
		prevp = free_list = p;
	}
	for (p = prevp->next_free;; prevp = p, p = p->next_free) {
		if (p->size == req_size) {
			prevp->next_free = p->next_free;

			free_list = prevp;
			FL_SET(p, FL_ALLOC);

			p->next_free = 0;

			return (void *)(p + 1);
		} else if (p->size > (req_size + HEADER_SIZE)) {
			p->size -= (req_size + HEADER_SIZE);

			p = NEXT_HEADER(p);
			memset(p, 0, HEADER_SIZE + req_size);
			p->size = req_size;

			free_list = prevp;
			FL_SET(p, FL_ALLOC);

			p->next_free = 0;

			return (void *)(p + 1);
		}

		if (p == free_list) {
			if (!do_gcollect) {
				minigc_gcollect();
				do_gcollect = true;
			} else if ((p = grow(req_size)) == NULL) {
				return NULL;
			}
		}
	}
}

void *minigc_realloc(void *ptr, size_t req_size)
{
	void *p;

	if (ptr == NULL) {
		p = minigc_malloc(req_size);
	} else if (req_size == 0 && ptr != NULL) {
		// FIXME: configure being lazy internal minigc_free().
		minigc_free(ptr);
		p = NULL;
	} else {
		p = minigc_malloc(req_size);
		if (p != NULL) {
			const header_t *hdr = (header_t *) ptr - 1;
			memcpy(p, ptr,
			       (hdr->size < req_size) ? hdr->size : req_size);
			// FIXME: configure being lazy internal minigc_free().
			minigc_free(ptr);
		}
	}

	return p;
}

void minigc_free(void *ptr)
{
	header_t *target = NULL;

	target = (header_t *) ptr - 1;

	/* check if ptr is valid */
	if (!is_pointer_to_heap(ptr) || !FL_TEST(target, FL_ALLOC)) {
		return;
	}

	join_freelist(target);

	target->flags = 0;
}

static void join_freelist(header_t * target)
{
	header_t *hit = NULL;

	/* search join point of target to free_list */
	for (hit = free_list; !(target > hit && target < hit->next_free);
	     hit = hit->next_free)
		/* heap end? And hit(search)? */
		if (hit >= hit->next_free
		    && (target > hit || target < hit->next_free)) {
			break;
		}

	if (NEXT_HEADER(target) == hit->next_free) {
		/* merge */
		target->size += (hit->next_free->size + HEADER_SIZE);
		target->next_free = hit->next_free->next_free;
	} else {
		/* join next free block */
		target->next_free = hit->next_free;
	}
	if (NEXT_HEADER(hit) == target) {
		/* merge */
		hit->size += (target->size + HEADER_SIZE);
		hit->next_free = target->next_free;
	} else {
		/* join before free block */
		hit->next_free = target;
	}

	free_list = hit;
}

struct root_range {
	void *start;
	void *end;
};

#define IS_MARKED(x) (FL_TEST(x, FL_ALLOC) && FL_TEST(x, FL_MARK))

// FIXME: Set default on configure.
// FIXME: Enable runtime tuning on init.
#define ROOT_RANGES_LIMIT 1000

static struct root_range root_ranges[ROOT_RANGES_LIMIT];
static size_t root_ranges_used = 0;
static void *stack_start = NULL;
static void *stack_end = NULL;
static heap_t *hit_cache = NULL;

static heap_t *is_pointer_to_heap(void *ptr)
{
	if (hit_cache &&
	    ((void *)hit_cache->slot) <= ptr &&
	    (size_t) ptr < (((size_t) hit_cache->slot) + hit_cache->size)) {
		return hit_cache;
	}

	for (size_t i = 0; i < heaps_used; i++) {
		if ((((void *)heaps[i].slot) <= ptr) &&
		    ((size_t) ptr <
		     (((size_t) heaps[i].slot) + heaps[i].size))) {
			hit_cache = &heaps[i];
			return &heaps[i];
		}
	}
	return NULL;
}

static header_t *get_header(heap_t * gh, void *ptr)
{
	header_t *p, *pend, *pnext;

	pend = (header_t *) (((size_t) gh->slot) + gh->size);
	for (p = gh->slot; p < pend; p = pnext) {
		pnext = NEXT_HEADER(p);
		if ((void *)(p + 1) <= ptr && ptr < (void *)pnext) {
			return p;
		}
	}
	return NULL;
}

void minigc_init(void)
{
	long dummy;

	/* referenced bdw-gc mark_rts.c */
	dummy = 42;

	/* check stack grow */
	stack_start = ((void *)&dummy);
}

static void set_stack_end(void)
{
	long dummy;

	/* referenced bdw-gc mark_rts.c */
	dummy = 42;

	stack_end = (void *)&dummy;
}

static void mark_range(void *start, void *end);

static void mark(void *ptr)
{
	heap_t *gh;
	header_t *hdr;

	/* mark check */
	if (!(gh = is_pointer_to_heap(ptr))) {
		return;
	}
	if (!(hdr = get_header(gh, ptr))) {
		return;
	}
	if (!FL_TEST(hdr, FL_ALLOC)) {
		return;
	}
	if (FL_TEST(hdr, FL_MARK)) {
		return;
	}

	/* marking */
	FL_SET(hdr, FL_MARK);
	DEBUG(printf("mark ptr : %p, header : %p\n", ptr, hdr));

	/* mark children */
	mark_range((void *)(hdr + 1), (void *)NEXT_HEADER(hdr));
}

static void mark_range(void *start, void *end)
{
	for (void *p = start; p < end; p++) {
		mark(*(void **)p);
	}
}

static void mark_register(void)
{
	jmp_buf env;
	setjmp(env);
	for (size_t i = 0; i < sizeof(env); i++) {
		mark(((void **)env)[i]);
	}
}

static void mark_stack(void)
{
	set_stack_end();
	if (stack_start > stack_end) {
		mark_range(stack_end, stack_start);
	} else {
		mark_range(stack_start, stack_end);
	}
}

static void sweep(void)
{
	for (size_t i = 0; i < heaps_used; i++) {
		header_t *pend =
		    (header_t *) (((size_t) heaps[i].slot) + heaps[i].size);
		for (header_t * p = heaps[i].slot; p < pend; p = NEXT_HEADER(p)) {
			if (FL_TEST(p, FL_ALLOC)) {
				if (FL_TEST(p, FL_MARK)) {
					DEBUG(printf("mark unset : %p\n", p));
					FL_UNSET(p, FL_MARK);
				} else {
					minigc_free(p + 1);
				}
			}
		}
	}
}

void minigc_add_roots(void *start, void *end)
{
	void *tmp;
	if (start > end) {
		tmp = start;
		start = end;
		end = tmp;
	}
	root_ranges[root_ranges_used].start = start;
	root_ranges[root_ranges_used].end = end;
	root_ranges_used++;

	if (root_ranges_used >= ROOT_RANGES_LIMIT) {
		fputs("Root OverFlow", stderr);
		abort();
	}
}

void minigc_gcollect(void)
{
	/* marking machine context */
	mark_register();
	mark_stack();

	/* marking roots */
	for (size_t i = 0; i < root_ranges_used; i++) {
		mark_range(root_ranges[i].start, root_ranges[i].end);
	}

	sweep();
}

#ifdef DO_TEST
// FIXME: Add test for minigc_realloc().
static void test_minigc_malloc_free(void)
{
	void *p1 = (void *)minigc_malloc(10);
	void *p2 = (void *)minigc_malloc(10);
	void *p3 = (void *)minigc_malloc(10);
	assert(((header_t *) p1 - 1)->size == ALIGN(10, PTRSIZE));
	assert(((header_t *) p1 - 1)->flags == FL_ALLOC);
	assert((header_t *) (((size_t) (free_list + 1)) + free_list->size) ==
	       ((header_t *) p3 - 1));

	minigc_free(p1);
	minigc_free(p3);
	minigc_free(p2);
	assert(free_list->next_free == free_list);
	assert((void *)heaps[0].slot == (void *)free_list);
	// FIXME: assert(heaps[0].size == TINY_HEAP_SIZE);
	assert(((header_t *) p1 - 1)->flags == 0);

	p1 = minigc_malloc(TINY_HEAP_SIZE + 80);
	assert(heaps_used == 2);
	// FIXME: assert(heaps[1].size == (TINY_HEAP_SIZE + 80));
	minigc_free(p1);
}

static void test_garbage_collect(void)
{
	void *p = minigc_malloc(100);
	assert(FL_TEST((((header_t *) p) - 1), FL_ALLOC));
	p = NULL;
	minigc_gcollect();
}

static void test_garbage_collect_load_test(void)
{
	void *p;

	for (size_t i = 0; i < 2000; i++) {
		p = minigc_malloc(100);
	}
	assert((((header_t *) p) - 1)->flags);
	assert(stack_end != stack_start);
}

static void test(void)
{
	minigc_init();

	test_minigc_malloc_free();
	test_garbage_collect();
	test_garbage_collect_load_test();
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "test") == 0) {
		test();
	}
	return 0;
}
#endif
