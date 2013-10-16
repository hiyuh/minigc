#include <stdio.h>
#include "gc.h"

static void test_mini_gc_malloc_free(void);
static void test_garbage_collect(void);
static void test_garbage_collect_load_test(void);
static void test(void);

int
main(int argc, char** argv)
{
    if (argc == 2 && strcmp(argv[1], "test") == 0)
    {
        test();
    }
    return 0;
}

static void
test_mini_gc_malloc_free(void)
{
    void* p1, *p2, *p3;

    /* malloc check */
    p1 = (void*)mini_gc_malloc(10);
    p2 = (void*)mini_gc_malloc(10);
    p3 = (void*)mini_gc_malloc(10);
#if 0
    assert(((Header*)p1 - 1)->size == ALIGN(10, PTRSIZE));
    assert(((Header*)p1 - 1)->flags == FL_ALLOC);
    assert((Header*)(((size_t)(free_list + 1)) + free_list->size) == ((Header*)p3 - 1));
#endif

    /* free check */
    mini_gc_free(p1);
    mini_gc_free(p3);
    mini_gc_free(p2);
#if 0
    assert(free_list->next_free == free_list);
    assert((void*)gc_heaps[0].slot == (void*)free_list);
    assert(gc_heaps[0].size == TINY_HEAP_SIZE);
    assert(((Header*)p1 - 1)->flags == 0);
#endif

    /* grow check */
    p1 = mini_gc_malloc(0x4000 + 80);
#if 0
    assert(gc_heaps_used == 2);
    assert(gc_heaps[1].size == (TINY_HEAP_SIZE + 80));
#endif

    mini_gc_free(p1);
}

static void
test_garbage_collect(void)
{
    void* p;

    p = mini_gc_malloc(100);
#if 0
    assert(FL_TEST((((Header*)p) - 1), FL_ALLOC));
#endif

    p = 0;
    garbage_collect();
}

static void
test_garbage_collect_load_test(void)
{
    void* p;
    int i;

    for (i = 0; i < 2000; i++)
    {
        p = mini_gc_malloc(100);
    }

#if 0
    assert((((Header*)p) - 1)->flags);
    assert(stack_end != stack_start);
#endif
}

static void
test(void)
{
    gc_init();

    test_mini_gc_malloc_free();
    test_garbage_collect();
    test_garbage_collect_load_test();
}
