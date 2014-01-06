AM_CFLAGS = -DDO_DEBUG -DDO_TEST

bin_PROGRAMS = gc
gc_SOURCES = gc.c

.PHONY: test

test: gc$(EXEEXT)
	./gc test
