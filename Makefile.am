AM_CFLAGS = -DDO_DEBUG -DDO_TEST

bin_PROGRAMS = minigc
minigc_SOURCES = minigc.c

.PHONY: test

test: minigc$(EXEEXT)
	./minigc test
