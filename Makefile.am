bin_PROGRAMS = minigc
minigc_SOURCES = minigc.c
minigc_CFLAGS = -DDO_DEBUG -DDO_TEST

lib_LTLIBRARIES = libminigc.la
libminigc_la_SOURCES = minigc.c
libminigc_la_CFLAGS = -UDO_DEBUG -UDO_TEST
libminigc_la_LDFLAGS = -version-info 0:0:0

.PHONY: test

test: minigc$(EXEEXT)
	./minigc test
