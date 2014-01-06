#
CC = gcc
AR = ar

ifdef DEBUG
CFLAGS = -g -DDO_DEBUG
else
CFLAGS = -O0
endif

LDFLAGS = -L.
ARFLAGS = -r

SRCS = gc.c
OBJS = $(SRCS:.c=.o)

BIN = gc
LIB = libgc.a

all: clean $(BIN)

clean:
	-rm -f *.o
	-rm -f $(LIB)
	-rm -f $(BIN)

lib: $(LIB)

.c.o:
	$(CC) $(CFLAGS) -c $<

$(LIB): $(OBJS)
	$(AR) $(ARFLAGS) $@ $?

$(BIN): main.o $(LIB)
	$(CC) $(LDFLAGS) -o $@ $< -lgc

test: $(BIN)
	./$(BIN) test

.PHONY: clean lib
