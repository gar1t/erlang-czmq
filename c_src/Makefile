CC = gcc
CFLAGS = -Wall -g
INCLUDES = -I/usr/local/lib/erlang/lib/erl_interface-3.7.11/include
INCLUDES_xxx = -I/usr/include/x86_64-linux-gnu
LFLAGS = -L/usr/local/lib/erlang/lib/erl_interface-3.7.11/lib
LIBS = -lerl_interface -lei -lpthread -lczmq

SRCS = $(wildcard *.c)

BIN_DIR = ../priv

CZMQ_PORT = $(BIN_DIR)/czmq-port
CZMQ_PORT_OBJS = czmq_port.o erl_czmq.o vector.o

CZMQ_BENCHMARK = $(BIN_DIR)/czmq-benchmark
CZMQ_BENCHMARK_OBJS = czmq_benchmark.o erl_czmq.o vector.o

.PHONY: depend clean

all:    $(CZMQ_PORT) $(CZMQ_BENCHMARK)

$(CZMQ_PORT): $(CZMQ_PORT_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(CZMQ_PORT) $(CZMQ_PORT_OBJS) \
              $(LFLAGS) $(LIBS)

$(CZMQ_BENCHMARK): $(CZMQ_BENCHMARK_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(CZMQ_BENCHMARK) $(CZMQ_BENCHMARK_OBJS) \
              $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	$(RM) *.o *~ $(CZMQ_PORT) $(CZMQ_BENCHMARK)

depend: $(SRCS)
	makedepend -Y. $^ 2>/dev/null

# DO NOT DELETE THIS LINE -- make depend needs it

vector.o: vector.h
