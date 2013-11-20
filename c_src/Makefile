CC = gcc
CFLAGS = -Wall -g
INCLUDES = -I/usr/include/x86_64-linux-gnu
LFLAGS =
LIBS =

SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
MAIN = vector

.PHONY: depend clean

all:    $(MAIN)

$(MAIN): $(OBJS) 
	$(CC) $(CFLAGS) $(INCLUDES) -o $(MAIN) $(OBJS) $(LFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) -c $<  -o $@

clean:
	$(RM) *.o *~ $(MAIN)

depend: $(SRCS)
	makedepend -Y. $^ 2>/dev/null

# DO NOT DELETE THIS LINE -- make depend needs it

vector.o: vector.h
