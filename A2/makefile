CC=gcc
CFLAGS=-g -Wall
LIB=-lpcap

all: TraceParse

remake: clean all

TraceParse: TraceParse.o
	$(CC) -o traceParse TraceParse.o $(LIB)

TraceParse.o: TraceParse.c TraceParse.h Headers.h TCP_Header.h ETH_Header.h IP_Header.h
	$(CC) $(CFLAGS) -c TraceParse.c

clean:
	rm -rf *.o ./traceParse
