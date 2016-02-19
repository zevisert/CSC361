CC=gcc
CFLAGS=-g -Wall
LIB=-lpcap

all: TraceParse

TraceParse: TraceParse.o
	$(CC) -o traceParse TraceParse.o $(LIB)

TraceParse.o: TraceParse.c TraceParse.h
	$(CC) $(CFLAGS) -c TraceParse.c

clean:
	rm -rf *.o ./traceParse
