CC=gcc
CFLAGS=-g -Wall

all: TraceParse

TraceParse: TraceParse.o
	$(CC) -o traceParse TraceParse.o

TraceParse.o: TraceParse.c TraceParse.h
	$(CC) $(CFLAGS) -c TraceParse.c

clean:
	rm -rf *.o ./traceParse
