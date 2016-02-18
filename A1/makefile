CC=gcc
CFLAGS=-g -Wall

all: client server

client: SimpClient.o
	$(CC) -o simpleClient SimpClient.o

server: SimpServer.o
	$(CC) -o simpleServer SimpServer.o

SimpServer.o: SimpServer.c SimpServer.h TCP_util.c
	$(CC) $(CFLAGS) -c SimpServer.c

SimpClient.o: SimpClient.c SimpServer.h TCP_util.c
	$(CC) $(CFLAGS) -c SimpClient.c

clean:
	rm -rf *.o ./simpleClient ./simpleServer
