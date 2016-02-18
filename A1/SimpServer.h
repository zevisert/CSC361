#pragma once
/*------------------------------
* SimpServer.h
* Description: HTTP over TCP server program
* CSC 361 - Assignment 1
* Author: Zev Isert
-------------------------------*/

#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

/* HTTP Status messages */
#define HTTP_200 "HTTP/1.0 200 OK\r\n\r\n"
#define HTTP_404 "HTTP/1.0 404 Not Found\r\n\r\n"
#define HTTP_500 "HTTP/1.0 500 Internal Server Error\r\n\r\n"
#define HTTP_501 "HTTP/1.0 501 Not Implemented\r\n\r\n"

#define HTTP_200_MORE "HTTP/1.0 200 OK\n"

#define HTTP_HEADER_DATE "Date: %s\r\n"
#define HTTP_HEADER_SERVER "Server: zevisert/SimpleTCPServer (1.0)\r\n"
#define HTTP_HEADER_PAYLDLEN "Content-Length: %ld\r\n"

#define HTTP_HEADER_END "\r\n"

/* Function signatures */
short parse_args(int, char*[]);
void usage();
int is_valid_path(const char*);
int perform_http(int);
