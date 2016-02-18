#pragma once
/*------------------------------
* SimpClient.c
* Description: HTTP over TCP client program
* CSC 361 - Assignment 1
* Author: Zev Isert
-------------------------------*/

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* HTTP protocols */
#define HTTP_GET "GET %s HTTP/1.0\r\n\r\n"
#define HTTP_GET_HEAD_HOST "GET %s HTTP/1.0\nHost: %s\r\n\r\n"
#define STR_REQ_END "---Request End---\nHTTP request sent, awaiting response...\n\n"
#define STR_RESP_HEAD "---Response Header---\n"
#define STR_RESP_BODY "---Response Body---\n"


/* Function signatures */
void parse_URI(const char*, char*, int*, char*);
void usage();
int open_connection(char*, int);
void perform_http(int, char*, char*);
