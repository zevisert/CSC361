/*------------------------------
* SimpServer.c
* Description: HTTP over TCP server program
* CSC 361 - Assignment 1
* Author: Zev Isert
-------------------------------*/

#include "SimpServer.h"
#include "TCP_util.c"

/* Set VERBOSE to non-zero to print extra info */
#define VERBOSE 0

/* maximum string length */
#define MAX_STR_LEN 120

/* default server port number */
#define SERVER_PORT_ID 9898

/*////// GLOBALS /////*/
/* used in usage(), set in main */
char* PROG_NAME;

/* path to serve files from, used in get_file, set in main */
char SERV_PATH[PATH_MAX];

/*---------------------main() routine--------------------------*
 * tasks for main
 * generate socket and get socket id
 * Accept request from client and generate new socket
 * Communicate with client and close new socket after done
 *-------------------------------------------------------------*/
int main(int count, char* args[])
{
    PROG_NAME = args[0];
	
	/* --help command switch */
	if (count == 2 && strcmp(args[1], "--help") == 0)
	{
		usage();
		quit(NULL);
	}

    getcwd(SERV_PATH, PATH_MAX);

    struct sockaddr_in sock_addr;
    ZeroMemory(sock_addr);
    sock_addr.sin_family = AF_INET;
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	sock_addr.sin_port = htons(parse_args(count, args));
    
    /* File path requests will always begin with '/'
       so to ensure we never have "//" as a substring
       remove the trailing '/' if possible */
    if (SERV_PATH[strlen(SERV_PATH)-1] == '/')
    {
        SERV_PATH[strlen(SERV_PATH)-1] = '\0';   
    }

	/* Create a new socket */
    int socket_FD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_FD == -1)
    {
        quit("Failed to create socket");
    }

	/* Bind the port to the socket */
    if (-1 == bind(socket_FD, (struct sockaddr*)&sock_addr, sizeof sock_addr))
    {
        close(socket_FD);
        quit("Failed to bind socket");
    }

	/* Begin listening on the socket */
    if (-1 == listen(socket_FD, 3))
    {
        close(socket_FD);
        quit("Unable to begin listening");
    }

	/* Loop forever! */
    for (;;)
    {
		/* Wait for a connection */
		int connect_FD = accept(socket_FD, NULL, NULL);
		if (connect_FD < 0)
		{
			close(connect_FD);
			close(socket_FD);
			quit("Failed to accept connection");
		}
		/* The fun part, reading and writing happens here */
		perform_http(connect_FD);
		close(connect_FD);
	}
    return EXIT_SUCCESS;
}

/* Print program usage */
void usage()
{
    printf("%s <argument list>\n", PROG_NAME);
    printf("\tWhere <argument list> has the form: [port] [path]\n");
    printf("\t\tport - Port number for server.\n");
    printf("\t\tpath - Path to serve resources from.\n");
}

/* Perform argument validation, set base path, return port */
short parse_args(int count, char* args[])
{
	/* Return this var at end */
	short port_result = SERVER_PORT_ID;

	switch (count)
	{
		/* Both args are defaults */
		case 1:
		{
			printf("--- Using default port: %d\n", SERVER_PORT_ID);
			printf("--- Serving from: './'\n");
			if (VERBOSE) printf("\t ./ <=> %s\n", SERV_PATH);
		}
		break;

		/* Need to decide if args[1] is a port or path */
		case 2:
		{
			/* if string to long passes, it was a port */
			long int port = strtoul(args[1], NULL, 10);
			if (port != 0)
			{
				/* There was no string to short, so just inspect the low word*/
				if (port > 0 && port < 0xFFFF)
				{
					printf("--- Using port: %li\n", port);
					/* Only return the low word, already has been validated */
					port_result = port & 0xFFFF;

					/* Other arguement default */
					printf("--- Serving from: './'\n");
					if (VERBOSE) printf("\t ./ <=> %s\n", SERV_PATH);
				}
				else
				{
					quit("Invalid port number.");
				}
			}
			else
			{
				/* String to long failed, must've specified a path */
				printf("--- Using default port: %d\n", SERVER_PORT_ID);

				/* make sure it's a directory that exists, and is not a file*/
				switch (is_valid_path(args[1]))
				{
				case -1:
					quit("Path provided does not exist.");
					break;
				case 1:
					quit("Path provided is not a directory");
					break;

				case 0:
					strcpy(SERV_PATH, args[1]);
					printf("--- Serving from: '%s'\n", SERV_PATH);
					break;
				}
			}
		}
		break;

		/* Check for port and path validity */
		case 3:
		{
			/* Use string to long to parse the port, should be first arguement */
			long int port = strtoul(args[1], NULL, 10);
			if (port > 0 && port < 0xFFFF)
			{
				printf("--- Using port: %li\n", port);
				port_result = port & 0xFFFF;
			}
			else
			{
				quit("Invalid port number");
			}


			/* make sure it's a directory that exists, and is not a file*/
			switch (is_valid_path(args[2]))
			{
			case -1:
				quit("Path provided does not exist.");
				break;
			case 1:
				quit("Path provided is not a directory");
				break;

			case 0:
				strcpy(SERV_PATH, args[2]);
				printf("--- Serving from: '%s'\n", SERV_PATH);
				break;
			}

		}
		break;

		default:
		{
			usage();
			quit("Wrong number of parameters specified");
		}
		break;
	}
	return port_result;
}

/* Check path validity */
int is_valid_path(const char* path)
{
    struct stat myFile;
    if (stat(path, &myFile) < 0)
    {
        /* Doesn't exist */
		return -1;
    }
    else if (!S_ISDIR(myFile.st_mode))
    {
        // Exists but is not a directory
		return 1;
    }
    return 0;
}

/* Accepts a request from "socket" and sends a response to "socket". */
int perform_http(int socket)
{
    char buff[MAX_STR_LEN];
    if (VERBOSE) printf("=== Accepted conxn, reading from socket: %d.\n", socket);
    int n = read(socket, buff, sizeof buff);
    if ( n == -1 )
    {
        printf("read error\n");
        quit(strerror(errno));
    }
    else if ( n == 0 )
    {
        quit("Read nothing in header!");
    }

    printf(">> Received %d bytes\n", n);
    
    enum 
    {
        METHOD,
        PATH,
        PROTOCOL
    };
	char* req[3];

	/* Parse the request into the enum fields above */
	int i = METHOD;
    char* tok = strtok(buff, " ");
    while (tok != NULL)
    {
        req[i] = strdup(tok);
        if (i == PROTOCOL)
        {
            /* trim the carriage returns from the protocol */
            char* end = strchr(req[PROTOCOL], '\n');
            int length = strlen(req[PROTOCOL]) - strlen(end);
            sprintf(req[PROTOCOL], "%.*s", length, req[PROTOCOL]);
        }

        /* Convert the protocol and method to uppercase */
        if (i == PROTOCOL || i == METHOD)
        {
            char* p;
            for (p = req[i]; *p ; *p = toupper(*p), p++);
        }

		/* process next */
        tok = NULL;
        if (++i <= PROTOCOL)
        {
            /* Only want first three tokens */
            tok = strtok(NULL, " ");
        }
    }
	/* Complete the "server received..." print above */
    printf("\t%s %s %s\n", req[METHOD], req[PATH], req[PROTOCOL]);

	/* Check for proper protocol */
    if (strcmp(req[PROTOCOL], "HTTP/1.0") == 0)
    {
		/* check for non-implemented methods */
        if (strcmp(req[METHOD], "GET") != 0)
        {
			/* 501 - Not implemented */
            write(socket, HTTP_501, strlen(HTTP_501));
        }
        else
        {
			/* Attempt to open the file */
            char path[PATH_MAX];
			
			/* like strcat, but I choose the output */
            sprintf(path, "%s%s", SERV_PATH, req[PATH]);

			if (is_valid_path(path) != 1)
			{
				/* Want not directory*/
				write(socket, HTTP_404, strlen(HTTP_404));
			}
			else
			{
				if (VERBOSE) printf("=== Opening %s\n", path);
				FILE* file = fopen(path, "r");
				if (file == NULL)
				{
					/* File not exist! */
					write(socket, HTTP_404, strlen(HTTP_404));
					close(socket);
				}
				else
				{
					/* Opened! Now setup some buffers */
					long lSize = 0;
					char* buffer = NULL;

					/* Get the file size */
					fseek(file, 0L, SEEK_END);
					lSize = ftell(file);
					rewind(file);

					/* allocate memory for entire content */
					/* calloc so we don't have to deal with temrinating byte */
					buffer = calloc(1, lSize + 1);
					if (buffer == NULL)
					{
						fclose(file);
						/* 500 - Internal error */
						write(socket, HTTP_500, strlen(HTTP_500));
						quit("Buffer allocation failed");
					}

					/* copy the file into the buffer */
					if (fread(buffer, lSize, 1, file) != 1)
					{
						/* failure case */
						fclose(file);
						free(buffer);
						/* 500 - Internal error */
						write(socket, HTTP_500, strlen(HTTP_500));
						quit("Copy file to send buffer failed");
					}

					/* Dont need file, have buffer */
					fclose(file);

					/* Write header */
					struct tm *tm;
					time_t t;
					char str_date[MAX_STR_LEN];
					char time_str[MAX_STR_LEN];
					t = time(NULL);
					tm = gmtime(&t);
					strftime(time_str, sizeof(time_str), "%a, %d %b %Y %T GMT", tm);
					sprintf(str_date, HTTP_HEADER_DATE, time_str);

					char cont_len[MAX_STR_LEN];
					sprintf(cont_len, HTTP_HEADER_PAYLDLEN, lSize);

					const int header_len = (
						strlen(HTTP_200_MORE) + 
						strlen(str_date) + 
						strlen(HTTP_HEADER_SERVER) + 
						strlen(cont_len) +
						strlen(HTTP_HEADER_END)
						);
					char header[header_len];

					sprintf(header, "%s%s%s%s%s", HTTP_200_MORE, str_date, HTTP_HEADER_SERVER, cont_len, HTTP_HEADER_END);

					write(socket, header, strlen(header));


					/* write body */
					long wrote = writen(socket, buffer, lSize);
					if (VERBOSE) printf("=== Able write %ld of %ld bytes.\n", wrote, lSize);
					free(buffer);
				}
			}
		}
	}
    
    return 0;
}











