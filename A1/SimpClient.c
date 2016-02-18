/*------------------------------
* SimpClient.c
* Description: HTTP over TCP client program
* CSC 361 - Assignment 1
* Author: Zev Isert
-------------------------------*/

#include "SimpClient.h"
#include "TCP_util.c"

/* Enable and disable debug print statements, non-zero for enabled */
#define VERBOSE 0

/* define maximal string and reply length */
/* INIT_RES_LEN grows as required */
#define MAX_STR_LEN 120
#define INIT_RES_LEN 512

/* Used in pringing usage, defined by main:uri[0] */
char* PROG_NAME;

/* --------- Main() routine ------------
 * accept the input URI and parse it into fragments for further operation
 * open socket connection with specified host and port
 * use the socket to connect to a specified server
 -------------------------------------*/
int main(int count, char* uri[])
{
    PROG_NAME = uri[0];

	/* --help command switch */
	if (count == 2 && strcmp(uri[1], "--help") == 0)
	{
		usage();
		quit(NULL);
	}

    char hostname[MAX_STR_LEN];
    char path[MAX_STR_LEN];
    int socket_FD;
    int port;

    if(count != 2)
    {
        usage();
        quit("List not implemented, only one uri supported per execution");
    }

	/* Parse the input */
    parse_URI(uri[1], hostname, &port, path);

	if (strcmp(path, "") == 0) strcpy(path, "/");

	/* Create the socket */
    socket_FD = open_connection(hostname, port);

	/* Use the new socket to ask for the resource */
    perform_http(socket_FD, hostname, path);

    return EXIT_SUCCESS;
}

void usage()
{
    printf("%s <URI list>\n", PROG_NAME);
    printf("\tWhere <URI list> has the form: [scheme://]host[:port][/path]\n");
    printf("\t\t scheme:// - Only supports \'http\', assumed if not supplied.\n");
    printf("\t\t host      - Canonical hostname or IP address. Required.\n");
    printf("\t\t :port     - Port number.\n");
    printf("\t\t /path     - Path to requested resource. e.g.: /public/index.html\n");
}

/* parse_URI: Parse a valid url to retrieive the host, port, and path elements.
    
    Params:
        - [in]   uri: char* - String containing an (unvalidated) URI
        - [out] host: char* - String containing the host section of the URI
        - [out] port: int*  - Host port number
        - [out] path: char* - String containing the location of the requested resource 

    A valid URI has the form: 

                        hierarchical part
            ┌───────────────────┴─────────────────────┐
                        authority               path
            ┌───────────────┴───────────────┐┌───┴────┐
      abc://username:password@example.com:123/path/data?key=value#fragid1
      └┬┘   └───────┬───────┘ └────┬────┘ └┬┘           └───┬───┘ └──┬──┘
    scheme  user information     host     port            query   fragment

    Though in the program, we'll only be accepting URI's with a form such as
        [http://]host[:port][/path]
*/
void parse_URI(const char* uri, char* host, int* port, char* path)
{
	/* Pre-set some default values */
    strcpy(host, "");
    strcpy(path, "");
    *port = -1;
    
	/* allocate a copy so we don't go breaking our data while tokenizing */
    char* temp_uri = strdup(uri);

    /* Check for the 'http://' scheme */
    char scheme[MAX_STR_LEN];
    char* scheme_ptr = strstr(temp_uri, "://");
    strcpy(scheme, scheme_ptr ? scheme_ptr : "");

	/* /Some/ scheme was specified, validate it */
    if (scheme_ptr != NULL)
    {
        /* check the scheme is http */
        int length = strlen(uri) - strlen(scheme);
        sprintf(scheme, "%.*s", length, uri);     

        if (VERBOSE) printf("=== Scheme: %s\n", scheme);
        if (strcmp(scheme, "http") == 0)
        {
            /* Remove the scheme now that it's verified, no longer needed. */
            sprintf(temp_uri, "%s", uri+7);
        }
        else
        {
			/* Only allow http connections */
            char err_desc[MAX_STR_LEN];
            sprintf(err_desc, "This program does not support %s://", scheme);
            quit(err_desc);
        }
    }

    /* find next ':' char, must be port. */
    /* if there's an @, then the above statment isn't true */    
    if (strchr(temp_uri, '@') != NULL)
    {
        /* user tried entering user:pass@host */
        quit("This program does not support login authentication");
    }
    else
    {
		/* Try and find the : and / characters. We could have either, both, or none */
        char* portnum = strchr(temp_uri, ':');
        char* resrc = strchr(temp_uri, '/');

		/* Found both ':' and '/' */
        if (resrc != NULL && portnum != NULL)
        {
            /* There is a port and a path, right now the port var includes the path */
			/* Use the difference to get just the port */
			char temp_port[6];
            int length = strlen(portnum) - strlen(resrc) - 1;
            sprintf(temp_port, "%.*s", length, portnum+1);

			/* Got the port, validate */
            long numeric_port = strtoul(temp_port, NULL, 10);

			/* Port is ok */
			if (numeric_port > 0 && numeric_port < 0xFFFF)
			{
				if (VERBOSE) printf("--- Using port: %li\n", numeric_port);
				*port = numeric_port & 0xFFFF;
			}
			/* Bad port */
			else
			{
				quit("Invalid port number");
			}
            
			/* remove and warn about any post-matter. eg queries */
            char* post_matter = strchr(resrc, '?');
            if ( post_matter != NULL )
            {
                length = strlen(temp_uri) - strlen(post_matter);
                sprintf(temp_uri, "%.*s", length, temp_uri);
                printf("<WARN> This program ignores URL queries (?example=data).\n");
            }
			/* Can't realllly validate the path, that's the server's job */
			/* I mean we could validate by valid chars but nah */
            strcpy(path, resrc);
        }
		
		/* Found one of ':' or '/', or found neiher */
        else
        {
			if (resrc)
			{
				/* remove and warn about any post-matter. eg queries */
				char* post_matter = strchr(resrc, '?');
				if (post_matter != NULL)
				{
					int length = strlen(temp_uri) - strlen(post_matter);
					sprintf(temp_uri, "%.*s", length, temp_uri);
					printf("<WARN> This program ignores URL queries (?example=data).\n");
				}
				strcpy(path, resrc);
			}

			if (portnum)
			{
				/* Got a port, validate it */
				/* Pointer artithmetic to skip the ':' char */
				long numeric_port = strtoul(portnum + 1, NULL, 10);

				/* Port is ok */
				if (numeric_port > 0 && numeric_port < 0xFFFF)
				{
					if (VERBOSE) printf("--- Using port: %li\n", numeric_port);
					*port = numeric_port & 0xFFFF;
				}
				/* Bad port */
				else
				{
					quit("Invalid port number");
				}
			}
            
            /* Use port:80 if not otherwise specified */
            *port = *port == -1 ? 80 : *port;
        }

        if (VERBOSE)
        {
            if (*port != -1)  printf("=== port: %d\n", *port);
            if (strlen(path)) printf("=== path: %s\n", path);
        }

        /* finally, set the host */
        
        strtok(temp_uri, ":/");
        sprintf(host, "%s", temp_uri); 
    }
    free(temp_uri);
}

/* Use the socket to get the resource specified by path*/
void perform_http(int socket_FD, char* host, char* path)
{
    /* connect to server and retrieve response */
    char getReq[MAX_STR_LEN];

	/* Use a path of scheme://host/[path] */
    sprintf(getReq, HTTP_GET_HEAD_HOST, path, host);

	printf("---Request begin---\n");
	printf("%s", getReq);
	
	/* write the request */
	int wrote = write(socket_FD, getReq, strlen(getReq));
    if ( wrote == -1 )
    {
        quit(strerror(errno));
    }
    else if ( wrote == 0 )
    {
        quit("Didn't write anything in header");
    }
	printf(STR_REQ_END);

	/* setup some dynamic buffers for reply reading */
    long i = 0;
    long amntRecvd = 0;
    long currentSize = INIT_RES_LEN;
    long oldSize = currentSize;
    char* buff = (char*) calloc(1, currentSize);
    if (buff == NULL)
    {
        quit("Read buffer allocation failed");
    }

	/* While we're still receiving */
    amntRecvd = read(socket_FD, buff + i, INIT_RES_LEN);
    while (amntRecvd > 0) {
		/* Keep expanding the buffer */
        if (VERBOSE) printf("=== Just read %ld bytes.. \n\t.. have to expand buffer\n", amntRecvd);
        i += amntRecvd;
        oldSize = currentSize; 
        currentSize += INIT_RES_LEN; 
        char *newBuffer = malloc(currentSize); 
        memcpy(newBuffer, buff, oldSize); 
        free(buff); 
        buff = newBuffer;
        amntRecvd = read(socket_FD, buff + i, INIT_RES_LEN);
    }

    if (strlen(buff) == 0)
    {
        quit("No data received");
    }

    /* All that beautiful work to optain a tcp response, then we don't even save it! */

	char* header = buff;
	char* body = strstr(header, "\r\n\r\n");
	int header_len = strlen(buff) - strlen(body);
	/* Really no double carriage return? Maybe the line feeds are ommitted */
	if (body == NULL)
	{
		body = strstr(header, "\n\n");
		header_len = strlen(buff) - strlen(body);
		/* Point to after the carriage return */
		if (body != NULL) body += 2;
	}
	else
	{
		header_len = strlen(buff) - strlen(body);
		/* Point to after the carriage return */
		body += 4;
	}

	if (body != NULL)
	{
		/* print just the header*/
		printf(STR_RESP_HEAD);
		printf("%.*s\n\n", header_len, header);

		printf(STR_RESP_BODY);
		/* If the reponse was large, mention the size, and confirm we're still outputting it */
		if ( i - header_len > 512)
		{
			char ans;
			printf("Received %ld bytes. Print server reply [Y|N]:", i - header_len);
			scanf("%c", &ans);

			if (toupper(ans) == 'Y')
			{
				printf("\n%s\n", body);
			}
		}
		else
		{
			printf("%s\n", body);
		}
	}
    else
    {
        printf("%s\n", buff);
    }
    
    free(buff);
    close(socket_FD);
}

/* Connect to a remote server on a specified port. */
int open_connection(char* hostname, int port)
{
	char host_ip[MAX_STR_LEN];
    int socket_FD = 0;
    int error = 0;

    /* Use getaddrinfo to resolve an IP address */
    struct addrinfo* result;
    ZeroMemory(result);

   /* TODO gethostbyname is depreciated */
   /* error = getaddrinfo(hostname, NULL, NULL, &result);
    if (error != 0)
    {
        quit(gai_strerror(error));
    }

    printf("%s\n", result->ai_canonname);
    error = getnameinfo(result->ai_addr, result->ai_addrlen, hostname, MAX_STR_LEN, NULL, 0, 0);
    if (error != 0)
    {
        quit(gai_strerror(error));
    }
   */

    struct hostent* host = gethostbyname(hostname); 
	struct in_addr **addr_list;
    addr_list = (struct in_addr **) host->h_addr_list;

	/* Take the first result */
    strcpy(host_ip, inet_ntoa(*addr_list[0]));

    if (VERBOSE) printf(">>> IP: %s\n", host_ip);

    /* generate socket, connect socket to the host address */
    struct sockaddr_in socket_addr;
    ZeroMemory(socket_addr);
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_port = htons(port);

	/* Convert the string hostname back to our socket data */
    error = inet_pton(AF_INET, host_ip, &socket_addr.sin_addr);
    if (error != 1)
    {
        quit("Error converting hostname to binary");
    }

	/* Try and create the socket */
    socket_FD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_FD == -1)
    {
        quit("Error creating socket");
    }

	/* Open the socket connection */
    error = connect(socket_FD, (struct sockaddr*)&socket_addr, sizeof socket_addr);
    if (error != 0)
    {
        quit("Error connecting to socket");
    }

	/* Could be a linked list, free it all! */
    freeaddrinfo(result);
    return socket_FD;
}
