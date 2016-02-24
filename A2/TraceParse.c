#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>

#include "TraceParse.h"


#define VERBOSE 1

#define FILTER "tcp"

/* I want booleans! */
typedef enum { true, false } bool;

int main(int count, char** args)
{
    /*Check input args*/
    count = verify_input(args);
    if (count == 0) quit("No valid input files");
    
    pcap_t* cap;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i;
    for (i = 1; i <= count; ++i)
    {
        if ((cap = pcap_open_offline(args[i], errbuf)) == NULL)
        {
            printf("Couldn't open file %s\nReason: %s\n", args[i], errbuf);
            continue;
        }
        else if (VERBOSE) printf("Opened cap file %s\n", args[i]);
        /* parse_cap closes for us */
        parse_cap(cap);
        
    }

    quit("Source code not complete");
    return EXIT_SUCCESS;
}

void quit(char* message)
{
    if (message != NULL)
    {
        printf("\n%s\n", message);
    }
    else printf("\n");

    printf("Exiting...\n");
    exit(EXIT_FAILURE);
}

/*
    Validates a list of input arguments
    Modifies the input string array to contain only valid files on return
    Input:
        An array of pointers to strings to test
    Return:
        Number of valid cap files in input
    Output:
        Input arg is modified by ref to contain only valid cap files
*/
int verify_input(char** args)
{
    /* Skip program name */
    args++;
    
    int numFiles = 0;
    int i = 0;
    char** argPtr = args;
    char* ext = NULL;
    
    bool shift = false;

    /* Count strings and reset argPtr to start*/
    for ( ; *argPtr; ++numFiles, ++argPtr);
    argPtr = args;
    
    /* While there's more input strings */ 
    while (*argPtr && strlen(*argPtr))
    {
        /* From right to left, find the first '.' in the string */
        if( (ext = strrchr(*argPtr, '.')) != NULL)
        {
            /* If everything after the point above is .cap */
            if(strcmp(ext, ".cap") == 0)
            {
                /* Good, input file ends in .cap */
                FILE* file = fopen(*argPtr, "r");
                if (file == NULL)
                {
                    printf("ERR: File %s doesn't exist, or doesn't have read permissions\n", *argPtr);
                    shift = true;
                }
                /* Just checking if the file exists, we're done now */
                else fclose(file);
            }
            /* The remainder of the string wasn't .cap */
            else
            {
               if (VERBOSE) printf("ERR: File %s is not a .cap file.\n", *argPtr);
               shift = true;
            }
        }
        /* The whole string didn't have a '.' in it */
        else
        {
            if (VERBOSE) printf("ERR: File %s has no extension.\n", *argPtr);
            shift = true;
        }
        
        /* The input we tested wasn't a .cap file */ 
        if (shift == true)
        {
            shift = false;
            char** currString = argPtr;
            int j = i;
            /* From the current point on, copy strings down an index */ 
            for (++currString; *currString; ++currString, ++j)
            {
                args[j] = *currString;
            }
            /* Nullify the last string */
            args[j] = "\0";

            /* Decrease the number of valid input files */ 
            numFiles -= 1;
        }
        /* Didn't shift the input array down, look at the next string */
        else
        {
            if (VERBOSE) printf("File %s exists\n", *argPtr);
            ++argPtr;
            ++i;
        }
    }
    return numFiles;
}

/* 
    Dump the required information from the pcap file pointed to by cap
    Input: A previously validated and opened .cap file
    Return: Void
    Output to console:
        State of the connection - One of:
            S0F0, S1F0, S2F0, S1F1, S2F1, S2F2, S0F1, S0F2, or R
        For completed connections:
            - Starting time, ending time, and duration for each connection.
            - Number of packets sent in EACH direction, and the Total
            - Number of data bytes sent in each direction, and the Totals

        Also need to provide the following on TCP conxns per cap file. 
            - Number of reset connections
            - Number of unclosed hanging connections
            - Number of completed connections
                - Regarding these:
                    - The minimum, mean, and maximum connection duration
                    - The minimim, mean, and maximim RTT times
                    - The minimum, mean, and maximum number of packets sent
                    - The minimum, mean, and maximum receive window sizes
*/
void parse_cap(pcap_t* cap)
{
    struct bpf_program fp;
    if (pcap_compile(cap, &fp, FILTER, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter '%s': %s\n", FILTER, pcap_geterr(cap));
        quit(NULL);
    }
    if (pcap_setfilter(cap, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter '%s': %s\n", FILTER, pcap_geterr(cap));
        quit(NULL);
    }
    /* Wooo! Function pointers! */
    pcap_loop(cap, -1, inspect_packet, 0);
    
    /* And close the session */
    pcap_close(cap);
}

void inspect_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* packet)
{
    unsigned int size_eth = 14;
    unsigned int size_ip;
    unsigned int size_tcp;
 
    const struct eth_header* ethernet = (struct eth_header*)(packet);
    const struct ip_header*  ip = (struct ip_header*)(packet + size_eth);

    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        quit(NULL);
    }

    const struct tcp_header* tcp = (struct tcp_header*)(packet + size_eth + size_ip);

    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
        quit(NULL);
    }

    

    const unsigned char* payload = (unsigned char *)(packet + size_eth + size_ip + size_tcp);
    if ((tcp->flags & SYN) || (tcp->flags & RST) || (tcp->flags & FIN))
    {
        char* flag_string = flag_to_string(tcp->flags);
        printf("Packet with flags [%s]\n", flag_string);
        free(flag_string);
    }

}
