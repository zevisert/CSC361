#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <limits.h>

#include "Headers.h"
#include "TraceParse.h"
#include "DynArray.h"

#define FILTER "tcp"
#define MAX_CONNECTIONS 1000

#define true 1
#define false 0

#define VERBOSE false
#define SHOW_RESET_PROIR_STATE false

struct report reports[MAX_CONNECTIONS];
struct timeval time_begin;
int tracked = 0;

int main(int count, char** args)
{
    /*Check input args*/
    count = verify_input(args);
    if (count == 0) quit("No valid input files");
    
    pcap_t* cap;
    char errbuf[PCAP_ERRBUF_SIZE];
	int i = 1;
    for ( ; i <= count; ++i)
    {
	    if (i > 1)
	    {
		    ZeroMemory(reports);
		    printf("################### NEXT FILE #####################");
	    }
	    tracked = 0;
	    
        if ((cap = pcap_open_offline(args[i], errbuf)) == NULL)
        {
            printf("Couldn't open file %s\nReason: %s\n", args[i], errbuf);
            continue;
        }
        else if (VERBOSE) printf("Opened cap file %s\n", args[i]);
        /* parse_cap closes for us */
        parse_cap(cap);
	    
	    print_report();
    }

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
    
	int shift = false;

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
                    shift = 1;
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
        if (shift)
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

/* PCAP_LOOP handler
   Seperate out the data into the appropriate headers, then update the tracked information
*/
void inspect_packet(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* data)
{
    unsigned int size_eth = 14;
    unsigned int size_ip;
    unsigned int size_tcp;
 
	/* Program doesn't use the ethernet header */
    /*const struct eth_header* ethernet = (struct eth_header*)(data); */
    const struct ip_header* ip = (struct ip_header*)(data + size_eth);

	/* Get and check the IP Header size*/
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
        quit(NULL);
    }

	/* Use that to get the TCP header */ 
    const struct tcp_header* tcp = (struct tcp_header*)(data + size_eth + size_ip);

	/* Get and check the size of the TCP header */
    size_tcp = TCP_OFF(tcp)*4;
    if (size_tcp < 20) {
        fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
        quit(NULL);
    }

    const unsigned char* payload = (unsigned char *)(packet + size_eth + size_ip + size_tcp);
	unsigned long payload_length = strlen((const char*) payload);

	/* Inialize the data structure containing the information we're tracking */
    const struct packet transmission = packet(ip, tcp, header, payload_length);

	/* Verbose print on processing a packet with the TCP flags below */
	if (VERBOSE && (transmission.header.flags & (SYN|RST|FIN)))
	{
        char* flag_string = FLAG_STRING(transmission.header.flags);
        printf("Packet with flags [%s]\n", flag_string);
        free(flag_string);
	}
    
	/* Update the tracked information */
    update_reports(&transmission);
}

/* 
	Find and update the information for the report tracking the information captured by this transmission
*/
void update_reports(const struct packet* transmission)
{
    int i = 0;
	struct report* iter;
	struct conxn ID = transmission->route;
	int haveReport = false;
	
	/* Verbose print on processing a packet with the TCP flags below */
	if (VERBOSE && (transmission->header.flags & (SYN | RST | FIN)))
	{
		printf("Transmission:\n\tsrc %s:%d\n", inet_ntoa(ID.src_ip), ID.src_port);
		printf("\tdst %s:%d\n", inet_ntoa(ID.dst_ip), ID.dst_port);
	}
	
    /* Linear search for report with matching conxn 4 tuple */
	for ( ; i <= tracked; ++i)
	{
		iter = &reports[i];
		if (cmpconxn(iter->ID, transmission->route) == 0)
		{
			haveReport = true;
			break;
		}
	}
    
	/* Verbose print on processing a packet with the TCP flags below */
	if (VERBOSE && (transmission->header.flags & (SYN | RST | FIN)))
	{
		printf("Tracking this connection: %s ", haveReport ? "true" : "false");
		if (haveReport) printf("at index %d at: %p\n\n", i, &reports[i]);
		else printf("\n\n");
	}
	
	struct timeval relative, non_const;
	non_const = transmission->info.ts;
	timersub(&non_const, &time_begin, &relative);
	
	/* Not tracking this connection yet, initalize a report */
	if (!haveReport)
	{
		/* if this is the very first one, store the time, as it's the relative baseline for all others */
		if (tracked == 0) time_begin = transmission->info.ts;
		tracked += 1;
		/* Set the conxn 4 tuple */
		iter->ID = transmission->route;
		
		/* Get the relative starting time */
		non_const = transmission->info.ts;
		timersub(&non_const, &time_begin, &relative);
		iter->time_start = relative;
		
		/* Initialize the window size dynamic arrays */
		
		if (initArray(&(iter->window_recv), 5) ||
			initArray(&(iter->window_send), 5) ||
			initArray(&(iter->RTT_ack), 5) ||
			initArray(&(iter->RTT_seq), 5))
		{
			quit("Malloc Failed!");
		}
	}

	/* Forward transmission host->client */
	if (cmpconxn_forward(iter->ID, transmission->route) == 0)
	{
		iter->packets_recv += 1;
		iter->bytes_recv += transmission->info.caplen;
		
		/* Store the window size and SEQ number */
		insertArray(&iter->window_recv, (struct array_t) { .data = transmission->header.window_size, .ts = transmission->info.ts});
		insertArray(&iter->RTT_ack, (struct array_t) { .data = transmission->header.ack_num, .ts = relative });
	}
	
	/* Backward transmission client->host */
	if (cmpconxn_backward(iter->ID, transmission->route) == 0)
	{
		iter->packets_sent += 1;
		iter->bytes_sent += transmission->info.caplen;
		/* Store the window size */
		insertArray(&iter->window_send, (struct array_t) { .data = transmission->header.window_size, .ts = transmission->info.ts });
		insertArray(&iter->RTT_seq, (struct array_t) { .data = transmission->header.seq_num, .ts = relative });
	}
	
	// Packet has SYN flag
	if (transmission->header.flags & SYN)
	{
		// Restore reset state
		if (iter->status == R) iter->status = iter->pre_reset_status;
		iter->status += S1F0;
	}
	
	// Packet has FIN flag
	if (transmission->header.flags & FIN)
	{
		if (iter->status == R) iter->status = iter->pre_reset_status;
		iter->status += S0F1;
	}
	
	// Packet has RST flag
	if (transmission->header.flags & RST)
	{
		iter->reset_count += 1;
		iter->pre_reset_status = iter->status;
		iter->status = R;
	}
	
	/* Last seen packet time is the end */
	/* New value seconds value is larger, or new value has same seconds but microseconds is larger. */
	if (iter->time_end.tv_sec < transmission->info.ts.tv_sec || (
		iter->time_end.tv_usec < transmission->info.ts.tv_usec && 
		iter->time_end.tv_sec == transmission->info.ts.tv_sec )
	   )
	{
		iter->time_end = relative;
	}
}

/*
	Generate the required statistics as we loop through the connections observed and print them
*/
void print_report()
{
	/* Iterator to reduce array accessing */
	struct report item;
	
	/* General statistic variables */
	int complete = 0;
	int resets = 0;
	int unclosed = 0;
	
	/* Variable for calulation of min max and mean */
	int packets_min, packets_mean, packets_max;
	packets_max = packets_mean = 0;
	packets_min = INT_MAX;
	
	unsigned int window_min, window_mean, window_max, window_count;
	window_count = window_max = window_mean = 0;
	window_min = UINT_MAX;
	
	struct timeval time_min, time_mean, time_max;
	time_min.tv_sec = time_min.tv_usec = LONG_MAX;
	time_mean.tv_sec = time_mean.tv_usec = time_max.tv_sec = time_max.tv_usec = 0;
	
	DynArray RTT[tracked];
	
	printf("A) Total number of connections: %d\n\n", tracked);
	
	printf("B) Connection Details:\n");
	
	/* Loop through all the connections we've tracked */
	int i = 0;
	for (; i < tracked; ++i)
	{
		/* Inialize the RTT array even if it's not used below, this way we can free them all in a loop */
		initArray(&RTT[i], 1);

		item = reports[i];
		
		printf("Connection %d:\n", i+1);
		printf("Source Address: %s\n", inet_ntoa(item.ID.src_ip));
		printf("Destination address: %s\n", inet_ntoa(item.ID.dst_ip));
		printf("Source Port: %d\n", item.ID.src_port);
		printf("Destination Port: %d\n", item.ID.dst_port);
		printf("Status: %s", STATUS_STRING(item.status));
		
		/* If verbosing, append more info to the RESET state */
		if (item.status == R) {
			resets += 1;
			if (SHOW_RESET_PROIR_STATE) printf(" (was %s)", STATUS_STRING(item.pre_reset_status));
		}
		printf("\n");
		
		/* Only if the connection is complete provide the extra information */
		int status = item.status;
		int prs = item.pre_reset_status;
		if ((status == S1F1 || status == S2F1 || status == S2F2) ||
			(status == R && (prs == S1F1 || prs == S2F1 || prs == S2F2 )))
		{
			/* Calculate all the info we need to report on this connection*/
			struct timeval diff; timersub(&item.time_end, &item.time_start, &diff);
			
			/* Calculate the info we need for all completed connections */
			complete += 1;
			time_min = min_time(time_min, diff);
			time_max = max_time(time_max, diff);
			time_mean.tv_sec += diff.tv_sec;
			time_mean.tv_usec += diff.tv_usec;
			
			/* Update counts for packets transmitted */
			packets_min = min(packets_min, item.packets_recv + item.packets_sent);
			packets_max = max(packets_max, item.packets_recv + item.packets_sent);
			packets_mean += item.packets_recv + item.packets_sent;
			
			/* Update counts for window, using received window size */
			int j = 0;
			for (; j < item.window_recv.used; ++j)
			{
				window_min = min(window_min, item.window_recv.array[j].data);
				window_max = max(window_max, item.window_recv.array[j].data);
				window_count += 1;
				window_mean += item.window_recv.array[j].data;
			}
			
			/* Update counts for window, using sent window size */
			for (j = 0; j < item.window_send.used; ++j)
			{
				window_min = min(window_min, item.window_send.array[j].data);
				window_max = max(window_max, item.window_send.array[j].data);
				window_count += 1;
				window_mean += item.window_send.array[j].data;
			}
			
			/* Update counts for RTT */
			int ack_match_index = -1;
			int ack_match_count = 0;

			for (j = 0; j < item.RTT_seq.used; ++j)
			{
				int k = 0;
				for ( ; k < item.RTT_ack.used; ++k)
				{
					/* Look at them all! */
					if (item.RTT_ack.array[k].data == item.RTT_seq.array[j].data)
					{
						ack_match_count += 1;
						ack_match_index = k;
					}
				}
				/* Can calculate RTT for this pair! */
				if (ack_match_count == 1)
				{
					struct timeval time_RTT;
					timersub(&item.RTT_seq.array[j].ts, &item.RTT_ack.array[ack_match_index].ts, &time_RTT);
					insertArray(&RTT[i], (struct array_t) { .data = item.RTT_seq.array[j].data, .ts = time_RTT});
				}
				ack_match_count = 0;
				ack_match_index = -1;
			}
			
			/* Print out the information for this connection */
			printf("Start time: %ld.%06ld\n", item.time_start.tv_sec, item.time_start.tv_usec);
			printf("End Time: %ld.%06ld\n", item.time_end.tv_sec, item.time_end.tv_usec);
			printf("Duration: %ld.%06ld\n", diff.tv_sec, diff.tv_usec);
			
			printf("Number of packets sent from Source to Destination: %ld\n", item.packets_sent);
			printf("Number of packets sent from Destination to Source: %ld\n", item.packets_recv);
			printf("Total number of packets: %ld\n", item.packets_recv + item.packets_sent);
			
			printf("Number of data bytes sent from Source to Destination: %ld\n", item.bytes_sent);
			printf("Number of data bytes sent from Destination to Source: %ld\n", item.bytes_sent);
			printf("Total number of data bytes: %ld\n", item.bytes_recv + item.bytes_sent);
		}
		/* This connection doesn't count as completed */
		else
		{
			unclosed += 1;
		}
		
		/* Printed out connection stats, done with these arrays */
		freeArray(&item.window_recv);
		freeArray(&item.window_send);
		printf("END\n");
		printf("+++++++++++++++++++++++++++++++++\n");
	}
	
	/* Done looping over the tracked connections */ 
	time_mean.tv_sec /= (complete ? complete : 1);
	time_mean.tv_usec /= (complete ? complete : 1);
	packets_mean /= (complete ? complete : 1);
	window_mean /= (window_count ? window_count : 0);

	struct timeval RTT_min;
	struct timeval RTT_max;
	struct timeval RTT_mean;
	int RTT_count = 0;
	
	RTT_mean.tv_sec = RTT_mean.tv_usec = RTT_max.tv_sec = RTT_max.tv_usec = 0;
	RTT_min.tv_sec = RTT_min.tv_usec = LONG_MAX;
	
	/* Update counts for RTT */
	for (i = 0; i < tracked; ++i)
	{
		int j = 0;
		for (; j < RTT[i].used; ++j)
		{
			RTT_min = min_time(RTT_min, RTT[i].array[j].ts);
			RTT_max = max_time(RTT_max, RTT[i].array[j].ts);
			RTT_mean.tv_sec += RTT[i].array[j].ts.tv_sec;
			RTT_mean.tv_usec += RTT[i].array[j].ts.tv_usec;
			RTT_count += 1;
		}
	}
	/* Divide by zero work around */ 
	RTT_mean.tv_sec /= (RTT_count ? RTT_count : 1);
	RTT_mean.tv_usec /= (RTT_count ? RTT_count : 1);
	
	/* Free each of the Dynamic Arrays used for storing RTT */ 
	for (i = 0; i < tracked; ++i)
		freeArray(&RTT[i]);
	
	/* Print the final report */ 
	printf("\nC) General:\n");
	printf("Total number of complete TCP connections: %d\n", complete);
	printf("Number of reset TCP connections: %d\n", resets);
	printf("Number of TCP connections that were still open when the trace capture ended: %d\n", unclosed);
	printf("\nD) Complete TCP connections:\n");
	printf("Minimum time durations: %ld.%06ld\n", time_min.tv_sec, time_min.tv_usec);
	printf("Mean time durations: %ld.%06ld\n", time_mean.tv_sec, time_mean.tv_usec);
	printf("Maximum time durations: %ld.%06ld\n", time_max.tv_sec, time_max.tv_usec);
	printf("\n");
	printf("Minimum RTT values including both send/received: %ld.%06ld\n", RTT_min.tv_sec, RTT_min.tv_usec);
	printf("Mean RTT values including both send/received: %ld.%06ld\n", RTT_mean.tv_sec, RTT_mean.tv_usec);
	printf("Maximum RTT values including both send/received: %ld.%06ld\n", RTT_max.tv_sec, RTT_max.tv_usec);
	printf("\n");
	printf("Minimum number of packets including both send/received: %d\n", packets_min);
	printf("Mean number of packets including both send/received: %d\n", packets_mean);
	printf("Maximum number of packets including both send/received: %d\n", packets_max);
	printf("\n");
	printf("Minimum receive window sizes including both send/received: %d\n", window_min);
	printf("Mean receive window sizes including both send/received:%d \n", window_mean);
	printf("Maximum receive window sizes including both send/received: %d\n", window_max);
}