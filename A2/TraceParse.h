#pragma once
/* Header file for TraceParse.c */

#include <sys/time.h>

#include "TCP_Header.h"

#define ZeroMemory(X) memset(&X, 0, sizeof X)

struct conxn {
    struct in_addr src_ip;
    unsigned short src_port;
    struct in_addr dst_ip;
    unsigned short dst_port;
};

struct packet {
    struct pcap_pkthdr info;
    struct tcp_header  header;
    struct conxn       route;
};

struct report {
    struct conxn   ID;
    struct timeval time_start;
    struct timeval time_end;
    long int       packets_sent;
    long int       packets_recv;
    long int       bytes_sent;
    long int       bytes_recv;
	enum
	{
		S0F0,
		S1F0,
		S2F0,
		S1F1,
		S2F1,
		S2F2,
		S0F1,
		S0F2,
		R
	} status;
};

static const char* STATUS_STRING[9] = {
	"S0F0",
	"S1F0",
	"S2F0",
	"S1F1",
	"S2F1",
	"S2F2",
	"S0F1",
	"S0F2",
	"R"
};

static inline struct packet packet(const struct ip_header* ip, const struct tcp_header* tcp, const struct pcap_pkthdr* header)
{
    return (struct packet)
        {
            .route = (struct conxn) 
            {
                .src_ip = ip->src_ip,
                .src_port = ntohs(tcp->src_port),
				.dst_ip = ip->dst_ip,
                .dst_port = ntohs(tcp->dst_port)
            },
        .info = *header,
        .header = *tcp
    };
}

static inline int cmpconxn_forward(const struct conxn a, const struct conxn b)
{
	int result = 0;
	if (a.src_ip.s_addr != b.src_ip.s_addr) result += 0x1;
	if (a.dst_ip.s_addr != b.dst_ip.s_addr) result += 0x2;
	if (a.src_port != b.src_port)           result += 0x3;
	if (a.dst_port != b.dst_port)           result += 0x4;
	return result;
}

static inline int cmpconxn_backward(const struct conxn a, const struct conxn b)
{
	int result = 0;
	if (a.src_ip.s_addr != b.dst_ip.s_addr) result += 0x10;
	if (a.dst_ip.s_addr != b.src_ip.s_addr) result += 0x20;
	if (a.src_port != b.dst_port)           result += 0x30;
	if (a.dst_port != b.src_port)           result += 0x40;
	return result;
}

static inline int cmpconxn(const struct conxn a, const struct conxn b)
{
	int result1 = cmpconxn_forward(a, b);
	int result2 = cmpconxn_backward(a, b);
	if (result1 == 0) return 0;
	if (result2 == 0) return 0;
    return result1 + result2;
}



int main(int, char**);
void quit(char*);
int verify_input(char**);
void parse_cap(pcap_t*);
void inspect_packet(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
void update_reports(const struct packet*);
void print_report();
