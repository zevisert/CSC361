#pragma once

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct eth_header {
    unsigned char addr_dest[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char addr_host[ETHER_ADDR_LEN]; /* Source host address */
    unsigned short type; /* IP? ARP? RARP? etc */
};
