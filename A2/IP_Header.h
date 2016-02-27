#pragma once

#include "netinet/ip.h"

#define IP_HL(ip)       (((ip)->version_headerlen) & 0x0f)
#define IP_V(ip)        (((ip)->version_headerlen) >> 4)
#define IP_RF  0x8000  /* reserved fragment flag */
#define IP_DF  0x4000  /* dont fragment flag */
#define IP_MF  0x2000  /* more fragments flag */
#define IP_OFF 0x1fff  /* mask for fragmenting bits */
    

/* IP header */
struct ip_header {
    

    unsigned char version_headerlen;      /* version << 4 | header length >> 2 */
    unsigned char service_type;      /* type of service */
    unsigned short length;
    unsigned short id;
    unsigned short offset;

    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    struct in_addr src_ip; 
    struct in_addr dst_ip;
};
