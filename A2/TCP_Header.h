#pragma once

#include <stdio.h>
#include <stdlib.h>

#define TCP_OFF(th)  (((th)->data_offset & 0xf0) >> 4)
#define TCP_FLAGS (FIN|SYN|RST|ACK|URG|ECE|CWR)

struct tcp_header {

    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_num;
    unsigned int ack_num;
    unsigned char data_offset;
    unsigned char flags;

    unsigned short window_size;
    unsigned short check_sum;
    unsigned short urgent_ptr;
};

enum {
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PUSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
    ECE = 0x40,
    CWR = 0x80
};

static const char* FLAG_STR[8] = {
    "FIN",
    "SYN",
    "RST",
    "PUSH",
    "ACK",
    "URG",
    "ECE",
    "CWR"
};

static inline char* FLAG_STRING(unsigned char flags)
{
    int i = flags;
    char* flag_string = (char*)calloc(1,42);
    while( i > 0 ){
             if( i & FIN ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[0]); i-=FIN; }
        else if( i & SYN ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[1]); i-=SYN; }
        else if( i & RST ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[2]); i-=RST; }
        else if( i & PUSH){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[3]); i-=PUSH;}
        else if( i & ACK ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[4]); i-=ACK; }
        else if( i & URG ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[5]); i-=URG; }
        else if( i & ECE ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[6]); i-=ECE; }
        else if( i & CWR ){ sprintf(flag_string, "%s-%s", flag_string, FLAG_STR[7]); i-=CWR; }
        else return "UNKNOWN";
    }
    sprintf(flag_string, "%s", flag_string+1);
    return flag_string;
}
