/* Header file for TraceParse.c */

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

#define IP_HL(ip)       (((ip)->version_headerlen) & 0x0f)
#define IP_V(ip)        (((ip)->version_headerlen) >> 4)

struct conxn {
    struct in_addr src_ip;
    unsigned short src_port;
    struct in_addr dst_ip;
    unsigned short dst_port;
}

int cmpconxn(struct conxn* a, struct conxn* b)
{
    int result = 0;
    if (a->src_ip.s_addr != b->src_ip.s_addr) i += 1;
    if (a->dst_ip.s_addr != b->dst_ip.s_addr) i += 2;
    if (a->src_port != b->src_port)           i += 4;
    if (a->dst_port != b->dst_port)           i += 8;
    
    return i;
}

typedef struct {
    struct conxn_llist* prev = NULL;
    struct conxn_llist* next = NULL;
    struct conxn* data = NULL;
} conxn_llist;

/* Ethernet header */
struct eth_header {
    unsigned char addr_dest[ETHER_ADDR_LEN]; /* Destination host address */
    unsigned char addr_host[ETHER_ADDR_LEN]; /* Source host address */
    unsigned short type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip_header {
    
    #define IP_RF  0x8000        /* reserved fragment flag */
    #define IP_DF  0x4000        /* dont fragment flag */
    #define IP_MF  0x2000        /* more fragments flag */
    #define IP_OFF 0x1fff   /* mask for fragmenting bits */
    
    unsigned char version_headerlen;      /* version << 4 | header length >> 2 */
    unsigned char service_type;      /* type of service */
    unsigned short length;     /* total length */
    unsigned short id;      /* identification */
    unsigned short offset;     /* fragment offset field */

    unsigned char ttl;      /* time to live */
    unsigned char protocol;        /* protocol */
    unsigned short checksum;     /* checksum */
    struct in_addr src_ip; /* source address */
    struct in_addr dst_ip; /* dest address */
};

struct tcp_header {
    #define TH_OFF(th)  (((th)->data_offset & 0xf0) >> 4)
    #define TH_FLAGS (FIN|SYN|RST|ACK|URG|ECE|CWR)

    unsigned short src_port;   /* source port */
    unsigned short dst_port;   /* destination port */
    unsigned int seq_num;     /* sequence number */
    unsigned int ack_num;     /* acknowledgement number */
    unsigned char data_offset;    /* data offset, rsvd */
    unsigned char flags;

    unsigned short window_size;     /* window */
    unsigned short check_sum;     /* checksum */
    unsigned short urgent_ptr;     /* urgent pointer */
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

static char* flag_to_string(unsigned char flags)
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


int main(int, char**);
void quit(char*);
int verify_input(char**);
void parse_cap(pcap_t*);
void inspect_packet(unsigned char*, const struct pcap_pkthdr*, const unsigned char*);
