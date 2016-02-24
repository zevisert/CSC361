
typedef struct {
    struct in_addr src_ip;
    unsigned short src_port;
    struct in_addr dst_ip;
    unsigned short dst_port;
    tcp_header tcp;
} conxn;

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
    struct conxn_llist* next = NULL;
    struct conxn* data = NULL;
    size_t length;
} conxn_llist;


conxn_llist* add(conxn*);
conxn_llist* remove(conxn*);
conxn_llist* is_empty();

