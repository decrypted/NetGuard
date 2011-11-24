/* there have been too many buffer overflows in resolver libraries */
#define DISTRUST_RESOLVER

typedef struct {
	int len;
	unsigned char * end;
	unsigned char * pos;
#ifdef DISTRUST_RESOLVER
	long magic1;
#endif
	union { 
		HEADER hdr; 
		unsigned char buf[PACKETSZ]; 
	} u;
#ifdef DISTRUST_RESOLVER
	long magic2;
#endif
} dns_ans_t;

unsigned short dns_getshort(unsigned char *c);
int resolve(const char *domain, int type, dns_ans_t *response, char *name);
