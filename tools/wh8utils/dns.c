#include <stdlib.h> /* malloc, free */
#include <string.h> /* memset */
#include <unistd.h> /* write */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include "dns.h"
#include "dns_int.h"

/* there have been too many buffer overflows in resolver libraries */
/* and yes, i have a good reason to do this, one of my machines has */
/* a buggy resolver library. */
#define DISTRUST_RESOLVER

unsigned short 
dns_getshort(unsigned char *s)
{ 
	return (((unsigned short)*s) << 8) + ((unsigned short)s[1]);
}

/* shamelessly stolen from qmail */
int 
resolve (const char *domain, int type, dns_ans_t *response, char *name)
{
	int n;
	int i;


#ifdef DISTRUST_RESOLVER
	/* note that making this static removes it from the stack */
	static volatile long magic=0;
	if (!magic) magic=0xdeadbeefUL;
	response->magic1=magic;
	response->magic2=magic;
#endif
	errno = 0;

	response->len = res_query (domain, C_IN, type, response->u.buf, sizeof (response->u));
#ifdef DISTRUST_RESOLVER
	/* for what it's worth ... maybe we never get here in case of a overflow */
	if (response->magic1!=magic || response->magic2!=magic) {
	 	/* this better be a system call! */
	 	write(2,"resolver library killed me\n",27);
	 	_exit(1);
	}
#endif

	if (response->len <= 0) {
		if (errno == ECONNREFUSED) return DNS_SOFT;
		if (h_errno == TRY_AGAIN) return DNS_SOFT;
		return DNS_HARD;
	}
	if ((size_t)response->len >= sizeof (response->u))
		response->len = sizeof (response->u);
	response->end = response->u.buf + response->len;
	response->pos = response->u.buf + sizeof (HEADER);
	/* now skip our questions, answer comes after that */
	n = ntohs (response->u.hdr.qdcount);
	while (n-- > 0) {
		i = dn_expand (response->u.buf, response->end, response->pos, name, MAXDNAME);
		if (i < 0) return DNS_SOFT;
		response->pos += i;
		i = response->end - response->pos;
		if (i < QFIXEDSZ) /* see arpa/namserv.h for QFIXSZ */
			return DNS_SOFT;
		response->pos += QFIXEDSZ;
	}
	return ntohs (response->u.hdr.ancount);
}

void
dns_free_chain(dns_t *a)
{
	dns_t *n;
	while (a) {
		free(a->name);
		n=a->next;
		free(a);
		a=n;
	}
}

/*
int main(int argc, char **argv)
{
	dns_t *mx;
	int count;
	int ec=0;
	int i;
	for (i=1;i<argc;i++) {
		if (argc>2)
			printf("%s\n",argv[i]);
		count=dns_a(argv[i],&mx);
		if (count==0) {
			printf("no mx\n");
			ec=0;
		} else if (count==DNS_SOFT) {
			printf("soft error\n");
			ec=1;
		} else if (count==DNS_HARD) {
			printf("hard error\n");
			ec=1;
		} else {
			while (mx) {
				dns_t *ip;
				int count2;
				printf("%d %s\n",mx->pref,mx->name);
				count2=dns_a(mx->name,&ip);
				if (count2==0) {
					printf("no ip address\n");
					ec=0;
				} else if (count2==DNS_SOFT) {
					printf("soft error on ip address\n");
					ec=1;
				} else if (count2==DNS_HARD) {
					printf("hard error on ip address\n");
					ec=1;
				} else {
					while (ip) {
						int count3;
						dns_t *ptr;
						char *s=inet_ntoa(ip->ip);
						if (s)
							printf("  %s\n",s);
						count3=dns_ptr(&ip->ip,&ptr);
						if (count3==0) {
							printf("no ptr name\n");
							ec=0;
						} else if (count3==DNS_SOFT) {
							printf("soft error on ptr name\n");
							ec=1;
						} else if (count3==DNS_HARD) {
							printf("hard error on ptr name\n");
							ec=1;
						} else {
							while (ptr) {
								printf("    %s\n",ptr->name);
								ptr=ptr->next;
							}
						}

						ip=ip->next;
					}
				}
				mx=mx->next;
			}
			ec=0;
		}
	}
	if (argc>2)
		exit(0);
	exit(ec);
}
*/
