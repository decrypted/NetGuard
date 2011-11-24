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
#include "str_ulong.h"


static int 
ip2in_addr_arpa(char *s, struct in_addr *ip)
{
	int len=0,l;
	unsigned char *p=(unsigned char *)ip;
	/* XXX IPv6 */
#define X(y) do { l=str_ulong(s,p[y]); len+=l; s+=l; } while(0)
#define Y(z) do { l=strlen(z); memcpy(s,z,l); s+=l; len+=l;} while(0)
	X(3); Y("."); X(2); Y("."); X(1); Y("."); X(0); Y(".in-addr.arpa.");
	*s=0;
	return ++len;
}

int
dns_ptr(struct in_addr *domain, dns_t **answer)
{
	int ans;
	int ret=0;
	dns_ans_t response;
	char name[MAXDNAME];
	dns_t *anker=NULL;
	int count=0;
	int i;
	int j;
	unsigned short rrtype;
	unsigned short rrdlen;
	char tmp[sizeof("111.222.333.444.in-addr.arpa")]; /* IPv6, too */

	ip2in_addr_arpa(tmp,domain);

	ans=resolve (tmp, T_PTR, &response, name);
	switch(ans)
	{
	case 0: return 0; /* keine addresse */
	case DNS_HARD: ret=DNS_HARD; goto cleanup;
	case DNS_SOFT: ret=DNS_SOFT; goto cleanup;
	}
	for (i=0;i<ans;i++) {
		if (response.pos == response.end) {
			ret=DNS_SOFT;
			goto cleanup;
		}
		j = dn_expand(response.u.buf,response.end,response.pos,name,MAXDNAME);
		if (j < 0)  {
			ret=DNS_SOFT;
			goto cleanup;
		}
		response.pos += j;

		j = response.end - response.pos;
		if (j < 4 + 3 * 2) {
			ret=DNS_SOFT;
			goto cleanup;
		}
		rrtype = dns_getshort(response.pos);
		rrdlen = dns_getshort(response.pos + 8);
		response.pos += 10;

		if (rrtype == T_PTR)
		{
			dns_t *n;
			j = dn_expand(response.u.buf,response.end,response.pos,name,MAXDNAME);
			if (j<0) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			n=malloc(sizeof(dns_t));
			if (!n) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			memset(n,0,sizeof(dns_t));
			n->name=malloc(strlen(name)+1);
			if (!n->name) {
				free(n);
				ret=DNS_SOFT;
				goto cleanup;
			}
			memcpy(n->name,name,strlen(name)+1);
			n->next=anker;
			anker=n;
			count++;
		}
		response.pos += rrdlen;
	}
	*answer=anker;
	return count;

	/* Failure handling - cleanup */
	cleanup:
	{
		dns_free_chain(anker);
		return ret;
	}
}
