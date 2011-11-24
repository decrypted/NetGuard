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

int
dns_a(const char *domain, dns_t **answer)
{
	int ans;
	dns_ans_t response;
	char name[MAXDNAME];
	dns_t *anker=NULL;
	int ret=0;
	int count=0;
	int i;
	int j;
	unsigned short rrtype;
	unsigned short rrdlen;

	ans=resolve (domain, T_A, &response, name);
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

		if (rrtype == T_A)
		{
			dns_t *n;
			if (rrdlen < 4) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			n=malloc(sizeof(dns_t));
			if (!n) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			memset(n,0,sizeof(dns_t));
			memcpy(&n->ip,response.pos,4);
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
