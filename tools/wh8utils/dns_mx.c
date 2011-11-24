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

static void sortit(dns_t *anker);

int dns_mx(const char *domain, dns_t **answer)
{
	int ans;
	int ret=0;
	dns_ans_t response;
	char name[MAXDNAME];
	dns_t *anker=NULL;
	int count=0;
	int i;
	int j;
	int pref;
	unsigned short rrtype;
	unsigned short rrdlen;

	ans=resolve (domain, T_MX, &response, name);
	switch(ans)
	{
	case 0: return 0; /* kein MX */
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

		if (rrtype == T_MX)
		{
			dns_t *n;
			if (rrdlen < 3) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			pref = (response.pos[0] << 8) + response.pos[1];
			if (dn_expand(response.u.buf,response.end,response.pos + 2,name,MAXDNAME) < 0) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			n=malloc(sizeof(dns_t));
			if (!n) {
				ret=DNS_SOFT;
				goto cleanup;
			}
			memset(n,0,sizeof(dns_t));
			n->pref=pref;
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
	/* sort it? */
	if (count==0) return 0;
	if (count>1) 
		sortit(anker);
	*answer=anker;
	return count;

	/* Failure handling - cleanup */
	cleanup:
		dns_free_chain(anker);
		return ret;
}

static void
sortit(dns_t *anker)
{
	/* bubblesort is good enough */
	dns_t *a,*b;
	a=anker;
	while (a) {
		b=a->next;
		while (b) {
			if (b->pref<a->pref) {
				int x;
				char *y;
				struct in_addr z;
				x=b->pref;
				b->pref=a->pref;
				a->pref=x;
				y=b->name;
				b->name=a->name;
				a->name=y;
				z=b->ip;
				b->ip=a->ip;
				a->ip=z;
			}
			b=b->next;
		}
		a=a->next;
	}
}

