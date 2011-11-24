#include <stdlib.h> /* malloc, free */
#include <string.h> /* memset */
#include <unistd.h> /* write */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "dns.h"
#include "dns_int.h"

int
dns_txt(const char *domain, dns_t **answer)
{
	int ans;
	dns_ans_t response;
	char name[MAXDNAME];
	int i;
	int j;
	unsigned short rrtype;
	unsigned short rrdlen;
	int count=0;
	dns_t *anker=0;

	ans=resolve (domain, T_TXT, &response, name);
	switch(ans)
	{
	case 0: return DNS_HARD;
	case DNS_HARD: return DNS_HARD;
	case DNS_SOFT: return DNS_SOFT;
	}
	for (i=0;i<ans;i++) {
		if (response.pos == response.end) { dns_free_chain(anker); return DNS_SOFT; }

		j = dn_expand(response.u.buf,response.end,response.pos,name,MAXDNAME);
		if (j < 0)  { dns_free_chain(anker); return DNS_SOFT; }
		response.pos += j;

		j = response.end - response.pos;
		if (j < 4 + 3 * 2) {dns_free_chain(anker); return DNS_SOFT;}

		rrtype = dns_getshort(response.pos);
		rrdlen = dns_getshort(response.pos + 8);
		response.pos += 10;

		if (rrtype == T_TXT)
		{
			dns_t *n;
			if (rrdlen < 4) {dns_free_chain(anker); return DNS_SOFT;}

			n=malloc(sizeof(dns_t));
			if (!n) { dns_free_chain(anker); return DNS_SOFT;}
			memset(n,0,sizeof(dns_t));
			n->name=malloc((*response.pos)+1); /* 1 byte len */
			if (!n->name) {dns_free_chain(anker); free(n); return DNS_SOFT;}
			memcpy(n->name,response.pos+1,*response.pos);
			n->name[*response.pos]=0;
			n->next=anker;
			anker=n;
			count++;
		}
		response.pos += rrdlen;
	}
	*answer=anker;
	return count;
}
