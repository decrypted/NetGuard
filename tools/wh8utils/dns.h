#ifndef NG_DNS_H
#define NG_DNS_H

#define DNS_SOFT -1
#define DNS_HARD -2

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dns_t {
	char *name;
	struct in_addr ip;
    int pref;
    struct dns_t *next;
} dns_t;

/* sorts it */
int dns_mx(const char *domain, dns_t **answer);
int dns_a(const char *domain, dns_t **answer);
int dns_txt(const char *domain, dns_t **answer);
int dns_ptr(struct in_addr *ip, dns_t **answer);

void dns_free_chain(dns_t *);

#endif

#ifdef __cplusplus
}
#endif

