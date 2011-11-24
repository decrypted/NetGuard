#include "str_ulong.h"

size_t
str_ulong_base(char *s, unsigned long u, unsigned int base)
{
	const char *b="0123456789abcdefghijklmnopqrstuvwxyz";
	unsigned int len=1;
	unsigned long tmp=u;
	char *end;
	while (tmp>=base) {
		len++;
		tmp/=base;
	}
	if (!s)
		return len;
	end=s=s+len;
	while (u>=base) {
		s--;
		*s=b[u%base];
		u/=base;
	}
	s--;
	*s=b[u%base];
	*end=0;
	return len;
}

#ifdef TEST
int main(int argc, char **argv)
{
	char b[STR_ULONG];
	size_t l;
	l=str_ulong_base(b, strtoul(argv[1],0,0), strtoul(argv[2],0,0));
	write(1,b,l);
	write(1,"\n",1);
	exit(1);
}
#endif
