#ifndef STR_ULONG_H
#define STR_ULONG_H

#define STR_ULONG 64 /* 64 bytes, far more than needed for 2^128 */
#include "stddef.h" /* need size_t */
size_t str_ulong_base(char *s, unsigned long u, unsigned int base);
#define str_ulong(s,u) str_ulong_base(s,u,10);

#endif
