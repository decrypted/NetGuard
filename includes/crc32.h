#ifndef NETGUARD_TOOLS_CRC_H
#define NETGUARD_TOOLS_CRC_H

#include <sys/types.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __cplusplus

extern "C" {
#endif

unsigned long crc32(const char *buf, size_t size);

#ifdef __cplusplus
}
#endif


#endif

