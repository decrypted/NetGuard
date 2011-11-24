/***************************************************************************
 *   NetGuard Tools                                                        *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
 *                                                                         *
 *                                                                         *
 *   This program is released under a dual license.                        *
 *   GNU General Public License for open source and educational use and    *
 *   the Net-Guard Professional License for commercial use.                *
 *   Details: http://www.net-guard.net/licence                             *
 *                                                                         *
 *   For open source and educational use:                                  *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 *                                                                         *
 *   For commercal use:                                                    *
 *   visit http://www.net-guard.net for details if you need a commercal    *
 *   license or not. All conditions are listed here:                       *
 *                 http://www.net-guard.net/licence                        *
 *                                                                         *
 *   If you are unsure what licence you can use you should take            *
 *   the Net-Guard Professional License.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef NETGUARD_TOOLS_H
#define NETGUARD_TOOLS_H

#include "defines.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netdb.h>


#ifdef __cplusplus

extern "C" {
#endif

#ifndef IPPROTO_SCTP
  #define IPPROTO_SCTP            132
#endif
#ifndef ETHERTYPE_8023
  #define ETHERTYPE_8023          0x0032  /* 802.3 protocol */
#endif
#ifndef ETHERTYPE_8021D
  #define ETHERTYPE_8021D         0x0026  /* 802.1d protocol */
#endif
#ifndef ETHERTYPE_PUP
  #define ETHERTYPE_PUP           0x0200  /* PUP protocol */
#endif
#ifndef ETHERTYPE_IP
  #define ETHERTYPE_IP            0x0800  /* IP protocol */
#endif
#ifndef ETHERTYPE_ARP
  #define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_REVARP
  #define ETHERTYPE_REVARP        0x8035  /* reverse Addr. resolution protocol */
#endif
#ifndef ETHERTYPE_NS
  #define ETHERTYPE_NS            0x0600
#endif
#ifndef ETHERTYPE_SPRITE
  #define ETHERTYPE_SPRITE        0x0500
#endif
#ifndef ETHERTYPE_TRAIL
  #define ETHERTYPE_TRAIL         0x1000
#endif
#ifndef ETHERTYPE_MOPDL
  #define ETHERTYPE_MOPDL         0x6001
#endif
#ifndef ETHERTYPE_MOPRC
  #define ETHERTYPE_MOPRC         0x6002
#endif
#ifndef ETHERTYPE_DN
  #define ETHERTYPE_DN            0x6003
#endif
#ifndef ETHERTYPE_LAT
  #define ETHERTYPE_LAT           0x6004
#endif
#ifndef ETHERTYPE_SCA
  #define ETHERTYPE_SCA           0x6007
#endif
#ifndef ETHERTYPE_REVARP
  #define ETHERTYPE_REVARP        0x8035
#endif
#ifndef ETHERTYPE_LANBRIDGE
  #define ETHERTYPE_LANBRIDGE     0x8038
#endif
#ifndef ETHERTYPE_DECDNS
  #define ETHERTYPE_DECDNS        0x803c
#endif
#ifndef ETHERTYPE_DECDTS
  #define ETHERTYPE_DECDTS        0x803e
#endif
#ifndef ETHERTYPE_VEXP
  #define ETHERTYPE_VEXP          0x805b
#endif
#ifndef ETHERTYPE_VPROD
  #define ETHERTYPE_VPROD         0x805c
#endif
#ifndef ETHERTYPE_ATALK
  #define ETHERTYPE_ATALK         0x809b
#endif
#ifndef ETHERTYPE_AARP
  #define ETHERTYPE_AARP          0x80f3
#endif
#ifndef ETHERTYPE_8021Q
  #define ETHERTYPE_8021Q         0x8100 //VLAN
#endif
#ifndef ETHERTYPE_IPX
  #define ETHERTYPE_IPX           0x8137
#endif
#ifndef ETHERTYPE_IPV6
  #define ETHERTYPE_IPV6          0x86dd
#endif
#ifndef ETHERTYPE_PPP
  #define ETHERTYPE_PPP           0x880b
#endif
#ifndef ETHERTYPE_MPLS
  #define ETHERTYPE_MPLS          0x8847
#endif
#ifndef ETHERTYPE_MPLS_MULTI
  #define ETHERTYPE_MPLS_MULTI    0x8848
#endif
#ifndef ETHERTYPE_PPPOED
  #define ETHERTYPE_PPPOED        0x8863
#endif
#ifndef ETHERTYPE_PPPOES
  #define ETHERTYPE_PPPOES        0x8864
#endif
#ifndef ETHERTYPE_LOOPBACK
  #define ETHERTYPE_LOOPBACK      0x9000
#endif


#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
#define ARPOP_InREQUEST 8               /* InARP request.  */
#define ARPOP_InREPLY   9               /* InARP reply.  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK.  */


#define ETH_NULL "\x00\x00\x00\x00\x00\x00"
#define ETH_BCAST "\xff\xff\xff\xff\xff\xff"

#define setNULL_HW_ADDR(mac) mac[0] = 0x00; mac[1] = 0x00 ; mac[2] = 0x00; mac[3] = 0x00; mac[4] = 0x00; mac[5] = 0x00;
#define setBCAST_HW_ADDR(mac) mac[0] = 0xFF; mac[1] = 0xFF ; mac[2] = 0xFF; mac[3] = 0xFF; mac[4] = 0xFF; mac[5] = 0xFF;

#define printf_mac_params(mac) mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]


struct tok {
	int v;                  /* value */
	const char *s;          /* string */
};

#define VLAN_ID(x) ntohs((unsigned short) x->h_vlan_TCI) & 0xFFF
struct vlan_hdr {
	unsigned short       h_vlan_TCI;                /* Encapsulates priority and VLAN ID */
	unsigned short       h_vlan_encapsulated_proto; /* packet type ID field (or len) */
};

typedef u_int8_t mac_addr[ETH_ALEN];

#define printmac(ether)  printf("%02x:%02x:%02x:%02x:%02x:%02x", ether[0],ether[1],ether[2],ether[3],ether[4],ether[5])
#define sprintmac(buffer,ether)  sprintf(buffer,"%02x:%02x:%02x:%02x:%02x:%02x", ether[0],ether[1],ether[2],ether[3],ether[4],ether[5])

extern int iface_get_id(int fd, const char *device);

extern int iface_bind(int fd, int ifindex);

extern char * IPPROTO_TO_STRING(int IPPROTO);
extern char * ETHERTYPE_TO_STRING(int ETHERTYPE);
extern const char *tok2str(const struct tok *, const char *, int);

extern const struct tok str_ethertype_values[];
extern const struct tok str_arpop_values[];
extern const struct tok str_proto_values[];
extern const struct tok skinny_callTypes[];

int check_skinny(struct ether_header *eth,struct iphdr *ip,struct tcphdr *tcp , void *data);

void print_package(unsigned int *vlanid, struct tpacket_hdr *h,struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);
void sprint_package(char*buffer,unsigned int *vlanid, struct tpacket_hdr *h,struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

inline u_int8_t compare_mac(mac_addr *m1,mac_addr *m2)
{
	int i;
	for(i=5;i>=0;i--) {
		if ((*m1)[i] != (*m2)[i]) return 0;
	};
	return 1;
};

int getmacfromchar(const char *input, mac_addr *mac);

char *get_ip_char(u_int32_t ip);

int dns_gethost(u_int32_t ip, char *buffer, int len);

#ifdef __cplusplus
}
#endif


#endif


