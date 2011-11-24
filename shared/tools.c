/***************************************************************************
 *   NetGuard Tools                                                        *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
 *                                                                         *
 *                                                                         *
 *   The Files are released under a dual license.                          *
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

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <stdarg.h>
#include <signal.h>

#include "../includes/tools.h"

const struct tok str_ethertype_values[] = {
	{ ETHERTYPE_IP,		"IPv4" },
	{ ETHERTYPE_8023,  "802.3" },
	{ ETHERTYPE_8021D,  "802.1D" },
	{ ETHERTYPE_MPLS,		"MPLS unicast" },
	{ ETHERTYPE_MPLS_MULTI,	"MPLS multicast" },
	{ ETHERTYPE_IPV6,		"IPv6" },
	{ ETHERTYPE_8021Q,		"802.1Q" },
	{ ETHERTYPE_PUP,            "PUP" },
	{ ETHERTYPE_ARP,            "ARP"},
	{ ETHERTYPE_REVARP ,        "Reverse ARP"},
	{ ETHERTYPE_NS,             "NS" },
	{ ETHERTYPE_SPRITE,         "Sprite" },
	{ ETHERTYPE_TRAIL,          "Trail" },
	{ ETHERTYPE_MOPDL,          "MOP DL" },
	{ ETHERTYPE_MOPRC,          "MOP RC" },
	{ ETHERTYPE_DN,             "DN" },
	{ ETHERTYPE_LAT,            "LAT" },
	{ ETHERTYPE_SCA,            "SCA" },
	{ ETHERTYPE_LANBRIDGE,      "Lanbridge" },
	{ ETHERTYPE_DECDNS,         "DEC DNS" },
	{ ETHERTYPE_DECDTS,         "DEC DTS" },
	{ ETHERTYPE_VEXP,           "VEXP" },
	{ ETHERTYPE_VPROD,          "VPROD" },
	{ ETHERTYPE_ATALK,          "Appletalk" },
	{ ETHERTYPE_AARP,           "Appletalk ARP" },
	{ ETHERTYPE_IPX,            "IPX" },
	{ ETHERTYPE_PPP,            "PPP" },
	{ ETHERTYPE_PPPOED,         "PPPoE D" },
	{ ETHERTYPE_PPPOES,         "PPPoE S" },
	{ ETHERTYPE_LOOPBACK,       "Loopback" },
	{ 0, NULL}
};

const struct tok str_arpop_values[] = {
	{ ARPOP_REQUEST,	"request" },
	{ ARPOP_REPLY,  	"reply" },
	{ ARPOP_RREQUEST,  	"r request" },
	{ ARPOP_RREPLY,		"r reply" },
	{ ARPOP_InREQUEST,	"in request" },
	{ ARPOP_InREPLY,	"in reply" },
	{ ARPOP_NAK,		"nak" },
	{ 0, NULL}
};

const struct tok str_proto_values[] = {
	{ IPPROTO_IP	,"Dummy protocol for TCP"},
	{ IPPROTO_ICMP	,"ICMP"},
	{ IPPROTO_IGMP	,"IGMP"},
	{ IPPROTO_IPIP	,"IPIP"},
	{ IPPROTO_TCP	,"TCP"},
	{ IPPROTO_EGP	,"EGP"},
	{ IPPROTO_PUP	,"PUP"},
	{ IPPROTO_UDP	,"UDP"},
	{ IPPROTO_IDP	,"IDP"},
	{ IPPROTO_TP	,"TP"},
	{ IPPROTO_IPV6	,"IPV6"},
	{ IPPROTO_ROUTING,"V6Routing"},
	{ IPPROTO_FRAGMENT,"V6Fragment"},
	{ IPPROTO_RSVP	,"RSVP"},
	{ IPPROTO_GRE	,"GRE"},
	{ IPPROTO_ESP	,"ESP"},
	{ IPPROTO_AH	,"AH"},
	{ IPPROTO_ICMPV6,"V6ICMP"},
	{ IPPROTO_NONE	,"V6NONE"},
	{ IPPROTO_DSTOPTS,"V6DSTOPTS"},
	{ IPPROTO_MTP	,"MTP"},
	{ IPPROTO_ENCAP	,"ENCAP"},
	{ IPPROTO_PIM 	,"PIM"},
	{ IPPROTO_COMP	,"COMP"},
	{ IPPROTO_SCTP	,"SCTP"},
	{ IPPROTO_RAW	,"RAW"},
	{ 0, NULL}
};

const struct tok skinny_callTypes[] = {
	{1		,"InBoundCall"},
	{2		,"OutBoundCall"},
	{3		,"ForwardCall"},
	{0		,NULL}
};

/*
 *  Return the index of the given device name. Fill ebuf and return
 *  -1 on failure.
 */
int iface_get_id(int fd, const char *device)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		printf("ERROR ON iface_get_id ioctl: %s\n", strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

/*
 *  Bind the socket associated with FD to the given device.
 */
int iface_bind(int fd, int ifindex)
{
	struct sockaddr_ll	sll;
	int			err;
	socklen_t		errlen = sizeof(err);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		printf("Cant bind to dev %d: %s\n", ifindex, strerror(errno));
		return -1;
	}

	/* Any pending errors, e.g., network is down? */

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		printf("getsockopt: %s\n", strerror(errno));
		return -2;
	}

	if (err > 0) {
		printf("bind: %s\n", strerror(err));
		return -2;
	}

	return 0;
}

/*
* Convert a token value to a string; use "fmt" if not found.
*/
const char *
tok2str(register const struct tok *lp, register const char *fmt,register int v)
{
	static char buf[128];

	while (lp->s != NULL) {
		if (lp->v == v)
			return (lp->s);
		++lp;
	}
	if (fmt == NULL)
		fmt = "#%d";
	(void)snprintf(buf, sizeof(buf), fmt, v);

	return (buf);
}


/**
int check_skinny(struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data){
	volatile u_int32_t * hdr_data_length = (volatile u_int32_t *) (data);
	u_int32_t * hdr_reserved = (u_int32_t *) (data+4);
	u_int32_t * data_messageid = (u_int32_t *) (data+8);

	if ((ntohs(tcp->dest) != 2000) && (ntohs(tcp->source) != 2000))
		return 0; //Not an SKINNY packet, wrong port

	if ((*hdr_data_length) < 4 || (*hdr_data_length) > 1024 || (*hdr_reserved) != 0) {
		//Not an SKINNY packet, just happened to use the same port
		return 0;
	}

	switch (*data_messageid) {
		case  0x1:  //register message
		{
			char *devicename = (void*)(data+12);
			if ((devicename[0] = 'S') && (devicename[1] = 'E') && (devicename[2] = 'P')) {
				if (strlen(devicename) != 15) return 0;
				//OK SKINNY Register message
				char layer2[12];
				sprintf(layer2,"%02X%02X%02X%02X%02X%02X",eth->ether_shost[0],eth->ether_shost[1],
							eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
				printf("register phone: %15s ",devicename);
				printf("ip: %15s ",inet_ntoa(*(struct in_addr *)&ip->saddr));
				printf("callmanager: %15s ",inet_ntoa(*(struct in_addr *)&ip->daddr));

				if (!strncmp((char*)(devicename+3),(char*)&layer2,12)) {
					//Layer 3 = Layer 2
					printf(" CHECK OK\n");
				} else  {
					//faked packet
					printf("layer2 from: ");
					printmac(eth->ether_shost);
					printf(" to: ");
					printmac(eth->ether_dhost);
					printf(" CHECK FAILED - layer 3 <> layer2 \n");
					return 1;
				}
			} else {
				//Not an SKINNY packet ? Strange register name
				printf("got strange SKINNY register message for: %s ",devicename);
				printf("layer2 from: ");
				printmac(eth->ether_shost);
				printf(" to: ");
				printmac(eth->ether_dhost);
				printf(" ip: %15s -> ",inet_ntoa(*(struct in_addr *)&ip->saddr));
				printf("%15s",inet_ntoa(*(struct in_addr *)&ip->daddr));
			}
			break;
		}
		case  0x27:  //get line
		{
			printf("unregister ");
			printf("ip: %15s ",inet_ntoa(*(struct in_addr *)&ip->saddr));
			printmac(eth->ether_shost);
			printf("\n");
			break;
		}
		case  0x92:  //get line
		{
			char *linedirnumber = (void*)(data+16);
			printf("ip: %15s ",inet_ntoa(*(struct in_addr *)&ip->daddr));
			printmac(eth->ether_shost);
			printf(" Phonenumber: %s\n",linedirnumber);
			break;
		}
		case  0x8a:  //startMediaTransmistion
		{
			u_int32_t * c_conf = (void*)(data+12);
			u_int32_t * c_party = (void*)(data+16);
			in_addr_t * c_ip = (void*)(data+20);
			struct in_addr c_ip_d;
			c_ip_d.s_addr = (*c_ip);
			u_int32_t * c_port = (void*)(data+24);

			printf("start media conf: %d party: %d ",(*c_conf),(*c_party));
			printf("ip: %15s:%d \n",inet_ntoa(*(struct in_addr *)&c_ip_d),(*c_port));
			break;
		}
		case  0x8b:  //startMediaTransmistion
		{
			u_int32_t * c_conf = (void*)(data+12);
			u_int32_t * c_party = (void*)(data+16);

			printf("stop media conf: %d party: %d \n",(*c_conf),(*c_party));
			break;
		}

		case  0x8f:  //callInfo
		{
			char * callingPartyName = (void*)(data+12);
			char * callingParty = (void*)(data+12+40);
			char * calledPartyName = (void*)(data+12+40+24);
			char * calledParty = (void*)(data+12+40+24+40);
			u_int32_t * lineInstance = (void*)(data+12+40+24+40+24);
			u_int32_t * callIdentifier = (void*)(data+12+40+24+40+24+4);
			u_int32_t * callType	= (void*)(data+12+40+24+40+24+4+4);
			char * originalCalledPartyName = (void*)(data+12+40+24+40+24+4+4+4);
			char * originalCalledParty  = (void*)(data+12+40+24+40+24+4+4+4+40);

			printf("call info party: %s(%s) -> %s(%s) [%s(%s)] Line: %d Call: %d Type: %s\n",
				callingPartyName,callingParty,calledPartyName,calledParty,
				originalCalledPartyName,originalCalledParty,
				(*lineInstance),(*callIdentifier),tok2str(skinny_callTypes,"unkown", (*callType))
				);
			break;
		}

		default:
			//printf("Got Message ID: %x from: ",(*data_messageid));
			//printmac(eth->ether_shost);
			//printf("\n");
			break;

	};
	return 0;
}
*/


void print_package(unsigned int *vlanid, struct tpacket_hdr *h,
			struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) {
	printf("from: ");
	printmac(eth->ether_shost);
	printf(" to: ");
	printmac(eth->ether_dhost);
	printf(" len:%4d",h->tp_len);

	if (*vlanid > 0) {
		printf(" (vlan:%4d)",*vlanid);
	} else  printf("            ");

	printf(" %6s (0x%04x)",tok2str(str_ethertype_values,"n.k.", ntohs(eth->ether_type)),ntohs(eth->ether_type));
	
	if (eth->ether_type == htons(ETHERTYPE_IP)) {
		printf(" %4s", tok2str(str_proto_values,"n.k.", ip->protocol)      );
		printf(" %-15s:%-6d -->",inet_ntoa(*(struct in_addr *)&ip->saddr),ntohs(tcp->source));
		printf(" %-15s:%-6d",inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(tcp->dest));
	} else if (eth->ether_type == htons(ETHERTYPE_ARP)) {
		struct ether_arp * arph = (struct ether_arp *)ip;
		printf(" arp %-7s", tok2str(str_arpop_values,"n.k.", ntohs(arph->arp_op)));
		printf(" %-15s -->",inet_ntoa(*(struct in_addr *)arph->arp_spa));
		printf(" %-15s",inet_ntoa(*(struct in_addr *)arph->arp_tpa));
		printf(" from: ");
		
		printmac(arph->arp_sha);
		printf(" to: ");
		printmac(arph->arp_tha);
	}
	printf("\n");
	return;
}

void sprint_package(char* buffer, unsigned int *vlanid, struct tpacket_hdr *h,struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	char *buffer2 = (char*)malloc(5000);
	sprintmac(buffer2,eth->ether_shost);
	sprintf(buffer,"(hw)from: %s",buffer2);
	sprintmac(buffer2,eth->ether_dhost);
	sprintf(buffer,"%s (hw)to: %s len:%4d",buffer,buffer2,h->tp_len);

	if ((*vlanid) > 0) {
		sprintf(buffer,"%s (vlan:%4d)",buffer,*vlanid);
	} else  sprintf(buffer,"%s            ",buffer);

	sprintf(buffer,"%s %6s (0x%04x)",buffer,tok2str(str_ethertype_values,"n.k.", ntohs(eth->ether_type)),ntohs(eth->ether_type));
	
	if (eth->ether_type == htons(ETHERTYPE_IP)) {
		sprintf(buffer,"%s %-4s",buffer,tok2str(str_proto_values,"n.k.", ip->protocol)      );
		sprintf(buffer,"%s %-15s:%-6d -->",buffer,inet_ntoa(*(struct in_addr *)&ip->saddr),ntohs(tcp->source));
		sprintf(buffer,"%s %-15s:%-6d",buffer,inet_ntoa(*(struct in_addr *)&ip->daddr), ntohs(tcp->dest));
	} else if (eth->ether_type == htons(ETHERTYPE_ARP)) {
		struct ether_arp * arph = (struct ether_arp *)ip;
		sprintf(buffer,"%s arp %7s",buffer,tok2str(str_arpop_values,"n.k.", ntohs(arph->arp_op)));
		sprintf(buffer,"%s %-15s -->",buffer,inet_ntoa(*(struct in_addr *)arph->arp_spa));
		sprintf(buffer,"%s %-15s",buffer,inet_ntoa(*(struct in_addr *)arph->arp_tpa));
		sprintf(buffer,"%s from: ",buffer);
		
		sprintmac(buffer2,arph->arp_sha);
		sprintf(buffer,"%s %s",buffer,buffer2);

		sprintmac(buffer2,arph->arp_tha);
		sprintf(buffer,"%s to %s",buffer,buffer2);
	}

	free(buffer2);
	return;
}

int getmacfromchar(const char *input, mac_addr *mac){
	char *tmpparse;
	int i=0, decoctet;
	const char *mdiv;
	char *myinput;
	myinput = strdup(input);
	if (strstr(myinput,":") != NULL) {mdiv = ":";} else {mdiv = " ";};
	for (i=0;i<=5;i++) (*mac)[i]=0;
	i=0;
	tmpparse = strsep(&myinput,mdiv);
	while (tmpparse != NULL) {
		sscanf(tmpparse,"%x", &decoctet);
		(*mac)[i] = (int)decoctet;
		i++;
		tmpparse = strsep(&myinput,mdiv);
	}
	free(myinput);
	return (i==6) ? 1 : 0;
}

char *get_ip_char(u_int32_t ip)
{
	char *tmp = (char*)malloc(sizeof(unsigned char)*15);
	sprintf(tmp,inet_ntoa(*(struct in_addr *)&ip)); 
	return tmp;
}


int dns_gethost(u_int32_t ip, char *buffer, int len)
{
	int shift;
	struct hostent *host;
		
	host = gethostbyaddr(&ip, sizeof(ip),AF_INET);
	if(host == NULL) {
		return h_errno;
	}

	shift=0;
	while(host->h_name[shift] != '.' && host->h_name[shift] != '\0') shift++;
	host->h_name[shift]='\0';

	snprintf(buffer,len,"%s", host->h_name);
	return 0;
}
