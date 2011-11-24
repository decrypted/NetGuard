/* dhcpd.c
 *
 * Lineo DHCP Server
 * Copyright (C) 1999 Matthew Ramsay <matthewr@lineo.com>
 *			Chris Trew <ctrew@lineo.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#include "dhcpd.h"
#include "options.h"



/* send a DHCP OFFER to a DHCP DISCOVER */
int sendOffer(int client_socket, struct dhcpMessage *oldpacket,u_int32_t offerip,u_int32_t subnet,u_int32_t router,u_int32_t dns1,u_int32_t dns2,u_int32_t wins) {
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	/*if((packet.yiaddr = findAddr(oldpacket->chaddr, oldpacket->xid)) == 0) {
		//TODO fprintf(stderr,"no IP addresses to give -- OFFER abandoned");
		return -1;
	}
	*/
	packet.yiaddr = offerip;

	packet.siaddr = router;
	packet.flags = oldpacket->flags;
	packet.giaddr = oldpacket->giaddr;
	
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);
	
	addOption(packet.options, 0x35, 0x01, "\x02");

	addOption(packet.options, 0x36, 0x04, (char *)&router);
	addOption(packet.options, 0x33, 0x04, LEASE_TIME);

	/* subnet */
	addOption(packet.options, 0x01, 0x04, (char *)&subnet);
	
	/* gateway */
	addOption(packet.options, 0x03, 0x04, (char *)&router);

	/* DNS */
	if (dns2 != 0)
	{
		add_multiple_option(packet.options, 0x06, 0x08, (char *)&dns1, (char *)&dns2, NULL);
	} else {
		add_multiple_option(packet.options, 0x06, 0x04, (char *)&dns1, NULL, NULL);
	}

	/* WINS */
	addOption(packet.options, 0x2C, 0x04, (char *)&wins);

	
	memcpy(buf, &packet, sizeof(packet));

	//syslog(LOG_INFO, "sending OFFER");
	//bytes = 0;
	bytes = send(client_socket, buf, sizeof(buf), 0);
	if(bytes == -1) {
		//syslog(LOG_ERR, "couldn't write to client_socket -- OFFER abandoned");
		return -1;
	}
	return 0;
}


int sendNAK(int client_socket, struct dhcpMessage *oldpacket,u_int32_t router) {
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);

	packet.siaddr = 0;
	packet.flags = oldpacket->flags;
	packet.giaddr = oldpacket->giaddr;

	/* options should look like this:
	* 0x350106 -- NAK 
	* 0x3604serverid - server id */
	addOption(packet.options, 0x35, 0x01, "\x06");
	addOption(packet.options, 0x36, 0x04, (char *)&router);
	
	memcpy(buf, &packet, sizeof(packet));
	//syslog(LOG_INFO, "sending NAK");
	bytes = send(client_socket, buf, sizeof(buf), 0);
	
	if(bytes == -1) {
		//syslog(LOG_ERR, "error writing to client -- NAK abandoned");
		return -1;
	}
	return 0;
}


int sendACK(int client_socket, struct dhcpMessage *oldpacket,u_int32_t offerip,u_int32_t subnet,u_int32_t router,u_int32_t dns1,u_int32_t dns2,u_int32_t wins) {
	struct dhcpMessage packet;
	char buf[sizeof(struct dhcpMessage)];
	int bytes;

	memset(&packet, 0, sizeof(packet));
	
	packet.op = BOOTREPLY;
	packet.htype = ETH_10MB;
	packet.hlen = ETH_10MB_LEN;
	packet.xid = oldpacket->xid;
	packet.ciaddr = oldpacket->ciaddr;
	memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	//memcpy(&packet.chaddr, oldpacket->chaddr, 16);
	memcpy(&packet.cookie, "\x63\x82\x53\x63", 4);
	memcpy(&packet.options, "\xff", 1);
	//memcpy(&packet.options, oldpacket->options, 308);


	packet.yiaddr = offerip;
	packet.siaddr = router;
	packet.flags = oldpacket->flags;
	packet.giaddr = oldpacket->giaddr;

	/* options should look like this:
	* 0x350106 -- NAK 
	* 0x3604 serverid - server id */
	addOption(packet.options, 0x35, 0x01, "\x05");

	//unsigned char *opt=getOption(oldpacket->options,0x50);
	//addOption(packet.options, 0x50, 0x04, (char *)opt[1]);

	addOption(packet.options, 0x36, 0x04, (char *)&router);
	addOption(packet.options, 0x33, 0x04, LEASE_TIME);

	/* subnet */
	addOption(packet.options, 0x01, 0x04, (char *)&subnet);
	
	/* gateway */
	addOption(packet.options, 0x03, 0x04, (char *)&router);

	/* DNS */
	if (dns2 != 0)
	{
		add_multiple_option(packet.options, 0x06, 0x08, (char *)&dns1, (char *)&dns2, NULL);
	} else {
		add_multiple_option(packet.options, 0x06, 0x04, (char *)&dns1, NULL, NULL);
	}

	/* WINS */
	addOption(packet.options, 0x2C, 0x04, (char *)&wins);
	
	memcpy(buf, &packet, sizeof(packet));
	//TODO syslog(LOG_INFO, "sending ACK");
	bytes = send(client_socket, buf, sizeof(buf), 0);
	
	if(bytes == -1) {
		//TODO syslog(LOG_ERR, "error writing to client_socket -- ACK abandoned");
		return -1;
	}

	return 0;
}

/*

struct dhcpMessage {
	u_int8_t op;
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t hops;
	u_int32_t xid;
	u_int16_t secs;
	u_int16_t flags;
	u_int32_t ciaddr;
	u_int32_t yiaddr;
	u_int32_t siaddr;
	u_int32_t giaddr;
	u_int8_t chaddr[16];
	u_int8_t sname[64];
	u_int8_t file[128];
	u_int32_t cookie;
	u_int8_t options[308]; 
};
*/

int sfn_print(char* buffer,u_char *s, u_char *ep)
{
	register int ret;
	u_char c;

	ret = 1;			/* assume truncated */
	while (ep == NULL || s < ep) {
		c = *s++;
		if (c == '\0') {
			ret = 0;
			break;
		}
		if (!isascii(c)) {
			c = toascii(c);
			sprintf(buffer,"%sM",buffer);
			sprintf(buffer,"%s-",buffer);
		}
		if (!isprint(c)) {
			c ^= 0x40;	/* DEL to ?, others to alpha */
			sprintf(buffer,"%s^",buffer);
		}
		sprintf(buffer,"%s%s",buffer,&c);
	}
	return(ret);
}


void sprint_dhcp_package(char* buffer,struct dhcpMessage *packet)
{
	sprintf(buffer,"op:%u ",packet->op);
	sprintf(buffer,"%s htype:%u ",buffer,packet->htype);
	sprintf(buffer,"%s hlen:%u ",buffer,packet->hlen);
	sprintf(buffer,"%s xid:%u ",buffer,packet->xid);
	sprintf(buffer,"%s secs:%u ",buffer,packet->secs);
	sprintf(buffer,"%s flags:%u ",buffer,packet->flags);
/*	sprintf(buffer,"%s ciaddr: %-15s ",buffer,inet_ntoa(*(struct in_addr *)&packet->ciaddr));
	sprintf(buffer,"%s yiaddr: %-15s ",buffer,inet_ntoa(*(struct in_addr *)&packet->yiaddr));
	sprintf(buffer,"%s siaddr: %-15s ",buffer,inet_ntoa(*(struct in_addr *)&packet->siaddr));
	sprintf(buffer,"%s giaddr: %-15s ",buffer,inet_ntoa(*(struct in_addr *)&packet->giaddr));*/

	sprintf(buffer,"%s chaddr: ",buffer);
	sfn_print(buffer,(u_char*)packet->chaddr,(u_char*)packet->sname);

	sprintf(buffer,"%s sname: ",buffer);
	//sfn_print(buffer,(u_char*)&packet->sname,(u_char*)&packet->file);

	sprintf(buffer,"%s file: ",buffer);
	return;
	//sfn_print(buffer,(u_char*)&packet->file,(u_char*)&packet->cookie);

	//sprintf(buffer,"%s cookie: %u ",buffer,packet->cookie);

	//sprintf(buffer,"%s options: ",buffer);
	//sfn_print(buffer,(u_char*)&packet->options,(u_char*)(&packet->options+208));

	return;
}
