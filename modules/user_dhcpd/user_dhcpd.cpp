/***************************************************************************
 *   NetGuard User RST Daemon Module                                       *
 *                                                                         *
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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/stat.h>
#include "user_dhcpd.hpp"
#include <fstream>
#include "compile.h"
#include "../../includes/logging.h"

NetGuard_DHCPD::NetGuard_DHCPD()
{
	ng_logdebug_spam("constructor");

	security = NULL;

	b_ip = ntohl(inet_addr("255.255.255.255"));
	my_ip = inet_addr("141.30.225.1");
	zero_ip = ntohl(inet_addr("0.0.0.0"));

	subnet_ip = inet_addr("255.255.255.0");

	wins_ip = inet_addr("141.30.225.3");
	dns_ip1 = inet_addr("141.30.225.3");
	dns_ip2 = inet_addr("141.30.66.135");

	interface_name = "eth5";

	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);

	required_modules.push_back("user_security");
}

NetGuard_DHCPD::~NetGuard_DHCPD()
{
	ng_logdebug_spam("destructor");
}

void NetGuard_DHCPD::loaddata()
{
}


void NetGuard_DHCPD::savedata()
{
}

int NetGuard_DHCPD::NetGuard_DHCPD::init(NetGuard_Config *data)
{
	security = NULL;
	ng_logdebug_spam("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetModule("module_user_security") == NULL) {
		ng_logerror("need user_security module needs to be loaded");
		return -2;
	}
	security = (NetGuard_User_Module*)data_->GetModule("module_user_security");


	if (data_->GetStr("ip") != "")
	{
		my_ip = inet_addr(data_->GetStr("ip").c_str());
		ng_logdebug("set ip %s",data_->GetStr("ip").c_str());
	}
	if (data_->GetStr("subnetmask") != "")
	{
		subnet_ip = inet_addr(data_->GetStr("subnetmask").c_str());
		ng_logdebug("set subnetmask to %s",data_->GetStr("subnetmask").c_str());
	}
	if (data_->GetStr("wins") != "")
	{
		wins_ip = inet_addr(data_->GetStr("wins").c_str());
		ng_logdebug("set wins to %s",data_->GetStr("wins").c_str());
	}
	if (data_->GetStr("dns1") != "")
	{
		dns_ip1 = inet_addr(data_->GetStr("dns1").c_str());
		ng_logdebug("set dns1 to %s",data_->GetStr("dns1").c_str());
	}
	if (data_->GetStr("dns2") != "")
	{
		dns_ip2 = inet_addr(data_->GetStr("dns2").c_str());
		ng_logdebug("set dns2 to %s",data_->GetStr("dns2").c_str());
	}
	if (data_->GetStr("interface") != "")
	{
		interface_name = data_->GetStr("interface");
		ng_logdebug("set interface to %s",data_->GetStr("interface").c_str());
	}

	ng_logdebug_spam("init OK");
	return 0;
}

void NetGuard_DHCPD::timer_tick()
{
}

void NetGuard_DHCPD::shutdown()
{
}
	
void NetGuard_DHCPD::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}
}

void NetGuard_DHCPD::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	if (!security) {
		ng_logerror_buff(0,"missing Security Module!");
		exit(-1);
		return;
	}

	//we only want it once
	if (*mode == TRAFFIC_INCOMING || *mode == TRAFFIC_OUTGOING ) return;
	//if (!(*mode == TRAFFIC_OUTGOING )) return;

	if (eth->ether_type != htons_ETHERTYPE_IP) return; //only ip
	if (ip->protocol!=IPPROTO_UDP) return; //udp only
	if (ntohs(tcp->dest) != LISTEN_PORT) return; //only the dhcpd port

	if ((ip->daddr != zero_ip) && (ip->daddr != ntohl(my_ip)) && (ip->daddr != b_ip)) return; //only send to us
	//if ((ip->saddr != zero_ip)) return; //only send from zero ip

	//so we got an dhcp package it seams like dest and port is correct

	struct dhcpMessage *packet;
	//void *data2 = data; //it crashes else?
	packet = (struct dhcpMessage *)((char*)data-12);  //TODO check why 12?! crashes?
	unsigned char *state; //, *hw_addr;
	unsigned char *server_id;


	if(htonl(packet->cookie) != MAGIC) {
		ng_logdebug_spam("ignoring dhcp message with wrong cookie %x",htonl(packet->cookie));
		return;
	}

	ng_logdebug_spam("got package -- processing");
	char *tmpstr = (char*)malloc(5000);
	sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
	ng_logdebug_spam("%s",tmpstr);
	free(tmpstr);
	tmpstr = (char*)malloc(5000);
	sprint_dhcp_package(tmpstr,packet);
	ng_logdebug_spam("%s",tmpstr);
	free(tmpstr);
	

	if((state = getOption(packet->options, DHCP_MESSAGE_TYPE)) == NULL) {
		ng_logdebug_spam("couldnt get option from packet (MSG_TYPE) -- ignoring");
		return;
	}

	sec_data_idx idx;
	memcpy(&idx.hw_addr,&eth->ether_shost,sizeof(mac_addr));
	idx.vlan_id = (*vlanid);
	user_data *m_u_data = (user_data *)security->get_data(&idx);

	u_int32_t offerip;
	//lets see if we can find the ip to offer
	if (!m_u_data) {
		ng_logdebug("got client message - but we dont have any known user for that mac %02x:%02x:%02x:%02x:%02x:%02x in vlan %d",printf_mac_params(eth->ether_shost),(*vlanid));
		return; //todo look at port etc
	}
	offerip = m_u_data->saddr;

/*
          Vendor-rfc1048 Extensions
            Magic Cookie 0x63825363
            DHCP-Message Option 53, length 1: Request
            CLASS Option 77, length 14: "RRAS.Microsoft"
            Client-ID Option 61, length 17: ether 52:41:53:20:00:14:0b:3b:43:00:00:00:01:00:00:00
            Requested-IP Option 50, length 4: 141.30.225.74
            Server-ID Option 54, length 4: 141.30.225.1
            Hostname Option 12, length 7: "Lins-PC"
            FQDN Option 81, length 10: [N] "Lins-PC"
            Vendor-Class Option 60, length 8: "MSFT 5.0"
            Parameter-Request Option 55, length 12:
              Subnet-Mask, Domain-Name, Default-Gateway, Domain-Name-Server
              Netbios-Name-Server, Netbios-Node, Netbios-Scope, Router-Discovery
              Static-Route, Classless-Static-Route, Classless-Static-Route-Microsoft, Vendor-Option

          Client-Ethernet-Address 08:10:75:0a:3a:33
          Vendor-rfc1048 Extensions
            Magic Cookie 0x63825363
            DHCP-Message Option 53, length 1: Request
            Client-ID Option 61, length 7: ether 08:10:75:0a:3a:33
            Hostname Option 12, length 9: "Routerata"
            Domain-Name Option 15, length 12: "RouterDomain"
            FQDN Option 81, length 13: "Routerata."
            Vendor-Class Option 60, length 8: "MSFT 5.0"
            Requested-IP Option 50, length 4: 141.30.225.42
            Subnet-Mask Option 1, length 4: 255.255.255.0
            Default-Gateway Option 3, length 4: 141.30.225.1
            Domain-Name-Server Option 6, length 8: 141.30.225.3,141.30.66.135
            Server-ID Option 54, length 4: 141.30.225.1
            Parameter-Request Option 55, length 11:
              Subnet-Mask, Domain-Name, Default-Gateway, Domain-Name-Server
              Netbios-Name-Server, Netbios-Node, Netbios-Scope, Router-Discovery
              Static-Route, Classless-Static-Route-Microsoft, Vendor-Option

*/

	unsigned char *host = getOption(packet->options, 12);
	unsigned int hostl = getOptionLength(packet->options, 12);
	unsigned char *fqdn = getOption(packet->options, 15);
	unsigned int fqdnl = getOptionLength(packet->options, 15);
	unsigned char *vendor = getOption(packet->options, 60);
	unsigned int vendorl = getOptionLength(packet->options, 60);
	unsigned char *dclass = getOption(packet->options, 77);
	unsigned int dclassl = getOptionLength(packet->options, 77);
	if (vendor != NULL)
	{
		if (strlen((const char*)vendor) == strlen("Adobe Flash Proxy Auto-Discovery"))
		{
			if (strncmp("Adobe Flash Proxy Auto-Discovery",(const char*)vendor,strlen("Adobe Flash Proxy Auto-Discovery")))	{

				ng_logdebug_spam("ignoring Adobe Flash Proxy Auto-Discovery");
				return;
			}
		}
	}
	ng_log_ext_buff(0,500,"offer %s to mac %02x:%02x:%02x:%02x:%02x:%02x - host:%.*s fqdn: %.*s vendor:%.*s class:%.*s", inet_ntoa(*(struct in_addr *)&offerip),printf_mac_params(eth->ether_shost),hostl,host,fqdnl,fqdn,vendorl,vendor,dclassl,dclass);

	int client_socket;
	if((client_socket = clientSocket(LISTEN_PORT, SEND_PORT)) == -1) {
		//syslog(LOG_ERR, "couldn't create client socket -- i'll try again");
		return;
	}

	struct ifreq intf;
	//syslog(LOG_INFO, "Binding to interface '%s'\n", interface_name);
	bzero(&intf, sizeof(intf));
	strncpy(intf.ifr_name, interface_name.c_str(), IFNAMSIZ);
	if (setsockopt(client_socket, SOL_SOCKET, SO_BINDTODEVICE, &intf, sizeof(intf)) < 0)
	{
		//syslog(LOG_INFO, "setsockopt(SO_BINDTODEVICE) %d\n", errno);
		close(client_socket);
		return;
	};

	switch(state[0]) {
		case DHCPDISCOVER:
			ng_logdebug_spam("received DISCOVER");
			if(sendOffer(client_socket, packet,offerip,subnet_ip,my_ip,dns_ip1,dns_ip2,wins_ip) == -1) {
				ng_logerror("send OFFER failed -- ignoring");
			} else 	ng_logdebug_spam("send sendOffer");
			break;
		case DHCPREQUEST:
			ng_logdebug_spam("received DHCPREQUEST");
			//syslog(LOG_INFO,"received REQUEST");
			server_id = getOption(packet->options, 0x36);
			if(server_id == NULL) {
				ng_logdebug("get option on 0x36 failed! NAKing");
				sendNAK(client_socket, packet,my_ip);
				/* Let's send an offer as well */
				if(sendOffer(client_socket, packet,offerip,subnet_ip,my_ip,dns_ip1,dns_ip2,wins_ip) == -1) {
					ng_logerror("send OFFER failed -- ignoring");
				}
			} else {
				ng_logdebug_spam("server_id = %02x%02x%02x%02x", server_id[0], server_id[1],server_id[2], server_id[3]);
				if(memcmp(server_id, (char *)&my_ip, 4) == 0) {
					ng_logdebug_spam("sending ACK - server_id matched");
					if (sendACK(client_socket, packet,offerip,subnet_ip,my_ip,dns_ip1,dns_ip2,wins_ip) == -1) {
						ng_logdebug("send ACK failed - sending NAK");
						sendNAK(client_socket, packet,my_ip);
					} else {
						ng_logdebug_spam("send ACK");
					}
				} else {
					ng_logdebug_spam("sending NAK - server_id missmatch");
					sendNAK(client_socket,packet,my_ip);
				}
			}
			break;
		default:
			ng_logdebug("unsupported DHCP message (%02x) -- ignoring",state[0]);
			break;
	}
	close(client_socket);
}

void NetGuard_DHCPD::user_init(struct user_data *u_data)
{
}

void NetGuard_DHCPD::user_shutdown(struct user_data *u_data)
{
}

void NetGuard_DHCPD::user_data_forgetday(int day)
{
}

