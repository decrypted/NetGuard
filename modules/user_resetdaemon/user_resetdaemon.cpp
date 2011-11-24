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
#include "user_resetdaemon.hpp"
#include <fstream>
#include "compile.h"
#include "../../includes/logging.h"

NetGuard_ResetDaemon::NetGuard_ResetDaemon()
{
	ng_logdebug_spam("constructor");
	g_ip_id = rand() & 0xffff;
}

NetGuard_ResetDaemon::~NetGuard_ResetDaemon()
{
	ng_logdebug_spam("destructor");
}


void NetGuard_ResetDaemon::loaddata()
{
	struct stat fileinfo;

	if (stat(db_filename.c_str(),&fileinfo))
	{
		ng_logerror("can not load %s",db_filename.c_str());
		return ;
	}

	clear();

	char str[255];
	char str2[20];
	char str3[20];
	int  tmp;
	std::fstream file_op(db_filename.c_str(),std::ios::in);
	int counter = 0;
	while(!file_op.eof())
	{
		file_op.getline(str,2000);
		if (sscanf (str,"%15s%15s%d",str2,str3,&tmp) == 3)
		{
			struct in_addr m_ip;
			if (!inet_aton(str2,&m_ip )) continue;
			struct in_addr dm_ip;
			if (!inet_aton(str3,&dm_ip)) continue;
			counter ++;

			rst_d_entry *my_entry = new rst_d_entry;
			my_entry->s_ip = m_ip.s_addr;
			my_entry->d_ip = dm_ip.s_addr;
			my_entry->syn_only = 0;
			if (tmp) my_entry->syn_only = 1;

			char *s_ip = get_ip_char(my_entry->s_ip);
			char *d_ip = get_ip_char(my_entry->d_ip);
			ng_logdebug("Added Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,my_entry->syn_only); 
			free(s_ip);
			free(d_ip);
			rst_ips.push_back(my_entry);
		}
	}
	file_op.close();

	ng_logdebug("loaded %d filters",counter);

	return;
}

void NetGuard_ResetDaemon::clear()
{
	std::vector<rst_d_entry *>::iterator itv  = rst_ips.begin();
	std::vector<rst_d_entry *>::iterator itve = rst_ips.end();
	for( ; itv != itve; ++itv )
	{
		rst_d_entry *entry = (*itv);
		rst_ips.erase(itv);
		char *s_ip = get_ip_char(entry->s_ip);
		char *d_ip = get_ip_char(entry->d_ip);
		ng_logdebug("deleted Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,entry->syn_only); 
		free(s_ip);
		free(d_ip);
		delete entry;
	}
}


void NetGuard_ResetDaemon::savedata()
{

	FILE *myfile;

	ng_logdebug_spam("saving data to %s",db_filename.c_str());
	myfile = fopen(db_filename.c_str(), "w+");
	if (!myfile) {
		ng_logerror("cant save data to %s",db_filename.c_str(),strerror(errno));
		return;
	}

	fprintf(myfile,"Source IP	DestinationIP	Syn_Only\n");
	std::vector<rst_d_entry *>::iterator itv  = rst_ips.begin();
	std::vector<rst_d_entry *>::iterator itve = rst_ips.end();
	for( ; itv != itve; ++itv )
	{
		rst_d_entry *entry = (*itv);
		char *s_ip = get_ip_char(entry->s_ip);
		char *d_ip = get_ip_char(entry->d_ip);
		fprintf(myfile,"%s	%s	%d\n",s_ip,d_ip,entry->syn_only);
		free(s_ip);
		free(d_ip);
	}

	fclose(myfile);
}

int NetGuard_ResetDaemon::NetGuard_ResetDaemon::init(NetGuard_Config *data)
{
	ng_logdebug("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (socket_fd < 0) {
		ng_logerror("Failed to open raw socket: %s",strerror(errno));
		return -1;
	}

	char on = 1;
	if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on))) {
		ng_logerror("Failed to set IP_HDRINCL on raw socket: %s",strerror(errno));
		return -1;
	}

	if (data_->GetStr("user_resetdaemon_filename") == "")
	{
		ng_logerror("need an user_resetdaemon_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("user_resetdaemon_filename");

	ng_logdebug("init OK");
	return 0;
}

void NetGuard_ResetDaemon::timer_tick() {

}

void NetGuard_ResetDaemon::shutdown()
{
	if (socket_fd > 0)
	{
		close(socket_fd);
	}
}
	
void NetGuard_ResetDaemon::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "help")
	{
		ng_logout("reset_add <s_ip address> [d_ip address] - reset all tcp connections from that ip");
		ng_logout("reset_add_syn <s_ip address> [d_ip address] - reset new tcp connections from that ip");
		ng_logout("reset_del - <s_ip address> [d_ip address] - delete the reset entry");
		ng_logout("reset_show - show reset database");
	}

	if (params[0] == "reset_del")
	{
		if (params.size() < 2 || params.size() > 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_del <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_del <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr dm_ip;
		dm_ip.s_addr = 0;
		if (params.size()==3)
		{
			if (!inet_aton(params[2].c_str(),&dm_ip ))
			{	
				ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_del <s_ip address> [d_ip address]");
				return;
			}
		}

		std::vector<rst_d_entry *>::iterator itv  = rst_ips.begin();
		std::vector<rst_d_entry *>::iterator itve = rst_ips.end();
		for( ; itv != itve; ++itv )
		{
			rst_d_entry *entry = (*itv);
			if (entry->s_ip == m_ip.s_addr)
			{
				if (!entry->d_ip ||  entry->d_ip == dm_ip.s_addr)
				{
					rst_ips.erase(itv);
					char *s_ip = get_ip_char(entry->s_ip);
					char *d_ip = get_ip_char(entry->d_ip);
					ng_logdebug("deleted Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,entry->syn_only); 
					free(s_ip);
					free(d_ip);
					delete entry;
					return;
				}
			}
		}
	}

	if (params[0] == "reset_add")
	{
		if (params.size() < 2 || params.size() > 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr dm_ip;
		dm_ip.s_addr = 0;
		if (params.size()==3)
		{
			if (!inet_aton(params[2].c_str(),&dm_ip ))
			{	
				ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add <s_ip address> [d_ip address]");
				return;
			}
		}

		rst_d_entry *my_entry = new rst_d_entry;
		my_entry->s_ip = m_ip.s_addr;
		my_entry->d_ip = dm_ip.s_addr;
		my_entry->syn_only = 0;

		char *s_ip = get_ip_char(my_entry->s_ip);
		char *d_ip = get_ip_char(my_entry->d_ip);
		ng_logout_ok("Added Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,my_entry->syn_only); 
		free(s_ip);
		free(d_ip);
		rst_ips.push_back(my_entry);
	}

	if (params[0] == "reset_add_syn")
	{
		if (params.size() < 2 || params.size() > 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add_syn <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add_syn <s_ip address> [d_ip address]");
			return;
		}
		struct in_addr dm_ip;
		dm_ip.s_addr = 0;
		if (params.size()==3)
		{
			if (!inet_aton(params[2].c_str(),&dm_ip ))
			{	
				ng_logout_ret(RET_WRONG_SYNTAX,"usage: reset_add_syn <s_ip address> [d_ip address]");
				return;
			}
		}

		rst_d_entry *my_entry = new rst_d_entry;
		my_entry->s_ip = m_ip.s_addr;
		my_entry->d_ip = dm_ip.s_addr;
		my_entry->syn_only = 1;

		char *s_ip = get_ip_char(my_entry->s_ip);
		char *d_ip = get_ip_char(my_entry->d_ip);
		ng_logout_ok("Added Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,my_entry->syn_only); 
		free(s_ip);
		free(d_ip);
		rst_ips.push_back(my_entry);
	}

	if (params[0] == "reset_show")
	{
		ng_logout("Entrys:");
		std::vector<rst_d_entry *>::iterator itv  = rst_ips.begin();
		std::vector<rst_d_entry *>::iterator itve = rst_ips.end();
		for( ; itv != itve; ++itv )
		{
			rst_d_entry *entry = (*itv);
			char *s_ip = get_ip_char(entry->s_ip);
			char *d_ip = get_ip_char(entry->d_ip);
			ng_logout("Source: %s Dest: %s ResetSynOnly: %d",s_ip,d_ip,entry->syn_only); 
			free(s_ip);
			free(d_ip);
		}
	}
}

int NetGuard_ResetDaemon::ipv4_checksum_add(const void *data, size_t len)
{
	int l = len, s = 0;
	u_int16_t a = 0;
	const u_int16_t *p = (const u_int16_t *)data;
	while (l > 1) {
		s += *p++;
		l -= 2;
	}
	if (l == 1) {
		*(u_int8_t *)(&a) = *(u_int8_t *) p;
		s += a;
	}
	return s;
}

u_int16_t NetGuard_ResetDaemon::ipv4_checksum_final(int s)
{
	s = (s >> 16) + (s & 0xffff);
	s += (s >> 16);
	return (u_int16_t) ~s;
}
 
void NetGuard_ResetDaemon::send_reset(u_int32_t saddr,u_int32_t daddr, u_int32_t sport,u_int32_t dport, u_int32_t seq_ack, u_int32_t id, u_int32_t seq, u_int32_t window)
{
	int r, sum;
	size_t len;
	struct sockaddr_in sa;
	struct send_tcp
	{
		struct iphdr ip;
		struct tcphdr tcp;
	} packet;

	//clear all fields like the unused
	memset(&packet,0,sizeof(packet));
	packet.ip.version = 4; // version of IP used
	packet.ip.ihl = 5; // Internet Header Length (IHL)
	len = (packet.ip.ihl << 2) + sizeof(struct tcphdr);
	packet.ip.tos = 0; // Type Of Service (TOS)
	packet.ip.tot_len = htons(60); // total length of the IP datagram
	packet.ip.frag_off = 0; // fragmentation flag
	packet.ip.ttl = 255; // Time To Live (TTL)
	packet.ip.protocol = IPPROTO_TCP; // protocol used (TCP in this case)
	packet.ip.saddr = saddr;
	packet.ip.daddr = daddr;
	if (id == 0)
	{
		packet.ip.id = htons(g_ip_id);
		g_ip_id += rand() & 0xf;
	} else packet.ip.id = id;
	
	//IP Checksum
	packet.ip.check = 0;
	sum = ipv4_checksum_add(&packet.ip, packet.ip.ihl << 2);
	packet.ip.check = ipv4_checksum_final(sum);

	packet.tcp.syn = 0;
	if (seq_ack != 0)
	{
		packet.tcp.ack = 1;
	} else packet.tcp.ack = 0;
	packet.tcp.rst = 1;
	packet.tcp.urg = 0;
	packet.tcp.ack_seq = seq_ack;
	packet.tcp.seq = seq;	
	packet.tcp.window = window;
	packet.tcp.source = sport;
	packet.tcp.dest = dport;
	//no data present but set behind
	packet.tcp.doff = sizeof(struct tcphdr) >> 2;
	
	//TCP checksum */
	packet.tcp.check = 0;
	sum = ipv4_checksum_add(&packet.ip.saddr, 8);
	sum += htons(IPPROTO_TCP + sizeof(struct tcphdr));
	sum += ipv4_checksum_add(&packet.tcp, sizeof(struct tcphdr));
	packet.tcp.check = ipv4_checksum_final(sum);

	//Set Packet Routing
	sa.sin_family = AF_INET;
	sa.sin_port = packet.tcp.dest;
	sa.sin_addr.s_addr = packet.ip.daddr;
	
	r = sendto(socket_fd, &packet.ip, len, 0, (struct sockaddr *) &sa, sizeof(sa));
	if (r < 0) {
		ng_logerror("sendto: %s", strerror(errno));
		return;
	}
	if ((size_t)r != len) {
		ng_logerror("sendto: bad write (%d != %d)", r, len);
		return;
	}
}

void NetGuard_ResetDaemon::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	if (ip->protocol!=IPPROTO_TCP) return;
	if (!rst_ips.size()) return;
	if (socket_fd <= 0) return;

	//we dont want to look at an package twice ..
	if (*mode == TRAFFIC_INCOMING || *mode == TRAFFIC_OUTGOING ) return;
	//if (*mode == TRAFFIC_OUTGOING ||  *mode == TRAFFIC_NOSOURCE ) return;

	std::vector<rst_d_entry *>::iterator itv  = rst_ips.begin();
	std::vector<rst_d_entry *>::iterator itve = rst_ips.end();
	for( ; itv != itve; ++itv )
	{
		rst_d_entry *entry = (*itv);
		if(tcp->syn && !tcp->ack &&  ip->saddr==entry->s_ip)
		{
			//we limit the target?
			if (!entry->d_ip || entry->d_ip  == ip->daddr)
			{
				send_reset(ip->daddr,ip->saddr,tcp->dest,tcp->source,htonl(ntohl(tcp->seq) + 1));

				char *s_ip = get_ip_char(entry->s_ip);
				char *d_ip = get_ip_char(entry->d_ip);
				ng_logdebug("Matched Source (SYN): %s Dest: %s ResetSynOnly: %d - resetting",s_ip,d_ip,entry->syn_only); 
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logdebug("%s",tmpstr);
				free(tmpstr);
				free(s_ip);
				free(d_ip);
			}
		}

		if(!entry->syn_only && !tcp->rst && !tcp->syn &&  entry->s_ip == ip->daddr)
		{
			//we limit the target?
			if (!entry->d_ip || entry->d_ip  == ip->saddr)
			{
				//calc what seq we use to reset - depends on the size of the current package
				int next_pkg = ntohs(ip->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
				int moot= next_pkg;
				send_reset(ip->saddr,ip->daddr,tcp->source,tcp->dest,0,ip->id,htonl(ntohl(tcp->seq) + moot),tcp->window);

				char *s_ip = get_ip_char(entry->s_ip);
				char *d_ip = get_ip_char(entry->d_ip);
				ng_logdebug("Matched Source: %s Dest: %s ResetSynOnly: %d - resetting",s_ip,d_ip,entry->syn_only); 
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logdebug("%s",tmpstr);
				free(tmpstr);
				free(s_ip);
				free(d_ip);
			}
		}
	}
}

void NetGuard_ResetDaemon::user_init(struct user_data *u_data)
{
}

void NetGuard_ResetDaemon::user_shutdown(struct user_data *u_data)
{
}

void NetGuard_ResetDaemon::user_data_forgetday(int day)
{
}

