/***************************************************************************
 *   NetGuard Accounting General Module                                    *
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
#include <time.h>

#include "general_accounting.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/state/state_handling.hpp"

#include <sys/stat.h>

NetGuard_Accounting::NetGuard_Accounting()
{
	ng_logdebug_spam("constructor");	
	userlist = new User_Data_Tools();
 	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
 	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);
}
  
NetGuard_Accounting::~NetGuard_Accounting()
{
	ng_logdebug_spam("destructor");	
	delete userlist;
}
		
void NetGuard_Accounting::loaddata()
{
	userlist->loaddata(db_filename,0);
}

void NetGuard_Accounting::savedata()
{
	userlist->savedata(db_filename,false);
	NetGuard_ModuleLoader_Base::send_cmsg(NULL,"users_savedata",NULL,NULL);
}

int NetGuard_Accounting::init(NetGuard_Config *data)
{
	ng_logdebug_spam("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetStr("accounting_filename") == "")
	{
		ng_logerror("need an accounting_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("accounting_filename");

	//filter for accountable traffic
	if (data_->GetStr("accounting_filter_own") == "")
	{
		ng_logerror("need an accounting_filter_own in config data");
		return -2;
	}
	std::string filter_name_own=data_->GetStr("accounting_filter_own");

	filter_own = NetGuard_Global_IP_Filter::Filter(filter_name_own);
	if (filter_own == NULL)
	{
		ng_logerror("filter passed with accounting_filter_own (%s) does not exists",filter_name_own.c_str());
		return -2;
	}
	ng_logdebug_spam("using filter (%s) for filtering accounting ips",filter_own->GetPrefixName().c_str());

	//filter for internal traffic
	if (data_->GetStr("accounting_filter_intern") == "")
	{
		ng_logerror("need an accounting_filter_intern in config data");
		return -2;
	}
	std::string filter_name_intern=data_->GetStr("accounting_filter_intern");

	filter_intern = NetGuard_Global_IP_Filter::Filter(filter_name_intern);
	if (filter_intern == NULL)
	{
		ng_logerror("filter passed with accounting_filter_intern (%s) does not exists",filter_name_intern.c_str());
		return -2;
	}
	ng_logdebug_spam("using filter (%s) for filtering internal traffic",filter_intern->GetPrefixName().c_str());

	last_day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
	ng_logdebug("Current WeekDay %d",last_day);

	loaddata();
	NetGuard_ModuleLoader_Base::send_cmsg(NULL,"users_loaddata",NULL,NULL);
	return 0;
}

void NetGuard_Accounting::shutdown()
{
	userlist->savedata(db_filename,true);
	ng_logdebug_spam("shutdown");
	userlist->list_clear();
}

void NetGuard_Accounting::account_package(user_data * u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	struct user_data_traffic *traffic_type;
	
	//set if internal or external traffic
	//default is internal for all non ip protocols

	traffic_type = &u_data->internal;
	if (eth->ether_type == htons_ETHERTYPE_IP) {
		//on ip its external per default
		traffic_type = &u_data->external;

		//if it match the filters its internal
		if ((*filter_intern) == &hl_daddr && (*filter_intern)==&hl_saddr) traffic_type = &u_data->internal;
	}

	struct user_data_timeslot_data *td_a; //over_all
	struct user_data_timeslot_data *td_w; //week
	struct user_data_timeslot_data *td_d; //this day	
	
	switch (*mode) {	
		case TRAFFIC_OUTGOING:
			//send
			td_a = &traffic_type->over_all.send;
			td_w = &traffic_type->week.send;
			td_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].send;
			break;
		case TRAFFIC_INCOMING:
			//send
			td_a = &traffic_type->over_all.resv;
			td_w = &traffic_type->week.resv;
			td_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].resv;
			break;	
		default:
			ng_logerror("account_package: unkown package type");
			return;
	}
	

	td_a->pkts++;
	td_a->bytes += h->tp_len;
	td_w->pkts++;
	td_w->bytes += h->tp_len;
	td_d->pkts++;
	td_d->bytes += h->tp_len;
	
	if (eth->ether_type == htons_ETHERTYPE_IP) {
		td_a->ip_pkts++;
		td_a->ip_bytes += h->tp_len;
		td_w->ip_pkts++;
		td_w->ip_bytes += h->tp_len;
		td_d->ip_pkts++;
		td_d->ip_bytes += h->tp_len;
		
		//print_package(vlanid,h,eth,ip,tcp,data);
		switch (ip->protocol) {
			case IPPROTO_TCP:
				td_a->tcpip_pkts++;
				td_a->tcpip_bytes += h->tp_len;
				td_w->tcpip_pkts++;
				td_w->tcpip_bytes += h->tp_len;
				td_d->tcpip_pkts++;
				td_d->tcpip_bytes += h->tp_len;
				
				if (tcp->syn && !tcp->ack){
					//new connect request
					td_a->connects++;
					td_w->connects++;
					td_d->connects++;
				}
				break;
			case IPPROTO_UDP:
				td_a->udp_pkts++;
				td_a->udp_bytes += h->tp_len;
				td_w->udp_pkts++;
				td_w->udp_bytes += h->tp_len;
				td_d->udp_pkts++;
				td_d->udp_bytes += h->tp_len;
				break;
			case IPPROTO_ICMP:
				td_a->icmp_pkts++;
				td_a->icmp_bytes += h->tp_len;
				td_w->icmp_pkts++;
				td_w->icmp_bytes += h->tp_len;
				td_d->icmp_pkts++;
				td_d->icmp_bytes += h->tp_len;
				break;
		}
	} else if (eth->ether_type == htons_ETHERTYPE_ARP) {
		td_a->arp_pkts++;
		td_a->arp_bytes += h->tp_len;
		td_w->arp_pkts++;
		td_w->arp_bytes += h->tp_len;
		td_d->arp_pkts++;
		td_d->arp_bytes += h->tp_len;
	}
}

void NetGuard_Accounting::packet_in(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	struct user_data * u_data;
	in_addr_t *index_addr;
	in_addr_t *index_addr2;
	index_addr = 0;
	index_addr2 = 0;

	if (eth->ether_type == htons_ETHERTYPE_IP) {
		hl_saddr = ntohl(ip->saddr);
		hl_daddr = ntohl(ip->daddr);
		if ((*filter_own)==&hl_saddr) index_addr = &ip->saddr;
		if ((*filter_own)==&hl_daddr) index_addr2 = &ip->daddr;
	} else if (eth->ether_type == htons_ETHERTYPE_ARP) {
		struct ether_arp * arph;
		//#if __GNUC__ >= 4
		arph = (struct ether_arp *)ip;
		//#else
		//(void *)arph = (void *)ip;
		//#endif		
		hl_saddr = ntohl(*(uint32_t *)&arph->arp_spa);
		hl_daddr = ntohl(*(uint32_t *)&arph->arp_tpa);
		if ((*filter_own)==&hl_saddr) index_addr = (uint32_t *)&arph->arp_spa;
		if ((*filter_own)==&hl_daddr) index_addr2 = (uint32_t *)&arph->arp_tpa;
	}

    //samstag 6 sonntag 0 montag   1 dienstag  2 mittwoch   3 donnerstag 4 freitag  5

	if (last_day != NetGuard_ModuleLoader_Base::GetTime()->tm_wday) {
		ng_logdebug_spam("New Current WeekDay %d (last %d)",NetGuard_ModuleLoader_Base::GetTime()->tm_wday,last_day);
		//day changed -> reset stats for all users of the current (new) day
		user_data_forgetday(NetGuard_ModuleLoader_Base::GetTime()->tm_wday);
		last_day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
	}

	
	//traffic comming from users
	if (index_addr) {
		int mode = TRAFFIC_OUTGOING;
		u_data = userlist->get_or_add_user(index_addr,vlanid);

		//set the source mac addr
		if (eth->ether_type == htons_ETHERTYPE_IP) 
			memcpy(&u_data->hw_addr,&eth->ether_shost,sizeof(u_data->hw_addr));

		//check/init state
		NetGuard_State_Handler::get_add_user_state(u_data);
		//count package
		account_package(u_data,&mode,vlanid,h,eth,ip,tcp,data);

		u_data->last_activity = NetGuard_ModuleLoader_Base::GetNow();
		
		//give it to other user modules
		NetGuard_ModuleLoader_Base::GetPointer()->broadcast_user_packet(u_data,&mode,vlanid,h,eth,ip,tcp,data);
	}

	//traffic going to users
	if (index_addr2) {
		int mode = TRAFFIC_INCOMING;
		u_data = userlist->get_or_add_user(index_addr2,vlanid);

		//check/init state
		NetGuard_State_Handler::get_add_user_state(u_data);

		//count package
		account_package(u_data,&mode,vlanid,h,eth,ip,tcp,data);

		//give it to other user modules
		NetGuard_ModuleLoader_Base::GetPointer()->broadcast_user_packet(u_data,&mode,vlanid,h,eth,ip,tcp,data);
	}
	
	int mode = 0;
	if (!index_addr)
	{
		if (!index_addr2) {
			mode = TRAFFIC_UNKOWN;
		} else {
			mode = TRAFFIC_NOSOURCE;
		}
	} else mode = TRAFFIC_KNOWN;

	NetGuard_ModuleLoader_Base::GetPointer()->broadcast_user_packet(NULL,&mode,vlanid,h,eth,ip,tcp,data);

}

void NetGuard_Accounting::do_sum_timeslot_data(struct user_data_timeslot_data *counter,struct user_data_timeslot_data data){
	counter->bytes += data.bytes;
	counter->pkts += data.pkts;
	counter->ip_bytes += data.ip_bytes;
	counter->ip_pkts += data.ip_pkts;
	counter->tcpip_bytes += data.tcpip_bytes;
	counter->tcpip_pkts += data.tcpip_pkts;
	counter->udp_bytes += data.udp_bytes;
	counter->udp_pkts += data.udp_pkts;
	counter->icmp_bytes += data.icmp_bytes;
	counter->icmp_pkts += data.icmp_pkts;
	counter->connects += data.connects;
	counter->arp_bytes += data.arp_bytes;
	counter->arp_pkts += data.arp_pkts;
}

void NetGuard_Accounting::do_sum_timeslot(struct user_data_timeslot *counter,struct user_data_timeslot data)
{
	do_sum_timeslot_data(&counter->send,data.send);
	do_sum_timeslot_data(&counter->resv,data.resv);
}

void NetGuard_Accounting::do_user_data_forgetday(int day, struct  user_data_traffic * u_data_traffic){
	int i;
	struct user_data_timeslot counter;

	//erase this day
	memset(&u_data_traffic->days[day],0,sizeof(struct user_data_timeslot));

	//recalc week
	memset(&counter,0,sizeof(struct user_data_timeslot));
	for (i=0; i <= 6; i++) {
		do_sum_timeslot(&counter,u_data_traffic->days[i]);
	};
	u_data_traffic->week = counter;
}

void NetGuard_Accounting::user_data_forgetday(int day){
	#ifdef userlist_use_simple
	struct	user_list * m_users;
	#endif
	struct	user_data * u_data;

	if (day < 0 || day > 6)  {
		ng_logerror("list: forget day <0 or >6 (%d) - ignoring",day);
		return;
	}
	ng_logdebug_spam("list: forget day %d",day);

	#ifdef userlist_use_simple
	m_users = userlist->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=userlist->get_list()->begin(); it != userlist->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
				
		//forget this day for external traffic
		do_user_data_forgetday(day,&u_data->external);

		//forget this day for internal traffic
		do_user_data_forgetday(day,&u_data->internal);

		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}

	NetGuard_ModuleLoader_Base::send_cmsg(NULL,"user_data_forgetday",NULL,(void*)NetGuard_ModuleLoader_Base::GetTime()->tm_wday);
}

void NetGuard_Accounting::timer_tick()
{
}

void NetGuard_Accounting::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("forget_day <day> - forget all accounting for this weekday (0 = sunday)");
		ng_logout("save_full - save userdata at once - no little chunks");
		#ifndef userlist_use_simple
		ng_logout("save_junksize <items> - number of items to save at once");
		#endif
		ng_logout("dumpip <ip> <vlan> - show details for an ip");
		ng_logout("dumpip_all <ip> <vlan> - show details for an ip");
	}

	if (params[0] == "forget_day")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: forget_day <day>");
			return;
		}
		ng_logout_ok("forgetting day %d",intparams[1]);
		user_data_forgetday(intparams[1]);
	}

	if (params[0] == "save_full")
	{
		userlist->savedata(db_filename,true);
	}

	#ifndef userlist_use_simple
	if (params[0] == "save_junksize")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			userlist->savejunk = intparams[1];
			ng_logout_ok("save_junksize set to %d",userlist->savejunk);
		} else {
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: save_junksize <items> - number of items to save at once");
			return;
		}
	}
	#endif

	if ((params[0] == "dumpip") ||  (params[0] == "dumpip_all"))
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = userlist->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}
		

		#define EINHEIT 1024/1024
		ng_logout("dump user for ip %s with mac %02x:%02x:%02x:%02x:%02x:%02x in vlan %d", inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params(u_data->hw_addr),intparams[2]);
		char l_a_time[50];
		int day = 0;

		if (!dns_gethost(u_data->saddr,l_a_time,sizeof(l_a_time)))
		{
			ng_logout("Hostname: %s",l_a_time);
		};
		

		day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",NetGuard_ModuleLoader_Base::GetTime());
		ng_logout("created at:\t%s",l_a_time);
		if (u_data->last_activity != 0) {
			strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&u_data->last_activity));
			ng_logout("last activitiy:\t%s",l_a_time);
		}

		struct tm time_i = {0,0};
		day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
		ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",u_data->external.week.send.bytes/EINHEIT,u_data->external.week.resv.bytes/EINHEIT,u_data->external.week.send.pkts,u_data->external.week.resv.pkts,u_data->external.week.send.connects,u_data->external.week.resv.connects);
		ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",u_data->internal.week.send.bytes/EINHEIT,u_data->internal.week.resv.bytes/EINHEIT,u_data->internal.week.send.pkts,u_data->internal.week.resv.pkts,u_data->internal.week.send.connects,u_data->internal.week.resv.connects);
		time_i.tm_wday = day;
		strftime(l_a_time, 80,"%a",&time_i);
		ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",l_a_time,u_data->external.days[day].send.bytes/EINHEIT,u_data->external.days[day].resv.bytes/EINHEIT,u_data->external.days[day].send.pkts,u_data->external.days[day].resv.pkts,u_data->external.days[day].send.connects,u_data->external.days[day].resv.connects);
		ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",l_a_time,u_data->internal.days[day].send.bytes/EINHEIT,u_data->internal.days[day].resv.bytes/EINHEIT,u_data->internal.days[day].send.pkts,u_data->internal.days[day].resv.pkts,u_data->internal.days[day].send.connects,u_data->internal.days[day].resv.connects);
		ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",u_data->external.over_all.send.bytes/EINHEIT,u_data->external.over_all.resv.bytes/EINHEIT,u_data->external.over_all.send.pkts,u_data->external.over_all.resv.pkts,u_data->external.over_all.send.connects,u_data->external.over_all.resv.connects);
		ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",u_data->internal.over_all.send.bytes/EINHEIT,u_data->internal.over_all.resv.bytes/EINHEIT,u_data->internal.over_all.send.pkts,u_data->internal.over_all.resv.pkts,u_data->internal.over_all.send.connects,u_data->internal.over_all.resv.connects);
		for(day=0;day<=6;day++)
		{    
			time_i.tm_wday = (day+1)%7;
			strftime(l_a_time, 80,"%A",&time_i);
			ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",l_a_time,u_data->external.days[(day+1)%7].send.bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.bytes/EINHEIT,u_data->external.days[(day+1)%7].send.pkts,u_data->external.days[(day+1)%7].resv.pkts,u_data->external.days[(day+1)%7].send.connects,u_data->external.days[(day+1)%7].resv.connects);
			ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts sconnects: %llu rconnects: %llu",l_a_time,u_data->internal.days[(day+1)%7].send.bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.pkts,u_data->internal.days[(day+1)%7].resv.pkts,u_data->internal.days[(day+1)%7].send.connects,u_data->internal.days[(day+1)%7].resv.connects);
		}	

		if (params[0] == "dumpip_all")
		{
			ng_logout("extended dump:");
			
			ng_logout("IP:");	
			day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
			ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.week.send.ip_bytes/EINHEIT,u_data->external.week.resv.ip_bytes/EINHEIT,u_data->external.week.send.ip_pkts,u_data->external.week.resv.ip_pkts);
			ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.week.send.ip_bytes/EINHEIT,u_data->internal.week.resv.ip_bytes/EINHEIT,u_data->internal.week.send.ip_pkts,u_data->internal.week.resv.ip_pkts);
			time_i.tm_wday = day;
			strftime(l_a_time, 80,"%a",&time_i);
			ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[day].send.ip_bytes/EINHEIT,u_data->external.days[day].resv.ip_bytes/EINHEIT,u_data->external.days[day].send.ip_pkts,u_data->external.days[day].resv.ip_pkts);
			ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[day].send.ip_bytes/EINHEIT,u_data->internal.days[day].resv.ip_bytes/EINHEIT,u_data->internal.days[day].send.ip_pkts,u_data->internal.days[day].resv.ip_pkts);
			ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.over_all.send.ip_bytes/EINHEIT,u_data->external.over_all.resv.ip_bytes/EINHEIT,u_data->external.over_all.send.ip_pkts,u_data->external.over_all.resv.ip_pkts);
			ng_logout("internal _all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.ip_bytes/EINHEIT,u_data->internal.over_all.resv.ip_bytes/EINHEIT,u_data->internal.over_all.send.ip_pkts,u_data->internal.over_all.resv.ip_pkts);
			for(day=0;day<=6;day++)
			{    
				time_i.tm_wday = (day+1)%7;
				strftime(l_a_time, 80,"%A",&time_i);
				ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[(day+1)%7].send.ip_bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.ip_bytes/EINHEIT,u_data->external.days[(day+1)%7].send.ip_pkts,u_data->external.days[(day+1)%7].resv.ip_pkts);
				ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[(day+1)%7].send.ip_bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.ip_bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.ip_pkts,u_data->internal.days[(day+1)%7].resv.ip_pkts);
			}	

			ng_logout("TCP:");	
			day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
			ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.week.send.tcpip_bytes/EINHEIT,u_data->external.week.resv.tcpip_bytes/EINHEIT,u_data->external.week.send.tcpip_pkts,u_data->external.week.resv.tcpip_pkts);
			ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.week.send.tcpip_bytes/EINHEIT,u_data->internal.week.resv.tcpip_bytes/EINHEIT,u_data->internal.week.send.tcpip_pkts,u_data->internal.week.resv.tcpip_pkts);
			time_i.tm_wday = day;
			strftime(l_a_time, 80,"%a",&time_i);
			ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[day].send.tcpip_bytes/EINHEIT,u_data->external.days[day].resv.tcpip_bytes/EINHEIT,u_data->external.days[day].send.tcpip_pkts,u_data->external.days[day].resv.tcpip_pkts);
			ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[day].send.tcpip_bytes/EINHEIT,u_data->internal.days[day].resv.tcpip_bytes/EINHEIT,u_data->internal.days[day].send.tcpip_pkts,u_data->internal.days[day].resv.tcpip_pkts);
			ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.over_all.send.tcpip_bytes/EINHEIT,u_data->external.over_all.resv.tcpip_bytes/EINHEIT,u_data->external.over_all.send.tcpip_pkts,u_data->external.over_all.resv.tcpip_pkts);
			ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.tcpip_bytes/EINHEIT,u_data->internal.over_all.resv.tcpip_bytes/EINHEIT,u_data->internal.over_all.send.tcpip_pkts,u_data->internal.over_all.resv.tcpip_pkts);
			for(day=0;day<=6;day++)
			{    
				time_i.tm_wday = (day+1)%7;
				strftime(l_a_time, 80,"%A",&time_i);
				ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[(day+1)%7].send.tcpip_bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.tcpip_bytes/EINHEIT,u_data->external.days[(day+1)%7].send.tcpip_pkts,u_data->external.days[(day+1)%7].resv.tcpip_pkts);
				ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[(day+1)%7].send.tcpip_bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.tcpip_bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.tcpip_pkts,u_data->internal.days[(day+1)%7].resv.tcpip_pkts);
			}	


			ng_logout("UDP:");	
			day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
			ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.week.send.udp_bytes/EINHEIT,u_data->external.week.resv.udp_bytes/EINHEIT,u_data->external.week.send.udp_pkts,u_data->external.week.resv.udp_pkts);
			ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.week.send.udp_bytes/EINHEIT,u_data->internal.week.resv.udp_bytes/EINHEIT,u_data->internal.week.send.udp_pkts,u_data->internal.week.resv.udp_pkts);
			time_i.tm_wday = day;
			strftime(l_a_time, 80,"%a",&time_i);
			ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[day].send.udp_bytes/EINHEIT,u_data->external.days[day].resv.udp_bytes/EINHEIT,u_data->external.days[day].send.udp_pkts,u_data->external.days[day].resv.udp_pkts);
			ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[day].send.udp_bytes/EINHEIT,u_data->internal.days[day].resv.udp_bytes/EINHEIT,u_data->internal.days[day].send.udp_pkts,u_data->internal.days[day].resv.udp_pkts);
			ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.over_all.send.udp_bytes/EINHEIT,u_data->external.over_all.resv.udp_bytes/EINHEIT,u_data->external.over_all.send.udp_pkts,u_data->external.over_all.resv.udp_pkts);
			ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.udp_bytes/EINHEIT,u_data->internal.over_all.resv.udp_bytes/EINHEIT,u_data->internal.over_all.send.udp_pkts,u_data->internal.over_all.resv.udp_pkts);
			for(day=0;day<=6;day++)
			{    
				time_i.tm_wday = (day+1)%7;
				strftime(l_a_time, 80,"%A",&time_i);
				ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[(day+1)%7].send.udp_bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.udp_bytes/EINHEIT,u_data->external.days[(day+1)%7].send.udp_pkts,u_data->external.days[(day+1)%7].resv.udp_pkts);
				ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[(day+1)%7].send.udp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.udp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.udp_pkts,u_data->internal.days[(day+1)%7].resv.udp_pkts);
			}	

			ng_logout("ICMP:");	
			day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
			ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.week.send.icmp_bytes/EINHEIT,u_data->external.week.resv.icmp_bytes/EINHEIT,u_data->external.week.send.icmp_pkts,u_data->external.week.resv.icmp_pkts);
			ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.week.send.icmp_bytes/EINHEIT,u_data->internal.week.resv.icmp_bytes/EINHEIT,u_data->internal.week.send.icmp_pkts,u_data->internal.week.resv.icmp_pkts);
			time_i.tm_wday = day;
			strftime(l_a_time, 80,"%a",&time_i);
			ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[day].send.icmp_bytes/EINHEIT,u_data->external.days[day].resv.icmp_bytes/EINHEIT,u_data->external.days[day].send.icmp_pkts,u_data->external.days[day].resv.icmp_pkts);
			ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[day].send.icmp_bytes/EINHEIT,u_data->internal.days[day].resv.icmp_bytes/EINHEIT,u_data->internal.days[day].send.icmp_pkts,u_data->internal.days[day].resv.icmp_pkts);
			ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.over_all.send.icmp_bytes/EINHEIT,u_data->external.over_all.resv.icmp_bytes/EINHEIT,u_data->external.over_all.send.icmp_pkts,u_data->external.over_all.resv.icmp_pkts);
			ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.icmp_bytes/EINHEIT,u_data->internal.over_all.resv.icmp_bytes/EINHEIT,u_data->internal.over_all.send.icmp_pkts,u_data->internal.over_all.resv.icmp_pkts);
			for(day=0;day<=6;day++)
			{    
				time_i.tm_wday = (day+1)%7;
				strftime(l_a_time, 80,"%A",&time_i);
				ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[(day+1)%7].send.icmp_bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.icmp_bytes/EINHEIT,u_data->external.days[(day+1)%7].send.icmp_pkts,u_data->external.days[(day+1)%7].resv.icmp_pkts);
				ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[(day+1)%7].send.icmp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.icmp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.icmp_pkts,u_data->internal.days[(day+1)%7].resv.icmp_pkts);
			}	

			ng_logout("ARP:");	
			day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
			ng_logout("external week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.week.send.arp_bytes/EINHEIT,u_data->external.week.resv.arp_bytes/EINHEIT,u_data->external.week.send.arp_pkts,u_data->external.week.resv.arp_pkts);
			ng_logout("internal week \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.week.send.arp_bytes/EINHEIT,u_data->internal.week.resv.arp_bytes/EINHEIT,u_data->internal.week.send.arp_pkts,u_data->internal.week.resv.arp_pkts);
			time_i.tm_wday = day;
			strftime(l_a_time, 80,"%a",&time_i);
			ng_logout("external today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[day].send.arp_bytes/EINHEIT,u_data->external.days[day].resv.arp_bytes/EINHEIT,u_data->external.days[day].send.arp_pkts,u_data->external.days[day].resv.arp_pkts);
			ng_logout("internal today(%s)\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[day].send.arp_bytes/EINHEIT,u_data->internal.days[day].resv.arp_bytes/EINHEIT,u_data->internal.days[day].send.arp_pkts,u_data->internal.days[day].resv.arp_pkts);
			ng_logout("external all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->external.over_all.send.arp_bytes/EINHEIT,u_data->external.over_all.resv.arp_bytes/EINHEIT,u_data->external.over_all.send.arp_pkts,u_data->external.over_all.resv.arp_pkts);
			ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.arp_bytes/EINHEIT,u_data->internal.over_all.resv.arp_bytes/EINHEIT,u_data->internal.over_all.send.arp_pkts,u_data->internal.over_all.resv.arp_pkts);
			for(day=0;day<=6;day++)
			{    
				time_i.tm_wday = (day+1)%7;
				strftime(l_a_time, 80,"%A",&time_i);
				ng_logout("external %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->external.days[(day+1)%7].send.arp_bytes/EINHEIT,u_data->external.days[(day+1)%7].resv.arp_bytes/EINHEIT,u_data->external.days[(day+1)%7].send.arp_pkts,u_data->external.days[(day+1)%7].resv.arp_pkts);
				ng_logout("internal %-10s \t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",l_a_time,u_data->internal.days[(day+1)%7].send.arp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].resv.arp_bytes/EINHEIT,u_data->internal.days[(day+1)%7].send.arp_pkts,u_data->internal.days[(day+1)%7].resv.arp_pkts);
			}	

		}
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

}

void *NetGuard_Accounting::get_data(void *data) {
	return userlist;
}

