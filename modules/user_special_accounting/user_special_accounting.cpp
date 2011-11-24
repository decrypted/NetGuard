/***************************************************************************
 *   NetGuard Special Accounting Module                                    *
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
#include <time.h>

#include "compile.h"
#include "user_special_accounting.hpp"
#include "../../includes/logging.h"

static const char *ACC_SPECIAL_VERSION_MAGIC = "netguard_special_accounting_db_v0.1";

NetGuard_Special_Accounting::NetGuard_Special_Accounting()
{
	ng_logdebug_spam("constructor");
	general_acccounting = NULL;
	muser_data = NULL;
	security = NULL;
	Mac_IgnoreSpecial= new NetGuard_Mac_Filter();
	Mac_IgnoreSpecial->name="NetGuard_Special_Accounting Ignore";

 	htons_ETHERTYPE_IPV6 = htons(ETHERTYPE_IPV6);

	required_modules.push_back("general_accounting");
	required_modules.push_back("user_security");
}

NetGuard_Special_Accounting::~NetGuard_Special_Accounting()
{
	ng_logdebug_spam("destructor");
	delete Mac_IgnoreSpecial;
}

void NetGuard_Special_Accounting::loaddata()
{
	if (Mac_IgnoreSpecial)
		Mac_IgnoreSpecial->loadfile("Special.Ignore");

	struct	user_data * u_data;
	#ifdef userlist_use_simple
	struct	user_list * m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		struct user_special_accounting_data *accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if (accouning_data) {
			user_shutdown(u_data);
		}
		user_init(u_data);
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
}

void NetGuard_Special_Accounting::savedata()
{
	#ifdef userlist_use_simple
	struct	user_list * m_users = NULL;
	#endif
	struct	user_data * u_data;
	FILE *myfile;

	if (Mac_IgnoreSpecial)
			Mac_IgnoreSpecial->savefile("Special.Ignore");

	if (!muser_data) return;

	ng_logdebug_spam("saving special users to %s",db_filename.c_str());

	myfile = fopen(db_filename.c_str(), "w+");
	if (!myfile) return;

	fwrite(ACC_SPECIAL_VERSION_MAGIC,strlen(ACC_SPECIAL_VERSION_MAGIC),1,myfile);

	struct user_special_accounting_data * accouning_data = NULL;

	
	int counter = 0;
	#ifdef userlist_use_simple
	m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if (accouning_data) counter++;
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
	//write number of users
	fwrite(&counter ,sizeof(counter),1, myfile);

	#ifdef userlist_use_simple
	m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if (accouning_data) {
			fwrite(&u_data->saddr ,sizeof(u_data->saddr),1, myfile);
		} else {
			ng_logerror("skipping user %-15s on saving - no data present",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}

	#ifdef userlist_use_simple
	m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if (accouning_data)
		{
			fwrite(accouning_data,sizeof(struct user_special_accounting_data),1, myfile);
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}

	ng_logdebug_spam("saved %d users",counter);

	fwrite(ACC_SPECIAL_VERSION_MAGIC,strlen(ACC_SPECIAL_VERSION_MAGIC),1,myfile);
	fclose(myfile);
}

struct user_special_accounting_data * NetGuard_Special_Accounting::load_accouning_data(struct user_data *u_data, int rename_onfail){
	FILE *myfile;
	struct stat fileinfo;
	char *tmpdata;
	struct user_special_accounting_data * accouning_data = NULL;
	int i;
	off_t f_pos;


	ng_logdebug_spam("loading data from %s",db_filename.c_str());

	if (stat(db_filename.c_str(),&fileinfo)) {
		ng_logerror("cant stat data file %s",db_filename.c_str());
		return NULL;
	}
	myfile = fopen(db_filename.c_str(), "r");
	if (!myfile) {
		ng_logerror("cant open data file %s",db_filename.c_str());
		return NULL;
	}
	
	//check file version
	tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(ACC_SPECIAL_VERSION_MAGIC)+1));
	tmpdata[strlen(ACC_SPECIAL_VERSION_MAGIC)] = 0;
	int count = fread(&tmpdata[0],strlen(ACC_SPECIAL_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_SPECIAL_VERSION_MAGIC) ) {
		ng_logerror("cant read traffic data from %s - illegal format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_SPECIAL_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(db_filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",db_filename.c_str(),(int)now);
			ng_log("renaming file to %s",tmpdata);
			rename(db_filename.c_str(),tmpdata);
		}
		return NULL;
	}

	f_pos = ftell(myfile);
	fseek(myfile,fileinfo.st_size-strlen(ACC_SPECIAL_VERSION_MAGIC),SEEK_SET);
	count = fread(&tmpdata[0],strlen(ACC_SPECIAL_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_SPECIAL_VERSION_MAGIC) ) {
		ng_logerror("cant read traffic data from %s - illegal (end) format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_SPECIAL_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(db_filename.c_str())+20));
			time_t now;
			time(&now);/* get the current time */
			sprintf(tmpdata,"%s_%d",db_filename.c_str(),(int)now);
			ng_logdebug("renaming file to %s",tmpdata);
			rename(db_filename.c_str(),tmpdata);
		}
		return NULL;
	}
	//set to old position again
	fseek(myfile,f_pos,SEEK_SET);

	ng_logdebug("loading %lu bytes data",fileinfo.st_size);

	int counter = 0;
	count = fread(&counter,sizeof(counter),1, myfile);
	if (count  != 1 ) return NULL;
	ng_logdebug("found %d users in file",counter);

	u_int32_t saddr;
	int found = 0;
	unsigned int seek_pos = 0;
	for (i=1; i<=counter ; i++ )
	{
		count = fread(&saddr ,sizeof(saddr),1, myfile);
		if (count  != 1 ) return NULL;
		if (saddr == u_data->saddr)
		{
			found = 1;
			seek_pos = i;
			ng_logdebug("found user %-15s on pos %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),seek_pos);
		}
	}

	if (!found) return NULL;
	seek_pos = (seek_pos-1) * sizeof(struct user_special_accounting_data) + ftell(myfile);
	fseek(myfile,seek_pos,SEEK_SET);


	accouning_data = (struct user_special_accounting_data *)malloc(sizeof(struct user_special_accounting_data));
	count = fread(accouning_data,sizeof(struct user_special_accounting_data),1, myfile);
	if (count  != 1 ) {
		delete accouning_data;
		return NULL;
	}

	fclose(myfile);
	free(tmpdata);

	return accouning_data;
}

int NetGuard_Special_Accounting::init(NetGuard_Config *data)
{
	general_acccounting = NULL;
	muser_data = NULL;
	security = NULL;

	ng_logdebug("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetStr("user_special_accounting_filename") == "")
	{
		ng_logerror("need an user_special_accounting_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("user_special_accounting_filename");

	if (data_->GetModule("module_general_accounting") == NULL) {
		ng_logerror("need general_accounting module needs to be loaded");
		return -2;
	}
	general_acccounting = (NetGuard_General_Module*)data_->GetModule("module_general_accounting");
	muser_data = (User_Data_Tools*)general_acccounting->get_data(NULL);

	if (data_->GetModule("module_user_security") == NULL) {
		ng_logerror("need user_security module needs to be loaded");
		return -2;
	}
	security = (NetGuard_User_Module*)data_->GetModule("module_user_security");

	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);	

	setNULL_HW_ADDR(null_hw_addr);
	setBCAST_HW_ADDR(bcast_hw_addr);

	loaddata();

	return 0;
}

void NetGuard_Special_Accounting::shutdown()
{
	ng_logdebug("destructor");
	savedata();
	
	if (muser_data)
	{
		#ifdef userlist_use_simple
		struct	user_list * m_users = muser_data->get_list();
		while (m_users != NULL) {
			struct	user_data *u_data = m_users->data;
		#else
		ip_storage_hash::iterator it;
		for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
			struct	user_data *u_data =  (*it).second;
		#endif
			user_shutdown(u_data);
			#ifdef userlist_use_simple
			m_users = m_users->next;
			#endif
		}
	}

	general_acccounting = NULL;
	muser_data = NULL;
	security = NULL;
}

struct user_special_accounting_data *NetGuard_Special_Accounting::my_user_init(struct user_data *u_data)
{
	struct user_special_accounting_data * accouning_data;
	
	//try to load it from file
	accouning_data = load_accouning_data(u_data,1);

	if (accouning_data == NULL)
	{
		ng_logdebug("new accounting for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		//we need to init a new user
		accouning_data = (struct user_special_accounting_data *)malloc(sizeof(struct user_special_accounting_data));

		//set default values
		memset(accouning_data,0,sizeof(struct user_special_accounting_data));
	};

	u_data->module_data[user_special_module_number] = accouning_data;

	return accouning_data;	
}

void NetGuard_Special_Accounting::user_init(struct user_data *u_data)
{
	if (!u_data) return;
	ng_logdebug("user_init for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	my_user_init(u_data);
}

void NetGuard_Special_Accounting::user_shutdown(struct user_data *u_data)
{
	struct user_special_accounting_data * accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
	if ( accouning_data != NULL ) {		
		ng_logdebug("free accounting data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		delete accouning_data;
	}
	u_data->module_data[user_special_module_number] = NULL;
}

void NetGuard_Special_Accounting::do_sum_timeslot_data(struct user_data_special_timeslot_data *counter,struct user_data_special_timeslot_data data){
	counter->nonip_bytes += data.nonip_bytes;
	counter->nonip_pkts +=  data.nonip_pkts;
}

void NetGuard_Special_Accounting::do_sum_timeslot(struct user_data_special_timeslot *counter,struct user_data_special_timeslot data)
{
	do_sum_timeslot_data(&counter->send,data.send);
	do_sum_timeslot_data(&counter->resv,data.resv);
}

void NetGuard_Special_Accounting::user_data_forgetday(int day)
{
	struct	user_data * u_data;

	if (day < 0 || day > 6)  {
		ng_logdebug("forget day <0 or >6 (%d) - ignoring",day);
		return;
	}
	ng_logdebug("forget day %d",day);


	#ifdef userlist_use_simple
	struct	user_list * m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		struct user_special_accounting_data * accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if (accouning_data)
		{
			//erase this day
			memset(&accouning_data->internal.days[day],0,sizeof(struct user_data_special_timeslot));
			//recalc week
			struct user_data_special_timeslot counter;
			memset(&counter,0,sizeof(struct user_data_special_timeslot));
			for (int i=0; i <= 6; i++) {
				do_sum_timeslot(&counter,accouning_data->internal.days[i]);
			};
			accouning_data->internal.week = counter;
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
}

void NetGuard_Special_Accounting::doaccount_package(user_data * u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	//we account a package
	struct user_data_special_timeslot_data *td_a; //over_all
	struct user_data_special_timeslot_data *td_w; //week
	struct user_data_special_timeslot_data *td_d; //this day	

	struct user_special_accounting_data *accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
	if ( accouning_data == NULL ) {
		accouning_data = my_user_init(u_data);
	}
	struct user_data_special_traffic *traffic_type = &accouning_data->internal;

	if (*mode == TRAFFIC_INCOMING)
	{
		td_a = &(traffic_type->over_all.resv);
		td_w = &traffic_type->week.resv;
		td_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].resv;
	} else if (*mode == TRAFFIC_OUTGOING)
	{
		td_a = &(traffic_type->over_all.send);
		td_w = &traffic_type->week.send;
		td_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].send;
	} else return;

	td_a->nonip_pkts ++;
	td_w->nonip_pkts ++;
	td_d->nonip_pkts ++;

	td_a->nonip_bytes += h->tp_len;
	td_w->nonip_bytes += h->tp_len;
	td_d->nonip_bytes += h->tp_len;
}

void NetGuard_Special_Accounting::account_package(user_data * u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	if (!security) {
		ng_logerror_buff(0,"missing Security Module!");
		exit(-1);
		return;
	}

	//we only look for traffic that was not assigned to a user yet
	//that should be always like that because only that 2 types that get ignored can search a user so package should be ALWAYS TRAFFIC_UNKOWN
	if (*mode != TRAFFIC_UNKOWN) return;

	if ((eth->ether_type != htons_ETHERTYPE_IP) && (eth->ether_type != htons_ETHERTYPE_ARP)) 
	{

		int m_mode;
		sec_data_idx idx;
		memcpy(&idx.hw_addr,&eth->ether_shost,sizeof(mac_addr));
		idx.vlan_id = (*vlanid);
		user_data *m_u_data = (user_data *)security->get_data(&idx);
		if (m_u_data)
		{
			m_mode = TRAFFIC_INCOMING;
			doaccount_package(m_u_data,&m_mode,vlanid,h,eth,ip,tcp,data);
		} else {
			if (!Mac_IgnoreSpecial->match(&eth->ether_shost,vlanid)) {
				ng_logerror_buff(1,"source mac has no user %02x:%02x:%02x:%02x:%02x:%02x - dont account data", printf_mac_params(eth->ether_shost));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logerror_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
		}

		//we dont account for broadcast as sender
		if (compare_mac(&eth->ether_dhost,&null_hw_addr)) return;
		if (compare_mac(&eth->ether_dhost,&bcast_hw_addr)) return;

		//vlan is still the same
		memcpy(&idx.hw_addr,&eth->ether_dhost,sizeof(mac_addr));
		m_u_data = (user_data *)security->get_data(&idx);
		if (m_u_data)
		{
			m_mode = TRAFFIC_OUTGOING;
			doaccount_package(m_u_data,&m_mode,vlanid,h,eth,ip,tcp,data);
		} else {
			if (eth->ether_type==htons_ETHERTYPE_IPV6) {
				//http://kb.juniper.net/index?page=content&id=KB13095&cat=IPV6_PROTOCOLS&actp=LIST
				//Ethernet dest mac = 33:33:00:00:00:00 OR'ed with the four lower order bytes of the IPv6 multicast address. So for an IPv6 multicast destination of ff02:abcd:dcba::2:1, the destination ethernet mac would be 33:33:00:00:02:01.
				//http://tools.ietf.org/html/rfc2464
				//ignore broadcasts
				if ((eth->ether_dhost[0] == 0x33) && (eth->ether_dhost[1] == 0x33)) return;
			}

			if (!Mac_IgnoreSpecial->match(&eth->ether_dhost,vlanid)) {
				ng_logerror_buff(1,"dest mac has no user %02x:%02x:%02x:%02x:%02x:%02x - dont account data", printf_mac_params(eth->ether_dhost));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logerror_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
		}
		return;
	};
}

void NetGuard_Special_Accounting::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	account_package(u_data,mode,vlanid,h,eth,ip,tcp,data);
}

void NetGuard_Special_Accounting::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("special_add_ignore <mac> <vlan> [comment] - add mac to ignore list");
		ng_logout("special_del_ignore <mac> <vlan> - del mac from ignore list");
		ng_logout("dumpip_all <ip> <vlan> - show details for an ip");
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "show")
	{
		if (params.size() == 1) {
			ng_logout("Ignore Mac Addreses:");
			Mac_IgnoreSpecial->print();
		}
	}

	if (params[0] == "special_add_ignore")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_add_ignore <mac> <vlan> [comment]");
			return;
		}
		char comment[255];
		memset(comment,0,255);
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_add_ignore <mac> <vlan> [comment]");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_add_ignore <mac> <vlan> [comment]");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];

		std::string my_tmp = GetParamComment(params,3);
		if (my_tmp.size() <= 255)
		{
			memcpy(&comment,my_tmp.c_str(),my_tmp.size());
		} else {
			memcpy(&comment,my_tmp.c_str(),255);
		}
		
		ng_logout_ret(0,"add mac %s vlan %u comment %s",params[1].c_str(),tmpint,comment);
		Mac_IgnoreSpecial->add(&mac,&tmpint,comment);
	}

	if (params[0] == "special_del_ignore")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_del_ignore <mac> <vlan>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_del_ignore <mac> <vlan>");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: special_del_ignore <mac> <vlan>");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ret(0,"del mac %s vlan %u",params[1].c_str(),tmpint);
		Mac_IgnoreSpecial->del(&mac,&tmpint);
	}

	if (params[0] == "dumpip_all")
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
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}
		
		//#define EINHEIT 1024/1024
		#define EINHEIT 1024

		struct user_special_accounting_data *accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_special_module_number];
		if ( accouning_data == NULL ) return;
		struct user_data_special_traffic *traffic_type = &accouning_data->internal;

		struct user_data_special_timeslot_data *td_a; //over_all
		struct user_data_special_timeslot_data *td_w; //week
		struct user_data_special_timeslot_data *td_d; //this day	

		struct user_data_special_timeslot_data *td_r_a; //over_all
		struct user_data_special_timeslot_data *td_r_w; //week
		struct user_data_special_timeslot_data *td_r_d; //this day	

		td_a = &(traffic_type->over_all.send);
		td_w = &traffic_type->week.send;
		td_r_a = &(traffic_type->over_all.resv);
		td_r_w = &traffic_type->week.resv;

		ng_logout("internal week \t\t- send non-ip: %llu KByte send non-ip: %llu pkts resv non-ip: %llu KByte resv non-ip: %llu pkts",td_a->nonip_bytes/EINHEIT,td_a->nonip_pkts,td_r_a->nonip_bytes/EINHEIT,td_r_a->nonip_pkts);
		td_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].send;
		td_r_d = &traffic_type->days[NetGuard_ModuleLoader_Base::GetTime()->tm_wday].resv;
		struct tm time_i = {0,0};
		char l_a_time[50];
		time_i.tm_wday = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
		strftime(l_a_time, 80,"%a",&time_i);
		ng_logout("internal today(%s)\t- send non-ip: %llu KByte send non-ip: %llu pkts resv non-ip: %llu KByte resv non-ip: %llu pkts",l_a_time, td_d->nonip_bytes/EINHEIT,td_d->nonip_pkts, td_r_d->nonip_bytes/EINHEIT,td_r_d->nonip_pkts);
		ng_logout("internal all \t\t- send non-ip: %llu KByte send non-ip: %llu pkts resv non-ip: %llu KByte resv non-ip: %llu pkts",td_a->nonip_bytes/EINHEIT,td_a->nonip_pkts,td_r_a->nonip_bytes/EINHEIT,td_r_a->nonip_pkts);
		for(int day=0;day<=6;day++)
		{    
			time_i.tm_wday = (day+1)%7;
			strftime(l_a_time, 80,"%A",&time_i);
			td_a = &traffic_type->days[(day+1)%7].send;
			td_r_a = &traffic_type->days[(day+1)%7].resv;
			ng_logout("internal %-10s \t- send non-ip: %llu KByte send non-ip: %llu pkts resv non-ip: %llu KByte resv non-ip: %llu pkts",l_a_time,td_a->nonip_bytes/EINHEIT,td_a->nonip_pkts,td_r_a->nonip_bytes/EINHEIT,td_r_a->nonip_pkts);
		}	
	}

}

void NetGuard_Special_Accounting::timer_tick() {
}
