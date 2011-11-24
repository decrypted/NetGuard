/***************************************************************************
 *   NetGuard Security Module                                              *
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
#include <values.h>

#include <sys/stat.h>
#include <time.h>

#include "user_security.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/state/state_handling.hpp"

NetGuard_Security::NetGuard_Security()
{
	ng_logdebug_spam("constructor");
	general_acccounting = NULL;
	muser_data = NULL;
	#ifndef hash_security
	memset(&mac_hash,0,sizeof(sec_hash_level));
	#endif

	zero_ip = ntohl(inet_addr("0.0.0.0"));

	Mac_IgnoreSpoof= new NetGuard_Mac_Filter();
	Mac_IgnoreSpoof->name="NetGuard_Security Spoof";
	Mac_IgnoreProtocols= new NetGuard_Mac_Filter();
	Mac_IgnoreProtocols->name="NetGuard_Security Protocols Ingores";
	Mac_IgnoreArpRequestDest= new NetGuard_Mac_Filter();
	Mac_IgnoreArpRequestDest->name="NetGuard_Security Arp Request Ingore Dest";
	Mac_IgnoreArpRequestSrc= new NetGuard_Mac_Filter();
	Mac_IgnoreArpRequestSrc->name="NetGuard_Security Arp Request Ingore Source";
	required_modules.push_back("general_accounting");
}

NetGuard_Security::~NetGuard_Security()
{
	delete Mac_IgnoreSpoof;
	delete Mac_IgnoreProtocols;
	delete Mac_IgnoreArpRequestDest;
	delete Mac_IgnoreArpRequestSrc;
	required_modules.clear();
	ng_logdebug_spam("destructor");
}

void NetGuard_Security::savedata()
{
	if (Mac_IgnoreSpoof)	Mac_IgnoreSpoof->savefile("Security.IgnoreSpoof");
	if (Mac_IgnoreProtocols)	Mac_IgnoreProtocols->savefile("Security.IgnoreProtocols");
	if (Mac_IgnoreArpRequestDest)	Mac_IgnoreArpRequestDest->savefile("Security.IgnoreArpRequestBDest");
	if (Mac_IgnoreArpRequestSrc)	Mac_IgnoreArpRequestSrc->savefile("Security.IgnoreArpRequestBSrc");
}

void NetGuard_Security::loaddata()
{
	Mac_IgnoreSpoof->loadfile("Security.IgnoreSpoof");
	Mac_IgnoreProtocols->loadfile("Security.IgnoreProtocols");
	Mac_IgnoreArpRequestDest->loadfile("Security.IgnoreArpRequestBDest");
	Mac_IgnoreArpRequestSrc->loadfile("Security.IgnoreArpRequestBSrc");


	mac_addr n_mac;
	setNULL_HW_ADDR(n_mac);
	//lets add all users to the mac lookup right away so other modules can use it ..
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
			if (!compare_mac(&n_mac,&(u_data->hw_addr)))
				addmac_user_hash(u_data,&(u_data->hw_addr));

			//lets see if the state has a different mac - if thats the case and its not the 0 mac add it
			NetGuard_User_State* user_state = NetGuard_State_Handler::user_state(u_data);
			if (user_state)
			{
				mac_addr *hw_addr_p = user_state->params()->GetMac("mac");
				if (!compare_mac(&n_mac,hw_addr_p))
					if (!compare_mac(&(u_data->hw_addr),hw_addr_p))
						addmac_user_hash(u_data,hw_addr_p);			
			}
			#ifdef userlist_use_simple
			m_users = m_users->next;
			#endif
		}
	}

}

int NetGuard_Security::init(NetGuard_Config *data)
{
	muser_data = NULL;
	general_acccounting = NULL;

	ng_logdebug_spam("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetModule("module_general_accounting") == NULL) {
		ng_logerror("need general_accounting module needs to be loaded");
		return -2;
	}
	general_acccounting = (NetGuard_General_Module*)data_->GetModule("module_general_accounting");
	muser_data = (User_Data_Tools*)general_acccounting->get_data(NULL);


	mode_enabled = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("state.enable","enabled"));
	if (!mode_enabled) {
		ng_logerror("state 'enabled' unkown");
		return -2;
	}
	mode_disabled = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("state.disabled","disabled"));
	if (!mode_disabled) {
		ng_logerror("state 'disabled' unkown");
		return -2;
	}
	mode_learn = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("state.learn","learn"));
	if (!mode_learn) {
		ng_logerror("state 'learn' unkown");
		return -2;
	}

	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);	
	htons_ETHERTYPE_8023 = htons(ETHERTYPE_8023);
	htons_ETHERTYPE_8021D= htons(ETHERTYPE_8021D);
	setNULL_HW_ADDR(null_hw_addr);
	setBCAST_HW_ADDR(bcast_hw_addr);

	loaddata();
	
	return 0;
}

void NetGuard_Security::shutdown()
{
	savedata();
	ng_logdebug_spam("shutdown");
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
	Mac_IgnoreSpoof->savefile("Security.IgnoreSpoof");
	Mac_IgnoreProtocols->savefile("Security.IgnoreProtocols");
	Mac_IgnoreArpRequestDest->savefile("Security.IgnoreArpRequestBDest");
	Mac_IgnoreArpRequestSrc->savefile("Security.IgnoreArpRequestBSrc");

    clear();
}

void NetGuard_Security::user_init(struct user_data *u_data)
{
	ng_logdebug_spam("init security data for %s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	struct user_security_data* msec_data = (struct user_security_data*) malloc(sizeof(struct user_security_data));
	memset(msec_data,0,sizeof(struct user_security_data));

	//lets restore a secure mac if already possible - sec mac is saved within the state in the param "mac"
	NetGuard_User_State* user_state = NetGuard_State_Handler::get_add_user_state(u_data,GlobalCFG::GetStr("state._init","unkown"));

	if ((*user_state) == GlobalCFG::GetStr("state.unkown","unkown"))
	{
		user_state->set(mode_learn,"default move to learn - user_init");
	}

	mac_addr *hw_addr_p = user_state->params()->GetMac("mac");
	memcpy(msec_data->hw_addr,hw_addr_p,sizeof(mac_addr));
	ng_logdebug_spam("(re)init security data for %s with mac %02x:%02x:%02x:%02x:%02x:%02x in state <%s>",inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params(msec_data->hw_addr),user_state->state_name().c_str());
	
	u_data->module_data[user_security_module_number] = msec_data;

	mac_addr n_mac;
	setNULL_HW_ADDR(n_mac);
	if (!compare_mac(&n_mac,&(msec_data->hw_addr)))
		if (addmac_user_hash(u_data,&(msec_data->hw_addr))) //should be already added from load most times but here we go
		{
			//why did we read a user here -> warning should have been added on load already
			if (!Mac_IgnoreSpoof->match(&msec_data->hw_addr,&u_data->vlan_id))
			{
				ng_logdebug("warning: %s with mac %02x:%02x:%02x:%02x:%02x:%02x in state <%s> caused a new mac to be added in security the hashmap",inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params(msec_data->hw_addr),user_state->state_name().c_str());
			} else {
				ng_logdebug_spam("warning: %s with mac %02x:%02x:%02x:%02x:%02x:%02x (allowed to spoof) in state <%s> caused a new mac to be added in security the hashmap",inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params(msec_data->hw_addr),user_state->state_name().c_str());
			}
		}
}

void NetGuard_Security::user_shutdown(struct user_data *u_data)
{
	struct user_security_data *security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
	if ( security_data != NULL ) {
		ng_logdebug_spam("free security data for %s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		delete security_data;
	}
	u_data->module_data[user_security_module_number] = NULL;
}


#ifndef hash_security
void NetGuard_Security::addmac_hash(struct user_data *u_data, mac_addr hw_addr,sec_hash_level hash_data, int lev)
{
	ng_logdebug_spam("adding mac %02x:%02x:%02x:%02x:%02x:%02x to hash for user ip src_ip: %s level: %d", printf_mac_params(hw_addr) ,inet_ntoa(*(struct in_addr *)&u_data->saddr),lev);
	struct sec_hash_entry *level_data;
	int pos = 5 - lev;
	level_data = hash_data[hw_addr[pos]];
	if (level_data == NULL)
	{
		//we need a new level
		level_data = (struct sec_hash_entry *)malloc(sizeof(struct sec_hash_entry));
		memset(level_data,0,sizeof(struct sec_hash_entry));
		hash_data[hw_addr[pos]] = level_data;
		level_data->users[0] = u_data;
		ng_logdebug_spam("added user ip src_ip: %s on - index %x - lev %d - index pos %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),hw_addr[pos],lev,pos);
	} else {
		if (lev == 5)
		{
			for(int user_index=0;user_index<255;user_index++) {
				if (level_data->users[user_index] == NULL)
				{
					
					level_data->users[user_index] = u_data;
					ng_logdebug("added user ip src_ip: %s on - index %x - lev %d - index pos %d - usr index %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),hw_addr[pos],lev,pos,user_index);
					return;
				}
			}
		} else {
			if (level_data->users[0] == u_data)
			{
				ng_logdebug("not adding mac - user present at level %d - index %x", lev +1 , hw_addr[pos]);
				return;
			}
			ng_logdebug_spam("forard to level %d - index %x", lev +1 , hw_addr[pos]);
			ng_logdebug_spam("forward new address");
			addmac_hash(u_data,hw_addr,level_data->next_level,lev+1);
	
			if (level_data->users[0])
			{
				ng_logdebug_spam("forward old address lev %d",lev);
				struct user_data *old_udata = (struct user_data *)level_data->users[0];
				struct user_security_data * security_data = (struct user_security_data *)old_udata->module_data[user_security_module_number];
				if (!security_data) {
					ng_logerror("problem - sec data not assigned on creating hash");
					return;
				}
				addmac_hash(level_data->users[0],security_data->hw_addr ,level_data->next_level,lev+1);
				level_data->users[0] = NULL;
			}
		}
	}

}

void NetGuard_Security::clearhash(sec_hash_level level,int lev)
{
	if (lev > 6 ) return;
	ng_logdebug_spam("cleering hash - depth %d", lev);
	struct sec_hash_entry *level_data;
	for(int index=0;index<UCHAR_MAX;index++) {
		level_data = level[index];
		if (level_data)
		{
			ng_logdebug_spam("level: %d - cleering hash index %x",lev,index);
			clearhash(level_data->next_level,lev+1);
			delete level_data;
		}
		level[index] = NULL;
	}
}

struct user_data *NetGuard_Security::get_user_for_mac(mac_addr *hw_addr, sec_hash_level hash_data, int lev)
{
	struct sec_hash_entry *level_data;
	int pos = 5 - lev;
	level_data = hash_data[(*hw_addr)[pos]];
	if (level_data == NULL) return NULL;

	struct user_data *u_data = get_user_for_mac(hw_addr,level_data->next_level,lev+1);
	if (u_data) return u_data;

	for(int user_index=0;user_index<255;user_index++) {
		u_data = (struct user_data *)level_data->users[user_index];
		if (u_data)
		{
			struct user_security_data * security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
			if (!security_data) {
				ng_logerror("problem - sec data not assigned on creating hash");
				return NULL;
			}
			if (compare_mac(hw_addr,&security_data->hw_addr)) {
						ng_logdebug_spam("hash found user %s for mac %02x:%02x:%02x:%02x:%02x:%02x level: %d", inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params((*hw_addr)),lev);
				return u_data;
			}
		}
	}
	return NULL;
}
#endif

struct user_data *NetGuard_Security::get_user(mac_addr *hw_addr, unsigned int *vlan_id)
{
	#ifndef hash_security
	return get_user_for_mac(hw_addr,mac_hash);
	#else
    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = (*vlan_id);
	ip_sec_hash::iterator it;
	it=sec_data.find(idx);
	if (it != sec_data.end()) return (*it).second;
	return NULL;
	#endif
}

bool NetGuard_Security::addmac_user_hash(struct user_data *u_data, mac_addr *hw_addr)
{
	mac_addr n_mac;
	setNULL_HW_ADDR(n_mac);
	if (compare_mac(&n_mac,hw_addr))
	{
		ng_logerror("want to add 0 mac for user %s vlan %u", inet_ntoa(*(struct in_addr *)&u_data->saddr), u_data->vlan_id); 
		return false;
	}

	#ifndef hash_security
	return addmac_hash(u_data,(*hw_addr),mac_hash);
	#else
	struct user_data * testuser = get_user(hw_addr,&u_data->vlan_id);
	if (testuser)
	{
		if (testuser == u_data) return false;
		if (!Mac_IgnoreSpoof->match(hw_addr,&u_data->vlan_id)) {
			char *tmpstr = get_ip_char(u_data->saddr);
			ng_log("addmac_user_hash already found user for %02x:%02x:%02x:%02x:%02x:%02x %s vlan %u (wanted: %s)", printf_mac_params((*hw_addr)),inet_ntoa(*(struct in_addr *)&testuser->saddr), u_data->vlan_id, tmpstr); 
			free(tmpstr);
		} else {
			char *tmpstr = get_ip_char(u_data->saddr);
			ng_logdebug_spam("addmac_user_hash (from mac allowed to spoof) already found user for %02x:%02x:%02x:%02x:%02x:%02x %s vlan %u (wanted: %s)", printf_mac_params((*hw_addr)),inet_ntoa(*(struct in_addr *)&testuser->saddr), u_data->vlan_id, tmpstr); 
			free(tmpstr);
		}
		delmac_user_hash(u_data,hw_addr);
	}
    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = u_data->vlan_id;
	ng_logdebug_spam("addmac_user_hash %02x:%02x:%02x:%02x:%02x:%02x %s vlan: %u", printf_mac_params(idx.hw_addr),inet_ntoa(*(struct in_addr *)&u_data->saddr), u_data->vlan_id); 
	sec_data.insert(pair<const struct sec_data_idx, struct user_data*>(idx, u_data));
		#ifdef ng_debug
		testuser = get_user(hw_addr,&u_data->vlan_id);
		if (testuser==NULL) {
			ng_logerror("addmac_user_hash could not find user which was added for %02x:%02x:%02x:%02x:%02x:%02x - %s", printf_mac_params(idx.hw_addr),inet_ntoa(*(struct in_addr *)&u_data->saddr)); 
		} else if (testuser != u_data)
			ng_logerror("addmac_user_hash could not find the same user which was added for %02x:%02x:%02x:%02x:%02x:%02x - other user %s", printf_mac_params(idx.hw_addr),inet_ntoa(*(struct in_addr *)&testuser->saddr)); 
		#endif
	#endif
	return true;
}					

bool NetGuard_Security::delmac_user_hash(struct user_data *u_data, mac_addr *hw_addr)
{
	#ifndef hash_security
	return true; //no real deletion here ...
	#else

    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = u_data->vlan_id;
	ip_sec_hash::iterator it;
	it=sec_data.find(idx);
	if (it != sec_data.end()) {
		ng_logdebug_spam("delmac_user_hash %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params(idx.hw_addr)); 
		//TODO check for leak
		//delete (*it*).fist;
		sec_data.erase(it);
		return true;
	};
	return false;
	#endif

}

void NetGuard_Security::clear()
{
	#ifndef hash_security
	clearhash(mac_hash,1);
	#else
	sec_data.clear();
	#endif
}


void *NetGuard_Security::get_data(void *data) {
	if (!data) return NULL;
	sec_data_idx *mydata = (sec_data_idx*)data;
	return get_user(&mydata->hw_addr,&mydata->vlan_id);
}

void NetGuard_Security::user_data_forgetday(int day)
{
}

void NetGuard_Security::timer_tick()
{
}

void NetGuard_Security::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	//TRAFFIC_KNOWN we saw before and we dont check that as we checked already as as TRAFFIC_INCOMING or TRAFFIC_OUTGOING
	if (*mode == TRAFFIC_KNOWN) return;

	if ((eth->ether_type != htons_ETHERTYPE_IP) && (eth->ether_type != htons_ETHERTYPE_ARP)) 
	{
		if (GlobalCFG::GetInt("user_security.ignore_unkown_protocols",0) == 1) return;
		if (Mac_IgnoreProtocols->match(&eth->ether_shost,vlanid))  return;
		ng_logdebug("not checking data for protocol %6s (0x%04x)",tok2str(str_ethertype_values,"n.k.", ntohs(eth->ether_type)),ntohs(eth->ether_type));
		char *tmpstr = (char*)malloc(5000);
		sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
		ng_logdebug("%s",tmpstr);
		free(tmpstr);
		return;
	};

	mac_addr *source_mac_addr;
	mac_addr *dest_mac_addr;
	in_addr_t *src_addr;
	in_addr_t *dst_addr;
	struct user_security_data *security_data = NULL;
	struct ether_arp * arph = (struct ether_arp *)(void *)ip;

	NetGuard_User_State* user_state = NULL;

	switch (htons(eth->ether_type))
	{
	case ETHERTYPE_ARP:
		source_mac_addr = &arph->arp_sha;
		dest_mac_addr = &arph->arp_tha;
		src_addr = &*(uint32_t *)&arph->arp_spa;
		dst_addr = &*(uint32_t *)&arph->arp_tpa;
		//we also care for TRAFFIC_INCOMING here as if this packet is screwed we can drop a warning here

		//arp src addr is a broadcast - how funny (not sure this is set then but we check both to be sure)
		if (compare_mac(source_mac_addr,&bcast_hw_addr)) {
				ng_log_buff(1,"arp src is broadcast addr (FF) from src_mac %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params(eth->ether_shost));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			
		}
		//arp src addr is a broadcast also - how funny
		if (compare_mac(source_mac_addr,&null_hw_addr)) {
				ng_log_buff(1,"arp src is broadcast addr from src_mac %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params(eth->ether_shost));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			
		}

		//is that packet marked as broadcast on mac layer?
		if (compare_mac(&eth->ether_dhost,&bcast_hw_addr)) {
			//but not on arp dst addr ?
			if (!compare_mac(dest_mac_addr,&null_hw_addr)) {
				if (Mac_IgnoreArpRequestDest->match(dest_mac_addr,vlanid))  return;
				if (Mac_IgnoreArpRequestSrc->match(source_mac_addr,vlanid))  return;
				ng_log_buff(1,"stealh arp broadcast src_mac %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params((*source_mac_addr)));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
		} else if (!compare_mac(dest_mac_addr,&eth->ether_dhost)) {
			//its no broadcast but somebody send crafted packages
			//arp dst mac <> dst mac
			//but we allow - arp dst mac to be the null addr (some comps send this - tell me why plz ;-) )
			if (!compare_mac(dest_mac_addr,&null_hw_addr)) {
				ng_log_buff(1,"arp dst faked src_mac %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params((*source_mac_addr)));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
		}

		//somebody send a packet with an different mac src then arp src
		//arp src mac <> src mac
		if (!compare_mac(source_mac_addr,&eth->ether_shost))
		{
			ng_log_buff(1,"arp src different to src_mac %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)),inet_ntoa(*(struct in_addr *)src_addr));
			char *tmpstr = (char*)malloc(5000);
			sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
			ng_log_buff(0,"%s",tmpstr);
			free(tmpstr);
		}

		switch (ntohs(arph->arp_op))
		{
		case ARPOP_REQUEST:
			//requests that that should always be broadcasts
			if (!compare_mac(dest_mac_addr,&null_hw_addr))
			{
				if (Mac_IgnoreArpRequestDest->match(dest_mac_addr,vlanid))  return;
				if (Mac_IgnoreArpRequestSrc->match(source_mac_addr,vlanid))  return;
				ng_log_buff(1,"arp request on non broadcast dst_mac %02x:%02x:%02x:%02x:%02x:%02x src_mac %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params((*dest_mac_addr)), printf_mac_params((*source_mac_addr)));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
			break;
		case ARPOP_REPLY:
			//replys should NEVER be broadcast
			if (compare_mac(dest_mac_addr,&null_hw_addr))
			{
				ng_log_buff(1,"arp reply to broadcast src_mac %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)),inet_ntoa(*(struct in_addr *)src_addr));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
			break;
		
		}
		
		switch (*mode)
		{
		case TRAFFIC_OUTGOING:
			//add the user to the mac lookup table if not already present
			if (!get_user(source_mac_addr,vlanid)) 
				addmac_user_hash(u_data,source_mac_addr);

			security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
			if ( security_data == NULL ) {
				user_init(u_data);
				security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
				if ( security_data == NULL ) {
					ng_logerror("we got a NULL data after init");
					return; //special case if still loading data
				}
			};

			user_state = NetGuard_State_Handler::user_state(u_data);
			if (!user_state) {
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logerror("TRAFFIC_OUTGOING (arp) we got a NULL user_state !? package: %s",tmpstr);
				free(tmpstr);
				return; 
			}
			
			if ((*user_state) == mode_enabled) {
				//source mac ok ?
				if (!compare_mac(source_mac_addr,&security_data->hw_addr))
				{
					if (Mac_IgnoreSpoof->match(source_mac_addr,vlanid)) return;
					//report the missmatch to the control structure
					ng_log_buff(1,"mac missmatch (arp) %02x:%02x:%02x:%02x:%02x:%02x <> %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), printf_mac_params(security_data->hw_addr), inet_ntoa(*(struct in_addr *)src_addr));
					char *tmpstr = (char*)malloc(5000);
					sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
					ng_log_buff(0,"%s",tmpstr);
					free(tmpstr);
				}
			} else if ((*user_state) == mode_learn) {
				//we learn a new mac
				//delmac_user_hash(u_data,&security_data->hw_addr); why delete - this way we still know who had the mac ;-)
				memcpy(&security_data->hw_addr,source_mac_addr,sizeof(security_data->hw_addr));
				user_state->params()->SetMac("mac",(*source_mac_addr)); //copy mac to state

				//set mode_learn
				if (!(user_state->set(mode_enabled,"learned (arp) %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), inet_ntoa(*(struct in_addr *)src_addr))))
				{
					ng_logerror("packet_in - can not set state to enabled - arp");
				}

				ng_log("learn mac (arp) %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), inet_ntoa(*(struct in_addr *)src_addr));
				addmac_user_hash(u_data,source_mac_addr);
			}

			break;
		}
		break;

	case ETHERTYPE_IP:
		//we dont check what people recieved we only want to make sure nobody send bullshit
		if (*mode == TRAFFIC_INCOMING) return;
		
		source_mac_addr = &eth->ether_shost;
		dest_mac_addr = &eth->ether_dhost;
		src_addr = &ip->saddr;
		dst_addr = &ip->daddr;
		switch (*mode)
		{
		case TRAFFIC_OUTGOING:
			//add the user to the mac lookup table if not already present
			if (!get_user(source_mac_addr,vlanid)) 
				addmac_user_hash(u_data,source_mac_addr);

			security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
			if ( security_data == NULL ) {
				user_init(u_data);
				security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
				if ( security_data == NULL )
				{
					ng_logerror("we got a NULL data after init");
					return; //special case if still loading data
				}
			};

			user_state = NetGuard_State_Handler::user_state(u_data);
			if (!user_state) {
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_logerror("TRAFFIC_OUTGOING (ip) we got a NULL user_state !? package: %s",tmpstr);
				free(tmpstr);
				return; 
			}
			
			if ((*user_state) == mode_enabled) {
				//source mac ok ?
				if (!compare_mac(source_mac_addr,&security_data->hw_addr))
				{
					if (Mac_IgnoreSpoof->match(source_mac_addr,vlanid)) return;
					//report the missmatch to the control structure
					ng_log_buff(1,"mac missmatch %02x:%02x:%02x:%02x:%02x:%02x <> %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), printf_mac_params(security_data->hw_addr), inet_ntoa(*(struct in_addr *)src_addr));
					char *tmpstr = (char*)malloc(5000);
					sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
					ng_log_buff(0,"%s",tmpstr);
					free(tmpstr);
				}
			} else if ((*user_state) == mode_learn) {
				//we learn a new mac
				//delmac_user_hash(u_data,&security_data->hw_addr,vlanid,src_addr); why delete this way we still know who had the mac
				memcpy(&security_data->hw_addr,source_mac_addr,sizeof(security_data->hw_addr));
				user_state->params()->SetMac("mac",(*source_mac_addr)); //copy mac to state

				//set mode_enabled
				if (!(user_state->set(mode_enabled,"learned (ip) %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), inet_ntoa(*(struct in_addr *)src_addr))))
				{
					ng_logerror("packet_in - can not set state to enabled - ip");
				}
				ng_log("learn mac %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)), inet_ntoa(*(struct in_addr *)src_addr));
				addmac_user_hash(u_data,source_mac_addr);
			};
			
			break;
			
		case TRAFFIC_NOSOURCE:
		case TRAFFIC_UNKOWN:
			//why the user wo send the package is not in our db?

			/*if (*mode == TRAFFIC_NOSOURCE)
			{
				//the gw can send packages with spoofed packages that are TRAFFIC_NOSOURCE
				if (Mac_IgnoreSpoof->match(source_mac_addr,vlanid)) return;
			}*/
			//no matter if we know a source or not we allow spoofing from that source mac (like gw or a machine with same mac and multiple ips like subnets etc)

			if (zero_ip == (*src_addr))
			{
				if ((eth->ether_type == htons_ETHERTYPE_IP) && (ip->protocol==IPPROTO_UDP) && (ntohs(tcp->dest) == 67)) {
					//lets ignore udp from source 0.0.0.0 with dst port 67 -> dhcp
					ng_logdebug_spam("got dhcp query port dest ip 0.0.0.0 - package - ignoring");
					char *tmpstr = (char*)malloc(5000);
					sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
					ng_logdebug_spam("%s",tmpstr);
					free(tmpstr);
					break;
				}
			}

			if (Mac_IgnoreSpoof->match(source_mac_addr,vlanid)) return;

			struct user_data *found_data = get_user(source_mac_addr,vlanid);
			if (found_data)
			{
				//we have a matching mac for the sender but he wasnt found by his ip (as its in this modes)-> spoofing
				ng_log_buff(2,"ip spoofed for %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params((*source_mac_addr)),inet_ntoa(*(struct in_addr *)&found_data->saddr));
				ng_log_buff(0,"spoofed: %s",inet_ntoa(*(struct in_addr *)src_addr));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			} else {
				//we dont know who send the package thats a little strange
				//maybe we dont have all local users in the db
				ng_log_buff(1,"mac totaly unkown %02x:%02x:%02x:%02x:%02x:%02x - why we dont account/secure this mac ?", printf_mac_params((*source_mac_addr)));
				char *tmpstr = (char*)malloc(5000);
				sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
				ng_log_buff(0,"%s",tmpstr);
				free(tmpstr);
			}
			break;
		}
		
		break;
	
	}

}

void NetGuard_Security::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "help")
	{
		ng_logout("learn <ip address> <vlan> [hw_addr] - learn new mac for a user");
		ng_logout("show - display ignore lists");
		ng_logout("security_add_ignorespoof <mac> <vlan> [comment] - add mac to ignore list");
		ng_logout("security_del_ignorespoof <mac> <vlan> - del mac from ignore list");
		ng_logout("security_add_ignoreprotocols <mac> <vlan> [comment] - add mac to ignore list");
		ng_logout("security_del_ignoreprotocols <mac> <vlan> - del mac from ignore list");
		ng_logout("security_add_ignorearpb <mac> <vlan> [comment] - add mac to arpb dst ignore list");
		ng_logout("security_del_ignorearpb <mac> <vlan> - del mac from arpb dst ignore list");
		ng_logout("security_add_ignorearpbsrc <mac> <vlan> [comment] - add mac to arpb src ignore list");
		ng_logout("security_del_ignorearpbsrc <mac> <vlan> - del mac from arpb src ignore list");
		ng_logout("findip <mac> <vlan> - show an ip for a mac addr");
		ng_logout("dumpip <ip> <vlan> - show details for an ip");
		ng_logout("reload - reload ignore lists from file");		
	}

	if (params[0] == "learn")
	{
		if (params.size() < 3 || params.size() > 4 )
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: learn <ip address> <vlan> [hw_addr]");
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: learn <ip address> <vlan> [hw_addr]");
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: learn <ip address> <vlan> [hw_addr]");
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("not found user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}
		if (u_data->saddr != m_ip.s_addr)
		{
			ng_logerror("found user - but ip differ maybe you have an index problem !! Found user with ip %s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
			return;
		}
		struct user_security_data *security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
		if (!security_data)
		{
			ng_logout_not_found("no security data for user: %s",inet_ntoa(*(struct in_addr *)&m_ip.s_addr));
			return;
		}

		NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(u_data);
		if (!user_state) {
			ng_logerror("we got a NULL user_state !?");
			return; 
		}

		if (!((*user_state) == mode_enabled))
		{
			ng_logerror("not enable learn for  %s - port is not in enabled mode",inet_ntoa(*(struct in_addr *)&m_ip.s_addr));
			return;
		}
		if (params.size() == 3) {
			//set learn
			if (!((*user_state) < mode_learn))
			{
				ng_logerror("can not set state to learn");
				return;
			}
			ng_logout_ok("enabled learning for user %s - old mac %02x:%02x:%02x:%02x:%02x:%02x",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),printf_mac_params(security_data->hw_addr));
		} else {
			mac_addr mac;
			if (!getmacfromchar(params[3].c_str(), &mac))
			{
				ng_logout_ret(RET_WRONG_SYNTAX,"usage: learn <ip address> [hw_addr]");
				return;
			}
			memcpy(&security_data->hw_addr,&mac,sizeof(security_data->hw_addr));
			user_state->params()->SetMac("mac",mac);
			//TODO remove from hash and add different u_user if present for this mac 
			//if it dont get deleted its maybe even best but then we need a restart thing ... and load should do
			ng_logout_ok("learn manually mac %02x:%02x:%02x:%02x:%02x:%02x src_ip: %s", printf_mac_params(security_data->hw_addr), inet_ntoa(*(struct in_addr *)&u_data->saddr));
		}
		return;
	}

	if (params[0] == "findip")
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: findip <mac> <vlan>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: findip <mac> <vlan>");
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: findip <mac> <vlan>");
			return;
		}

		unsigned int data = intparams[2];
		struct user_data *u_data = get_user(&mac,&data);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with this mac");
			return;
		}

		ng_logout_ok("found ip %s for mac %02x:%02x:%02x:%02x:%02x:%02x in vlan %d", inet_ntoa(*(struct in_addr *)&u_data->saddr),printf_mac_params(mac),intparams[2]);
	}

	if (params[0] == "dumpip")
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: dumpip <ip> <vlan>");
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: dumpip <ip> <vlan>");
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: dumpip <ip> <vlan>");
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}

		struct user_security_data *security_data = (struct user_security_data *)u_data->module_data[user_security_module_number];
		if (!security_data)
		{
			ng_logout_not_found("no security data for user: %s vlan %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		} else ng_logout_ok("security data for user: %s vlan %d present",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
	}

	if (params[0] == "security_add_ignorespoof")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorespoof <mac> <vlan> [comment]");
			return;
		}
		char comment[255];
		memset(comment,0,255);
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorespoof <mac> <vlan> [comment]");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorespoof <mac> <vlan> [comment]");
			return;
		}

		std::string my_tmp = GetParamComment(params,3);
		if (my_tmp.size() <= 255)
		{
			memcpy(&comment,my_tmp.c_str(),my_tmp.size());
		} else {
			memcpy(&comment,my_tmp.c_str(),255);
		}
		
		ng_logout_ok("security_add_ignorespoof add mac %s vlan %u comment %s",params[1].c_str(),intparams[2],comment);
		unsigned int tmpint = (unsigned int)intparams[2];
		Mac_IgnoreSpoof->add(&mac,&tmpint,comment);
	}
	if (params[0] == "security_del_ignorespoof")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorespoof <mac> <vlan>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorespoof <mac> <vlan>");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorespoof <mac> <vlan> [comment]");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_del_ignorespoof del mac %s vlan %u",params[1].c_str(),tmpint);
		Mac_IgnoreSpoof->del(&mac,&tmpint);
	}

	if (params[0] == "security_add_ignoreprotocols")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignoreprotocols <mac> <vlan> [comment]");
			return;
		}
		char comment[255];
		memset(comment,0,255);
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignoreprotocols <mac> <vlan> [comment]");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignoreprotocols <mac> <vlan> [comment]");
			return;
		}

		std::string my_tmp = GetParamComment(params,3);
		if (my_tmp.size() <= 255)
		{
			memcpy(&comment,my_tmp.c_str(),my_tmp.size());
		} else {
			memcpy(&comment,my_tmp.c_str(),255);
		}

		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_add_ignoreprotocols add mac %s vlan %u comment %s",params[1].c_str(),tmpint,comment);
		Mac_IgnoreProtocols->add(&mac,&tmpint,comment);
	}

	if (params[0] == "security_del_ignoreprotocols")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignoreprotocols <mac> <vlanid>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignoreprotocols <mac>");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignoreprotocols <mac> <vlan>");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_del_ignoreprotocols del mac %s vlan %u",params[1].c_str(),tmpint);
		Mac_IgnoreProtocols->del(&mac,&tmpint);
	}


	if (params[0] == "security_add_ignorearpb")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpb <mac> <vlan> [comment]");
			return;
		}
		char comment[255];
		memset(comment,0,255);
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpb <mac> <vlan> [comment]");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpb <mac> <vlan> [comment]");
			return;
		}
		
		std::string my_tmp = GetParamComment(params,3);
		if (my_tmp.size() <= 255)
		{
			memcpy(&comment,my_tmp.c_str(),my_tmp.size());
		} else {
			memcpy(&comment,my_tmp.c_str(),255);
		}

		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_add_ignorearpb add mac %s vlan %u comment %s",params[1].c_str(),tmpint,comment);
		Mac_IgnoreArpRequestDest->add(&mac,&tmpint,comment);
	}

	if (params[0] == "security_del_ignorearpb")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpb <mac> <vlanid>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpb <mac>");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpb <mac> <vlan>");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_del_ignorearpb del mac %s vlan %u",params[1].c_str(),tmpint);
		Mac_IgnoreArpRequestDest->del(&mac,&tmpint);
	}

	if (params[0] == "security_add_ignorearpbsrc")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpbsrc <mac> <vlan> [comment]");
			return;
		}
		char comment[255];
		memset(comment,0,255);
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpbsrc <mac> <vlan> [comment]");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_add_ignorearpbsrc <mac> <vlan> [comment]");
			return;
		}
		
		std::string my_tmp = GetParamComment(params,3);
		if (my_tmp.size() <= 255)
		{
			memcpy(&comment,my_tmp.c_str(),my_tmp.size());
		} else {
			memcpy(&comment,my_tmp.c_str(),255);
		}

		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_add_ignorearpbsrc add mac %s vlan %u comment %s",params[1].c_str(),tmpint,comment);
		Mac_IgnoreArpRequestSrc->add(&mac,&tmpint,comment);
	}

	if (params[0] == "security_del_ignorearpbsrc")
	{
		if (params.size() < 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpbsrc <mac> <vlanid>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpbsrc <mac>");
			return;
		}
		if (intparams[2] == MININT)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: security_del_ignorearpbsrc <mac> <vlan>");
			return;
		}
		unsigned int tmpint = (unsigned int)intparams[2];
		ng_logout_ok("security_del_ignorearpbsrc del mac %s vlan %u",params[1].c_str(),tmpint);
		Mac_IgnoreArpRequestSrc->del(&mac,&tmpint);
	}

	if (params[0] == "show")
	{
		if (params.size() == 1) {
			ng_logout("NetGuard_Security IgnoreProtocols:");
			Mac_IgnoreProtocols->print();
			ng_logout("NetGuard_Security IgnoreSpoof:");
			Mac_IgnoreSpoof->print();
			ng_logout("NetGuard_Security Ignore Arp Broadcast Dest:");
			Mac_IgnoreArpRequestDest->print();
			ng_logout("NetGuard_Security Ignore Arp Broadcast Src:");
			Mac_IgnoreArpRequestSrc->print();
		}
	}


	if (params[0] == "reload")
	{
		Mac_IgnoreSpoof->loadfile("Security.IgnoreSpoof");
		Mac_IgnoreProtocols->loadfile("Security.IgnoreProtocols");
		Mac_IgnoreArpRequestDest->loadfile("Security.IgnoreArpRequestBDest");
	}
}
