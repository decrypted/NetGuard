	/***************************************************************************
 *   NetGuard Group Accounting Module                                      *
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

#include "group_accounting.hpp"

#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/state/state_handling.hpp"

#include <sys/stat.h>


bool NetGuard_User_SCE_Groups::set_failure_state(NetGuard_User_State *user, std::string error) 
{
	NetGuard_State *my_state_f = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("group.failure_state","failure"));
	if (!my_state_f) {
		ng_slogerror(Get_Name().c_str(),"%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("group.failure_state","failure").c_str());
		return false;
	}
	return user->set(my_state_f,error);
}

bool NetGuard_User_SCE_Groups::exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason)
{
	if (user->Getuser().vlan_id != 999999) //if its not the magic group vlan we ignore it and pass it to the default handler
		return false;
	
	Group_Data *mygroup = my_instance->glist->get_group(&user->Getuser().saddr,&user->Getuser().vlan_id);
	if (!mygroup)
	{
		ng_slogerror("NetGuard_User_SCE_Groups","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason %s - for non existing group",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
		return false;
	}

	//this handler make sure we do the actions we want on enable and disable
	//it always have to return true on the -> enabled or ->disabled state as we handle them - no matter if the transition itself failed or not!
	ng_slogdebug_spam("NetGuard_User_SCE_Groups","enter exec state change from <%s> to <%s> (group %s) - reason %s",(*from)->GetName().c_str(),to->GetName().c_str(),mygroup->name.c_str(),reason.c_str());

	if ((*to) == GlobalCFG::GetStr("state.disabled","disabled"))
	{
		ng_slogdebug("NetGuard_User_SCE_Groups","exec state change from <%s> to <%s> (group: %s) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),mygroup->name.c_str(),reason.c_str());

		//do the state change!
		(*from) = to;

		//the group gets disabled - lets disable the members
		guser_data_list_idx *members = mygroup->get_members();
		guser_data_list_idx::iterator git;
		for (git=members->begin(); git != members->end(); git++) {
			struct guser_data_idx gdata = (*git);
			NetGuard_User_State* user_state = NetGuard_State_Handler::user_state(&gdata.saddr,&gdata.vlan_id);
			if (user_state)
			{
				if (!(*user_state == my_instance->my_dis_state)) { //todo what about faliure state
					if (!user_state->set(my_instance->my_dis_state,GlobalCFG::GetStr("group_limit.disabled_group","disabled user because group got disabled"))) {
						ng_slogerror("NetGuard_User_SCE_Groups","could not do the state transition from <%s> to <%s> (user: %s vlan: %d)",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id);
					}
				}
			}
		}
		return true;
	} else if ((*to) == GlobalCFG::GetStr("state.enabled","enabled")) {
		//if ((**from) == GlobalCFG::GetStr("state.learn","learn")) 
		//	return false;

		ng_slogdebug("NetGuard_User_SCE_Groups","exec state change from <%s> to <%s> (group: %s) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),mygroup->name.c_str(),reason.c_str());

		//do the state change!
		(*from) = to;

		//the group gets disabled - lets disable the members
		guser_data_list_idx *members = mygroup->get_members();
		guser_data_list_idx::iterator git;
		for (git=members->begin(); git != members->end(); git++) {
			struct guser_data_idx gdata = (*git);
			NetGuard_User_State* user_state = NetGuard_State_Handler::user_state(&gdata.saddr,&gdata.vlan_id);
			if (user_state)
			{
				if (!(*user_state == my_instance->my_dis_state)) { //todo what about faliure state
					if (!user_state->set(my_instance->my_dis_state,GlobalCFG::GetStr("group_limit.disabled_group","disabled user because group got disabled"))) {
						ng_slogerror("NetGuard_User_SCE_Groups","could not do the state transition to from <%s> to <%s> (user: %s vlan: %d)",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id);
					}
				}
			}
		}
		return true;
	}
	return false;
}


NetGuard_GAccounting::NetGuard_GAccounting()
{
	ng_logdebug_spam("constructor");	
	glist = new GUser_Data_Tools();
	glist->log_str = "Group_Data_Tools";
 	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
 	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);

	general_acccounting = NULL;
	user_limit = NULL;
	my_dis_state = NULL;
	my_enabled_state = NULL;
	required_modules.push_back("general_accounting");
	required_modules.push_back("user_limit");
}
  
NetGuard_GAccounting::~NetGuard_GAccounting()
{
	ng_logdebug_spam("destructor");	
	delete glist;
}
		
void NetGuard_GAccounting::loaddata()
{
	glist->loaddata(db_filename,0);
}

void NetGuard_GAccounting::savedata()
{
	glist->savedata(db_filename,false);
}

int NetGuard_GAccounting::init(NetGuard_Config *data)
{
	general_acccounting = NULL;
	user_limit = NULL;
	ng_logdebug("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetModule("module_general_accounting") == NULL) {
		ng_logerror("need general_accounting module needs to be loaded");
		return -2;
	}
	general_acccounting = (NetGuard_General_Module_ACC*)data_->GetModule("module_general_accounting");

	if (data_->GetStr("gaccounting_filename") == "")
	{
		ng_logerror("need an gaccounting_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("gaccounting_filename");


	if (data_->GetModule("module_user_limit") == NULL) {
		ng_logerror("need user_limit module needs to be loaded");
		return -2;
	}
	user_limit = (NetGuard_Limit*)data_->GetModule("module_user_limit");
	

	loaddata();

	NetGuard_State_Handler::GetPointer()->register_exec(new NetGuard_User_SCE_Groups(this));

	my_dis_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("group_limit.disable_state","disabled"));
	if (!my_dis_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("group_limit.disable_state","disabled").c_str());
		return -2;
	}
	my_enabled_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("group_limit.enable_state","enabled"));
	if (!my_enabled_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("group_limit.enable_state","enabled").c_str());
		return -2;
	}	

	return 0;
}

void NetGuard_GAccounting::shutdown()
{
	ng_logdebug_spam("shutdown");
	glist->savedata(db_filename,true);
	glist->clear();
	NetGuard_State_Handler::GetPointer()->do_clear_registered_exec("group_accounting");
	general_acccounting = NULL;
	user_limit = NULL;
}

void NetGuard_GAccounting::packet_in(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	struct user_data * u_data;
	in_addr_t index_addr;
	in_addr_t index_addr2;
	index_addr = 0;
	index_addr2 = 0;
	int mode;

	if (eth->ether_type == htons_ETHERTYPE_IP) {
		index_addr = ip->saddr;
		index_addr2 = ip->daddr;
	} else if (eth->ether_type == htons_ETHERTYPE_ARP) {
		struct ether_arp * arph;
		arph = (struct ether_arp *)ip;
		index_addr = *(uint32_t *)&arph->arp_spa;
		index_addr2 = *(uint32_t *)&arph->arp_tpa;
	}
	
	//account it for all groups who have a member with that SOURCE ip
	guser_data_list_vector *mylist = glist->get_groups(&index_addr,vlanid);
	guser_data_list_vector::const_iterator it;
	if (mylist) {
		mode = TRAFFIC_OUTGOING;
		for (it=(*mylist).begin(); it != (*mylist).end(); it++) 
		{
			u_data = (*it)->GetData();
			general_acccounting->account_package(u_data,&mode,vlanid,h,eth,ip,tcp,data);
			u_data->last_activity = NetGuard_ModuleLoader_Base::GetNow();
			user_limit->checkmax((*it)->GetLimits(),u_data); //check limits
		}
	}

	//account it for all groups who have a member with that DEST ip
    mylist = glist->get_groups(&index_addr2,vlanid);
	if (mylist) {
		mode = TRAFFIC_INCOMING;
		for (it=(*mylist).begin(); it != (*mylist).end(); it++) 
		{
			u_data = (*it)->GetData();
			general_acccounting->account_package(u_data,&mode,vlanid,h,eth,ip,tcp,data);
			u_data->last_activity = NetGuard_ModuleLoader_Base::GetNow();
			//user_limit->checkmax((*it)->GetLimits(),u_data);  //check limits
		}
	}
}

void NetGuard_GAccounting::user_data_forgetday(int day){
	struct	user_data * u_data;

	if (!general_acccounting)
	{
		ng_logerror("cant do user_data_forgetday - general_acccounting not avaiable");
		return;
	}
	if (day < 0 || day > 6)  {
		ng_logerror("list: forget day <0 or >6 (%d) - ignoring",day);
		return;
	}
	ng_logdebug_spam("list: forget day %d",day);

	guser_data_list_vector mylist = glist->get_vector_list();
	guser_data_list_vector::iterator it;
	for (it=mylist.begin(); it != mylist.end(); it++) {
		u_data =  (*it)->GetData();
		//forget this day for external traffic
		general_acccounting->do_user_data_forgetday(day,&u_data->external);

		//forget this day for internal traffic
		general_acccounting->do_user_data_forgetday(day,&u_data->internal);
	}
}

void NetGuard_GAccounting::timer_tick()
{
}

void *NetGuard_GAccounting::get_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) 
{
	if (command=="user_data_forgetday") {
		ng_logdebug("got user_data_forgetday command for %d",(int)data);
		user_data_forgetday((int)data);
	}
	return NULL;
}

void NetGuard_GAccounting::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("save - save groupdata");
		ng_logout("group_list - list all groups");
		ng_logout("group_list_all - list all groups with members");
		ng_logout("group_create <name> - create a new group with a *unique* name");
		ng_logout("group_del <name> - delete a group with a *unique* name");
		ng_logout("group_show <name> - show group details");
		ng_logout("group_member_add <name> <ip> <vlan> - add a member to a group");
		ng_logout("group_member_del <name> <ip> <vlan> - remove a member from a group");
		ng_logout("group_search <ip> <vlan> - list all groups with that member");
		ng_logout("group_dump <name> - dump group traffic details");
		ng_logout("group_dumpall <name> - dump *full* group traffic details");
		ng_logout("group_set_limit_day <name> <external MB> <internal MB> - set day limits for an group - 0 = no limit");
		ng_logout("group_set_limit_week <name> <external MB> <internal MB> - set weekly limits for an group - 0 = no limit");
		ng_logout("group_set_limit_all <name> <external MB> <internal MB> - set overall limits for an group - 0 = no limit");
	}

	if (params[0] == "save")
	{
		glist->savedata(db_filename,true);
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if ((params[0] == "group_list") || (params[0] == "group_list_all"))
	{
		guser_data_list_vector mylist = glist->get_vector_list();
		
		guser_data_list_vector::iterator it;
		for (it=mylist.begin(); it != mylist.end(); it++) {
			Group_Data *group = (*it);
			ng_logout("group: %s",group->name.c_str());

			if ((params[0] == "group_list_all") && (group)) {
				guser_data_list_idx *members = group->get_members();
				guser_data_list_idx::iterator git;
				for (git=members->begin(); git != members->end(); git++) {
					struct guser_data_idx data = (*git);
					ng_logout("member ip:%s vlan %d",inet_ntoa(*(struct in_addr *)&data.saddr),data.vlan_id);
				}

				struct user_data *u_data = group->GetData();
				NetGuard_User_State* group_state = NetGuard_State_Handler::get_add_user_state(&u_data->saddr,&u_data->vlan_id);
				if (group_state)
				{
					ng_logout("state report [%s] state: %s",group->name.c_str(),group_state->state()->GetName().c_str());
					ng_logout("state report [%s] params: %s",group->name.c_str(),group_state->params()->get_string().c_str());

					std::vector<NetGuard_Config*> hist = group_state->GetHistory();
					std::vector<NetGuard_Config*>::iterator it_h;
					for (it_h=hist.begin(); it_h != hist.end(); it_h++) {
						ng_logout("state report [%s] history: %s",group->name.c_str(),(*it_h)->get_string().c_str());
					}
				}
				ng_logout("");
			}
		}
	}

	if (params[0] == "group_create")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: group_create <name> - create a new group with a *unique* name");
			return;
		}

		Group_Data *group = glist->create_group(params[1]);
		if (group) {
			ng_logout_ok("created group with name %s",params[1].c_str());
		} else {
			ng_logerror("can not create group with name %s - make sure name is unique",params[1].c_str());
		}
	}

	if (params[0] == "group_del")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: group_del <name> - create a new group with a *unique* name");
			return;
		}

		Group_Data *group = glist->get_group(params[1]);
		if (group) {
			NetGuard_State_Handler::GetPointer()->delete_user_state(group->GetData()); //todo: this can be raced from packages i guess? but we are locking everything normaly
		}
		if (glist->del_group(params[1])) {
			ng_logout("deleted group with name %s",params[1].c_str());
		} else {
			ng_logout_not_found("can not delete group with name %s - not found",params[1].c_str());
		}
	}

	if (params[0] == "group_member_add")
	{
		if (params.size() != 4)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <ip> <vlan> - add a member to a group",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[2].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <ip> <vlan> - add a member to a group",params[0].c_str());
			return;
		}
		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <ip> <vlan> - add a member to a group",params[0].c_str());
			return;
		}


		Group_Data *group = glist->get_group(params[1]);
		if (group) {
			group->add_member(m_ip.s_addr,intparams[3]);
			ng_logout_ok("added member with ip:%s vlan:%d to group with name %s",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[3],params[1].c_str());
		} else {
			ng_logout_not_found("can not find group with name %s",params[1].c_str());
		}
	}


	if (params[0] == "group_search")
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> - list all groups with that member",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> - list all groups with that member",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> - list all groups with that member",params[0].c_str());
			return;
		}

		ng_logout_ok("ip:%s vlan:%d is groupmember of:",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
		unsigned int myparm = intparams[2];
		guser_data_list_vector *mygroups = glist->get_groups(&m_ip.s_addr,&myparm);
		if (mygroups) {
			guser_data_list_vector::iterator it;
			for (it=(*mygroups).begin(); it != (*mygroups).end(); it++) {
				ng_logout("member in: %s",(*it)->name.c_str());
			}
		}
	}

	if (params[0] == "group_show")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: group_show <name> - show group details");
			return;
		}

		Group_Data *group = glist->get_group(params[1]);
		if (group) {
			ng_logout("group %s:",group->name.c_str());
			guser_data_list_idx *members = group->get_members();
			guser_data_list_idx::iterator it;
			for (it=members->begin(); it != members->end(); it++) {
				struct guser_data_idx data = (*it);
				ng_logout("member ip:%s vlan %d",inet_ntoa(*(struct in_addr *)&data.saddr),data.vlan_id);
			}

			struct user_data *u_data = group->GetData();
			NetGuard_User_State* group_state = NetGuard_State_Handler::get_add_user_state(&u_data->saddr,&u_data->vlan_id);
			if (group_state)
			{
				ng_logout("state report [%s] state: %s",params[1].c_str(),group_state->state()->GetName().c_str());
				ng_logout("state report [%s] params: %s",params[1].c_str(),group_state->params()->get_string().c_str());

				std::vector<NetGuard_Config*> hist = group_state->GetHistory();
				std::vector<NetGuard_Config*>::iterator it_h;
				for (it_h=hist.begin(); it_h != hist.end(); it_h++) {
					ng_logout("state report [%s] history: %s",params[1].c_str(),(*it_h)->get_string().c_str());
				}
			}

			ng_logout("group state at ip:%s vlan: %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),u_data->vlan_id);


		} else {
			ng_logout_not_found("can not find group with name %s",params[1].c_str());
		}
	}


	if ((params[0] == "group_dump") ||  (params[0] == "group_dumpall"))
	{
		if (params.size() != 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name>",params[0].c_str());
			return;
		}

		Group_Data *group = glist->get_group(params[1]);
		if (!group) {
			ng_logout_not_found("can not find group with name %s",params[1].c_str());
			return;
		}

		struct user_data *u_data = group->GetData();

		#define EINHEIT 1024/1024
		ng_logout("dump group %s", params[1].c_str());
		char l_a_time[50];
		int day = 0;

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


		#define EINHEIT 1024/1024
		struct user_limit_data *limit_data = group->GetLimits();

		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->external.max_day_date));
		ng_logout("external day \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->external.limit_day/EINHEIT,limit_data->external.max_day/EINHEIT,l_a_time);
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->internal.max_day_date));
		ng_logout("internal day \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->internal.limit_day/EINHEIT,limit_data->internal.max_day/EINHEIT,l_a_time);

		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->external.max_week_date));
		ng_logout("external week \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->external.limit_week/EINHEIT,limit_data->external.max_week/EINHEIT,l_a_time);
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->internal.max_week_date));
		ng_logout("internal week \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->internal.limit_week/EINHEIT,limit_data->internal.max_week/EINHEIT,l_a_time);

		ng_logout("external all \t\t- limit: %llu MByte",limit_data->external.limit_overall/EINHEIT);
		ng_logout("internal all \t\t- limit: %llu MByte",limit_data->internal.limit_overall/EINHEIT);

		NetGuard_User_State* group_state = NetGuard_State_Handler::get_add_user_state(&u_data->saddr,&u_data->vlan_id);
		if (group_state)
		{
			ng_logout("state report [%s] state: %s",params[1].c_str(),group_state->state()->GetName().c_str());
			ng_logout("state report [%s] params: %s",params[1].c_str(),group_state->params()->get_string().c_str());

			std::vector<NetGuard_Config*> hist = group_state->GetHistory();
			std::vector<NetGuard_Config*>::iterator it_h;
			for (it_h=hist.begin(); it_h != hist.end(); it_h++) {
				ng_logout("state report [%s] history: %s",params[1].c_str(),(*it_h)->get_string().c_str());
			}
		}

		if (params[0] == "group_dumpall")
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
			ng_logout("internal all \t\t- send: %llu MByte resv: %llu MByte send: %llu pkts resv: %llu pkts",u_data->internal.over_all.send.ip_bytes/EINHEIT,u_data->internal.over_all.resv.ip_bytes/EINHEIT,u_data->internal.over_all.send.ip_pkts,u_data->internal.over_all.resv.ip_pkts);
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


	if ((params[0] == "group_set_limit_day") || (params[0] == "group_set_limit_week") || (params[0] == "group_set_limit_all"))
	{
		if (params.size() != 4)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <eMB> <iMB>",params[0].c_str());
			return;
		}

		Group_Data *group = glist->get_group(params[1]);
		if (!group) {
			ng_logout_not_found("can not find group with name %s",params[1].c_str());
			return;
		}

		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <eMB> <iMB>",params[0].c_str());
			return;
		}

		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <name> <eMB> <iMB>",params[0].c_str());
			return;
		}


		#define EINHEIT 1024/1024
		#define EINHEIT2 1024*1024
		struct user_limit_data *limit_data = group->GetLimits();

		unsigned long long int tmpval,tmpval2;
		tmpval = (unsigned long long int)intparams[2] * (unsigned long long int)EINHEIT2;
		tmpval2 = (unsigned long long int)intparams[3] * (unsigned long long int)EINHEIT2;

		ng_logout_ok("setting limits external: %llu Byte internal: %llu Byte", tmpval, tmpval2);
		if (params[0] == "group_set_limit_day")
		{
			ng_logout("setting day limit");
			limit_data->external.limit_day = tmpval;
			limit_data->internal.limit_day = tmpval2;
		}
		if (params[0] == "group_set_limit_week")
		{
			ng_logout("setting week limit");
			limit_data->external.limit_week = tmpval;
			limit_data->internal.limit_week = tmpval2;
		}
		if (params[0] == "group_set_limit_all")
		{
			ng_logout("setting overall limit");
			limit_data->external.limit_overall = tmpval;
			limit_data->internal.limit_overall = tmpval2;
		}

		char l_a_time[50];		
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->external.max_day_date));
		ng_logout("external day \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->external.limit_day/EINHEIT,limit_data->external.max_day/EINHEIT,l_a_time);
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->internal.max_day_date));
		ng_logout("internal day \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->internal.limit_day/EINHEIT,limit_data->internal.max_day/EINHEIT,l_a_time);

		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->external.max_week_date));
		ng_logout("external week \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->external.limit_week/EINHEIT,limit_data->external.max_week/EINHEIT,l_a_time);
		strftime(l_a_time, 80,"%a %d.%m.%Y %X",localtime(&limit_data->internal.max_week_date));
		ng_logout("internal week \t\t- limit: %llu MByte max: %llu MByte date: %s",limit_data->internal.limit_week/EINHEIT,limit_data->internal.max_week/EINHEIT,l_a_time);

		ng_logout("external all \t\t- limit: %llu MByte",limit_data->external.limit_overall/EINHEIT);
		ng_logout("internal all \t\t- limit: %llu MByte",limit_data->internal.limit_overall/EINHEIT);

	}

}

void *NetGuard_GAccounting::get_data(void *data) {
	return glist;
}

