/***************************************************************************
 *   NetGuard Limit Module                                                 *
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
#include "user_limit.hpp"
#include "../../includes/logging.h"
#include "../../includes/state/state_handling.hpp"

static const char *ACC_LIMIT_VERSION_MAGIC = "netguard_limit_db_v0.3";

NetGuard_Limit::NetGuard_Limit()
{
	ng_logdebug_spam("constructor");
	general_acccounting = NULL;
	muser_data = NULL;
	my_dis_state = NULL;
	my_fail_state = NULL;

	default_external_limit_week = 5; //5GB
	default_external_limit_week = default_external_limit_week * 1024 * 1024 * 1024;
	default_internal_limit_week = 0; 
	default_external_limit_day  = 0;
	default_internal_limit_day  = 0;
	default_external_limit_overall = 0;
	default_internal_limit_overall = 0;

	required_modules.push_back("general_accounting");
}
  
NetGuard_Limit::~NetGuard_Limit()
{
	ng_logdebug_spam("destructor");
}

void NetGuard_Limit::loaddata()
{
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
		struct user_special_accounting_data *accouning_data = (struct user_special_accounting_data *)u_data->module_data[user_limit_module_number];
		if (accouning_data) {
			user_shutdown(u_data);
		}
		user_init(u_data);
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
}

void NetGuard_Limit::savedata()
{
	struct	user_data * u_data;

	FILE *myfile;

	ng_logdebug_spam("saving users to %s",db_filename.c_str());

	myfile = fopen(db_filename.c_str(), "w+");
	if (!myfile) return;

	fwrite(ACC_LIMIT_VERSION_MAGIC,strlen(ACC_LIMIT_VERSION_MAGIC),1,myfile);

	struct user_limit_data * limit_data;

	int counter = 0;
	#ifdef userlist_use_simple
	struct	user_list * m_users = muser_data->get_list();
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;
	for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
		u_data =  (*it).second;
	#endif
		limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
		if	(limit_data) {
			counter++;
		}
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
		limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
		if	(limit_data) {
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
		limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
		if	(limit_data) {
			fwrite(limit_data,sizeof(struct user_limit_data),1, myfile);
			ng_logdebug_spam("save user %-15s max %lld",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->external.max_week);
			ng_logdebug_spam("save user %-15s int max %lld",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->internal.max_week);
		}
		#ifdef userlist_use_simple
		m_users = m_users->next;
		#endif
	}
	ng_logdebug_spam("saved %d users",counter);

	fwrite(ACC_LIMIT_VERSION_MAGIC,strlen(ACC_LIMIT_VERSION_MAGIC),1,myfile);
	fclose(myfile);
}

struct user_limit_data * NetGuard_Limit::load_limit_data(struct user_data *u_data, char *filename, int rename_onfail){
	FILE *myfile;
	struct stat fileinfo;
	char *tmpdata;
	struct user_limit_data * limit_data = NULL;
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
	tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(ACC_LIMIT_VERSION_MAGIC)+1));
	tmpdata[strlen(ACC_LIMIT_VERSION_MAGIC)] = 0;
	int count = fread(&tmpdata[0],strlen(ACC_LIMIT_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_LIMIT_VERSION_MAGIC) ) {
		ng_logerror("limit: cant read traffic data from %s - illegal format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_LIMIT_VERSION_MAGIC);

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
	fseek(myfile,fileinfo.st_size-strlen(ACC_LIMIT_VERSION_MAGIC),SEEK_SET);
	count = fread(&tmpdata[0],strlen(ACC_LIMIT_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_LIMIT_VERSION_MAGIC) ) {
		ng_logerror("cant read traffic data from %s - illegal (end) format (%s <> %s)",db_filename.c_str(),(char *)tmpdata,ACC_LIMIT_VERSION_MAGIC);

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
	//set to old position again
	fseek(myfile,f_pos,SEEK_SET);

	ng_logdebug_spam("loading %lu bytes data",fileinfo.st_size);

	int counter = 0;
	count = fread(&counter,sizeof(counter),1, myfile);
	if (count  != 1 ) return NULL;
	ng_logdebug_spam("found %d users in file",counter);

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
			ng_logdebug_spam("found user %-15s on pos %d",inet_ntoa(*(struct in_addr *)&u_data->saddr),seek_pos);
		}
	}

	if (!found) return NULL;
	seek_pos = (seek_pos-1) * sizeof(struct user_limit_data) + ftell(myfile);
	fseek(myfile,seek_pos,SEEK_SET);


	limit_data = (struct user_limit_data *)malloc(sizeof(struct user_limit_data));
	count = fread(limit_data,sizeof(struct user_limit_data),1, myfile);
	if (count  != 1 ) {
		delete limit_data;
		return NULL;
	}
	ng_logdebug_spam("loaded user data for %-15s (max: %lld) ",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->external.max_week);
	ng_logdebug_spam("loaded user data for %-15s (int max: %lld) ",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->internal.max_week);

	fclose(myfile);
	free(tmpdata);

	return limit_data;
}

int NetGuard_Limit::init(NetGuard_Config *data)
{
	general_acccounting = NULL;
	muser_data = NULL;

	ng_logdebug_spam("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	if (data_->GetStr("user_limit_filename") == "")
	{
		ng_logerror("need a user_limit_filename in config data");
		return -2;
	}
	db_filename=data_->GetStr("user_limit_filename");

	if (data_->GetModule("module_general_accounting") == NULL) {
		ng_logerror("need general_accounting module needs to be loaded");
		return -2;
	}

	if (data_->GetInt("default_external_limit_week") != MININT)
	{
		default_external_limit_week = data_->GetInt("default_external_limit_week");
		default_external_limit_week = default_external_limit_week*1024*1024;
		ng_logdebug("set default_external_limit_week to %llu",default_external_limit_week);
	}

	if (data_->GetInt("default_internal_limit_week") != MININT)
	{
		default_internal_limit_week = data_->GetInt("default_internal_limit_week");
		default_internal_limit_week = default_internal_limit_week*1024*1024;
		ng_logdebug("set default_internal_limit_week to %llu",default_internal_limit_week);
	}

	if (data_->GetInt("default_external_limit_day") != MININT)
	{
		default_external_limit_day = data_->GetInt("default_external_limit_day");
		default_external_limit_day = default_external_limit_day*1024*1024;
		ng_logdebug("set default_external_limit_day to %llu",default_external_limit_day);
	}

	if (data_->GetInt("default_internal_limit_day") != MININT)
	{
		default_internal_limit_day = data_->GetInt("default_internal_limit_day");
		default_internal_limit_day = default_internal_limit_day*1024*1024;
		ng_logdebug("set default_internal_limit_day to %llu",default_internal_limit_day);
	}

	if (data_->GetInt("default_external_limit_overall") != MININT)
	{
		default_external_limit_overall = data_->GetInt("default_external_limit_overall");
		default_external_limit_overall = default_external_limit_overall*1024*1024;
		ng_logdebug("set default_external_limit_overall to %llu",default_external_limit_overall);
	}

	if (data_->GetInt("default_internal_limit_overall") != MININT)
	{
		default_external_limit_overall = data_->GetInt("default_internal_limit_overall");
		default_internal_limit_overall = default_internal_limit_overall*1024*1024;
		ng_logdebug("set default_internal_limit_overall to %llu",default_internal_limit_overall);
	}

	general_acccounting = (NetGuard_General_Module*)data_->GetModule("module_general_accounting");
	muser_data = (User_Data_Tools*)general_acccounting->get_data(NULL);

	my_dis_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("user_limit.disable_state","disabled"));
	if (!my_dis_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("user_limit.disable_state","disabled").c_str());
		return -2;
	}

	my_fail_state = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("user_limit.failure_state","failure"));
	if (!my_fail_state) {
		ng_logerror("%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("user_limit.failure_state","failure").c_str());
		return -2;
	}



	loaddata();

	return 0;
}

void NetGuard_Limit::shutdown()
{
	ng_logdebug_spam("shutdown");
	if (muser_data)
	{
		struct	user_data *u_data;
		#ifdef userlist_use_simple
		struct	user_list *m_users = muser_data->get_list();
		while (m_users != NULL) {
			u_data = m_users->data;
		#else
		ip_storage_hash::iterator it;
		for (it=muser_data->get_list()->begin(); it != muser_data->get_list()->end(); it++) {
			u_data =  (*it).second;
		#endif
			user_shutdown(u_data);
			#ifdef userlist_use_simple
			m_users = m_users->next;
			#endif
		}
	}

	general_acccounting = NULL;
	muser_data = NULL;
}

struct user_limit_data *NetGuard_Limit::my_user_init(struct user_data *u_data, bool doload)
{
	struct user_limit_data * limit_data = NULL;
	
	//try to load it from file
	if (doload)
		limit_data = load_limit_data(u_data,NULL,1);

	if (limit_data == NULL)
	{
		ng_logdebug("setting new default limits for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		//we need to init a new user
		limit_data = (struct user_limit_data *)malloc(sizeof(struct user_limit_data));

		//set default values
		memset(limit_data,0,sizeof(struct user_limit_data));
		limit_data->external.limit_day = (unsigned long long int)default_external_limit_day;
		limit_data->internal.limit_day = (unsigned long long int)default_internal_limit_day;
		limit_data->external.limit_week = (unsigned long long int)default_external_limit_week;
		limit_data->internal.limit_week = (unsigned long long int)default_internal_limit_week;
		limit_data->external.limit_overall = (unsigned long long int)default_external_limit_overall;
		limit_data->internal.limit_overall = (unsigned long long int)default_internal_limit_overall;
	};

	u_data->module_data[user_limit_module_number] = limit_data;

	return limit_data;	
}

void NetGuard_Limit::user_init(struct user_data *u_data)
{
	if (!u_data) return;
	ng_logdebug_spam("user_init for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	my_user_init(u_data,true);
}

void NetGuard_Limit::user_shutdown(struct user_data *u_data)
{
	struct user_limit_data * limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
	if ( limit_data != NULL ) {		
		ng_logdebug_spam("free limits data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		delete limit_data;
	}
	u_data->module_data[user_limit_module_number] = NULL;
}

void NetGuard_Limit::user_data_forgetday(int day)
{
}

void NetGuard_Limit::checkmax(struct user_limit_data * limit_data,struct user_data *u_data) {
	unsigned long long int counter = 0;

	counter = u_data->external.week.send.bytes + u_data->external.week.resv.bytes;
	if (counter > limit_data->external.max_week)
	{
		limit_data->external.max_week = counter;
		limit_data->external.max_week_date = NetGuard_ModuleLoader_Base::GetNow();
	}
	if (limit_data->external.limit_week)
	{
		if (counter > limit_data->external.limit_week)
		{
			//ng_logdebug("limit exeeded for %-15s - max: %lld used: %lld",inet_ntoa(*(struct in_addr *)&u_data->saddr),limit_data->external.limit_week,counter);
			//ng_logdebug("limit exeeded for %-15s - used: %lld",inet_ntoa(*(struct in_addr *)&u_data->saddr),counter);

			// we have somebody over the external week limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("external_week_exceeded",nu_state->params()->GetInt("external_week_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_ext_state_week_msg","over the external week limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

	counter = u_data->internal.week.send.bytes + u_data->internal.week.resv.bytes;
	if (counter > limit_data->internal.max_week)
	{
		limit_data->internal.max_week = counter;
		limit_data->internal.max_week_date = NetGuard_ModuleLoader_Base::GetNow();
	}
	if (limit_data->internal.limit_week)
	{
		if (counter > limit_data->internal.limit_week)
		{
			// we have somebody over the internal week limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("internal_week_exceeded",nu_state->params()->GetInt("internal_week_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_int_state_week_msg","over the internal week limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

	int c_day = NetGuard_ModuleLoader_Base::GetTime()->tm_wday;
	counter = u_data->external.days[c_day].send.bytes + u_data->external.days[c_day].resv.bytes;
	if (counter > limit_data->external.max_day)
	{
		limit_data->external.max_day = counter;
		limit_data->external.max_day_date = NetGuard_ModuleLoader_Base::GetNow();
	}
	if (limit_data->external.limit_day)
	{
		if (counter > limit_data->external.limit_day)
		{
			// we have somebody over the external day limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("external_day_exceeded",nu_state->params()->GetInt("external_day_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_ext_state_day_msg","over the external daily limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

	counter = u_data->internal.days[c_day].send.bytes + u_data->internal.days[c_day].resv.bytes;
	if (counter > limit_data->internal.max_day)
	{
		limit_data->internal.max_day = counter;
		limit_data->internal.max_day_date = NetGuard_ModuleLoader_Base::GetNow();
	}
	if (limit_data->internal.limit_day)
	{
		if (counter > limit_data->internal.limit_day)
		{
			// we have somebody over the internal day limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("internal_day_exceeded",nu_state->params()->GetInt("internal_day_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_int_state_day_msg","over the internal daily limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

	if (limit_data->external.limit_overall)
	{
		counter = u_data->external.over_all.send.bytes + u_data->external.over_all.resv.bytes;
		if (counter > limit_data->external.limit_overall)
		{
			// we have somebody over the external over all limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("external_overall_exceeded",nu_state->params()->GetInt("external_overall_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_ext_state_overall_msg","over the external overall limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

	if (limit_data->internal.limit_overall)
	{
		counter = u_data->internal.over_all.send.bytes + u_data->internal.over_all.resv.bytes;
		if (counter > limit_data->internal.limit_overall)
		{
			// we have somebody over the internal over all limit
			NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);

			//ignore if we are already in the same state
			if (*nu_state == my_dis_state) return;
			if (*nu_state == my_fail_state) return;

			nu_state->params()->SetInt("internal_overall_exceeded",nu_state->params()->GetInt("internal_overall_exceeded",0)+1);
			if (!nu_state->set(my_dis_state,GlobalCFG::GetStr("user_limit.disable_int_state_overall_msg","over the internal overall limit"))) {
				ng_logerror("%s - %s - %d - ip: %s vlan: %d - could not do the state transition from %s to %s",__FUNCTION__,__FILE__,__LINE__,inet_ntoa(*(struct in_addr *)&nu_state->Getuser().saddr),nu_state->Getuser().vlan_id,nu_state->state()->GetName().c_str(),my_dis_state->GetName().c_str());
				return;
			}
		}
	}

}

void NetGuard_Limit::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	//we are only interested in packages that are linked to a user already	
	if (!u_data) return;

	//we only check data thats comming from the user in question
	if (*mode != TRAFFIC_OUTGOING) return;
	
	struct user_limit_data *limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
	if ( limit_data == NULL ) {
		limit_data = my_user_init(u_data,true);
	}
	checkmax(limit_data,u_data);
}

void NetGuard_Limit::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("save - save limit data");
		ng_logout("dumpip <ip> <vlan> - show details for an ip");
		ng_logout("dumpip_all <ip> <vlan> - show details for an ip");
		ng_logout("limit_reset <ip> <vlan> - reset limits to default for an ip");
		ng_logout("set_limit_day <ip> <vlan> <external MB> <internal MB> - set day limits for an ip - 0 = no limit");
		ng_logout("set_limit_week <ip> <vlan> <external MB> <internal MB> - set weekly limits for an ip - 0 = no limit");
		ng_logout("set_limit_all <ip> <vlan> <external MB> <internal MB> - set overall limits for an ip - 0 = no limit");

		ng_logout("set_exceeded_limit_day <ip> <vlan> <external count> <internal count> - set daily limit exceed count for an ip");
		ng_logout("set_exceeded_limit_week <ip> <vlan> <external count> <internal count> - set weekly limit exceed count for an ip");
		ng_logout("set_exceeded_limit_all <ip> <vlan> <external count> <internal count> - set overall limit exceed count for an ip");
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "save")
	{
		savedata();
	}

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
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}
		

		#define EINHEIT 1024/1024
		struct user_limit_data *limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
		if ( limit_data == NULL ) {
			limit_data = my_user_init(u_data,true);
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

	if ((params[0] == "limit_reset"))
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
		
		user_shutdown(u_data);
		my_user_init(u_data,false);
	}

	if ((params[0] == "set_exceeded_limit_day") || (params[0] == "set_exceeded_limit_week") || (params[0] == "set_exceeded_limit_all"))
	{
		if (params.size() != 5)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <count> <count>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <count> <count>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <count> <count>",params[0].c_str());
			return;
		}

		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <count> <count>",params[0].c_str());
			return;
		}

		if (intparams[4]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <count> <count>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}


		NetGuard_User_State* nu_state = NetGuard_State_Handler::user_state(u_data);
		if (!nu_state) return;
		if (params[0] == "set_exceeded_limit_day")
		{
			ng_logout_ok("setting day exceeded count");
			nu_state->params()->SetInt("internal_day_exceeded",intparams[3]);
			nu_state->params()->SetInt("external_day_exceeded",intparams[4]);
		}
		if (params[0] == "set_exceeded_limit_week")
		{
			ng_logout_ok("setting week exceeded count");
			nu_state->params()->SetInt("internal_week_exceeded",intparams[3]);
			nu_state->params()->SetInt("external_week_exceeded",intparams[4]);
		}
		if (params[0] == "set_exceeded_limit_all")
		{
			ng_logout_ok("setting overall exceeded count");
			nu_state->params()->SetInt("internal_overall_exceeded",intparams[3]);
			nu_state->params()->SetInt("external_overall_exceeded",intparams[4]);
		}
	}

	if ((params[0] == "set_limit_day") || (params[0] == "set_limit_week") || (params[0] == "set_limit_all"))
	{
		if (params.size() != 5)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <eMB> <iMB>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <eMB> <iMB>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <eMB> <iMB>",params[0].c_str());
			return;
		}

		if (intparams[3]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <eMB> <iMB>",params[0].c_str());
			return;
		}

		if (intparams[4]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <eMB> <iMB>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlanid);
		if (!u_data) 
		{
			ng_logout_not_found("could not find user with ip: %s vlan: %d",inet_ntoa(*(struct in_addr *)&m_ip.s_addr),intparams[2]);
			return;
		}

		#define EINHEIT 1024/1024
		#define EINHEIT2 1024*1024
		struct user_limit_data *limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
		if ( limit_data == NULL ) {
			limit_data = my_user_init(u_data,true);
		}

		unsigned long long int tmpval,tmpval2;
		tmpval = (unsigned long long int)intparams[3] * (unsigned long long int)EINHEIT2;
		tmpval2 = (unsigned long long int)intparams[4] * (unsigned long long int)EINHEIT2;

		ng_logout_ok("setting limits external: %llu Byte internal: %llu Byte", tmpval, tmpval2);
		if (params[0] == "set_limit_day")
		{
			ng_logout("setting day limit");
			limit_data->external.limit_day = tmpval;
			limit_data->internal.limit_day = tmpval2;
		}
		if (params[0] == "set_limit_week")
		{
			ng_logout("setting week limit");
			limit_data->external.limit_week = tmpval;
			limit_data->internal.limit_week = tmpval2;
		}
		if (params[0] == "set_limit_all")
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

void NetGuard_Limit::timer_tick() {
}
