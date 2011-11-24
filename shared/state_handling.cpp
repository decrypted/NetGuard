/***************************************************************************
 *   NetGuard State Handling                                               *
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


#include "../includes/logging.h"
#include "../includes/state/state_handling.hpp"
#include <stdarg.h>

#define log_str "NetGuard_State_Handler"
#define log_str_us "NetGuard_UState"
#define NG_STATE_VERSION_MAGIC "ng_state_db_ver_0.1"

//NetGuard_State
NetGuard_State::NetGuard_State(std::string inname)
{
	log_name = "state_";
	log_name.append(inname);
	name = inname;
	ng_slogdebug_spam(log_name.c_str(),"constructor");
}

NetGuard_State::~NetGuard_State()
{
	clear_registerd_check_exec();
	ng_slogdebug_spam(log_name.c_str(),"destructor");
}

bool NetGuard_State::valid_change(NetGuard_State *to,std::string reason)
{
	if (!to) return false;
	ng_slogdebug_spam(log_name.c_str(),"check for valid state from <%s> to <%s>",name.c_str(),to->GetName().c_str());	
	std::set<std::string>::iterator it = valid_to.find(to->GetName());
	if (it == valid_to.end()) {
		ng_slogdebug_spam(log_name.c_str(),"state transition from <%s> to <%s> NOT valid",name.c_str(),to->GetName().c_str());	
		return false;
	}
	it = to->valid_from.find(name);
	if (it == to->valid_from.end()) {
		ng_slogdebug_spam(log_name.c_str(),"state transition from <%s> to <%s> NOT valid",name.c_str(),to->GetName().c_str());	
		return false;
	}
	ng_slogdebug_spam(log_name.c_str(),"state transition valid from <%s> to <%s>",name.c_str(),to->GetName().c_str());	
	return true;
}

bool NetGuard_State::checkstate(NetGuard_User_State* state_data) {
	ng_slogdebug_spam(log_name.c_str(),"check state <%s> - for ip: %s vlan: %d",name.c_str(),inet_ntoa(*(struct in_addr *)&state_data->Getuser().saddr),state_data->Getuser().vlan_id);	
	State_State_Check_Set::iterator it;
	for (it=check_exec.begin(); it != check_exec.end(); it++) {
		NetGuard_User_State_Check *my_state = (*it);
		if (!my_state->checkstate(state_data)) return false;
	}
	return true;
}

void NetGuard_State::clear_registerd_check_exec() {
	State_State_Check_Set::iterator it;
	for (it=check_exec.begin(); it != check_exec.end(); it++) delete (*it);
	check_exec.clear();
}

bool NetGuard_State::do_clear_registerd_check_exec(std::string inname) {
	std::string tmpstr = "USCE_";
	tmpstr.append(inname);
	State_State_Check_Set::iterator it2;
	for (it2=check_exec.begin(); it2 != check_exec.end(); it2++) {
		if ((*it2)->Get_Name() == tmpstr)
		{
			check_exec.erase(it2);
			delete (*it2);
			return true;
		}
	}
	return false;
}

state_nusc_list NetGuard_State::GetNUSCList()
{
	state_nusc_list my_vector;
	State_State_Check_Set::iterator it;
	for (it=check_exec.begin(); it != check_exec.end(); it++)
		my_vector.push_back((*it));
	return my_vector;
}

//NetGuard_User_State
NetGuard_User_State::NetGuard_User_State(user_state_idx inuser, std::string instate)
{	 
	user = inuser;
    active_state = NetGuard_State_Handler::get_state(instate);
	if (!active_state)
		throw string("no valid state passed");
	params()->SetTime("created",NetGuard_ModuleLoader_Base::GetNow());
	params()->SetTime("timeenter",NetGuard_ModuleLoader_Base::GetNow());
	params()->SetStr("reason","created");
	ng_slogdebug_spam(log_str_us,"init state: %s vlan: %d state: <%s> - %x",inet_ntoa(*(struct in_addr *)&user.saddr),user.vlan_id,active_state->GetName().c_str(),(int)this);	
}

NetGuard_User_State::~NetGuard_User_State()
{
	ng_slogdebug_spam(log_str_us,"destroy state: %s vlan: %d state: <%s>",inet_ntoa(*(struct in_addr *)&user.saddr),user.vlan_id,active_state->GetName().c_str());	
	active_state = NULL;
	clear();
}

bool NetGuard_User_State::check_state_trans(NetGuard_State *to,std::string reason)
{
	assert(active_state != NULL);
	return active_state->valid_change(to,reason);
}

bool NetGuard_User_State::do_state_trans(NetGuard_State *to,std::string reason)
{
	assert(active_state != NULL);
	if (!check_state_trans(to,reason)) return false;
	NetGuard_State *from = active_state;
	bool changeok = NetGuard_State_Handler::exec_state_change(this,&active_state,to,reason);
	if (changeok)
	{
		time_t mytime = NetGuard_ModuleLoader_Base::GetNow();
		params()->SetTime("timeenter",mytime);
		params()->SetStr("reason",reason);
		//add history
		NetGuard_Config *mydata = new NetGuard_Config();
		mydata->SetTime("time",mytime);
		if (from) {
			mydata->SetStr("from",from->GetName());
			params()->SetStr("from",from->GetName());
		}
		mydata->SetStr("to",to->GetName());
		mydata->SetStr("reason",reason);
		mydata->SetConfig("config",&_params);
		_params.remove("trans_manual");
		history.push_back(mydata);		
	}
	return changeok;
}

bool NetGuard_User_State::check(NetGuard_State *to,const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return false;
	while (1) {
		sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size) {
			NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			break;
		}
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			free(p);
			p = NULL;
			NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			break;
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
	}
	
	if (!p) return false;
	bool tmp_result = check(to,(std::string)p);
	free(p);
	return tmp_result;
}

bool NetGuard_User_State::set(NetGuard_State *to,const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return false;
	while (1) {
		sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
		{
			NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			break;
		}
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			free(p);
			p = NULL;
			NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			break;
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
	}
	if (!p) return false;
	bool tmp_result = set(to,(std::string)p);
	free(p);
	return tmp_result;

}

struct sort_NetGuard_State_history : public std::binary_function<NetGuard_Config*,NetGuard_Config*, bool > 
{
	bool operator()(NetGuard_Config* c1, NetGuard_Config* c2) const 
	{
		return (c1->GetTime("time") < c2->GetTime("time"));
	}
};
std::vector<NetGuard_Config*> NetGuard_User_State::GetHistory() {
	std::sort( history.begin(), history.end(), sort_NetGuard_State_history() );
	return history;
}

void NetGuard_User_State::clear() {
	std::vector<NetGuard_Config*>::iterator it;
	for (it=history.begin(); it != history.end(); it++)
		delete (*it);
	history.clear();
}

bool NetGuard_User_State::savedata(FILE *myfile) {
	fwrite(NG_STATE_SAVE_VERSION,strlen(NG_STATE_SAVE_VERSION),1,myfile);

	size_t statelen = state()->GetName().length();
	fwrite(&statelen,sizeof(statelen),1, myfile);
	fwrite(state()->GetName().c_str(),statelen,1, myfile);

	_params.savedata(myfile);

	//write history
	statelen = history.size();
	fwrite(&statelen,sizeof(statelen),1, myfile);
	std::vector<NetGuard_Config*>::iterator it;
	for (it=history.begin(); it != history.end(); it++) 	
		(*it)->savedata(myfile);

	return true;
}

bool NetGuard_User_State::loaddata(FILE *myfile) {
	size_t	statelen;

	clear();

	char * tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(NG_STATE_SAVE_VERSION)+1));
	tmpdata[strlen(NG_STATE_SAVE_VERSION)] = 0;
	int count = fread(&tmpdata[0],strlen(NG_STATE_SAVE_VERSION),1,myfile);
	if ((count != 1) || strcmp(tmpdata,NG_STATE_SAVE_VERSION) ) {
		free(tmpdata);
		return false;
	} else free(tmpdata);
	
	fread(&statelen,sizeof(statelen),1, myfile);
	if (statelen > 500) 
		throw string("could not load state info");
	char *tmpstate_d = (char*)malloc(sizeof(unsigned char)*(statelen+1));
	memset(tmpstate_d,0,sizeof(unsigned char)*(statelen+1));
	fread(tmpstate_d,statelen,1, myfile);

	ng_slogdebug_spam(log_str_us,"loading user (setting state): %s vlan: %d with state: <%s>",inet_ntoa(*(struct in_addr *)&user.saddr),user.vlan_id,tmpstate_d);

	std::string my_state = tmpstate_d;
	active_state = NetGuard_State_Handler::get_state(my_state);
	free(tmpstate_d);
	if (!active_state)
		throw string("loaded unkown state");

	if (!_params.loaddata(myfile)) return false;

	//load history
	fread(&statelen,sizeof(statelen),1, myfile);
	for (unsigned int i=1;i<=statelen;i++)
	{
		NetGuard_Config *mydata = new NetGuard_Config();
		if (!mydata->loaddata(myfile)) return false;
		history.push_back(mydata);
	}
	if (_params.GetTime("created",0) == 0)
		_params.SetTime("created",NetGuard_ModuleLoader_Base::GetNow());
	if (_params.GetTime("timeenter",0) == 0)
		_params.SetTime("timeenter",NetGuard_ModuleLoader_Base::GetNow());
	if (_params.GetStr("reason","") == "")
		_params.SetStr("reason","loaded without data");

	ng_slogdebug_spam(log_str_us,"loaded user: %s vlan: %d state: <%s>",inet_ntoa(*(struct in_addr *)&user.saddr),user.vlan_id,active_state->GetName().c_str());
	return true;
}


//NetGuard_User_SCE_Default
bool NetGuard_User_SCE_Default::exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason)
{
	//ng_slogdebug_spam("NetGuard_User_SCE_Default","enter exec state change from <%s> to <%s> (user: %s vlan: %d) - reason %s",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());	

	ng_slogdebug_spam("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
	(*from) = to;
	return true;

	/*	the checks done here are just for demo purposes the valid_to and valid_from are obeyed anyhow - use them in your code if you want to
	*	feel free to do additional checks in the possible transition - that is what is is for
	*/

	//state change from unkown to ... always good
/*	if ((*(*from)) == "unkown") {
		ng_slog("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason %s",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());	
		(*from) = to;
		return true;
	}

	if ((*(*from)) == "learn") {
		if ((*to) == "enabled")
		{
			ng_slog("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
			(*from) = to;
			return true;
		} else if ((*to) == "disabled")	{
			ng_slog("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
			(*from) = to;
			return true;
		}
	}

	if ((*(*from)) == "enabled") {
		if ((*to) == "disabled")
		{
			ng_slog("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
			(*from) = to;
			return true;
		} else if ((*to) == "learn")	{
			ng_slog("NetGuard_User_SCE_Default","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());
			(*from) = to;
			return true;
		}
	}
	
	return false;*/
}



//NetGuard_State_Handler
NetGuard_State_Handler* NetGuard_State_Handler::onlyInstance = NULL;

NetGuard_State_Handler::NetGuard_State_Handler()
{
	onlyInstance = this;

	//register default handler
	register_exec(new NetGuard_User_SCE_Default());

	//register default states
	register_state(new NetGuard_State_Unkown());
	register_state(new NetGuard_State_Failure());	
	register_state(new NetGuard_State_Disabled());
	register_state(new NetGuard_State_Learn());
	register_state(new NetGuard_State_Enabled());
}

NetGuard_State_Handler::~NetGuard_State_Handler()
{
	onlyInstance = NULL;
	clear();

	do_clear_registerd_states();
	do_clear_registerd_exec();
}

void NetGuard_State_Handler::do_clear_registerd_states()
{
	NetGuard_State_Map::iterator it2;
	for (it2=states.begin(); it2 != states.end(); it2++) {
		delete (*it2).second;
	}
	states.clear();
}

bool NetGuard_State_Handler::do_clear_registered_exec(std::string name) {
	std::string tmpstr = "USCE_";
	tmpstr.append(name);
	State_Exec_Set::iterator it2;
	for (it2=state_exec_set.begin(); it2 != state_exec_set.end(); it2++) {
		if ((*it2)->Get_Name() == tmpstr)
		{
			state_exec_set.erase(it2);
			delete (*it2);
			return true;
		}
	}
	return false;
}

void NetGuard_State_Handler::do_clear_registerd_exec()
{
	ng_slogdebug(log_str,"clearing USCE entrys");
	State_Exec_Set::iterator it;
	for (it=state_exec_set.begin(); it != state_exec_set.end(); it++) 
	{
		delete (*it);
	}
	state_exec_set.clear();
}

user_state_list NetGuard_State_Handler::GetUserList(std::string state)
{
	user_state_list my_vector;
	User_State_Hash::iterator it;
	for (it=users.begin(); it != users.end(); it++) {
		if ((state=="") || ( (*((*it).second->state())) == state) )
			my_vector.push_back((*it).second);
	}
	return my_vector;
}

state_list NetGuard_State_Handler::GetStateList()
{
	state_list my_vector;
	NetGuard_State_Map::iterator it;
	for (it=states.begin(); it != states.end(); it++)
		my_vector.push_back((*it).second);
	return my_vector;
}

state_usce_list NetGuard_State_Handler::GetUSCEList()
{
	state_usce_list my_vector;
	State_Exec_Set::iterator it;
	for (it=state_exec_set.begin(); it != state_exec_set.end(); it++)
		my_vector.push_back((*it));
	return my_vector;
}

bool NetGuard_State_Handler::user_state_present(u_int32_t *saddr, unsigned int *vlan_id)
{
    user_state_idx idx;
	idx.saddr = (*saddr);
	idx.vlan_id = (*vlan_id);
	User_State_Hash::iterator it;
	it=users.find(idx);
	if (it != users.end()) return true;
	return false;
}

NetGuard_User_State* NetGuard_State_Handler::get_user_state(u_int32_t *saddr, unsigned int *vlan_id, std::string default_state)
{
    user_state_idx idx;
	idx.saddr = (*saddr);
	idx.vlan_id = (*vlan_id);
	User_State_Hash::iterator it;
	it=users.find(idx);
	if (it != users.end()) return (*it).second;
	if (default_state == "") return NULL;

	try
	{
		NetGuard_User_State *muser_state = new NetGuard_User_State(idx,default_state);
		users.insert(pair<user_state_idx, NetGuard_User_State*>(idx, muser_state));
		return muser_state;
	}
	catch (...)
	{
		ng_slogerror(log_str_us,"can not add user with state <%s>",default_state.c_str());
		return NULL;
	}
		
}

bool NetGuard_State_Handler::delete_user_state(u_int32_t *saddr, unsigned int *vlan_id) {
    user_state_idx idx;
	idx.saddr = (*saddr);
	idx.vlan_id = (*vlan_id);
	User_State_Hash::iterator it;
	it=users.find(idx);
	if (it != users.end()) {
		delete (*it).second;
		users.erase(it);
		return true;
	}
	return false;
}

bool NetGuard_State_Handler::do_exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to, std::string reason)
{
	NetGuard_State *oldfrom = (*from);
	State_Exec_Set::iterator preit;
	for (preit=state_exec_set.begin(); preit != state_exec_set.end(); preit++) {
		NetGuard_User_State_Change_Execution *premy_state = (*preit);
		if (!premy_state->pre_state_change(user, from, to, reason)) return false;
	}

	State_Exec_Set::iterator it;
	for (it=state_exec_set.begin(); it != state_exec_set.end(); it++) {
		NetGuard_User_State_Change_Execution *my_state = (*it);
		if (my_state->exec_state_change(user, from, to, reason)) {
			//we changed the state - lets distribute that
			State_Exec_Set::iterator it2;
			for (it2=state_exec_set.begin(); it2 != state_exec_set.end(); it2++) {
				NetGuard_User_State_Change_Execution *my_state2 = (*it2);
				my_state2->done_state_change(user, &oldfrom, to, reason);
			}
			return true;
		}
	}
	return false;
}
 
bool NetGuard_State_Handler::savedata(std::string filename)
{
	ng_slogdebug_spam(log_str,"saving states to %s",filename.c_str());

	FILE *myfile = fopen(filename.c_str(), "w+");
	if (!myfile) return false;

	fwrite(NG_STATE_VERSION_MAGIC,strlen(NG_STATE_VERSION_MAGIC),1,myfile);

	int counter = 0;
	User_State_Hash::iterator it;
	for (it=users.begin(); it != users.end(); it++) {
		NetGuard_User_State *u_state =  (*it).second;
		counter++;
		fwrite(&u_state->Getuser().saddr ,sizeof(u_state->Getuser().saddr),1, myfile);
		fwrite(&u_state->Getuser().vlan_id ,sizeof(u_state->Getuser().vlan_id),1, myfile);

		u_state->savedata(myfile);

		ng_slogdebug_spam(log_str,"save user state: %s vlan: %d state: <%s>",inet_ntoa(*(struct in_addr *)&u_state->Getuser().saddr),u_state->Getuser().vlan_id,u_state->state()->GetName().c_str());	
	}
	ng_slogdebug_spam(log_str,"saved %d states",counter);

	fwrite(NG_STATE_VERSION_MAGIC,strlen(NG_STATE_VERSION_MAGIC),1,myfile);
	fclose(myfile);

	return true;
}

bool NetGuard_State_Handler::loaddata(std::string filename, bool rename_onfail)
{
	char *tmpdata;
	int count = 0;
	FILE *myfile;
	struct stat fileinfo;

	clear();

	if (!filename.length()) {
		ng_slogerror(log_str,0,"can not load - got emtpy filename");
		return false;
	}
	
	ng_slogdebug_spam(log_str,"loading data from %s",filename.c_str());	

	if (stat(filename.c_str(),&fileinfo)) {
		ng_slogerror(log_str,"cant stat data file %s",filename.c_str());
		return false;
	}
	myfile = fopen(filename.c_str(), "r");
	if (!myfile) {
		ng_slogerror(log_str,"cant open data file %s",filename.c_str());
		return false;
	}

	tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(NG_STATE_VERSION_MAGIC)+1));
	tmpdata[strlen(NG_STATE_VERSION_MAGIC)] = 0;

	count = fread(&tmpdata[0],strlen(NG_STATE_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,NG_STATE_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant read state data from %s - illegal format (%s <> %s)",filename.c_str(),(char *)tmpdata,NG_STATE_VERSION_MAGIC);
		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogext(log_str,0,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}
		free(tmpdata);
		return false;
	}

	ng_slogdebug_spam(log_str,"loading %lu bytes state-data",fileinfo.st_size);

	off_t f_pos =  ftell(myfile);
	int counter = 0;
	while ( (unsigned int)(fileinfo.st_size - f_pos - strlen(NG_STATE_VERSION_MAGIC)) >= sizeof(mac_addr) ) {
		unsigned int	vlan_id;
		u_int32_t		saddr;

		fread(&saddr,sizeof(saddr),1, myfile);
		fread(&vlan_id,sizeof(vlan_id),1, myfile);

		ng_slogdebug_spam(log_str,"loading user: %s vlan: %d",inet_ntoa(*(struct in_addr *)&saddr),vlan_id);
		NetGuard_User_State *u_state =  get_add_user_state(&saddr,&vlan_id);
		if (u_state)
		{
			try
			{
				if (!u_state->loaddata(myfile))
					throw string("could not load state details");

				if (!u_state->state()->checkstate(u_state)) {
					ng_slogerror(log_str,"loaded user: %s vlan: %d state: %s - with invalid state",inet_ntoa(*(struct in_addr *)&saddr),vlan_id,u_state->state()->GetName().c_str());	
					if (!delete_user_state(&saddr,&vlan_id)) 
						ng_slogerror(log_str,"error loading user: %s vlan: %d - user could not be deleted ...",inet_ntoa(*(struct in_addr *)&saddr),vlan_id);				
				} else counter++;
				
			}
			catch (...)
			{
				ng_slogerror(log_str,"error loading user: %s vlan: %d",inet_ntoa(*(struct in_addr *)&saddr),vlan_id);	
				if (!delete_user_state(&saddr,&vlan_id)) 
					ng_slogerror(log_str,"error loading user: %s vlan: %d - user could not be deleted ...",inet_ntoa(*(struct in_addr *)&saddr),vlan_id);				
				ng_slogerror(log_str,"cant read state data from %s - illegal format - read error",filename.c_str());
				return false;			    
			}
		} else {
			ng_slogerror(log_str,"could not load user: %s vlan: %d",inet_ntoa(*(struct in_addr *)&saddr),vlan_id);	
		}
		f_pos =  ftell(myfile);
	}

	count = fread(tmpdata,strlen(NG_STATE_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,NG_STATE_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant read state data file (end) from %s - illegal format",filename.c_str());
		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogext(log_str,0,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}
		free(tmpdata);
		clear();
		return false;
	}

	ng_slogdebug(log_str,"loaded %d users",counter);

	fclose(myfile);
	free(tmpdata);
	
	return true;
}

void NetGuard_State_Handler::clear()
{
	ng_slogdebug_spam(log_str,"clearing state-user list");
	User_State_Hash::iterator it;
	for (it=users.begin(); it != users.end(); it++) {
		delete (*it).second;
	}
	users.clear();
	ng_slogdebug_spam(log_str,"cleared state-user list");
}
