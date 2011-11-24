/***************************************************************************
 *   NetGuard State Handling                                               *
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

#ifndef NG_STATE_HANDLING
#define NG_STATE_HANDLING

#include "../defines.h"
#include "../tools.h"
#include "../logging.h"
#include "../storage/user_data.hpp"
#include "../types.hpp"
#include "../config.hpp"
#include <list>

#define NG_STATE_SAVE_VERSION "nss0.1"



class NetGuard_User_State;
class NetGuard_User_State_Check;
typedef std::vector<NetGuard_User_State_Check*> state_nusc_list;

class NetGuard_State
{
	protected:
		std::string name;
		std::string log_name;
		std::list<NetGuard_User_State_Check *> check_exec;
	public:
		std::set<std::string> valid_from;
		std::set<std::string> valid_to;

		NetGuard_State(std::string inname);
		virtual ~NetGuard_State();

		std::string GetName() {return name;};
		std::string GetLogName() {return log_name;};

		bool valid_change(NetGuard_State *to,std::string reason);
		bool checkstate(NetGuard_User_State* state_data);

		inline bool operator==(std::string inname) { return inname == name; };
		inline bool operator!=(std::string inname) { return !(*this == inname); };
		inline bool operator==(NetGuard_State *instate) { return this->GetName() == instate->GetName(); };
		inline bool operator!=(NetGuard_State *other) { return !(*this == other); };

		bool register_check(NetGuard_User_State_Check* exec_obj) 
		{
			check_exec.push_front(exec_obj);
			return true;
		};

		void clear_registerd_check_exec();
		bool do_clear_registerd_check_exec(std::string name);
		state_nusc_list GetNUSCList();

		//inline operator int() const { return (int)*this; }
};

class NetGuard_State_Unkown : public NetGuard_State
{
	public:
		NetGuard_State_Unkown(): NetGuard_State("unkown") {
			valid_to.insert("disabled");
			valid_to.insert("learn");
			valid_to.insert("enabled");
		};
};

class NetGuard_State_Failure : public NetGuard_State
{
	public:
		NetGuard_State_Failure(): NetGuard_State("failure") {
			valid_to.insert("disabled");
			valid_to.insert("learn");
			valid_to.insert("enabled");
			valid_from.insert("enabled");
			valid_from.insert("disabled");
		};
};

class NetGuard_State_Disabled : public NetGuard_State
{
	public:
		NetGuard_State_Disabled(): NetGuard_State("disabled") {
			valid_from.insert("enabled");
			valid_from.insert("learn");
			valid_to.insert("enabled");
			valid_to.insert("learn");
			valid_to.insert("failure");
		};
};

class NetGuard_State_Learn : public NetGuard_State
{
	public:
		NetGuard_State_Learn(): NetGuard_State("learn") {
			valid_from.insert("unkown");
			valid_from.insert("enabled");
			valid_to.insert("enabled");
			valid_to.insert("disabled");
			valid_to.insert("failure");
		};
};

class NetGuard_State_Enabled : public NetGuard_State
{
	public:
		NetGuard_State_Enabled(): NetGuard_State("enabled") {
			valid_from.insert("unkown");
			valid_from.insert("disabled");
			valid_from.insert("learn");
			valid_to.insert("disabled");
			valid_to.insert("learn");
			valid_to.insert("failure");
		};
		bool checkstate(NetGuard_User_State* state_data);
};

#define DEFAULT_STATE "unkown"

//user state storage
struct user_state_idx
{
   	u_int32_t          saddr;
    unsigned int       vlan_id;
};

class NetGuard_User_State
{
	protected:
		user_state_idx user;
		NetGuard_State *active_state;
		NetGuard_Config _params;
		std::vector<NetGuard_Config*> history;

	public:
		NetGuard_User_State(user_state_idx inuser, std::string state);
		virtual ~NetGuard_User_State();

		NetGuard_State *state() { return active_state;};
		user_state_idx Getuser() { return user;};
		NetGuard_Config *params() { return &_params;};		

		bool check_state_trans(NetGuard_State *to,std::string reason);
		bool do_state_trans(NetGuard_State *to,std::string reason);		

		inline bool check(NetGuard_State *to,std::string reason) {
			return check_state_trans(to,reason);
		}

		bool check(NetGuard_State *to,const char *fmt, ...);

		inline bool set(NetGuard_State *to,std::string reason) {
			return do_state_trans(to,reason);
		}

		bool set(NetGuard_State *to,const char *fmt, ...);
		
		inline std::string state_name() {
			//if (!active_state && !init_state()) return ""; initialized on contructor
			return active_state->GetName();
		};

		inline bool operator==(NetGuard_State *instate) { 
			//if (!active_state && !init_state()) return false; initialized on contructor
			assert(active_state != NULL);
			return instate == active_state;
		};

		inline bool operator==(std::string name) { 
			//if (!active_state && !init_state()) return false; initialized on contructor
			assert(active_state != NULL);
			return active_state->GetName() == name;
		};

		//is state change allowed?
		inline bool operator&&(NetGuard_State *instate) { 
			assert(active_state != NULL);
			return check_state_trans(instate,"<unkown>");
		};

		//do state change
		inline bool operator<(NetGuard_State* right) {
			assert(active_state != NULL);
			return do_state_trans(right,"<unkown>");
		}

		void clear();
		std::vector<NetGuard_Config*> GetHistory();

		bool savedata(FILE *myfile);
		bool loaddata(FILE *myfile);
};

struct hash_user_state
{
	size_t operator()(const struct user_state_idx t) const
	{
		return (t.vlan_id * MAXLONG) + t.saddr;
	}
};

struct eq_user_state_idx
{
  bool operator()(const struct user_state_idx s1, const struct user_state_idx s2) const
  {
    return (s1.saddr == s2.saddr) && (s1.vlan_id == s2.vlan_id);
  }
};


class NetGuard_User_State_Change_Execution
{
	private:
		std::string _name;
	public:
		std::string Get_Name() { return _name; };
		NetGuard_User_State_Change_Execution(std::string inname) {
			_name = "USCE_";
			_name.append(inname);
			ng_slogdebug_spam(_name.c_str(),"constructor");
		}
		virtual ~NetGuard_User_State_Change_Execution() {
			ng_slogdebug_spam(_name.c_str(),"destructor");
		}
		//called before a state change - if false -> we wont allow the change
		virtual bool pre_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason) { return true;};

		//called to change the state - true means we did handle the change and we can leave the handling -> not all modules will be called and the order is important here		
		virtual bool exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason) { return false;};

		//after a successfull state change this function is called in all modules
		virtual void done_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason) { return;};
};

class NetGuard_User_SCE_Default: public NetGuard_User_State_Change_Execution
{
	public:
		NetGuard_User_SCE_Default(): NetGuard_User_State_Change_Execution("default") {};
		bool exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason);
};

typedef std::list<NetGuard_User_State_Change_Execution *> State_Exec_Set;



class NetGuard_User_State_Check
{
	private:
		std::string _name;
	public:
		std::string Get_Name() { return _name; };
		NetGuard_User_State_Check(std::string inname) {
			_name = "NUSC_";
			_name.append(inname);
			ng_slogdebug_spam(_name.c_str(),"constructor");
		}
		virtual ~NetGuard_User_State_Check() {
			ng_slogdebug_spam(_name.c_str(),"destructor");
		}
		virtual bool checkstate(NetGuard_User_State* state_data) { return false;};
};

typedef std::list<NetGuard_User_State_Check *> State_State_Check_Set;

typedef hash_map<std::string, NetGuard_State*, string_hash> NetGuard_State_Map;
typedef hash_map<const struct user_state_idx, NetGuard_User_State* , hash_user_state, eq_user_state_idx> User_State_Hash;
typedef std::vector<NetGuard_User_State*> user_state_list;
typedef std::vector<NetGuard_State*> state_list;

typedef std::vector<NetGuard_User_State_Change_Execution*> state_usce_list;


class NetGuard_State_Handler
{
	protected:
		static class NetGuard_State_Handler *onlyInstance;
		NetGuard_State_Map states;
		User_State_Hash users;
		State_Exec_Set state_exec_set;
	public:

		inline static NetGuard_State_Handler& Get()
		{
			return *onlyInstance;
		}

		inline static NetGuard_State_Handler* GetPointer()
		{
			return onlyInstance;
		}

		static void InitPointer(NetGuard_State_Handler* data) 
		{
			onlyInstance = data;
		}

		NetGuard_State_Handler();
		virtual ~NetGuard_State_Handler();

		inline static bool register_state(NetGuard_State* state) 
		{
			ng_slogdebug("NetGuard_State_Handler","register state '%s' ",state->GetName().c_str());
			if (!onlyInstance) {
				ng_slogerror("NetGuard_State_Handler","cant register state '%s' - NetGuard_State_Handler not present",state->GetName().c_str());
				return false;
			}
			if (get_state(state->GetName())) {
				ng_slogerror("NetGuard_State_Handler","cant register state '%s' - already known",state->GetName().c_str());
				return false;
			}
			ng_slogdebug_spam("NetGuard_State_Handler","did register state '%s' ",state->GetName().c_str());
			onlyInstance->states.insert(pair<std::string, NetGuard_State*>(state->GetName(), state));
			return true;
		}

		inline static bool register_exec(NetGuard_User_State_Change_Execution* exec_obj) 
		{
			if (!onlyInstance) return false;
			onlyInstance->state_exec_set.push_front(exec_obj);
			return true;
		}

		static bool clear_registerd_states() 
		{
			if (!onlyInstance) return false;
			onlyInstance->do_clear_registerd_states();
			return true;
		}

		void do_clear_registerd_states();

		static bool clear_registerd_exec() 
		{
			if (!onlyInstance) return false;
			onlyInstance->do_clear_registerd_exec();
			return true;
		}
		void do_clear_registerd_exec();
		bool do_clear_registered_exec(std::string name);


		inline static NetGuard_State* get_state(std::string name) 
		{
			if (!onlyInstance) return NULL;
			NetGuard_State_Map::iterator it;
			it=onlyInstance->states.find(name);
			if (it != onlyInstance->states.end()) return (*it).second;
			return NULL;
		}

		inline static NetGuard_User_State* user_state(u_int32_t *saddr, unsigned int *vlan_id)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(saddr,vlan_id,"");
		}


		inline static NetGuard_User_State* user_state(struct user_data *u_data)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(&u_data->saddr,&u_data->vlan_id,"");
		}		

		inline static NetGuard_User_State* get_add_user_state(u_int32_t *saddr, unsigned int *vlan_id, std::string def_state)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(saddr,vlan_id,def_state);
		}

		inline static NetGuard_User_State* get_add_user_state(u_int32_t *saddr, unsigned int *vlan_id)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(saddr,vlan_id,DEFAULT_STATE);
		}

		inline static NetGuard_User_State* get_add_user_state(struct user_data *u_data, std::string def_state)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(&u_data->saddr,&u_data->vlan_id,def_state);
		}

		inline static NetGuard_User_State* get_add_user_state(struct user_data *u_data)
		{
			if (!onlyInstance) return NULL;
			return onlyInstance->get_user_state(&u_data->saddr,&u_data->vlan_id,DEFAULT_STATE);
		}


		inline static bool exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to, std::string reason)
		{
			if (!onlyInstance) return false;
			return onlyInstance->do_exec_state_change(user,from,to,reason);
		};

		user_state_list GetUserList(std::string state="");
		state_list GetStateList();
		state_usce_list GetUSCEList();

		bool user_state_present(u_int32_t *saddr, unsigned int *vlan_id);

		NetGuard_User_State* get_user_state(u_int32_t *saddr, unsigned int *vlan_id, std::string default_state);

		inline NetGuard_User_State* get_user_state(struct user_data *u_data, std::string default_state){ return get_user_state(&u_data->saddr,&u_data->vlan_id,default_state);}

		bool delete_user_state(u_int32_t *saddr, unsigned int *vlan_id);
		inline bool delete_user_state(struct user_data *u_data){return delete_user_state(&u_data->saddr,&u_data->vlan_id);}

		bool do_exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to, std::string reason);

 		bool savedata(std::string filename);
 		bool loaddata(std::string filename,bool rename_onfail = true);

		void clear();

};

#endif 
