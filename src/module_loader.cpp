/***************************************************************************
 *   NetGuard Module Loader                                                *
 *                                                                         *
 *   Copyright (c) 2011       Daniel Rudolph <daniel at net-guard net>     *
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

#include "module_loader.hpp"

#include <dlfcn.h>
#include <values.h>
#include <time.h>
#include "../includes/modules/module.hpp"
#include "../includes/logging.h"
#include "../includes/config.hpp"
#include "../includes/ip_filter.hpp"
#include "../includes/state/state_handling.hpp"

#define log_str "NetGuard_ModuleLoader"

//NetGuard_ModuleLoader_General_Module_Entry
NetGuard_ML_General_Module::NetGuard_ML_General_Module(void *handle) : NetGuard_ModuleLoader_Entry(handle) {
	
	ng_slogdebug_spam("NetGuard_ML_General_Module","constructor - handle %x",(int)handle_);
	type_ = NETGUARD_GENERAL_MODULE_TYPE;
	create_general_module = NULL;
	destroy_general_module  = NULL;
}

NetGuard_ML_General_Module::~NetGuard_ML_General_Module() {
	ng_slogdebug_spam("NetGuard_ML_General_Module","destructor - handle %x",(int)handle_);
}

int NetGuard_ML_General_Module::loadmodule() {
	ng_slogdebug_spam("NetGuard_ML_General_Module","loading - handle %x ...",(int)handle_);
	state_ = NETGUARD_MODULE_STATE_INIT;

	create_general_module = (create_general_module_t) load_symbol("create_general_module");
	if (!create_general_module) return 1;
	destroy_general_module = (destroy_general_module_t) load_symbol("destroy_general_module");
	if (!destroy_general_module) return 1;

	ng_slogdebug_spam("NetGuard_ML_General_Module","creating module instance - handle %x ...",(int)handle_);
	module_ = create_general_module();
	state_ = NETGUARD_MODULE_STATE_LOADED;
	return 0;
};

int NetGuard_ML_General_Module::unloadmodule() {
	ng_slogdebug_spam("NetGuard_ML_General_Module","unloading...");
	state_ = NETGUARD_MODULE_STATE_INIT;
	if (module_)
	{
		module_->shutdown();
		destroy_general_module((NetGuard_General_Module*)module_);
		module_ = NULL;
	}
	return 0;
};

//NetGuard_ModuleLoader_User_Module_Entry
NetGuard_ML_User_Module::NetGuard_ML_User_Module(void *handle) : NetGuard_ModuleLoader_Entry(handle) {
	
	ng_slogdebug_spam("NetGuard_ML_User_Module","constructor - handle %x",(int)handle_);
	type_ = NETGUARD_GENERAL_MODULE_TYPE;
	create_user_module = NULL;
	destroy_user_module  = NULL;
}

NetGuard_ML_User_Module::~NetGuard_ML_User_Module() {
	ng_slogdebug_spam("NetGuard_ML_User_Module","destructor - handle %x",(int)handle_);
}

int NetGuard_ML_User_Module::loadmodule() {
	ng_slogdebug_spam("NetGuard_ML_User_Module","loading - handle %x ...",(int)handle_);
	state_ = NETGUARD_MODULE_STATE_INIT;

	create_user_module = (create_user_module_t) load_symbol("create_user_module");
	if (!create_user_module) return 1;
	destroy_user_module = (destroy_user_module_t) load_symbol("destroy_user_module");
	if (!destroy_user_module) return 1;

	ng_slogdebug_spam("NetGuard_ML_User_Module","creating module instance - handle %x ...",(int)handle_);
	module_ = create_user_module();
	state_ = NETGUARD_MODULE_STATE_LOADED;
	return 0;
};

int NetGuard_ML_User_Module::unloadmodule() {
	ng_slogdebug_spam("NetGuard_ML_User_Module","unloading...");
	state_ = NETGUARD_MODULE_STATE_INIT;
	if (module_)
	{
		module_->shutdown();
		destroy_user_module((NetGuard_User_Module*)module_);
		module_ = NULL;
	}
	return 0;
};

//NetGuard_ModuleLoader_Input_Module_Entry
NetGuard_ML_Input_Module::NetGuard_ML_Input_Module(void *handle) : NetGuard_ModuleLoader_Entry(handle) {
	
	ng_slogdebug_spam("NetGuard_ML_Input_Module","constructor - handle %x",(int)handle_);
	type_ = NETGUARD_INPUT_MODULE_TYPE;
	create_input_module = NULL;
	destroy_input_module  = NULL;
}

NetGuard_ML_Input_Module::~NetGuard_ML_Input_Module() {
	ng_slogdebug_spam("NetGuard_ML_Input_Module","destructor - handle %x",(int)handle_);
}

int NetGuard_ML_Input_Module::loadmodule() {
	ng_slogdebug_spam("NetGuard_ML_Input_Module","loading - handle %x ...",(int)handle_);
	state_ = NETGUARD_MODULE_STATE_INIT;

	create_input_module = (create_input_module_t) load_symbol("create_input_module");
	if (!create_input_module) return 1;
	destroy_input_module = (destroy_input_module_t) load_symbol("destroy_input_module");
	if (!destroy_input_module) return 1;

	ng_slogdebug_spam("NetGuard_ML_Input_Module","creating module instance - handle %x ...",(int)handle_);
	module_ = create_input_module();
	state_ = NETGUARD_MODULE_STATE_LOADED;
	return 0;
};

int NetGuard_ML_Input_Module::unloadmodule() {
	ng_slogdebug_spam("NetGuard_ML_Input_Module","unloading...");
	state_ = NETGUARD_MODULE_STATE_INIT;
	if (module_)
	{
		module_->shutdown();
		destroy_input_module((NetGuard_Input_Module*)module_);
		module_ = NULL;
	}
	return 0;
};

//NetGuard_ML_Command_Input_Module
NetGuard_ML_Command_Input_Module::NetGuard_ML_Command_Input_Module(void *handle): NetGuard_ModuleLoader_Entry(handle) {
	ng_slogdebug_spam("NetGuard_ML_Command_Input_Module","constructor - handle %x",(int)handle_);
	type_ = NETGUARD_COMMAND_INPUT_MODULE_TYPE;
	create_command_input_module = NULL;
	destroy_command_input_module = NULL;
}

NetGuard_ML_Command_Input_Module::~NetGuard_ML_Command_Input_Module() {
	ng_slogdebug_spam("NetGuard_ML_Command_Input_Module","destructor - handle %x",(int)handle_);
}

int NetGuard_ML_Command_Input_Module::loadmodule() {
	state_ = NETGUARD_MODULE_STATE_INIT;
	ng_slogdebug_spam("NetGuard_ML_Command_Input_Module","loading - handle %x ...",(int)handle_);

	create_command_input_module = (create_command_input_module_t) load_symbol("create_command_input_module");
	if (!create_command_input_module) return 1;
	destroy_command_input_module = (destroy_command_input_module_t) load_symbol("destroy_command_input_module");
	if (!destroy_command_input_module) return 1;

	ng_slogdebug_spam("NetGuard_ML_Command_Input_Module","creating module instance - handle %x ...",(int)handle_);
	module_ = create_command_input_module();
	state_ = NETGUARD_MODULE_STATE_LOADED;
	return 0;
};

int NetGuard_ML_Command_Input_Module::unloadmodule() {
	ng_slogdebug_spam("NetGuard_ML_Command_Input_Module","unloading...");
	state_ = NETGUARD_MODULE_STATE_INIT;
	if (module_)
	{
		module_->shutdown();
		destroy_command_input_module((NetGuard_Command_Input_Module*)module_);
		module_ = NULL;
	}
	return 0;
};

NetGuard_ModuleLoader_Entry *NetGuard_ModuleLoader::load_lib(std::string filename) {

	// open the library
	ng_slogdebug_spam(log_str,"Opening %s...",filename.c_str());
	void* handle = dlopen(filename.c_str(), RTLD_LAZY);

	if (!handle) {
		ng_slogerror(log_str,"Cannot open library %s ",dlerror());
		return NULL;
	} else ng_slogdebug_spam(log_str," as %x",(int)handle);

	net_guard_module_t net_guard_module = (net_guard_module_t) load_symbol(handle,"net_guard_module");
	if (!net_guard_module) return NULL;

	get_interface_version_t get_interface_version = (get_interface_version_t) load_symbol(handle,"get_interface_version");
	if (!get_interface_version) return NULL;

	get_module_name_t get_module_name = (get_module_name_t) load_symbol(handle,"get_module_name");
	if (!get_module_name) return NULL;

	get_module_version_t get_module_version = (get_module_version_t) load_symbol(handle,"get_module_version");
	if (!get_module_version) return NULL;

	//get module version
	ng_slogdebug_spam(log_str,"get module type from from %x ...",(int)handle);
	const char *net_guard_module_value = net_guard_module();
	ng_slogdebug_spam(log_str,"got \"%s\" as moduletype from %x",net_guard_module_value,(int)handle);

	int found = 0;
	if (!strncmp(net_guard_module_value, NETGUARD_GENERAL_MODULE_IDENT,strlen(NETGUARD_GENERAL_MODULE_IDENT)))
		found = NETGUARD_GENERAL_MODULE_TYPE;
	if (!strncmp(net_guard_module_value, NETGUARD_USER_MODULE_IDENT, strlen(NETGUARD_USER_MODULE_IDENT)))
		found = NETGUARD_USER_MODULE_TYPE;
	if (!strncmp(net_guard_module_value, NETGUARD_INPUT_MODULE_IDENT, strlen(NETGUARD_INPUT_MODULE_IDENT)))
		found = NETGUARD_INPUT_MODULE_TYPE;
	if (!strncmp(net_guard_module_value, NETGUARD_COMMAND_INPUT_MODULE_IDENT, strlen(NETGUARD_COMMAND_INPUT_MODULE_IDENT)))
		found = NETGUARD_COMMAND_INPUT_MODULE_TYPE;

	if (!found)
	{
		ng_slogerror(log_str,"\"%s\" is no valid netguard module",net_guard_module_value);
		dlclose(handle);
		return NULL;
	} else ng_slogdebug(log_str,"\"%s\" is netguard module type %d",net_guard_module_value,found);

	const char *get_interface_version_value = get_interface_version();
	if (strncmp(get_interface_version_value, NETGUARD_MODULE_INTERFACE_VERSION,strlen(NETGUARD_MODULE_INTERFACE_VERSION))) {
		ng_slogerror(log_str,"\"%s\" not compatible interface version \"%s\" - we need \"%s\"",net_guard_module_value,get_interface_version_value,NETGUARD_MODULE_INTERFACE_VERSION);
		dlclose(handle);
		return NULL;
	}


	NetGuard_ModuleLoader_Entry *module_entry = NULL;
	int module_type = found;
	switch (module_type)
	{
	case NETGUARD_GENERAL_MODULE_TYPE:
		module_entry = new NetGuard_ML_General_Module(handle);
		break;
	case NETGUARD_USER_MODULE_TYPE:
		module_entry = new NetGuard_ML_User_Module(handle);
		break;
	case NETGUARD_INPUT_MODULE_TYPE:
		module_entry = new NetGuard_ML_Input_Module(handle);
		break;
	case NETGUARD_COMMAND_INPUT_MODULE_TYPE:
		module_entry = new NetGuard_ML_Command_Input_Module(handle);
		break;
	default:
		ng_slogerror(log_str,"ERROR - cant init module - TYPE UNKOWN - %d",module_type);
		return NULL;
		break;
	
	}
	const char *tmp_value = get_module_name();
	module_entry->setName(tmp_value);
	tmp_value = get_module_version();
	module_entry->setVersion(tmp_value);
	module_entry->SetFileName(filename);

	found = module_entry->loadmodule();

	if (!found)
	{
		tmp_value = get_module_name();
		module_entry->setName(tmp_value);
		modules[module_entry->Name()] = module_entry;
		ng_slogdebug_spam(log_str,"loaded module \"%s\" as \"%s\" from \"%s\"",module_entry->Name().c_str(),net_guard_module_value,filename.c_str());
	} else {
		ng_slogerror(log_str,"ERROR - cant load module - type %d",module_type);
		module_entry->unloadmodule();
		delete module_entry;
		return NULL;
	}

	return module_entry;
}

//NetGuard_ModuleLoader
NetGuard_ModuleLoader::NetGuard_ModuleLoader(NetGuard_General_Module *main_module)
{
	do_broadcasting_input = 0;
	timer_counter = 0;
	loglevel = 9999;
	logdelay = 0;
	save_timer = 300; // 5 mins
	log_buff_timer = 60; //1min
	time(&now);	/* get the current time */
	my_time = *localtime(&now);	/* get the tm structure */
	last_save = now;
	ignore_next_log_buff_msg = 0;


	log_buff_recent_spam = 100;
	log_buff_recent = 100;

	//ng_slogdebug_spam(log_str,"constructor"); hard to silence over config

	main_module_ = main_module;
	module_swaping = false;
	polling = false;
	load_params = new NetGuard_Config();
}

NetGuard_ModuleLoader::~NetGuard_ModuleLoader()
{	
	ng_slogdebug_spam(log_str,"destructor");
	clear();
	delete load_params;
	onlyInstance = NULL; //make sure the print dont fail as the object goes down
}

void* NetGuard_ModuleLoader::load_symbol(void *handle, const char *symbol) {
	ng_slogdebug_spam(log_str,"Loading symbol \"%s\" ...",symbol);
	void *result = dlsym(handle, symbol);
	if (!result) {
		ng_slogerror(log_str,"Cannot load symbol %s - %s ",symbol, dlerror());
		dlclose(handle);
		return NULL;
	} else {
		ng_slogdebug_spam(log_str,"done.");
		return result;
	}
}

int NetGuard_ModuleLoader::can_unload(std::string name) {
	ModuleLoader_Map::iterator it;
	for (it=modules.begin(); it != modules.end(); it++) {
		NetGuard_ModuleLoader_Entry *module =  (*it).second;
		if (module)
		{
			std::vector<std::string>::iterator it_modules;
			for (it_modules=module->module()->required_modules.begin(); it_modules != module->module()->required_modules.end(); it_modules++) {
				if ((*it_modules) == name) {
					ng_slogerror(log_str,"can not unload \"%s\" needed from \"%s\"",name.c_str(),module->Name().c_str());
					return -1;
				}
			}
		}
	}
	return 0;
}

int NetGuard_ModuleLoader::free_lib(std::string name) {
	ModuleLoader_Map::iterator it = modules.find(name);
	if (it == modules.end()) {		// not in map.
		return -1;
	} else {
		if (can_unload(name)) return -2;
		NetGuard_ModuleLoader_Entry *module_entry = (*it).second;
		ng_slogdebug_spam(log_str,"unloading module \"%s\"",module_entry->Name().c_str());
		modules.erase(name);
		module_entry->unloadmodule();
		delete module_entry;
		return 0;
	}
}

int NetGuard_ModuleLoader::free_lib(NetGuard_ModuleLoader_Entry *entry) {
	if (!entry) return -1;
	ModuleLoader_Map::iterator it = modules.find(entry->Name());
	if (it == modules.end()) {		// not in map.
		return -1;
	} else {
		NetGuard_ModuleLoader_Entry *module_entry = (*it).second;
		if (can_unload(module_entry->Name())) return -2;
		ng_slogdebug_spam(log_str,"deleting module \"%s\"",module_entry->Name().c_str());
		modules.erase(entry->Name());
		entry->unloadmodule();
		delete entry;
		return 0;
	}
}

NetGuard_ModuleLoader_Entry *NetGuard_ModuleLoader::get_loaded_lib(std::string name) {
	ModuleLoader_Map::iterator it = modules.find(name);
	if (it == modules.end()) {
		return NULL;
	} else {
		return modules[name];
	}
}

void NetGuard_ModuleLoader::clear() {
	ModuleLoader_Map::iterator it;
	int found = 1;
	while (found)
	{
		found = 0;
		for (it=modules.begin(); it != modules.end(); it++) {
			NetGuard_ModuleLoader_Entry *module =  (*it).second;
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (module && (!can_unload(module->Name()))) {
				found = 1;
				module->unloadmodule();
				delete module;
				(*it).second = NULL;
			}
		}
	}
	modules.clear();
}

void NetGuard_ModuleLoader::timer_tick() {

	time(&now); /* get the current time */
	my_time = *localtime(&now); /* get the tm structure */
	timer_counter++;

	ModuleLoader_Map::iterator it;
	int do_delete = 1;
	if (!modules.empty())
		for (it=modules.begin(); it != modules.end(); it++) {
			NetGuard_ModuleLoader_Entry *module =  (*it).second;
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (!module->GetDoDelete() && !module->GetDoReload())
				module->module()->timer_tick();
			
			if (module->module()->GetType() == NETGUARD_INPUT_MODULE_TYPE)
			{
				if (module->GetDoDelete() || module->GetDoReload())
				{
					module_swaping = true;
					//((NetGuard_Input_Module*)module->module())->stop_poll();
					do_delete = !polling;
					if (!do_delete) {
						ng_slogdebug(log_str,"still polling .. waiting to release input modules %s ..",module->Name().c_str());
					};
				}
			}

			if (do_delete)
			{
				if (module->GetDoDelete()) {
					free_lib(module);
					return;
				}
				if (module->GetDoReload()) {
					std::string tmpfilename = module->FileName();
					std::string tmpname = module->Name();
					ng_slogdebug_spam(log_str,"reloading module %s ..",tmpname.c_str());

					NetGuard_Config *init_param = new NetGuard_Config();
					init_param->assign(module->module()->GetConfigData());
					init_param->add(load_params);

					if (free_lib(module)) return;

					ng_slogdebug_spam(log_str,"reloading module %s - from %s ",tmpname.c_str(),tmpfilename.c_str());
					NetGuard_ModuleLoader_Entry *mmodule = load_lib(tmpfilename);
					if (mmodule)
					{
						if (mmodule->module()->init(init_param))
						{
							ng_slogerror(log_str,"asking to unload module (failed init) %s ..",tmpname.c_str());
							mmodule->DoDelete();
						} else ng_slogdebug_spam(log_str,"reloading module .. done");

					} else ng_slogerror(log_str,"cant reload module %s - from %s ",tmpname.c_str(),tmpfilename.c_str());
					return;
				}
				module_swaping = false;
			}
		}

	if (last_save + save_timer <= now)
	{
		ng_slogdebug(log_str,"list: save_timer saving data");
		last_save = now;
		std::vector<std::string> params;
		std::vector<int> paramsint;
		params.push_back("save");
		paramsint.push_back(MININT);
		main_module_->got_input(params,paramsint,"");
		ng_slogdebug_spam(log_str,"saved ..");				
		last_save = now;

		//flush to clear memory
		log_ignore_buffer.clear();
		log_ignore_buffer_counter.clear();
	}

}

void NetGuard_ModuleLoader::poll() {
	polling = true;
	if (module_swaping) {
		polling = false;
		return;
	}

	ModuleLoader_Map::iterator it;
	long int found = 0;
	for (it=modules.begin(); it != modules.end(); it++) {
		if (!(*it).second) continue;
		NetGuard_Module *module =  (*it).second->module();
		if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
		if (module->GetType() == NETGUARD_INPUT_MODULE_TYPE)
		{
			found = found + ((NetGuard_Input_Module*)module)->poll();
		}
	}

	#ifndef no_input_timer
	patch this
	#endif

//                                1000000000 1 sec
//  const struct timespec ts1 = {0,500000000}; //1/2sec
	const struct timespec ts1 = {0,125000000}; //50  msec
	const struct timespec ts2 = {0,250000000}; //300 msec
	const struct timespec ts3 = {0,500000000}; //500 msec

	if (!found) {
		//ng_slog(log_str,"sleep");
		//int tmpres = ualarm(100000,0);
		//ng_slog(log_str,"alarm was scheduled %d",tmpres);
		//usleep(10000); // -> just creates crazy cpu load?! why?!
		//tmpres = 
		//sleep(1);
		nanosleep(&ts3,0);
		//usleep(10);
		//ng_slog(log_str,"sleep end %d",tmpres);
	} else {
		if (found <= 100)
		{
			nanosleep(&ts2,0);
		} else nanosleep(&ts1,0);
	}
	polling = false;
}

void NetGuard_ModuleLoader::stop_poll() {
	if (module_swaping) return;

	ModuleLoader_Map::iterator it;
	int found = 0;
	for (it=modules.begin(); it != modules.end(); it++) {
		if (!(*it).second) continue;
		NetGuard_Module *module =  (*it).second->module();
		if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
		if (module->GetType() == NETGUARD_INPUT_MODULE_TYPE)
		{
			((NetGuard_Input_Module*)module)->stop_poll();
			found = 1;
		}
	}
}


void *NetGuard_ModuleLoader::broadcast_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) {

	if (command == "user_shutdown")
	{
		ng_slogext(log_str,700,"broadcast user_shutdown");
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (module->GetType() == NETGUARD_USER_MODULE_TYPE)
			{
				((NetGuard_User_Module*)module)->user_shutdown((struct user_data *)data);
			}
		}
	}

	if (command == "user_init")
	{
		ng_slogext(log_str,700,"broadcast user_init");
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (module->GetType() == NETGUARD_USER_MODULE_TYPE)
			{
				((NetGuard_User_Module*)module)->user_init((struct user_data *)data);
			}
		}
	}

	if (command == "user_data_forgetday")
	{
		ng_slogext(log_str,700,"broadcast user_data_forgetday");
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (module->GetType() == NETGUARD_USER_MODULE_TYPE)
			{
				((NetGuard_User_Module*)module)->user_data_forgetday((int)data);
			}
		}
	}

	void *myret;
	ModuleLoader_Map::iterator it;
	for (it=modules.begin(); it != modules.end(); it++) {
		if (!(*it).second) continue;
		NetGuard_Module *module =  (*it).second->module();
		if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
		myret = ((NetGuard_Module*)module)->get_control_message(sender, command, params, data);
		if (myret)
		{
			return myret;
		}
	}
	return NULL;
}

void NetGuard_ModuleLoader::broadcast_packet(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) {
	polling = true;
	if (module_swaping) {
		polling = false;
		return;
	}

	ModuleLoader_Map::iterator it;
	for (it=modules.begin(); it != modules.end(); it++) {
		if (!(*it).second) continue;
		NetGuard_Module *module =  (*it).second->module();
		if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
		if (module->GetType() == NETGUARD_GENERAL_MODULE_TYPE)
		{
			((NetGuard_General_Module*)module)->packet_in(vlanid,h,eth,ip,tcp,data);
		}
	}

	polling = false;
}

void NetGuard_ModuleLoader::broadcast_user_packet(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) {
	if (module_swaping) return;
	polling = true;

	ModuleLoader_Map::iterator it;
	for (it=modules.begin(); it != modules.end(); it++) {
		if (!(*it).second) continue;
		NetGuard_Module *module =  (*it).second->module();
		if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
		if (module->GetType() == NETGUARD_USER_MODULE_TYPE)
		{
			((NetGuard_User_Module*)module)->packet_in(u_data,mode,vlanid,h,eth,ip,tcp,data);
		}
	}

	polling = false;
}

void NetGuard_ModuleLoader::log_message(NetGuard_Module *sender, char *message, int level) {
	
	if (do_broadcasting_input)//we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender->GetName(), tmessage, MININT, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		if (level >= 100) return;
	}

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	};
	
	LogLevel_Map::iterator entry = loglevels.find(sender->GetName());
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	if (sender) {
		printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
	} else  printf("%s - Log (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}

void NetGuard_ModuleLoader::log_message(std::string sender, char *message, int level) {

	if (do_broadcasting_input) //we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender, tmessage, MININT, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		if (level >= 100) return;
	}

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	}

	LogLevel_Map::iterator entry = loglevels.find(sender);
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}

void NetGuard_ModuleLoader::log_message_code(NetGuard_Module *sender, char *message, int retcode, int level) {
	
	if (do_broadcasting_input)//we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender->GetName(), tmessage, retcode, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		if (level >= 100) return;
	}

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	};
	
	LogLevel_Map::iterator entry = loglevels.find(sender->GetName());
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	if (sender) {
		printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
	} else  printf("%s - Log (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}

void NetGuard_ModuleLoader::log_message_code(std::string sender, char *message, int retcode, int level) {

	if (do_broadcasting_input) //we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender, tmessage, retcode, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		if (level >= 100) return;
	}

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	}

	LogLevel_Map::iterator entry = loglevels.find(sender);
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}



void NetGuard_ModuleLoader::log_message_buff(NetGuard_Module *sender, char *message, int ignore, int level) {
	
	if (do_broadcasting_input)//we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender->GetName(), tmessage, MININT, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);

		if (level >= 100) {
			if (ignore_next_log_buff_msg > 0) ignore_next_log_buff_msg--;
			return;
		}
	}

	if (ignore_next_log_buff_msg > 0)
	{
		ignore_next_log_buff_msg--;
		return;
	}

	long unsigned  int oldignore = 0 ;	
	LogBuff_Map::iterator entrylb = log_ignore_buffer.find(message);
	if (entrylb != log_ignore_buffer.end()) {
		if (difftime(GetNow(),(*entrylb).second) <= log_buff_timer)
		{
			log_ignore_buffer_counter[message]++;
			ignore_next_log_buff_msg = ignore;
			return;
		};
		log_ignore_buffer.erase(entrylb);
		oldignore = log_ignore_buffer_counter[message];
		LogBuff_Map_COUNT::iterator entrylbc = log_ignore_buffer_counter.find(message);
		log_ignore_buffer_counter.erase(entrylbc);
	}
	log_ignore_buffer[message] = GetNow();
	log_ignore_buffer_counter[message] = 0;

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	};
	
	LogLevel_Map::iterator entry = loglevels.find(sender->GetName());
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = "";
		if (sender) ldata->source = sender->GetName();
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	if (sender) {
		if (oldignore) printf("%s - Log \"%s\" (%d): next message(s) were ignored %lu times\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,oldignore);
		printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
	} else {
		if (oldignore) printf("%s - Log (%d): next message(s) were ignored %lu times\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,oldignore);
		printf("%s - Log (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
	}
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}

void NetGuard_ModuleLoader::log_message_buff(std::string sender, char *message, int ignore, int level) {

	if (do_broadcasting_input) //we are processing a command -> we pipe it back as result
	{
		sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
		ModuleLoader_Map::iterator it;
		for (it=modules.begin(); it != modules.end(); it++) {
			if (!(*it).second) continue;
			NetGuard_Module *module =  (*it).second->module();
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			std::string tmessage = message;
			((NetGuard_Module*)module)->got_result(NetGuard_ModuleLoader_Base::GetTime(), sender, tmessage, MININT, level);
		}
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);

		if (level >= 100) {
			if (ignore_next_log_buff_msg > 0) ignore_next_log_buff_msg--;
			return;
		}
	}

	if (ignore_next_log_buff_msg > 0)
	{
		ignore_next_log_buff_msg--;
		return;
	}

	long unsigned int oldignore = 0 ;	
	LogBuff_Map::iterator entrylb = log_ignore_buffer.find(message);
	if (entrylb != log_ignore_buffer.end()) {
		if (difftime(GetNow(),(*entrylb).second) <= log_buff_timer)
		{
			log_ignore_buffer_counter[message]++;
			ignore_next_log_buff_msg = ignore;
			return;
		};
		log_ignore_buffer.erase(entrylb);
		oldignore = log_ignore_buffer_counter[message];
		LogBuff_Map_COUNT::iterator entrylbc = log_ignore_buffer_counter.find(message);
		log_ignore_buffer_counter.erase(entrylbc);
	}
	log_ignore_buffer[message] = GetNow();
	log_ignore_buffer_counter[message] = 0;

	if (log_buff_recent_spam) 
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent_Spam.size() > log_buff_recent_spam)
			LogBuff_Recent_Spam.erase(LogBuff_Recent_Spam.begin());
	}

	LogLevel_Map::iterator entry = loglevels.find(sender);
	if ((entry != loglevels.end()) && (level > (*entry).second)) return;
	if ((entry == loglevels.end()) && (level>loglevel)) return;

	if (log_buff_recent)
	{
		log_buff_data* ldata = new log_buff_data;
		ldata->time = NetGuard_ModuleLoader_Base::GetNow();
		ldata->source = sender;
		ldata->level = level;
		ldata->message = message;
		LogBuff_Recent_Spam.push_back(ldata);
		while (LogBuff_Recent.size() > log_buff_recent)
			LogBuff_Recent.erase(LogBuff_Recent.begin());
	}

	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (logdelay >0) usleep(logdelay);
	if (oldignore) printf("%s - Log \"%s\" (%d): next message(s) were ignored %lu times\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,oldignore);
	printf("%s - Log \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}


void NetGuard_ModuleLoader::broadcast_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	NetGuard_ModuleLoader_Base::broadcast_input(params, intparams, command);

	ModuleLoader_Map::iterator it;

	if (params[0] == "loglevel")
	{
		if (params.size() == 3 && intparams[2]>=-1)
		{
			loglevels[params[1]] = intparams[2];
			ng_slogdebug(log_str,"loglevel for %s set to %d",params[1].c_str(),intparams[2]);
			return;
		}

		if (params.size() == 2 && intparams[1]>=-1)
		{
			loglevel = intparams[1];
			NetGuard_ModuleLoader_Base::basic_loglevel = loglevel;
			ng_slogdebug(log_str,"loglevel set to %d",loglevel);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: loglevel [<module>] <level>");
			return;
		}

	}

	if (params[0] == "logdelay")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			logdelay = intparams[1];
			ng_slogdebug(log_str,"logdelay set to %d",logdelay);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: logdelay <microsecond>");
			return;
		}
	}

	if (params[0] == "save_timer")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			save_timer = intparams[1];
			ng_slogdebug(log_str,"save_timer set to %d",save_timer);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: save_timer <seconds>");
			return;
		}
	}

	if (params[0] == "log_buff_sec")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			log_buff_timer = intparams[1];
			ng_slogdebug(log_str,"log_buff_sec set to %d",log_buff_timer);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: log_buff_sec <seconds>");
			return;
		}
	}

	if (params[0] == "log_buff_test")
	{
		ng_slog_buff(log_str,0,"test");
	}

	if (params[0] == "log_buff_recent")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			log_buff_recent = intparams[1];
			ng_slogdebug(log_str,"log_buff_recent set to %u",log_buff_recent);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: log_buff_recent <entrys>");
			return;
		}
		if (!log_buff_recent) LogBuff_Recent.clear();
		return;
	}

	if (params[0] == "log_buff_recent_spam")
	{
		if (params.size() == 2 && intparams[1]>0)
		{
			log_buff_recent_spam = intparams[1];
			ng_slogdebug(log_str,"log_buff_recent_spam set to %u",log_buff_recent_spam);
		} else {
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: log_buff_recent_spam <entrys>");
			return;
		}
		if (!log_buff_recent_spam) LogBuff_Recent_Spam.clear();
		return;
	}


	if (params[0] == "show")
	{
		if ((params.size() == 2)  && ((params[1] == "log_buff")  || (params[1] == "log_buff_spam"))) {
			if (do_broadcasting_input)
			{
				sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
				if (params[1] == "log_buff") {
					LogBuff::iterator itm;
					for (itm=LogBuff_Recent.begin(); itm != LogBuff_Recent.end(); itm++) {
						struct log_buff_data* mlogdata = (*itm);
						ng_slogout(log_str,"%u:%s:%d:%s",mlogdata->time,mlogdata->source.c_str(),mlogdata->level,mlogdata->message.c_str());
					}
				}
				if (params[1] == "log_buff_spam") {
					LogBuff::iterator itm;
					for (itm=LogBuff_Recent_Spam.begin(); itm != LogBuff_Recent_Spam.end(); itm++) {
						struct log_buff_data* mlogdata = (*itm);
						ng_slogout(log_str,"%u:%s:%d:%s",mlogdata->time,mlogdata->source.c_str(),mlogdata->level,mlogdata->message.c_str());
					}
				}
				NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
			} else {
				ng_slogout_ret(log_str,-1,"ignoring show as we dont have a client connected");
			}
		}
	}

	if (params[0] == "module_list")
	{
		ng_slogout(log_str,"Module List:");
		for (it=modules.begin(); it != modules.end(); it++) {
			const char *tmpstr;
			if (!(*it).second) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			switch ((*it).second->module()->GetType())
			{
				case NETGUARD_GENERAL_MODULE_TYPE: tmpstr = NETGUARD_GENERAL_MODULE_IDENT;break;
				case NETGUARD_USER_MODULE_TYPE: tmpstr = NETGUARD_USER_MODULE_IDENT; break;
				case NETGUARD_INPUT_MODULE_TYPE: tmpstr = NETGUARD_INPUT_MODULE_IDENT; break;
				case NETGUARD_COMMAND_INPUT_MODULE_TYPE: tmpstr = NETGUARD_COMMAND_INPUT_MODULE_IDENT;break;
				default: tmpstr = "unkown";
			}
			ng_slogout(log_str,"Name:%-30s\tVersion:%s\tType: %s",(*it).second->Name().c_str(),(*it).second->Version().c_str(),tmpstr);
		}
		return;
	}

	if (params[0] == "module_reload")
	{
		if (params.size() < 2)
		{
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: module_reload <name>");
			return;
		}
		NetGuard_ModuleLoader_Entry *entry = get_loaded_lib(params[1]);
		if (entry)
		{
			ng_slogout(log_str,"asking to reload module %s ..",params[1].c_str());
			entry->DoReload();
			return;
		}
	}

	if (params[0] == "module_unload")
	{
		if (params.size() < 2)
		{
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: module_unload <name>");			
			return;
		}
		NetGuard_ModuleLoader_Entry *entry = get_loaded_lib(params[1]);
		if (entry)
		{
			ng_slogdebug_spam(log_str,"asking to unload module %s ..",params[1].c_str());
			entry->DoDelete();
			timer_tick(); //save to call it here ?
			return;
		}
	}

	if (params[0] == "module_load")
	{
		if (params.size() < 2)
		{
			ng_slogout_ret(log_str,RET_WRONG_SYNTAX,"usage: module_load <filename>");
			return;
		}
		ng_slogdebug(log_str,"loading module %s ..",params[1].c_str());

		NetGuard_ModuleLoader_Entry *module = load_lib(params[1]);
		if (module)
		{
			NetGuard_Config *init_param = new NetGuard_Config();

			init_param->SetModule("root_module",main_module_);
			init_param->SetStr("control_pipe","/netguard"); //set default can be overwritten with load_params
			//this is used to init the singelton in the loaded dll
			init_param->SetPointer("module_loader",this); 
			init_param->SetPointer("global_ip_filter",NetGuard_Global_IP_Filter::GetPointer()); 
			init_param->SetPointer("global_cfg",GlobalCFG::GetPointer()); 
			init_param->SetPointer("state_handler",NetGuard_State_Handler::GetPointer());
			

			init_param->add(load_params);

			for (it=modules.begin(); it != modules.end(); it++) {
				if ((*it).second) { //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
					init_param->SetModule("module_"+(*it).second->Name(),(*it).second->module());
				}
			}

			if (module->module()->init(init_param))
			{
				ng_slogout(log_str,"unload module (failed on first init) %s ..",params[1].c_str());
				//module->DoDelete();
				free_lib(module);
			} else ng_slogdebug_spam(log_str,"module init ok %s ..",params[1].c_str());
			delete init_param;
		}
		return;
	}

	if (params[0] == "module_initparams_list")
	{
		ng_slogout(log_str,"init parameter list:");
		ConfigMap::iterator c_it;
		for (c_it = load_params->GetData()->begin(); c_it != load_params->GetData()->end(); c_it++) {
			switch ((*c_it).second->GetType())
			{
				case 0:
						ng_slogout(log_str,"name: %s value(int): %d",(*c_it).first.c_str(),(*c_it).second->GetInt());
						break;
				case 1:
						ng_slogout(log_str,"name: %s value: %s",(*c_it).first.c_str(),(*c_it).second->GetStr().c_str());
						break;
			}
		}
	}

	if (params[0] == "module_initparams_add")
	{
		if (params.size() < 3)
		{
			ng_slogout(log_str,"module_initparams_add <name> <value> - add a param");
			return;
		}

		
		if (intparams[2] != MININT)
		{
			 load_params->SetInt(params[1],intparams[2]);
			 ng_slogdebug(log_str,"added: %s (int) value: %s",params[1].c_str(),params[2].c_str());
		} else {
			load_params->SetStr(params[1],params[2]);
			ng_slogdebug(log_str,"added: %s value: %s",params[1].c_str(),params[2].c_str());
		}				
	}

	if (params[0] == "help")
	{
		ng_slogout(log_str,"save - list loaded modules");
		ng_slogout(log_str,"loglevel [<module>] <level> - set the loglevel");
		ng_slogout(log_str,"logdelay <microsecond> - delay each log line x microsecond");
		ng_slogout(log_str,"savetimer <seconds> - save data all x seconds");
		ng_slogout(log_str,"log_buff_sec <seconds> - log buffer ignores are buffered x seconds");		
		ng_slogout(log_str,"module_list - list loaded modules");
		ng_slogout(log_str,"module_reload <name> - reload a module");
		ng_slogout(log_str,"module_load <filename> - load a module from a file");
		ng_slogout(log_str,"module_unload <name> - unload a module ");
		ng_slogout(log_str,"module_initparams_list - list currently set init params");
		ng_slogout(log_str,"module_initparams_add <name> <value> - add a param");
		ng_slogout(log_str,"log_buff_recent <entrys> - keep x log entrys");
		ng_slogout(log_str,"log_buff_recent_spam <entrys> - keep x log entrys - filtered also");
		ng_slogout(log_str,"show log_buff[_spam] - show log buffers");
		
	}

	if (params[0] == "save")
	{
		ng_slogdebug_spam(log_str,"saving data"); 
		for (it=modules.begin(); it != modules.end(); it++) {
			NetGuard_ModuleLoader_Entry *module =  (*it).second;
			if (!module) continue; //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			if (!module->GetDoDelete() && !module->GetDoReload())	
				module->module()->savedata();
		}
	}

	for (it=modules.begin(); it != modules.end(); it++)
		if ((*it).second) { //can happen on clear etc - just make sure it dont make us crash -- check should not be needed here 
			(*it).second->module()->got_input(params,intparams,command);
		}

}
