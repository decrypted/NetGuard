/***************************************************************************
 *   NetGuard Module Loader                                                *
 *                                                                         *
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

#ifndef NETGUARD_MODULE_LOADER
#define NETGUARD_MODULE_LOADER

#include "../includes/tools.h"
#include "../includes/module_loader_base.hpp"
#include "../includes/modules/module.hpp"
#include "../includes/modules/general_module.hpp"
#include "../includes/modules/user_module.hpp"
#include "../includes/modules/input_module.hpp"
#include "../includes/modules/command_input_module.hpp"

class NetGuard_ML_General_Module:public NetGuard_ModuleLoader_Entry
{
	protected:
		create_general_module_t create_general_module;
		destroy_general_module_t destroy_general_module;

	public:
		NetGuard_General_Module* module() { return (NetGuard_General_Module*)module_;}

		NetGuard_ML_General_Module(void *handle);
		~NetGuard_ML_General_Module();

		int loadmodule();
		int unloadmodule();
};

class NetGuard_ML_User_Module:public NetGuard_ModuleLoader_Entry
{
	protected:
		create_user_module_t create_user_module;
		destroy_user_module_t destroy_user_module;

	public:
		NetGuard_User_Module* module() { return (NetGuard_User_Module*)module_;}

		NetGuard_ML_User_Module(void *handle);
		~NetGuard_ML_User_Module();

		int loadmodule();
		int unloadmodule();
};

class NetGuard_ML_Input_Module:public NetGuard_ModuleLoader_Entry
{
	protected:
		create_input_module_t create_input_module;
		destroy_input_module_t destroy_input_module;

	public:
		NetGuard_Input_Module* module() { return (NetGuard_Input_Module*)module_;}

		NetGuard_ML_Input_Module(void *handle);
		~NetGuard_ML_Input_Module();

		int loadmodule();
		int unloadmodule();
};

class NetGuard_ML_Command_Input_Module: public NetGuard_ModuleLoader_Entry
{
	protected:
		create_command_input_module_t create_command_input_module;
		destroy_command_input_module_t destroy_command_input_module;

	public:
		NetGuard_Command_Input_Module* module() { return (NetGuard_Command_Input_Module*)module_;}

		NetGuard_ML_Command_Input_Module(void *handle);
		~NetGuard_ML_Command_Input_Module();

		int loadmodule();
		int unloadmodule();
};

struct log_buff_data
{
	time_t		time;
	std::string source;
	int			level;
	std::string	message;
};


typedef std::map<std::string, NetGuard_ModuleLoader_Entry*> ModuleLoader_Map;
typedef std::map<std::string, int> LogLevel_Map;
typedef std::map<std::string, time_t> LogBuff_Map;
typedef std::map<std::string, long unsigned int> LogBuff_Map_COUNT;
typedef std::vector<struct log_buff_data*> LogBuff;

class NetGuard_ModuleLoader: public NetGuard_ModuleLoader_Base
{
	private:
		NetGuard_Config *load_params;
		bool module_swaping;
		bool polling;

		void* load_symbol(void *handle, const char *symbol);

		void clear();

		int can_unload(std::string name);

		int loglevel;
		unsigned int logdelay;
		LogLevel_Map loglevels;
		LogBuff_Map log_ignore_buffer; //contains string -> time until ignore
		LogBuff_Map_COUNT log_ignore_buffer_counter;
		int ignore_next_log_buff_msg;
		int save_timer;
		int log_buff_timer;
		time_t last_save;

		unsigned int log_buff_recent;
		LogBuff LogBuff_Recent;
		unsigned int log_buff_recent_spam;
		LogBuff LogBuff_Recent_Spam;
	public:

		NetGuard_ModuleLoader(NetGuard_General_Module *main_module);
		~NetGuard_ModuleLoader();

		NetGuard_ModuleLoader_Entry *load_lib(std::string filename);

		NetGuard_ModuleLoader_Entry *get_loaded_lib(std::string name);
		int free_lib(std::string name);
		int free_lib(NetGuard_ModuleLoader_Entry *entry);

		void timer_tick(); //all modules
		void poll();  //all input modules
		void stop_poll();  //all input modules

		void broadcast_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		void *broadcast_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data);
		void log_message(NetGuard_Module *sender, char *message, int level = 0);
		void log_message(std::string sender, char *message, int level = 0);
		void log_message_code(NetGuard_Module *sender, char *message, int retcode, int level);
		void log_message_code(std::string sender, char *message, int retcode, int level);
		void log_message_buff(NetGuard_Module *sender, char *message, int ignore, int level);
		void log_message_buff(std::string sender, char *message, int ignore, int level);

		void broadcast_packet(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);
		void broadcast_user_packet(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		int Getloglevel() {return loglevel;};
		void Setloglevel(int level) {loglevel=level;};


};

#endif

