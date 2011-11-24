/***************************************************************************
 *   NetGuard Module Definitions                                           *
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

#ifndef NETGUARD_MODULE_HPP
#define NETGUARD_MODULE_HPP

#include "../config.hpp"


//do not forget to change this if there was changes in the shared objects
//this is even more important if the shared objects get staticly linked in the modules and dont use a shared so
#define NETGUARD_MODULE_INTERFACE_VERSION "0.0.2"

//strings for the net_guard_module module call
#define NETGUARD_GENERAL_MODULE_IDENT "netguard_general_module"
#define NETGUARD_USER_MODULE_IDENT "netguard_user_module"
#define NETGUARD_INPUT_MODULE_IDENT "netguard_input_module"
#define NETGUARD_COMMAND_INPUT_MODULE_IDENT "netguard_command_input_module"

enum {
	NETGUARD_GENERAL_MODULE_TYPE = 1,
	NETGUARD_USER_MODULE_TYPE = 2,
	NETGUARD_INPUT_MODULE_TYPE = 3,
	NETGUARD_COMMAND_INPUT_MODULE_TYPE = 4,
};


class NetGuard_Module
{
	protected:
		std::string name_;
		//0  = 
		int type;
		NetGuard_Config *data_;

	public:
		std::vector<std::string> required_modules;

		NetGuard_Module()
			: name_("default_module"),type(0),data_(NULL) { };

		virtual ~NetGuard_Module();

		//load/save module data to this file
		virtual void loaddata() = 0;
		virtual void savedata() = 0;

		//initialize module structures
		virtual int init(NetGuard_Config *data);

		//stop the module
		virtual void shutdown() = 0;
		
		//processing of inputs comming from the pipe
		virtual void got_input_out(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		virtual void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command) = 0;
		virtual void got_result(const struct tm * time, std::string sender, std::string message, int retcode, int level) { return ;};

		//timer tick to check timed events etc
		virtual void timer_tick()  = 0;

		//get some data out of the module - it depends on the module what data this gonna be
		virtual void *get_data(void *data) = 0;

		//get a control message
		virtual void *get_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) { return NULL;};


		NetGuard_Config *GetConfigData() {return data_;};
		int GetType() {return type;};
		std::string GetName() {return name_;};
		void SetName(std::string invalue) {name_ = invalue;};

		inline std::string GetParamComment(std::vector<std::string> params, int startl) 
		{
			std::string my_tmp = "";
			for(size_t i=startl; i < params.size(); i++) {
				my_tmp.append(params[i]);
				if (i+1 < params.size())
				  my_tmp.append(" ");
			}
			return my_tmp;
		};


};


// the types of the module calls
typedef const char* (*net_guard_module_t)();
typedef const char* (*get_module_name_t)();
typedef const char* (*get_module_version_t)();
typedef const char* (*get_interface_version_t)();

#endif

