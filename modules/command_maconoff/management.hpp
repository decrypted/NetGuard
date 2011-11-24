/***************************************************************************
 *   NetGuard Command Input Example Module                                 *
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

#ifndef NETGUARD_MACONOFF
#define NETGUARD_MACONOFF


#include "../../includes/tools.h"
#include "../../includes/types.hpp"
#include "../../includes/modules/command_input_module.hpp"
#include "../../includes/state/state_handling.hpp"

class NetGuard_Maconoff: public NetGuard_Command_Input_Module
{
	private:
	public:
		unsigned int mof_vlan_id;

		NetGuard_Maconoff();
		~NetGuard_Maconoff();

		int init(NetGuard_Config *data);

		void parse_cmd(char *line, char **argv);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);

		void shutdown();
		
		void timer_tick();

		void loaddata() {};
		void savedata() {};

		void *get_data(void *data) {return NULL;};


		int resolve_room(in_addr_t *addr, char *swip, int *swport);
		
		int run_maconoff(char **argv);
};

class NetGuard_User_SCE_Maconoff: public NetGuard_User_State_Change_Execution
{
	private:
		bool set_failure_state(NetGuard_User_State *user, std::string error);
	public:
		NetGuard_Maconoff *my_instance;
		NetGuard_User_SCE_Maconoff(NetGuard_Maconoff *instance): NetGuard_User_State_Change_Execution("maconoff") {my_instance=instance;};
		bool exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason);
};

class NetGuard_User_State_Check_Maconoff_Enable: public NetGuard_User_State_Check
{
	public:
		NetGuard_Maconoff *my_instance;
		NetGuard_User_State_Check_Maconoff_Enable(NetGuard_Maconoff *instance): NetGuard_User_State_Check("maconoff") {my_instance=instance;};
		bool checkstate(NetGuard_User_State* state_data);
};


#endif

