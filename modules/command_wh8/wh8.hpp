/***************************************************************************
 *   NetGuard Command Input WH8 Module                                     *
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

#ifndef NETGUARD_WH8_STATE_COMMAND
#define NETGUARD_WH8_STATE_COMMAND


#include "../../includes/tools.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/types.hpp"
#include "../../includes/modules/command_input_module.hpp"
#include "../../includes/modules/user_module.hpp"
#include "../../includes/modules/general_module.hpp"
#include "../../includes/state/state_handling.hpp"

#include <netinet/in.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <linux/socket.h>
#include "snmp_layer.h"
#include "nsnmp_layer.h"

#define MAXDUMPQUERRYLENGTH 1024

typedef vector<mac_addr *> mac_vector;

class NetGuard_Command_Input_WH8: public NetGuard_Command_Input_Module
{
	private:
		string community;

		NetGuard_General_Module *general_acccounting;
		User_Data_Tools *muser_data;
		
		unsigned char *getmacfromoid(char *input);
		char *doquery(char *ip, char* oid);
		void dowalkquery(char *ip, char* oid, char *results[]);
		char *doset(char *ip, char* oid, char *value);
		char *doportquery(char *ip,char *oid, int port);
		char *doportset(char *ip,char *oid, int port, char *value);

		int getmaxmacs(u_int32_t ip, int port);
		int getmacslearned(u_int32_t ip, int port);
		unsigned char *getmacfrommac_addr(mac_addr mac);
		int getadminstatus(u_int32_t ip, int port);

		mac_vector getmacs(u_int32_t ip, int port);

	public:
		NetGuard_Command_Input_WH8();
		~NetGuard_Command_Input_WH8();

		int init(NetGuard_Config *data);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);

		void shutdown();
		
		void timer_tick();

		void loaddata() {};
		void savedata() {};

		void *get_data(void *data) {return NULL;};


		bool find_mac(mac_addr mac,u_int32_t *ip, int *port, string *name);
		string get_room_from_mac(mac_addr mac);
		int resolve_room(in_addr_t *addr, u_int32_t *swip, int *swport);
		int user_state_load_logins();
		int user_state_load_rooms();
		

};

class NetGuard_User_SCE_WH8: public NetGuard_User_State_Change_Execution
{
	public:
		NetGuard_Command_Input_WH8 *my_instance;
		NetGuard_User_SCE_WH8(NetGuard_Command_Input_WH8 *instance): NetGuard_User_State_Change_Execution("wh8") {my_instance=instance;};
		void done_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason);
};


#endif

