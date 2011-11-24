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

#ifndef NETGUARD_USER_SECURITY
#define NETGUARD_USER_SECURITY

#include "../../includes/tools.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/mac_filter.hpp"
#include "../../includes/types.hpp"
#include "../../includes/config.hpp"
#include "../../includes/modules/user_module.hpp"
#include "../../includes/modules/general_module.hpp"
#include "../../includes/state/state_handling.hpp"

#define user_security_module_number 30

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct user_security_data
	{
	//	int 			mode;
		mac_addr		hw_addr;
	} user_security_data;

#ifdef __cplusplus
}
#endif


typedef hash_map<const struct sec_data_idx, struct user_data* , hash_sec_data_idx, eq_sec_data_idx> ip_sec_hash;

#ifdef __cplusplus

class NetGuard_Security : public NetGuard_User_Module
{
	private:
		//not longer needed as we dont load/save int loaded;
		ip_sec_hash sec_data;
		//not longer needed as we dont load/save std::string db_filename;
		//not longer needed as we dont load/save int rename_onfail;

		u_int32_t zero_ip;

		NetGuard_General_Module *general_acccounting;
		User_Data_Tools *muser_data;

		int htons_ETHERTYPE_IP;
		int htons_ETHERTYPE_ARP;
		int htons_ETHERTYPE_8023;
		int htons_ETHERTYPE_8021D;

		NetGuard_Mac_Filter *Mac_IgnoreSpoof; //add gateways etc
		NetGuard_Mac_Filter *Mac_IgnoreProtocols; //add some macs you dont want to have warnings from because packages from other protocols
		NetGuard_Mac_Filter *Mac_IgnoreArpRequestDest; //add some macs you allow non broadcast arps as dests
		NetGuard_Mac_Filter *Mac_IgnoreArpRequestSrc; //add some macs you allow non broadcast arps as src
		
		mac_addr	null_hw_addr;
		mac_addr	bcast_hw_addr;

		NetGuard_State *mode_enabled;
		NetGuard_State *mode_disabled;
		NetGuard_State *mode_learn;
	public:
		
		NetGuard_Security();
		~NetGuard_Security();
		
		struct user_data *get_user(mac_addr *hw_addr,unsigned int *vlan_id);
		bool addmac_user_hash(struct user_data *u_data, mac_addr *hw_addr);
		bool delmac_user_hash(struct user_data *u_data, mac_addr *hw_addr);


		void loaddata();
		void savedata();
		void timer_tick();

		int init(NetGuard_Config *data);
		void shutdown();
		void clear();
		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		
		void user_init(struct user_data *u_data);
		void user_shutdown(struct user_data *u_data);
		void user_data_forgetday(int day);
	
		void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		//get a user based on the mac address
		void *get_data(void *data);

};

#endif

#endif

