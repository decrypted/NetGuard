/***************************************************************************
 *   NetGuard FileSharing Detection Module                                 *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
 *                                                                         *
 *   This program module is released under        .                        *
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
 *                                                                         *
 *   Detection taken from   http://www.ipp2p.org/                          *
 *                                                                         *
 ***************************************************************************/

#ifndef NETGUARD_USER_EXAMPLE
#define NETGUARD_USER_EXAMPLE

#ifdef __cplusplus

extern "C" int match(struct iphdr *ip);

extern "C" const struct tok p2p_Types[];


#include "../../includes/tools.h"
#include "../../includes/types.hpp"
#include "../../includes/modules/user_module.hpp"


class NetGuard_User_Example : public NetGuard_User_Module
{
	private:
		int htons_ETHERTYPE_IP;
		int htons_ETHERTYPE_ARP;

		int get_p2p_type(int type);
	public:
		NetGuard_User_Example();
		~NetGuard_User_Example();
		
		int init(NetGuard_Config *data);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);

		void shutdown();
		
		void timer_tick();

		void loaddata();
		void savedata();
		

		void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		void user_init(struct user_data *u_data);

		void user_shutdown(struct user_data *u_data);
		
		void user_data_forgetday(int day);

		void *get_data(void *data) {return NULL;};

};

#endif

#endif

