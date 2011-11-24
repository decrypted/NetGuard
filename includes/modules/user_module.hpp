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


#ifndef NETGUARD_USERMODULE_HPP
#define NETGUARD_USERMODULE_HPP

#include "module.hpp"

enum {
	TRAFFIC_INCOMING = 1, //TRAFFIC where the dst ip was found in the db
	TRAFFIC_OUTGOING = 2,  //TRAFFIC where the src ip was found in the db
	TRAFFIC_NOSOURCE = 3,  //TRAFFIC where the dst ip was found in the db but not the src ip
	TRAFFIC_UNKOWN = 4,    //TRAFFIC where non was found not source ip and not target ip
	TRAFFIC_KNOWN = 5,    //TRAFFIC that had a known source - added to make it possible to only check a package once
	//packet_in get called at least 2 times in a NetGuard_User_Module if (its not ) TRAFFIC_UNKOWN
};

class NetGuard_User_Module : public NetGuard_Module
{
	private:
	public:
		NetGuard_User_Module() { name_ = ("default_user_module"); type = NETGUARD_USER_MODULE_TYPE;};
		virtual ~NetGuard_User_Module() {};

		//u_data can be null
		virtual void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) = 0;
		virtual void user_init(struct user_data *u_data)  = 0;
		virtual void user_shutdown(struct user_data *u_data)  = 0;
		virtual void user_data_forgetday(int day)  = 0;
};

// the types of the class factories
typedef NetGuard_User_Module* (*create_user_module_t)();
typedef void (*destroy_user_module_t) (NetGuard_User_Module* p);

#endif

