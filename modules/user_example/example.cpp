/***************************************************************************
 *   NetGuard Example User Module                                          *
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

#include "example.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/storage/user_data.hpp"

NetGuard_User_Example::NetGuard_User_Example()
{
	ng_logdebug_spam("constructor");
	htons_ETHERTYPE_IP = htons(ETHERTYPE_IP);
	htons_ETHERTYPE_ARP = htons(ETHERTYPE_ARP);	
}

NetGuard_User_Example::~NetGuard_User_Example()
{
	ng_logdebug_spam("destructor");
}

void NetGuard_User_Example::savedata()
{
	ng_logdebug("%s %s %d",__FUNCTION__,__FILE__,__LINE__);
}

void NetGuard_User_Example::loaddata()
{
}

int NetGuard_User_Example::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	//ng_ is printf like
	ng_logdebug("%s %s %d",__FUNCTION__,__FILE__,__LINE__);
	
	ng_log("Hello World - Init");
	ng_logext(100,"Hello World - not that important");
	ng_logdebug("Hello World im at add %x",(int)this);
	ng_logerror("log an example error at line %d",__LINE__);

	return 0;
}

void NetGuard_User_Example::shutdown() {	
	//deinit your private data here
	ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_User_Example::timer_tick() {
	//this function get called every sec
	ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_User_Example::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	//here you get all commands send to netguard
	//in params you see the commands - intparams get filled if the param is an int and in command you see the unparsed input
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}
}


void NetGuard_User_Example::user_init(struct user_data *u_data)
{
	//init log dependent user data
	ng_logdebug("init module data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	//u_data->module_data[<mymodulenumber>] = my_data;
}

void NetGuard_User_Example::user_shutdown(struct user_data *u_data)
{
	ng_logdebug("shutdown module data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	//free your own data before
	//u_data->module_data[<mymodulenumber>] = NULL;
}

void NetGuard_User_Example::user_data_forgetday(int day)
{
	//forget user data for a special day of the week
	ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_User_Example::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	ng_logdebug("%s got a package",__FUNCTION__);

	//EXAMPLE USAGE check what modes you want for yourself !
	//TRAFFIC_KNOWN we saw before and we dont check that as we checked already if needed
	if (*mode == TRAFFIC_KNOWN) return;

	if ((eth->ether_type != htons_ETHERTYPE_IP) && (eth->ether_type != htons_ETHERTYPE_ARP)) 
	{
		ng_logdebug("not checking data for protocol %6s (0x%04x)",tok2str(str_ethertype_values,"n.k.", ntohs(eth->ether_type)),ntohs(eth->ether_type));
		print_package(vlanid,h,eth,ip,tcp,data);
		return;
	};

	switch (htons(eth->ether_type))
	{
	case ETHERTYPE_ARP:
		break;
	case ETHERTYPE_IP:
		break;
	}

}

