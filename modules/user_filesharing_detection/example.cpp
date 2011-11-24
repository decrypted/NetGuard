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

#include "example.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/storage/user_data.hpp"

#include "ipt_ipp2p.h"
#include "math.h"

const struct tok p2p_Types[] = {
	{ IPP2P_EDK,	"EDK" },
	{ IPP2P_DATA_KAZAA, "DATA_KAZAA" },
	{ IPP2P_DATA_EDK, "DATA_EDK" },
	{ IPP2P_DATA_DC, "DATA_DC" },
	{ IPP2P_DC, "DC" },
	{ IPP2P_DATA_GNU, "DATA_GNU" },
	{ IPP2P_GNU, "GNU" },
	{ IPP2P_KAZAA, "KAZAA" },
	{ IPP2P_BIT,  "BIT" },
	{ IPP2P_APPLE,  "APPLE" },
	{ IPP2P_SOUL, "SOUL" },
	{ IPP2P_WINMX, "WINMX" },
	{ IPP2P_ARES, "ARES" },
	{ 0, NULL}
};

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

	ng_logdebug("%s",__FUNCTION__);

	if (ret) return ret;
	return 0;
}

void NetGuard_User_Example::shutdown() {	
	//deinit your private data here
}

void NetGuard_User_Example::timer_tick() {
	//this function get called every sec
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


int NetGuard_User_Example::get_p2p_type(int type) {
	double tmp = trunc(type/100);
	return (int)round(tmp);
}

void NetGuard_User_Example::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	//ng_logdebug("%s got a package",__FUNCTION__);

	//EXAMPLE USAGE check what modes you want for yourself !
	//TRAFFIC_KNOWN we saw before and we dont check that as we checked already if needed
	if (*mode == TRAFFIC_KNOWN) return;
	if (!u_data) return;

	int result = match(ip);
	if (result) {
		result = get_p2p_type(result);
		ng_logext(300,"src_ip: %-15s - detected p2p (id: %d) - %s\n ",inet_ntoa(*(struct in_addr *)&u_data->saddr),result,tok2str(p2p_Types,"n.k.", result));
		char *tmpstr = (char*)malloc(5000);
		sprint_package(tmpstr,vlanid,h,eth,ip,tcp,data);
		ng_logdebug("%s",tmpstr);
		free(tmpstr);
	}

}

