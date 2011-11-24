	/***************************************************************************
 *   NetGuard Group Accounting Module                                      *
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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "rrd.hpp"

#include "compile.h"
#include "../../includes/logging.h"

#include <sys/stat.h>

NetGuard_RRD::NetGuard_RRD()
{
	ng_logdebug_spam("constructor");	
}
  
NetGuard_RRD::~NetGuard_RRD()
{
	ng_logdebug_spam("destructor");	
}
		
void NetGuard_RRD::loaddata()
{
}

void NetGuard_RRD::savedata()
{
}

int NetGuard_RRD::init(NetGuard_Config *data)
{
	ng_logdebug("init");
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	loaddata();

	return 0;
}

void NetGuard_RRD::shutdown()
{
	ng_logdebug_spam("shutdown");
}

void NetGuard_RRD::packet_in(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	return;
}

void NetGuard_RRD::user_data_forgetday(int day){
}

void NetGuard_RRD::timer_tick()
{
}

void NetGuard_RRD::mrrd_update(std::string filename,long long int value)
{
	int argc = 3;
	int ret = 0;
	char *tmpstr = (char*)malloc(5000);
	sprintf(tmpstr,"N:%lli",value);
	const char *argv[] = {
		"netguard", filename.c_str(), tmpstr, NULL
	};
	if ((ret = rrd_update (argc, (char **)argv))) {
		ng_logerror("Error updating RRD file: %s: %s", filename.c_str(), rrd_get_error ());
	}
	free(tmpstr);
}


void *NetGuard_RRD::get_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) 
{
	if (command=="5min_stats_pkssecs") {
		long long int *value =  (long long int *)data;
		ng_logdebug_spam("got 5min_stats_pkssecs - %lli ",(*value));
	}
	if (command=="5min_stats_sizesecs") {
		long long int *value =  (long long int *)data;
		ng_logdebug_spam("got 5min_stats_sizesecs - %lli",(*value));
	}
	if (command=="5min_stats_pks") {
		long long int *value =  (long long int *)data;
		ng_logdebug_spam("got 5min_stats_pks - %lli ",(*value));
		mrrd_update(GlobalCFG::GetStr("rrd.pks","rrd_pks.rrd"),(*value));
	}
	if (command=="5min_stats_size") {
		long long int *value =  (long long int *)data;
		ng_logdebug_spam("got 5min_stats_size - %lli",(*value));
		mrrd_update(GlobalCFG::GetStr("rrd.size","rrd_size.rrd"),(*value));
	}
	return NULL;
}

void NetGuard_RRD::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		//ng_logout("save - save groupdata");
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

}

void *NetGuard_RRD::get_data(void *data) {
	return NULL;
}

