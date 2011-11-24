/***************************************************************************
 *   NetGuard Global IP Filter                                             *
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


#include "../includes/tools.h"
#include "../includes/logging.h"
#include "../includes/ip_filter.hpp"
#include <values.h>

void NetGuard_Global_IP_Filter::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_slogout("ip_filter","ip_filters are connected with or within the same level - and with and on lower levels");
		ng_slogout("ip_filter","ip_filter_list - show all global config values set");
		ng_slogout("ip_filter","ip_filter_create <name> - add a filter in the filter chain (test.x.y ...)");
		//ng_slogout("ip_filter","ip_filter_erase <name> - delete a filter (test.x.y ...)");
		ng_slogout("ip_filter","ip_filter_add <name> <min_ip> <max_ip> - add a rule in the filter chain (test.x.y ...)");
		ng_slogout("ip_filter","ip_filter_del <name> <min_ip> <max_ip> - delete rule from the filter chain (test.x.y ...)");
		ng_slogout("ip_filter","ip_filter_del <name> <id> - delete rule with (id - from list) out of the filter chain (test.x.y ...)");
		ng_slogout("ip_filter","ip_filter_test <name> <ip> - test a filter chain (test.x.y ...) with ip");
	}

	if (params[0] == "ip_filter_list")
	{
		ng_slogout("ip_filter","listing:");
		listranges(1);
	}

	if (params[0] == "ip_filter_create")
	{
		if (params.size() == 2)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],true);
		} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_create <name> - add a filter in the filter chain (test.x.y ...)");
	}

	if (params[0] == "ip_filter_erase")
	{
		ng_slogerror("ip_filter","ip_filter can not be erased for now - you need to restart netguard");
/*		if (params.size() == 2)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],false);
			if (tmpConfig == NULL) return;
			std::string tmpname;
			if (tmpConfig->filtercount() !=0)
			{
				ng_slogout("ip_filter","ip_filter_erase can not delete filters with subfilters for a security reason");
				return;
			}
			tmpname =  tmpConfig->name();
			tmpConfig = get_filter(params[1],false,1);
			if (tmpConfig == NULL) return;
			tmpConfig->del_filter(tmpname);

		} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_erase <name> - delete a filter (test.x.y ...)");*/
	}

	if (params[0] == "ip_filter_add")
	{
		if (params.size() == 4)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],false);
			if (tmpConfig == NULL) return;

			struct in_addr min_ip;
			min_ip.s_addr = 0;
			if (!inet_aton(params[2].c_str(),&min_ip ))
			{	
				ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_add <name> <min_ip> <max_ip> - add a rule in the filter chain (test.x.y ...)");
				return;
			}
			struct in_addr max_ip;
			max_ip.s_addr = 0;
			if (!inet_aton(params[3].c_str(),&max_ip ))
			{	
				ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_add <name> <min_ip> <max_ip> - add a rule in the filter chain (test.x.y ...)");
				return;
			}

			tmpConfig->addrange(min_ip.s_addr,max_ip.s_addr);
		} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_add <name> <min_ip> <max_ip> - add a rule in the filter chain (test.x.y ...)");
	}

	if (params[0] == "ip_filter_del")
	{
		if (params.size() == 3)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],false);
			if (tmpConfig == NULL) return;

			if (intparams[2] != MININT)
			{
				tmpConfig->delrange_id(intparams[2]);
				return;
			} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_del <name> <id> - delete rule with (id - from list) out of the filter chain (test.x.y ...)");
		}
		if (params.size() == 4)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],false);
			if (tmpConfig == NULL) return;

			struct in_addr min_ip;
			min_ip.s_addr = 0;
			if (!inet_aton(params[2].c_str(),&min_ip ))
			{	
				ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_del <name> <min_ip> <max_ip> - delete rule from the filter chain (test.x.y ...)");
				return;
			}
			struct in_addr max_ip;
			max_ip.s_addr = 0;
			if (!inet_aton(params[3].c_str(),&max_ip ))
			{	
				ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_del <name> <min_ip> <max_ip> - delete rule from the filter chain (test.x.y ...)");
				return;
			}

			tmpConfig->delrange(min_ip.s_addr,max_ip.s_addr);
		} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_del <name> <min_ip> <max_ip> - delete rule from the filter chain (test.x.y ...)");
	}


	if (params[0] == "ip_filter_test")
	{
		if (params.size() == 3)
		{
			NetGuard_IP_Filter* tmpConfig = NULL;
			tmpConfig = get_filter(params[1],false);
			if (tmpConfig == NULL) return;

			struct in_addr my_ip;
			my_ip.s_addr = 0;
			if (!inet_aton(params[2].c_str(),&my_ip ))
			{	
				ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_test <name> <ip> - test a filter chain (test.x.y ...) with ip");
				return;
			}
			my_ip.s_addr = ntohl(my_ip.s_addr);
			if ((*tmpConfig) == &my_ip.s_addr)
			{
				ng_slogout_ok("ip_filter","ip_filter_test DID match for %s in chain %s",params[2].c_str(),params[1].c_str());
			} else ng_slogout_ok("ip_filter","ip_filter_test did NOT match for %s in chain %s",params[2].c_str(),params[1].c_str());
		} else ng_slogout_ret("ip_filter",RET_WRONG_SYNTAX,"usage: ip_filter_test <name> <ip> - test a filter chain (test.x.y ...) with ip");
	}

}
