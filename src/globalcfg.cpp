/***************************************************************************
 *   NetGuard Global Config                                                *
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


#include "../includes/config.hpp"
#include "../includes/logging.h"
#include <values.h>

void GlobalCFG::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_slogout("gcfg","gcfg_list - show all global config values set");
		ng_slogout("gcfg","gcfg <name> <value> - set a global cfg value");
	}

	if (params[0] == "gcfg_list")
	{
		ng_slogout("gcfg","listing:");
		ConfigMap *cmdata = GetData();
		ConfigMap::iterator it;
		for (it=cmdata->begin(); it != cmdata->end(); it++) {
			ConfigData *entry = (*it).second;
			if (!entry) continue;

			switch (entry->GetType())
			{
				case 0:
						ng_slogout("gcfg","int %s: %d",(*it).first.c_str(),entry->GetInt());
						break;
				case 1:
						ng_slogout("gcfg","str %s: %s",(*it).first.c_str(),entry->GetStr().c_str());
						break;
				default:
						ng_slogout("gcfg","%s: <unkown type>",(*it).first.c_str());
			}
		}
	}

	if (params[0] == "gcfg")
	{
			
		if (params.size() >= 3)
		{
			if (intparams[2]!=MININT)
			{
				SetInt(params[1],intparams[2]);
			} else {
				std::string mydata;
				for( unsigned int i=2; i < params.size(); i++ )
				{
					if (i>2)
						mydata.append(" ");
					mydata.append(params[i]);
				}
				SetStr(params[1],mydata);
			}

			ConfigData *entry = GetItem(params[1]);
			if (!entry) {
				ng_slogerror("gcfg","could not set %s",params[1].c_str());
				return;
			}

			switch (entry->GetType())
			{
				case 0:
						ng_slogout("gcfg","set int %s: %d",params[1].c_str(),entry->GetInt());
						break;
				case 1:
						ng_slogout("gcfg","set str %s: %s",params[1].c_str(),entry->GetStr().c_str());
						break;
			}
		} else ng_slogout_ret("gcfg",RET_WRONG_SYNTAX,"usage: gcfg <name> <value> - set a global cfg value");
	}
}
