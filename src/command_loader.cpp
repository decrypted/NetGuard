/***************************************************************************
 *   NetGuard Command Loader                                               *
 *                                                                         *
 *                                                                         *
 *   Copyright (c) 2011       Daniel Rudolph <daniel at net-guard net>     *
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

#include "command_loader.hpp"
#include "../includes/logging.h"
#include <values.h>

int NetGuard_Command_Loader::parsefile(std::string filename, NetGuard_Module *module) {

	if (!module) return -1;
	char str[65536];	
	std::fstream file_op(filename.c_str(),std::ios::in);
	if (file_op.fail()) {
		ng_slogerror("NetGuard_Command_Loader","error reading from file %s",filename.c_str());
		return -1;
	}

	while(!file_op.eof())
	{
		file_op.getline(str,sizeof(str));
		std::vector<std::string> params;
		std::vector<int> intparams;
		if (file_op.gcount() > 0)
		{
			ng_slogdebug("NetGuard_Command_Loader","read line: %s",str);
			if (str[0] != '#')
			{
				params.clear();
				intparams.clear();
				split(str," ",params, false);
				for( unsigned int i=0; i < params.size(); i++ )
				{
					int tmpval = 0;
					int read_ok = sscanf(params[i].c_str(),"%d", &tmpval);

					int parsed_ok = 0;
					if (read_ok)
					{
						//check if read number is whole string
						char buf[1024];
						sprintf(buf, "%d",tmpval);
						if (!strncmp(params[i].c_str(),buf,params[i].size())) parsed_ok = 1;
					}
				
					if (parsed_ok)
					{
						intparams.push_back(tmpval);
						ng_slogdebug_spam("NetGuard_Command_Loader","substring %d is an integer = '%d'\n", i+1, intparams[i]);
					} else {
						ng_slogdebug_spam("NetGuard_Command_Loader","substring %d = '%s'\n", i+1, params[i].c_str());
						intparams.push_back(MININT);
					}
					
				}

				if (module)
				{
					std::string data = str;
					if (params.size()) module->got_input(params,intparams,data);
				}

				usleep(100);
			} else ng_slogdebug("NetGuard_Command_Loader","ignored line: %s",str);
		}	
	}
	file_op.close();
	return 0;
}

