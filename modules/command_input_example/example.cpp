/***************************************************************************
 *                                                                         *
 *   NetGuard Command Input Example Module                                 *
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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>

#include "example.hpp"
#include "compile.h"
#include "../../includes/logging.h"

NetGuard_Command_Input_Example::NetGuard_Command_Input_Example()
{
	ng_logdebug_spam("constructor");
	CallBack_ = NULL;
}

NetGuard_Command_Input_Example::~NetGuard_Command_Input_Example()
{
	ng_logdebug_spam("destructor");
}

int NetGuard_Command_Input_Example::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	//thats defined for all command modules
	CallBack_ = data_->GetModule("root_module");

	//ng_ is printf like
	ng_logdebug("%s %s %d",__FUNCTION__,__FILE__,__LINE__);
	
	ng_log("Hello World - Init");
	ng_logext(100,"Hello World - not that important");
	ng_logdebug("Hello World im at add %x",(int)this);
	ng_logerror("log an example error at line %d",__LINE__);

	return 0;
}

void NetGuard_Command_Input_Example::shutdown() {	
	//deinit your private data here
	ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_Command_Input_Example::timer_tick() {
	//this function get called every sec
	ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_Command_Input_Example::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	//here you get all commands send to netguard
	//in params you see the commands - intparams get filled if the param is an int and in command you see the unparsed input
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}
}

