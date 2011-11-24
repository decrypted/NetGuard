/***************************************************************************
 *   NetGuard Mac Filter                                                   *
 *   Class to fast matching a list of mac addresses                        *
 *   working with a 5 level (dynamic depth hash)                           *
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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>
#include <cstdlib>
#include <cc++/socket.h>
#include <cc++/address.h>

#include "input.hpp"
#include "compile.h"
#include <values.h>
#include "../../includes/logging.h"

void *polling(void *arg)                    /* servlet thread */
{	
	NetGuard_Input *ngi = (NetGuard_Input*)arg;

	while (ngi->running && ngi->sd)
	{
		int done, n, s2;
		struct sockaddr_un remote;
		socklen_t t;
		char str[1024];

		ng_slogdebug_spam(ngi,"Waiting for a connection...");
		t = sizeof(remote);
		if ((s2 = accept(ngi->sd, (struct sockaddr *)&remote, &t)) == -1) {
			continue;
		}

		if (!(ngi->running && ngi->sd))
		{
			if (s2) close(s2);
			return 0;
		}

		ng_slogdebug_spam(ngi,"Connected.");

		done = 0;
		do {
			bzero(&str,sizeof(str));
			n = recv(s2, str, sizeof(str), 0);
			if (n <= 0) {
				if (n < 0) ng_slogerror(ngi,"recv");
				done = 1;
			}

			if (!done)  {
				std::string data = str;
				if (data != "" ) {
					ngi->log_buffer.clear();
					std::vector<std::string> cmd_splited;
					std::vector<int> cmd_splited_ints;
					ngi->parse_line(cmd_splited,cmd_splited_ints,data);
					if (ngi->CallBack_)
					{
						if (cmd_splited.size()) {
							if (cmd_splited[0] == "bye") done = 1;
							if (cmd_splited[0] == "quit") done = 1;
							if (cmd_splited[0] == "exit") done = 1;
							if (!done) ngi->CallBack_->got_input_out(cmd_splited,cmd_splited_ints,data);
						}
					}


					int write_out = 1;
					for( unsigned int i=0; i < ngi->log_buffer.size(); i++ )
					{
						
						if (cmd_splited[0] == "help")  {
							if (cmd_splited.size() > 1) {
								std::string::size_type pos=ngi->log_buffer[i].find(cmd_splited[1]);
								write_out = pos!=string::npos;
							}							
						}

						//fputs(ngi->log_buffer[i].c_str(), s2);
						if (write_out) {
							ngi->log_buffer[i] += "\r\n";
							if (send(s2,ngi->log_buffer[i].c_str(),ngi->log_buffer[i].size(),0) < 0)
							{
								s2 = 0;
								done = 1;
								break;
							}
						}
					}

					ngi->log_buffer.clear();
				}	
			}
		} while (!done);

		if (s2)
		{
			close(s2);
		}
	}
	return 0;
}


NetGuard_Input::NetGuard_Input()
{
	ng_logdebug_spam("constructor");
	running = 1;
}

NetGuard_Input::~NetGuard_Input()
{
	ng_logdebug_spam("destructor");
	stop();
}

bool NetGuard_Input::start()
{
	int len;
	struct sockaddr_un local;

	if ((sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ng_logerror("cant get socket");
		return false;
	}

	local.sun_family = AF_UNIX;
	strcpy(local.sun_path, SOCK_PATH);
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);
	if (bind(sd, (struct sockaddr *)&local, len) == -1) {
		ng_logerror("cant bind socket");
		return false;
	}

	if (listen(sd, 5) == -1) {
		ng_logerror("cant listen socket");
		return false;
	}

	if (socketmode)
		chmod(SOCK_PATH,socketmode);

	pthread_t child;
	pthread_create(&child, NULL, polling, this);       /* start thread */
	pthread_detach(child);							    /* don't track it */

	return true;
}

void NetGuard_Input::stop()
{
	running = 0;
	int tmpsd = sd;
	sd = 0;
	if (tmpsd)
	  close(tmpsd);
	sleep(1);
}

void NetGuard_Input::parse_line(std::vector<std::string>& params, std::vector<int>& intparams, std::string& command)
{
	if (!command.empty() && command[command.length()-1] == '\n') {
		command.erase(command.length()-1);
	}
	if (!command.empty() && command[command.length()-1] == '\r') {
		command.erase(command.length()-1);
	}

	params.clear();
	intparams.clear();
	split(command.c_str()," ",params, false);
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
			ng_logdebug_spam("substring %d is an integer = '%d'", i+1, intparams[i]);
		} else {
			ng_logdebug_spam("substring %d = '%s'", i+1, params[i].c_str());
			intparams.push_back(MININT);
		}
		
	}

}

int NetGuard_Input::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	CallBack_ = data_->GetModule("root_module");
	//if (data_->GetStr("control_pipe") == "")

	socketmode = 0;
	if (data_->GetInt("mode") != MININT) {
		socketmode = data_->GetInt("mode");
	}
	

	start();
	return 0;
}

void NetGuard_Input::shutdown() {
	stop();
}

void NetGuard_Input::timer_tick() {
	return;
}

void NetGuard_Input::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}
}

void NetGuard_Input::got_result(const struct tm * time, std::string sender, std::string message, int retcode, int level)
{
	if (level < 2000)
	{
		if (retcode != MININT)
		{
			ostringstream tmpstr;
			tmpstr << "ret:" << retcode << ":" << message;
			log_buffer.push_back(tmpstr.str());
		} else log_buffer.push_back(message);
	}
}


