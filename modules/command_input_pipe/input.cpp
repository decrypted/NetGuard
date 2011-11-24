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

#include "input.hpp"
#include "compile.h"
#include <values.h>
#include "../../includes/logging.h"

#ifdef no_input_timer
#define DN_ACCESS       0x00000001      /* File accessed in directory */
#define DN_MODIFY       0x00000002      /* File modified in directory */
#define DN_CREATE       0x00000004      /* File created in directory */
#define DN_DELETE       0x00000008      /* File removed from directory */
#define DN_RENAME       0x00000010      /* File renamed in directory */
#define DN_ATTRIB       0x00000020      /* File changed attribute */
#define DN_MULTISHOT    0x80000000      /* Don't remove notifier */
#define F_NOTIFY 1026

#include <fcntl.h>	/* in glibc 2.2 this has the needed
				   values defined */
#include <signal.h>
#endif


NetGuard_Input::NetGuard_Input()
{
	ng_logdebug_spam("constructor");
	pipe_fd = -1;
	CallBack_ = NULL;
	pipename = "";
	p_mode = 0622;
	enforce_pipe_perms = true;
}

NetGuard_Input::~NetGuard_Input()
{
	ng_logdebug_spam("destructor");
	stop();
}

bool NetGuard_Input::start()
{
	if (pipe_fd != -1 )  return false;
	int res = 0;
	res = mkfifo(pipename.c_str(),p_mode);
	if (enforce_pipe_perms) chmod(pipename.c_str(),p_mode);
	pipe_fd = open(pipename.c_str(),O_RDONLY|O_NONBLOCK);

	if(pipe_fd == -1) {
		ng_logerror("failed to open fifo at '%s': %s",pipename.c_str(),strerror(errno));
		exit(-1);
	} else {
		ng_logdebug("opened fifo at '%s'",pipename.c_str());
	}

	#ifdef no_input_timer
	fcntl(pipe_fd, F_SETOWN, getpid());
	fcntl(pipe_fd, F_SETSIG, fd_change_signal);
	//fcntl(pipe_fd, F_NOTIFY, DN_MODIFY|DN_MULTISHOT);
	fcntl(pipe_fd, F_NOTIFY, DN_MODIFY);
	fcntl(pipe_fd,F_SETFL,fcntl(pipe_fd,F_GETFL)|O_ASYNC);
	#endif

	std::string tmp_str;
	while (read_line(tmp_str));
	return true;
}

void NetGuard_Input::stop()
{
	if (pipe_fd == -1 )  return;
	ng_logdebug("closing fifo file at '%s'",pipename.c_str());
	close(pipe_fd);
	pipe_fd = -1;
	unlink(pipename.c_str());
}

bool NetGuard_Input::read_line(std::string& str)
{
	if(pipe_fd == -1) {
		return false;
	}

	const size_t block_size = 4096;
	char block[block_size];

	const size_t nbytes = read(pipe_fd,block,block_size);
	std::copy(block,block+nbytes,std::back_inserter(buffer));

	const std::deque<char>::iterator itor = std::find(buffer.begin(),buffer.end(),'\n');
	if(itor != buffer.end()) {
		str.resize(itor - buffer.begin());
		std::copy(buffer.begin(),itor,str.begin());
		buffer.erase(buffer.begin(),itor+1);
		ng_logdebug("read '%s' from pipe",str.c_str());
		return true;
	} else {
		return false;
	}
	
}

void NetGuard_Input::parse_line(std::vector<std::string>& params, std::vector<int>& intparams, std::string& command)
{
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
	if (data_->GetStr("control_pipe") == "")
	{
		ng_logerror("need an pipe filename in config data");
		return -2;
	}
	pipename = data_->GetStr("control_pipe");

	if (data_->GetInt("control_pipe_mode") != MININT) {
		p_mode = data_->GetInt("control_pipe_mode");
	}
	ng_logdebug("using mode %u for input pipe %s",p_mode,pipename.c_str());

	if (data_->GetStr("control_pipe_ignoremode") != "") {
		enforce_pipe_perms = false;
	}

	start();
	return 0;
}

void NetGuard_Input::shutdown() {
	stop();
}

void NetGuard_Input::timer_tick() {
	std::string data;
	while (read_line(data))
	{
		if (data != "" ) {
			std::vector<std::string> cmd_splited;
			std::vector<int> cmd_splited_ints;
			parse_line(cmd_splited,cmd_splited_ints,data);
			if (CallBack_)
			{
				if (cmd_splited.size()) CallBack_->got_input(cmd_splited,cmd_splited_ints,data);
			}
		}		
	}
}

void NetGuard_Input::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}
}



