/***************************************************************************
 *   NetGuard Fifo Input                                                   *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
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

#ifndef NETGUARD_FIFO
#define NETGUARD_FIFO


#include "../../includes/tools.h"
#include "../../includes/types.hpp"
#include "../../includes/modules/command_input_module.hpp"

#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <pthread.h>
#include <netdb.h>


typedef struct sql_run_entry{
		std::string sql;
		int resid;
} sql_run_entry;


class NetGuard_Input: public NetGuard_Command_Input_Module
{
	private:
		struct sockaddr_in addr;
		bool start();
		void stop();
	
	public:
		volatile int running;

		std::string ip;
		std::string database;
		std::string login;
		std::string password;
		int port;

		std::vector<sql_run_entry> sql_buffer;
		NetGuard_Input();
		~NetGuard_Input();

		int init(NetGuard_Config *data);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		void got_result(const struct tm * time, std::string sender, std::string message, int retcode, int level);

		void shutdown();
		
		void timer_tick();

		void loaddata() {};
		void savedata() {};

		void *get_data(void *data) {return NULL;};

};


#endif

