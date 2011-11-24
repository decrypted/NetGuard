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


#include <net/ethernet.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>


MYSQL_RES *runquery(void *arg, const char* query, bool wantres = false) {
	MYSQL mysql;
	NetGuard_Input *ngi = (NetGuard_Input*)arg;

	ng_slogdebug_spam(ngi,"executing query: %s",query);

	if (!mysql_init(&mysql))
	{
		ng_slogerror(ngi,"error on mysql_init: %s",mysql_error(&mysql));
		return NULL;
	};

	if (!mysql_real_connect(&mysql,ngi->ip.c_str(),ngi->login.c_str(),ngi->password.c_str(),ngi->database.c_str(),ngi->port,NULL,0))
	{
		ng_slogerror(ngi,"error connecting to database: %s",mysql_error(&mysql));
		return NULL;
	} else ng_slogdebug_spam(ngi,"connected...");

	int qres = mysql_real_query(&mysql,query,(unsigned int) strlen(query));
	if (qres)
	{
		ng_slogerror(ngi,"error on query %s: %s",query,mysql_error(&mysql));
		return NULL;
	}	else ng_slogdebug_spam(ngi,"query executed");

	
	if (wantres)
	{
		MYSQL_RES *mres = mysql_store_result(&mysql);
		mysql_close(&mysql);
		return mres;
	}
	mysql_close(&mysql);
	return NULL;
}

std::string output_result_set (MYSQL_RES *res_set)
{
	MYSQL_ROW row;
	unsigned int  i;
	unsigned int num_fields;


	ostringstream tmpstr;
	num_fields = mysql_num_fields (res_set);
	while ((row = mysql_fetch_row (res_set)) != NULL)
	{
		//unsigned long *lengths;
		//lengths = mysql_fetch_lengths(res_set);
		for (i = 0; i < num_fields; i++)
		{
			if (i > 0) tmpstr <<  '\t';
			//tmpstr << "[%.*s] " << (int)lengths[i] << row[i];
			tmpstr << row[i];
		};
		tmpstr << endl;
	}


	return tmpstr.str();
}

void *polling(void *arg)                    /* servlet thread */
{	
	NetGuard_Input *ngi = (NetGuard_Input*)arg;
	ng_slogdebug_spam(ngi,"polling");
	while (ngi->running)
	{
		if (ngi->sql_buffer.size() > 0)
		{
			sql_run_entry msql = ngi->sql_buffer.front();
			ngi->sql_buffer.erase(ngi->sql_buffer.begin());
			runquery(arg,msql.sql.c_str(),msql.resid > 0);

		}
		sleep(1);
	}
	ng_slogdebug_spam(ngi,"polling exit");
	return 0;
}

NetGuard_Input::NetGuard_Input()
{
	ng_logdebug_spam("constructor");
}

NetGuard_Input::~NetGuard_Input()
{
	ng_logdebug_spam("destructor");
	stop();
}

bool NetGuard_Input::start()
{
	running = 1;
	ng_logdebug_spam("init thread");

	pthread_t child;
	pthread_create(&child, 0, polling, this);       /* start thread */
	pthread_detach(child);							    /* don't track it */

	ng_logdebug_spam("start done");
	return true;
}

void NetGuard_Input::stop()
{
	running = 0;
	sleep(2);
}

int NetGuard_Input::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	CallBack_ = data_->GetModule("root_module");
	//if (data_->GetStr("control_pipe") == "")

	if (data_->GetStr("ip") == "") {
		ng_logerror("need ip in config data");
		return -2;
	}
	ip = data_->GetStr("ip");

	if (data_->GetStr("database") == "") {
		ng_logerror("need database in config data");
		return -2;
	}
	database = data_->GetStr("database");

	if (data_->GetStr("login") == "") {
		ng_logerror("need login in config data");
		return -2;
	}
	login = data_->GetStr("login");

	if (data_->GetStr("password") == "") {
		ng_logerror("need password in config data");
		return -2;
	}
	password = data_->GetStr("password");

	if (data_->GetInt("port") == 0) {
		ng_logerror("need an port in config data");
		return -2;
	}
	port = data_->GetInt("port");

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

	if (params[0] == "help")
	{
		ng_logout("run_sql [dump] <sql> - execute an sql query - it will happen async if dump 0 or not present");
	}

	if (params[0] == "run_sql")
	{
		int dump = 0;
		int startl = 1;

		if (params.size() < 1)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: run_sql [dump] <sql>");
			return;
		}

		if (intparams[1]!=MININT)
		{	
			dump = intparams[1];
			startl = 2;
		}

		std::string my_tmp = GetParamComment(params,startl);
		if (my_tmp == "") {
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: run_sql [dump] <sql>");
			return;
		}

		if (dump)
		{
			MYSQL_RES *myres = runquery(this, my_tmp.c_str(), true);
			if (myres != NULL)
			{
				ng_logout("%s",output_result_set(myres).c_str());
			}
		} else {
			sql_run_entry msql;
			msql.sql = my_tmp;
			msql.resid = 0;
			sql_buffer.push_back(msql);
		}
	}
}

void NetGuard_Input::got_result(const struct tm * time, std::string sender, std::string message, int retcode, int level)
{
	if (level < 2000)
	{
		//log_buffer.push_back(message);
	}
}


