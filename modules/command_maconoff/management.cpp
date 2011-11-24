/***************************************************************************
 *                                                                         *
 *   NetGuard MaconOff Module                                              *
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
#include <fstream>

#include "management.hpp"
#include "compile.h"
#include "../../includes/logging.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <stdio.h>

#include <wait.h>

#define STRSIZE 1024

bool NetGuard_User_SCE_Maconoff::set_failure_state(NetGuard_User_State *user, std::string error) 
{
	NetGuard_State *my_state_f = NetGuard_State_Handler::get_state(GlobalCFG::GetStr("mof.failure_state","failure"));
	if (!my_state_f) {
		ng_slogerror(Get_Name().c_str(),"%s state %s unkown",__FUNCTION__,GlobalCFG::GetStr("mof.failure_state","failure").c_str());
		return false;
	}
	return user->set(my_state_f,error);
}

bool NetGuard_User_SCE_Maconoff::exec_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason)
{
	char swip[100];
	int swport;
	char *argv[255];

	if (user->Getuser().vlan_id != my_instance->mof_vlan_id) //if it is not our vlan -> return false which  results in use of another handler
		return false;

	//this handler make sure we do the actions we want on enable and disable
	//it always have to return true on the -> enabled or ->disabled state as we handle them - no matter if the transition itself failed or not!
	ng_slogdebug_spam("NetGuard_User_SCE_Maconoff","enter exec state change from <%s> to <%s> (user: %s vlan: %d) - reason %s",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());

	char *tmp = (char*)malloc(sizeof(unsigned char)*20);
	sprintmac(tmp,(*(user->params()->GetMac("mac"))));
	std::string my_mac = tmp;
	free(tmp);

	ng_slogdebug_spam("NetGuard_User_SCE_Maconoff","have mac %s",my_mac.c_str());


	if ((*to) == GlobalCFG::GetStr("state.disabled","disabled"))
	{
		ng_slogdebug("NetGuard_User_SCE_Maconoff","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());

		//can we find a room?
	    if(my_instance->resolve_room(&user->Getuser().saddr,swip,&swport))
	    {	
			char *tmpstr=(char*)malloc(STRSIZE);
			snprintf(tmpstr,STRSIZE-2,"%s -m s -s disable -i %s -p %i -a %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),swip,swport,my_mac.c_str());
			my_instance->parse_cmd(tmpstr,argv);
			//can we execute the command?
			if (my_instance->run_maconoff(argv)) {
				set_failure_state(user,"error on run_maconoff - disable"); //we could not execute -> set to failure state
			} else (*from) = to;
			free(tmpstr);			
	    } else {
			ng_slogerror("NetGuard_User_SCE_Maconoff","disable - could not find switch for user (user: %s vlan: %d)",inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id);
			set_failure_state(user,"disable - could not find switch for user");
		}
		return true;
	} else if ((*to) == GlobalCFG::GetStr("state.enabled","enabled")) {
		if ((**from) == GlobalCFG::GetStr("state.learn","learn")) 
			return false;

		ng_slogdebug("NetGuard_User_SCE_Maconoff","exec state change from <%s> to <%s> (user: %s vlan: %d) - reason '%s'",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());

		//can we find a room?
		if(my_instance->resolve_room(&user->Getuser().saddr,swip,&swport))
	    {	
			char *tmpstr=(char*)malloc(STRSIZE);
			snprintf(tmpstr,STRSIZE-2,"%s -m s -s enable -i %s -p %i -a %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),swip,swport,my_mac.c_str());
			my_instance->parse_cmd(tmpstr,argv);
			//can we execute the command?
			if (my_instance->run_maconoff(argv)) {
				set_failure_state(user,"error on run_maconoff - enable"); //we could not execute -> set to failure state
			} else (*from) = to;
			free(tmpstr);			
	    } else {
			ng_slogerror("NetGuard_User_SCE_Maconoff","enable - could not find switch for user (user: %s vlan: %d)",inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id);
			set_failure_state(user,"enable - could not find switch for user");
		}
		return true;
	}
	return false;
}

bool NetGuard_User_State_Check_Maconoff_Enable::checkstate(NetGuard_User_State* state_data)
{
	if (state_data->Getuser().vlan_id != my_instance->mof_vlan_id) //if it is not our vlan -> return false which  results in use of another handler
		return true;

	ng_slogdebug_spam(Get_Name().c_str(),"check state change for user (user: %s vlan: %d)",inet_ntoa(*(struct in_addr *)&state_data->Getuser().saddr),state_data->Getuser().vlan_id);	
	mac_addr n_hw_addr = {0,0,0,0,0,0};
	if (compare_mac(state_data->params()->GetMac("mac"),&n_hw_addr))
	{
		ng_slogerror(Get_Name().c_str(),"invalid enabled state - no mac in params (user: %s vlan: %d)",inet_ntoa(*(struct in_addr *)&state_data->Getuser().saddr),state_data->Getuser().vlan_id);	
		return false;
	}
	return true;
}

NetGuard_Maconoff::NetGuard_Maconoff()
{
//	ng_logdebug_spam("constructor");
	mof_vlan_id = 0;
	CallBack_ = NULL;
}

NetGuard_Maconoff::~NetGuard_Maconoff()
{
//	ng_logdebug_spam("destructor");
}

int NetGuard_Maconoff::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	//thats defined for all command modules
	CallBack_ = data_->GetModule("root_module");

	
	if (data_->GetInt("vlan_id") != MININT) {
		mof_vlan_id = data_->GetInt("vlan_id");
	}

	NetGuard_State_Handler::GetPointer()->register_exec(new NetGuard_User_SCE_Maconoff(this));

	NetGuard_State *my_state_f = NetGuard_State_Handler::get_state("enabled");
	if (!my_state_f) return -1;
	my_state_f->register_check(new NetGuard_User_State_Check_Maconoff_Enable(this));

	return 0;
}

void NetGuard_Maconoff::shutdown() {
	NetGuard_State_Handler::GetPointer()->do_clear_registered_exec("maconoff");
	NetGuard_State *my_state_f = NetGuard_State_Handler::get_state("enabled");
	if (my_state_f) my_state_f->do_clear_registerd_check_exec("maconoff");
	//deinit your private data here
	//ng_logdebug("%s",__FUNCTION__);
}

void NetGuard_Maconoff::timer_tick() {
	//this function get called every sec
	//ng_logdebug("%s",__FUNCTION__);
}

int NetGuard_Maconoff::resolve_room(in_addr_t *addr, char *swip, int *swport){
    struct hostent *host;
    char *ptr;
    struct stat fileinfo;

    char str[255];
    char room[100];
    char tmpswip[100];
    int  tmpswport;
    int check=0;
    	
	host = gethostbyaddr((char *)addr, sizeof(addr), AF_INET);
    if (host)
	{
		//get only the room number
		ng_logdebug_spam("Found full Hostname:%s", host->h_name);
		ptr = strtok(host->h_name,".");
    	ptr[strlen(ptr)+1] = '\0';
		ng_logdebug_spam("Check for Hostname:%s in db file", ptr);		
	    
		if (stat(GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),&fileinfo))
   		{
			ng_logerror("can not load %s",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str());
			return 0;
   		}

   		std::fstream file_op(GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),std::ios::in);
    
        while(!file_op.eof())
   		{
			file_op.getline(str,2000);
			if (sscanf (str,"%100s %100s %d",room,tmpswip,&tmpswport) == 3)
			{
				//ng_logdebug("check if :%s", room);
				int tmpval = strncasecmp(room,host->h_name,100);
				//ng_logdebug("check if :%s %i", room,tmpval);
				if(tmpval<=GlobalCFG::GetInt("mof.roomcheckboundry",-80))
				{
					ng_logdebug_spam("checked %s and room found... matched line (%i):\"%s\"",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),tmpval,str);
					strcpy(swip,tmpswip);
					*swport=*(&tmpswport);
					check=1;
					break;
				}		                		
			}
    	}

		if(check==0)
		    ng_logerror("checked %s - room *not* found...",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str());
		file_op.close();
		return check;
		
	} else {
		ng_logerror("can *not* resolve hostname!");
		return 0;
	}
}

int NetGuard_Maconoff::run_maconoff(char **argv){
    int len=0;
    int pipe_stdout_fd[2];
	//,pipe_stderr_fd[2];
    char puffer[PIPE_BUF];
    int pid,pid_get;
    
    int status;
    
    if(pipe(pipe_stdout_fd)<0)
    {
		ng_logerror("can not stdout_pipe");
		return -1;
    }

	char **mydata = argv;
	std::string tmp_str;
	while (*mydata != '\0' && mydata != NULL)
	{ 			
		tmp_str.append(*mydata);
		tmp_str.append(" ");
		*mydata++;
	} 
    
    /*if(pipe(pipe_stderr_fd)<0)
    {
	ng_logext(0,"can not stderr_pipe");
	return;
    }*/
    
    /*if((pid=fork())<0)
        ng_logext(0,"can not fork1!");
    else
    {
	if(pid>0)
	{
	    //main-prozess der weiter laeuft
	    pid_get=getpid();
	    ng_log("ich bin main-prozess mit ID: %i und habe child mit ID: %i",pid_get,pid);
	    wait(&status);
	}
	else
	{*/
	    if ((pid=fork())<0)  {
			ng_logerror("can not fork2!");
	    } else {
			if(pid>0)
			{
				//parent(der den rueckgabewert entgegen nimmt und auf den nicht gewartet wird)
				pid_get=getpid();
				//ng_log("ich bin parent mit ID: %i und habe child mit ID: %i",pid_get,pid);
				//schreiben schliessen, lesen von child
				close(pipe_stdout_fd[1]);
			
				while(read(pipe_stdout_fd[0],puffer + len,1))
				{	 
					if(len==sizeof(puffer)-2)
					{
						len++;
						puffer[len] = '\0';
						ng_logdebug("read (%d): %s",pid,puffer);
						len=0;
						continue;
					}
					len++;    
				}
				puffer[len] = '\0';
				if (strlen(puffer))
					ng_logdebug("read (%d): %s",pid,puffer);

				wait(&status);
				ng_logext(50,"executed %s - exitcode: %i",tmp_str.c_str(),WEXITSTATUS(status)); //make sure its also in the logfile
				return WEXITSTATUS(status);
			} else {    
				pid_get=getpid();
				ng_logdebug_spam("running %s",tmp_str.c_str());
				//ng_log("ich bin child mit ID: %i und habe child mit ID: %i",pid_get,pid);
			
				//lesen schliesen, schreiben in parent
				close(pipe_stdout_fd[0]);

				dup2(pipe_stdout_fd[1],STDOUT_FILENO);
				dup2(pipe_stdout_fd[1],STDERR_FILENO);
			
				//daemon(1,1);
				int errc = execvp(*argv,argv);
				ng_logerror("failed to execute %s - exitcode: %i",tmp_str.c_str(),errc);
				close(pipe_stdout_fd[1]);
				exit(-1);
			}
		}
//	}
//  }
	return -1;
}

void NetGuard_Maconoff::parse_cmd(char *line, char **argv) { 
	while (*line != '\0')  /* if not the end of line ....... */ 
	{ 			
		while (*line == ' ' || *line == '\t' || *line == '\n') *line++ = '\0';  /* replace white spaces with 0 */ 
		*argv++ = line; /* save the argument position */ 
		while (*line != '\0' && *line != ' ' && *line != '\t' && *line != '\n') line++; /* skip the argument until ... */ 
	} 
	*argv = '\0'; /* mark the end of argument list */ 
}

void NetGuard_Maconoff::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	in_addr_t addr;    
	char swip[100];
	int swport;

	char *argv[255];

	//here you get all commands send to netguard
	//in params you see the commands - intparams get filled if the param is an int and in command you see the unparsed input
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}


	if (params[0] == "help")
	{
		ng_logout("mof_enable <ip> - enable room based on ip");
		ng_logout("mof_disable <ip> - disable room based on ip");
		ng_logout("mof_renable <room> - enable room");
		ng_logout("mof_rdisable <room> - disable room ");
		ng_logout("mof_dump <ip> - dump roomnumber information for ip");
		ng_logout("mof_dump_r <room> - dump roomnumber information for room string");
		ng_logout("mof_exec <string> - exec maconoff command");
		ng_logout("mof_info - display some module config params");
	}

	if (params[0] == "mof_info")
	{
		ng_logout("Database File: %s",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str());
	}

	if (params[0] == "mof_enable")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_enable <ip>");
			return;
		}
	    		
	    addr = inet_addr(params[1].c_str());
	    if(resolve_room(&addr,swip,&swport))
	    {	
			char *tmpstr=(char*)malloc(STRSIZE);
			snprintf(tmpstr,STRSIZE-2,"%s -m s -s enable -i %s -p %i",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),swip,swport);
			parse_cmd(tmpstr,argv);
			run_maconoff(argv);
			free(tmpstr);
	    } else ng_logout_not_found("mof_enable - could not find switch");    
	}
	
	if (params[0] == "mof_renable")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_renable <room>");
			return;
		}
	    		
		char *tmpstr=(char*)malloc(STRSIZE);
		snprintf(tmpstr,STRSIZE-2,"%s -m s -s enable -r %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),params[1].c_str());
		parse_cmd(tmpstr,argv);
		run_maconoff(argv);
		free(tmpstr);
	}
	

	if (params[0] == "mof_disable")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_disable <ip>");
			return;
		}
	    		
	    addr = inet_addr(params[1].c_str());
	    if(resolve_room(&addr,swip,&swport))
	    {	
			char *tmpstr=(char*)malloc(STRSIZE);
			snprintf(tmpstr,STRSIZE-2,"%s -m s -s disable -i %s -p %i",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),swip,swport);
			parse_cmd(tmpstr,argv);
			run_maconoff(argv);
			free(tmpstr);
	    } else ng_logout_not_found("mof_disable - could not find switch");    
	}


	if (params[0] == "mof_rdisable")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_disable <room>");
			return;
		}
	    		
		char *tmpstr=(char*)malloc(STRSIZE);
		snprintf(tmpstr,STRSIZE-2,"%s -m s -s disable -r %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),params[1].c_str());
		parse_cmd(tmpstr,argv);
		run_maconoff(argv);
		free(tmpstr);
	}
	
	if (params[0] == "mof_dump")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_dump <ip>");
			return;
		}
	    		
	    addr = inet_addr(params[1].c_str());
	    if(resolve_room(&addr,swip,&swport))
	    {	
			//dump:
			//maconoff -m dump (-i ip [-p port] | -f) [-s dumpmacs]
			//maconoff -m dump (-r room | -a macaddress) [-s dumpmacs]
			//show port details
			char *tmpstr=(char*)malloc(STRSIZE);
			snprintf(tmpstr,STRSIZE-2,"%s -m dump -i %s -p %i",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),swip,swport);
			parse_cmd(tmpstr,argv);
			run_maconoff(argv);
			free(tmpstr);
	    } else ng_logout_not_found("mof_dump - could not find switch");    
	}
	
	if (params[0] == "mof_dump_r")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_dump_r <room>");
			return;
		}
	    		
		char *tmpstr=(char*)malloc(STRSIZE);
		snprintf(tmpstr,STRSIZE-2,"%s -m dump -r %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),params[1].c_str());
		parse_cmd(tmpstr,argv);
		run_maconoff(argv);
		free(tmpstr);
	}

	if (params[0] == "mof_exec")
	{
	    if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: mof_exec <string>");
			return;
		}
	    		
		char *tmpstr=(char*)malloc(STRSIZE);
		
		std::string my_tmp = GetParamComment(params,1);
		snprintf(tmpstr,STRSIZE-2,"%s %s",GlobalCFG::GetStr("mof.maconoff","./maconoff").c_str(),my_tmp.c_str());
		parse_cmd(tmpstr,argv);
		run_maconoff(argv);
		free(tmpstr);
	}

	if (params[0] == "mof_test")
	{
		ng_logdebug("mof_test .. running ls");
		argv[0]=(char*)malloc(STRSIZE);
		snprintf(argv[0],STRSIZE-2,"ls"); 
		if (params.size() >=2) {
			argv[1]=(char*)malloc(STRSIZE);
			snprintf(argv[1],STRSIZE-2,params[1].c_str()); 
		} else argv[1]=NULL;
		argv[2]=NULL;
		
		run_maconoff(argv);
	
		free(argv[0]);
		if (argv[1]) free(argv[1]);
	}
}
