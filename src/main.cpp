/***************************************************************************
 *   NetGuard Main Program                                                 *
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
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>
#include <string>
#include <time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <math.h>

#include "main.hpp"
#include "command_loader.hpp"
#include "compile.h"
#include "../includes/logging.h"
#include "../includes/config.hpp"
#include <values.h>

NetGuard_Main * __netguard = NULL;

NetGuard_Main::NetGuard_Main(int argc, char *argv[]){
	name_ = "NetGuard_Main";	
	ng_logdebug_spam("constructor");	
	pkt_count = 0;
	pkt_size = 0;
	pkt_count_l5 = 0;
	pkt_size_l5 = 0;
	is_running = 1;
	main_pid = getpid();
	#ifndef no_input_timer
	timer = 0;
	alarm_seconds = 1;
	#else
	alarm_seconds = 3;
	#endif
	logfile_spam = NULL;
	logfile_name_save = "";
	logfile_spamname_save = "";
	umask(022);
	isdaemon = false;
    NetGuard_Global_IP_Filter::Get();
	//GlobalCFG::Get(); done even more early

	int mylev = 0;

	//set log levels -> new default is 0 - and can be adjusted with command line -v
	NetGuard_ModuleLoader_Base::basic_loglevel = mylev;
	int i;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "-vvv") == 0)
			mylev = 9999;
		else if (strcmp(argv[i], "-vv") == 0)
			mylev = 2000;
		else if (strcmp(argv[i], "-v") == 0)
			mylev = 1000;
		else if (strcmp(argv[i], "-q") == 0)
			mylev = -1;
	}
	NetGuard_ModuleLoader_Base::basic_loglevel  = mylev;

	ng_slog("NetGuard","netguard starting ...");

	modules = new NetGuard_ModuleLoader(this);
	modules->Setloglevel(mylev);

	state_handler = new NetGuard_State_Handler();
}

NetGuard_Main::~NetGuard_Main(){
	ng_logdebug_spam("destructor");
	//set basic loglevel so logging stays the same
	NetGuard_ModuleLoader_Base::basic_loglevel = modules->Getloglevel();
	delete modules;
    NetGuard_Global_IP_Filter::Delete();
	delete state_handler;
	ng_logdebug_spam("netguard closed");
	GlobalCFG::Delete();
	//printf("count: %i\n",GlobalCFG::GlobalCFG_CNT);
	fclose(stdout); 
}

void NetGuard_Main::SigHandler(int sig_num)
{
	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	//ng_slogext("NetGuard_Main",3000,"got signal %d pid %d",sig_num,getpid());
	if (!__netguard) {
		//ng_slogerror("NetGuard_Main","on signal __netguard obj!?");
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		return;
	}

	if (__netguard->main_pid != getpid())
	{
		//ng_slogdebug("NetGuard_Main","signal for non main thread (%d) -> ignoring it",__netguard->main_pid);
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		return;
	}

	switch (sig_num)
	{
		case SIGINT:
		case SIGTERM:
			//ng_slog("NetGuard_Main","got SIGINT pid %d",getpid());
			__netguard->is_running=0;
			__netguard->check_inputs();
			break;
		case SIGHUP:
			//ng_slog("NetGuard_Main","got SIGHUP pid %d",getpid());
			__netguard->save_data();
			break;
		#ifdef no_input_timer
		case fd_change_signal:
			//ng_slogext("NetGuard_Main",3000,"got fd_change_signal pid %d",getpid());
			__netguard->check_inputs();
			break;
		case SIGALRM:
			//ng_slogext("NetGuard_Main",1,"got SIGARLM pid %d",getpid());
			__netguard->check_inputs();
			break;
		#endif
		case SIGPIPE:
			break;
	}
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}

#ifndef no_input_timer
not used atm!
void timer_signal(int signo)
{
	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	if (!__netguard) {
		printf("on timer __netguard obj!?");
		NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
		return;
	}
	__netguard->check_inputs();
	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);
}
#endif

void NetGuard_Main::save_data() {
	//sync call
	alarm_raised_s = true;
	modules->stop_poll();
}

void NetGuard_Main::check_inputs() {
	alarm_raised++;
	modules->stop_poll();
}

#ifndef no_input_timer
not used atm
void NetGuard_Main::start_timer()
{
	struct sigevent ev;
	struct sigaction act;
	struct itimerspec its = { {alarm_seconds,500000000}, {0,1000} };

	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = SIGUSR1;

	act.sa_flags=SA_RESTART;
	act.sa_handler=timer_signal;
	
	if (sigemptyset(&act.sa_mask) == -1) {
		ng_logerror("start_timer (sigemptyset) [%d]: %s", __LINE__, strerror (errno));
		return;
	}
	if (sigaction(SIGUSR1, &act, 0) == -1) {
		ng_logerror("start_timer (sigaction) [%d]: %s", __LINE__, strerror (errno));
		return;
	}

	if (timer_create(CLOCK_REALTIME, &ev, &timer) != 0) {
		ng_logerror("start_timer (timer_create) [%d]: %s", __LINE__, strerror (errno));
		exit(-2);
	}

	if (timer_settime(timer, 0, &its, NULL) != 0) {
		ng_logerror("start_timer (timer_settime) [%d]: %s", __LINE__, strerror (errno));
		exit(-2);
	}

}

void NetGuard_Main::stop_timer()
{
	if (timer)
	{
		if (timer_delete (timer) < 0)
		{
			ng_logerror("stop_timer [%d]: %s", __LINE__, strerror (errno));
		}
	}
}
#else

unsigned int NetGuard_Main::alarm(unsigned int mseconds) {
  struct itimerval newv;
  int long sec =  lround(trunc(mseconds/1000));
  int long msecond = mseconds - (sec * 1000);
  newv.it_interval.tv_usec = 1000 * msecond;
  newv.it_interval.tv_sec = sec;
  newv.it_value.tv_usec	= 1000 * msecond;
  newv.it_value.tv_sec = sec;
  if (setitimer(ITIMER_REAL,&newv,NULL)==-1) return 0;
  return 1;
}
#endif

void NetGuard_Main::do_init(int argc, char *argv[]){
	ng_log("Version: %s",NetGuard_VERSION);
	ng_logdebug_spam("static libnetguard: %d",NetGuard_STATIC);
	ng_logdebug_spam("build: %s",NetGuard_COMPILE_DATE);
	ng_logdebug_spam("builddetails: from %s - at %s - with %s",NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	ng_logdebug_spam("PID: %d",getpid());

	
	//check for root user
	int uid = getuid();
	if(uid != 0) {
		ng_logerror("You must have UID 0 instead of %d.",uid);
		throw(1);
	}

	main_pid = getpid();

	//open device
	setpriority(PRIO_PROCESS,getpid(),-5);
	ng_log("priority %d",getpriority(PRIO_PROCESS,getpid()));
}

void NetGuard_Main::packet_in(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
	pkt_count ++;
	pkt_size += h->tp_len;

	#ifdef printpacket
		print_package(vlanid,h,eth,ip,tcp,data);
	#endif
		
	#ifdef checkskinny
		check_skinny(eth,ip,tcp,data);
	#endif
	//if (pkt_count%10000 == 1 )  ng_logdebug_spam("I saw %llu packages with a total size of %llu Bytes",pkt_count,pkt_size);
	modules->broadcast_packet(vlanid,h,eth,ip,tcp,data);
}


void NetGuard_Main::parse_line(std::vector<std::string>& params, std::vector<int>& intparams, std::string& command)
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

void NetGuard_Main::main_loop(){
	__netguard = (NetGuard_Main *)this;
	
	signal(SIGINT,NetGuard_Main::SigHandler);
	signal(SIGTERM,NetGuard_Main::SigHandler);
	signal(SIGHUP,NetGuard_Main::SigHandler);
	signal(SIGPIPE,NetGuard_Main::SigHandler);	
	#ifdef no_input_timer
	signal(fd_change_signal,NetGuard_Main::SigHandler);
	signal(SIGALRM,NetGuard_Main::SigHandler);
	#endif
	//signal(SIGALRM,NetGuard_Main::SigHandler);


	sigset_t mysig = NetGuard_ModuleLoader_Base::MaskSignals();
	
	ng_log("Startup at UID: %d PID: %d",getuid(),getpid());	

	ng_logdebug_spam("entering main loop ...");

	std::vector<std::string> params;
	std::vector<int> paramsint;
	params.push_back("execute");
	params.push_back("./.netguardrc");
	paramsint.push_back(MININT);
	paramsint.push_back(MININT);
	got_input(params,paramsint,"");

	NetGuard_ModuleLoader_Base::UnMaskSignals(mysig);

	#ifndef no_input_timer
	start_timer();
	#else
	alarm(alarm_seconds);
	#endif

	alarm_raised = 0;
	alarm_raised_s = false;

	pkt_count_l = 0;
	pkt_size_l = 0;
	last_stats = NetGuard_ModuleLoader_Base::GetNow();
	last_stats5 = NetGuard_ModuleLoader_Base::GetNow();

	std::vector<std::string>::iterator it2;
	while(is_running)
	{

		modules->poll();

		if (alarm_raised_s) 
		{
			ng_logdebug_spam("issue saving ..");
			params.clear();
			paramsint.clear();
			params.push_back("save");
			paramsint.push_back(MININT);
			got_input(params,paramsint,"");
			ng_logdebug_spam("save issued ..");		

			ng_logdebug_spam("issue logfilerotate ..");
			params.clear();
			paramsint.clear();
			params.push_back("logfilerotate");
			paramsint.push_back(MININT);
			got_input(params,paramsint,"");
			ng_logdebug_spam("save logfilerotate ..");		

			alarm_raised_s = false;
		}
		if (alarm_raised) {
			long int secsdiff =  lround(difftime(NetGuard_ModuleLoader_Base::GetNow(),last_stats5));
			if (secsdiff >= 300) {
				unsigned long long int diffpkg = pkt_count - pkt_count_l5;
				unsigned long long int diffsize = pkt_size - pkt_size_l5;
				NetGuard_ModuleLoader_Base::send_cmsg(NULL,"5min_stats_pks",NULL,&diffpkg);
				NetGuard_ModuleLoader_Base::send_cmsg(NULL,"5min_stats_size",NULL,&diffsize);
				long long int pkssec =  llround(diffpkg/secsdiff);
				long long int sizesec =  llround(diffsize/secsdiff);
				NetGuard_ModuleLoader_Base::send_cmsg(NULL,"5min_stats_pkssecs",NULL,&pkssec);
				NetGuard_ModuleLoader_Base::send_cmsg(NULL,"5min_stats_sizesecs",NULL,&sizesec);
				pkt_count_l5 = pkt_count;
				pkt_size_l5 = pkt_size;
				last_stats5 = NetGuard_ModuleLoader_Base::GetNow();
			}

			ng_logext(3000,"indirect timer tick...");
			modules->timer_tick();
			alarm_raised--;
		}
	}
	NetGuard_ModuleLoader_Base::MaskSignals();
	ng_logdebug_spam("leaving main loop ...");

	params.clear();
	params.push_back("execute");
	params.push_back("./.netguardshutdown");
	paramsint.clear();
	paramsint.push_back(MININT);
	paramsint.push_back(MININT);
	got_input(params,paramsint,"");

	ng_logdebug_spam("issue saving ..");
	params.clear();
	paramsint.clear();
	params.push_back("save");
	paramsint.push_back(MININT);
	got_input(params,paramsint,"");
	ng_logdebug_spam("save issued ..");				

	ng_logdebug_spam("exiting ..");
	for (it2=do_onexit.begin(); it2 != do_onexit.end(); it2++)  {
		params.clear();
		paramsint.clear();
		parse_line(params,paramsint,(*it2));
		if (params.size()) {
			ng_logdebug_spam("exiting .. %s",(*it2).c_str());
			got_input(params,paramsint,*it2);
		}
	}
	ng_logdebug_spam("exiting done ..");

	if (NetGuard_STATIC) {
		ng_logdebug_spam("static lib .. clearing shared objects");
		state_handler->clear();
		ng_logdebug_spam("static lib .. clearing shared objects .. done");
	}
	
	#ifndef no_input_timer
	stop_timer();
	#endif
	
}

void NetGuard_Main::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help")
	{
		ng_logout("NetGuard http://www.net-guard.net");
		ng_logout("Contact: contact@net-guard.net");
		ng_logout("possible commands (VERSION %s):",NetGuard_VERSION);
		ng_logout("help - show this");
		ng_logout("version - show version information");
		ng_logout("exit - shutdown the program");
		ng_logout("stats - show some stats");
		ng_logout("show - show config details");
		ng_logout("setuid <uid> - set uid to the given id");
		ng_logout("daemon - demonize");
		ng_logout("logfilerotate - rotate logfiles");
		ng_logout("logfile <filename> - redirect output to a logfile");
		ng_logout("logfilespam <filename> - spam output to a logfile");
		ng_logout("execute <filename> - execute netguard command files");
		ng_logout("umask <umask> - set umask");
		ng_logout("timer <seconds> - set timer to x seconds (only effective if in rc file)");
		ng_logout("load_states - load all user states from disk (all custom states should be loaded as module)");
		ng_logout("save_states - save all user states from disk");		
		ng_logout("clear_registerd_states - USE WITH CAUTION");
		ng_logout("clear_registerd_exec [<name>]- USE WITH CAUTION");
		ng_logout("list_registerd_exec - list all registered NG USCE");

		ng_logout("onexit_add <command> - execute netguard command on exit");
		ng_logout("onexit_clear - clear all queued exit commands");
		ng_logout("onexit_list - list all queued exit commands");

		ng_logout("onsave_add <command> - execute netguard command on save command");
		ng_logout("onsave_clear - clear all queued save commands ");
		ng_logout("onsave_list - list all queued save commands");
		
		ng_logout("state_dump <ip> <vlan> - show state information if present");
		ng_logout("state_list - show all currently registred states");
		ng_logout("state_change <ip> <vlan> <state> <comment> - change state of an ip");

	}

	if (params[0] == "exit" || params[0] == "quit" )
	{
		ng_logout_ok("got exit from pipe");
		__netguard->is_running=0;
		//if (__netguard->Ring) __netguard->Ring->break_poll();
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "save_states")
	{
		if (GlobalCFG::GetStr("state_filename") == "")
		{
			ng_logerror("can not save state information - 'state_filename' not set in global config");			
		} else if (!state_handler->savedata(GlobalCFG::GetStr("state_filename")))
			ng_logerror("could not save state information to '%s'",GlobalCFG::GetStr("state_filename").c_str());			
	}

	if (params[0] == "state_list") 
	{
		ng_logout("statelist:");
		state_list mystates = state_handler->GetStateList();
		state_list::iterator it;
		for (it=mystates.begin(); it != mystates.end(); it++) {

			user_state_list my_l = state_handler->GetUserList((*it)->GetName());
			ng_logout("state: %s (used %d times)",(*it)->GetName().c_str(),my_l.size());

			state_nusc_list nusc = (*it)->GetNUSCList();
			state_nusc_list::iterator it2;
			for (it2=nusc.begin(); it2 != nusc.end(); it2++) {
				ng_logout("NUSC: %s",(*it2)->Get_Name().c_str());
			}		
		}		
	}

	if (params[0] == "state_change") 
	{
		//ng_logout("state_change <ip> <vlan> <state> <comment>- show state information if present");
		if (params.size() < 4)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <state> <comment>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <state> <comment>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan> <state> <comment>",params[0].c_str());
			return;
		}

		NetGuard_State *my_state = NetGuard_State_Handler::get_state(params[3]);
		if (!my_state) {
			ng_logerror("state %s unkown",params[3].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		NetGuard_User_State* nu_state = state_handler->get_user_state(&m_ip.s_addr,&tmpvlanid,"");
		if (!nu_state)
		{
			ng_logout_not_found("state for user %s on vlan %d not found",params[1].c_str(),intparams[2]);
			return;
		}

		std::string my_tmp = GetParamComment(params,4);
		if (my_tmp == "") my_tmp = "admin transition";

		nu_state->params()->SetInt("trans_manual",true);
		std::string old_state = nu_state->state()->GetName();
		if (nu_state->set(my_state,my_tmp))
		{
			ng_logout_ret(0,"state change from %s for user %s on vlan %d to %s done",old_state.c_str(),params[1].c_str(),intparams[2],params[3].c_str());
		} else ng_logerror_ret(-1,"state change from %s for user %s on vlan %d to %s not possible",old_state.c_str(),params[1].c_str(),intparams[2],params[3].c_str());
	}

	if (params[0] == "state_dump")
	{
		if (params.size() != 3)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}
		if (intparams[2]==MININT)
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip> <vlan>",params[0].c_str());
			return;
		}

		unsigned int tmpvlanid = intparams[2];
		NetGuard_User_State* nu_state = state_handler->get_user_state(&m_ip.s_addr,&tmpvlanid,"");
		if (!nu_state)
		{
			ng_logout_not_found("state for user %s on vlan %d not found",params[1].c_str(),intparams[2]);
			return;
		}


        ng_logout("state report [%s,%d] state: %s",params[1].c_str(),intparams[2],nu_state->state()->GetName().c_str());
		ng_logout("state report [%s,%d] params: %s",params[1].c_str(),intparams[2],nu_state->params()->get_string().c_str());

		std::vector<NetGuard_Config*> hist = nu_state->GetHistory();
		std::vector<NetGuard_Config*>::iterator it_h;
		for (it_h=hist.begin(); it_h != hist.end(); it_h++) {
			ng_logout("state report [%s,%d] history: %s",params[1].c_str(),intparams[2],(*it_h)->get_string().c_str());
		}
	}
	
	if (params[0] == "load_states")
	{
		if (GlobalCFG::GetStr("state_filename") == "")
		{
			ng_logerror("can not load state information - 'state_filename' not set in global config");			
		} else if (!state_handler->loaddata(GlobalCFG::GetStr("state_filename")))
			ng_logerror("could not load state information from '%s'",GlobalCFG::GetStr("state_filename").c_str());			
	}

	if (params[0] == "clear_registerd_states")
	{	
		state_handler->do_clear_registerd_states();
		ng_logout_ok("executed clear_registerd_states");
	}
	
	if (params[0] == "clear_registerd_exec")
	{	
		if (params.size() == 2)
		{
			if (state_handler->do_clear_registered_exec(params[1])) {
				ng_logout_ok("unregistred the USCE %s",params[1].c_str());
			} else ng_logout_ok("could not unregister the USCE %s",params[1].c_str());
		} else {
			state_handler->do_clear_registerd_exec();
			ng_logout_ok("executed clear_registerd_exec");
		}
	}

	
	if (params[0] == "list_registerd_exec")
	{	
		ng_logout("USCE list:");
		
		state_usce_list mystates = state_handler->GetUSCEList();
		state_usce_list::iterator it;
		for (it=mystates.begin(); it != mystates.end(); it++) {			
			ng_logout("USCE: %s",(*it)->Get_Name().c_str());
		}		

	}

	if (params[0] == "logfilerotate")
	{
		if (logfile_name_save != "")
		{
			if (!freopen(logfile_name_save.c_str(), "a+", stdout))
			{
				ng_logerror("failed to open logfile STDOUT at '%s': %s",logfile_name_save.c_str(),strerror(errno));
				exit(-1);
			}

			if (!freopen(logfile_name_save.c_str(), "a+", stderr))
			{
				ng_logerror("failed to open logfile STDERR at '%s': %s",logfile_name_save.c_str(),strerror(errno));
				exit(-1);
			}

			setbuf(stdout, NULL);
			setbuf(stderr, NULL);
		}
		if (logfile_spamname_save != "")
		{
			if (!freopen(logfile_spamname_save.c_str(), "a+", logfile_spam))
			{
				ng_logerror("failed to open logfile at '%s': %s",logfile_spamname_save.c_str(),strerror(errno));
			};
			setbuf(logfile_spam, NULL);
		}
	}

	if (params[0] == "logfile")
	{
		if (intparams.size() == 2)
		{
			logfile_name_save = "";
			if (!freopen(params[1].c_str(), "a+", stdout))
			{
				ng_logerror("failed to open logfile STDOUT at '%s': %s",params[1].c_str(),strerror(errno));
				exit(-1);
			}

			if (!freopen(params[1].c_str(), "a+", stderr))
			{
				ng_logerror("failed to open logfile STDERR at '%s': %s",params[1].c_str(),strerror(errno));
				exit(-1);
			}

			logfile_name_save = params[1].c_str();
			
			setbuf(stdout, NULL);
			setbuf(stderr, NULL);
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: logfile <filename> - redirect output to a logfile");
	}

	if (params[0] == "logfilespam")
	{
		if (intparams.size() == 2)
		{
			if (logfile_spam!=NULL)
			{
				fclose(logfile_spam);
			}

			logfile_spamname_save = "";
			logfile_spam = fopen(params[1].c_str(), "a+");
			if (logfile_spam==NULL)
			{
				ng_logerror("failed to open logfile at '%s': %s",params[1].c_str(),strerror(errno));
			} else logfile_spamname_save = params[1].c_str();

			setbuf(logfile_spam, NULL);
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: logfilespam <filename> - output to a logfile");
	}

	if (params[0] == "umask")
	{
		if (params.size() != 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: umask <umask> - set umask");
			return;
		}
		
		if (intparams[1] != MININT)
		{
			 ng_logout_ok("umask: %u",umask(intparams[1]));
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: umask <umask> - set umask");
	}

	if (params[0] == "timer")
	{
		if (params.size() != 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: timer <seconds> - set timer to x seconds");
			return;
		}
		
		if (intparams[1] != MININT)
		{
			 alarm_seconds = intparams[1];
			 ng_logout_ok("set timer to: %u",alarm_seconds);
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: timer <mseconds> - set timer to x mseconds");
	}

	if (params[0] == "setuid")
	{
		if (intparams.size() == 2 && (intparams[1] >= 0))
		{			
			if ((unsigned int)intparams[1] == getuid()) 
			{
				ng_logerror("UID already set to %d ",getuid());	
				return;
			}
			setuid(intparams[1]);
			if ((unsigned int)intparams[1] != getuid())
			{
				ng_logerror("could not set UID to %d its still %d",intparams[1],getuid());	
				return;
			}
			ng_logout_ok("uid set to UID: %d",getuid());	
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: setuid <uid> - set uid to the given id");
	}

	if (params[0] == "save") {
		std::vector<std::string> mparams;
		std::vector<int> mparamsint;
		std::vector<std::string>::iterator it2;
		ng_logdebug_spam("saving ..");
		for (it2=do_onsave.begin(); it2 != do_onsave.end(); it2++)  {
			mparams.clear();
			mparamsint.clear();
			parse_line(mparams,mparamsint,(*it2));
			if (mparams.size()) {
				ng_logdebug_spam("saving .. %s",(*it2).c_str());
				got_input(mparams,mparamsint,*it2);
			}
		}
		ng_logdebug_spam("saved ..");
	}

	if (params[0] == "onsave_add")
	{
		if (params.size() >= 2)
		{
			std::string my_tmp = GetParamComment(params,1);
			do_onsave.push_back(my_tmp);
			ng_logout_ok("added onsave command:%s",my_tmp.c_str());
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: onsave_add <command> - execute netguard command on save");
	}

	if (params[0] == "onsave_clear")
	{
		do_onexit.clear();
		ng_logout_ok("cleared onexit commands");
	}

	if (params[0] == "onsave_list")
	{
		ng_logout("onsave List:");
		std::vector<std::string>::iterator it2;
		for (it2=do_onsave.begin(); it2 != do_onsave.end(); it2++) 
			ng_logout("Command: %s",(*it2).c_str());
	}

	if (params[0] == "onexit_add")
	{
		if (params.size() >= 2)
		{
			std::string my_tmp = GetParamComment(params,1);
			do_onexit.push_back(my_tmp);
			ng_logout_ok("added onexit command:%s",my_tmp.c_str());
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: onexit_add <command> - execute netguard command on exit");
	}

	if (params[0] == "onexit_clear")
	{
		do_onexit.clear();
		ng_logout_ok("cleared onexit commands");
	}

	if (params[0] == "onexit_list")
	{
		ng_logout("onexit List:");
		std::vector<std::string>::iterator it2;
		for (it2=do_onexit.begin(); it2 != do_onexit.end(); it2++) 
			ng_logout("Command: %s",(*it2).c_str());
	}

	if (params[0] == "daemon")
	{
		if (isdaemon) return;
		isdaemon = true;
		ng_logdebug_spam("demonize - current pid: %d",getpid());
		daemon(1,1);
		ng_logdebug("pid after demonize: %d",getpid());
		main_pid = getpid();
	}

	if (params[0] == "execute")
	{
		if (intparams.size() == 2)
		{
			ng_logdebug_spam("executing ... %s",params[1].c_str());
			NetGuard_Command_Loader::parsefile(params[1], this);
			ng_logout_ret(0,"executed %s",params[1].c_str());
		} else ng_logout_ret(RET_WRONG_SYNTAX,"usage: execute <filename> - execute netguard command files");
	}
	

	if (params[0] == "stats")
	{	
		ng_logout("seen %llu MByte in %llu Packages ",(unsigned long long)(pkt_size/1024/1024),pkt_count);
		unsigned long long int diffpkg = pkt_count - pkt_count_l;
		unsigned long long int diffsize = pkt_size - pkt_size_l;
		long int secsdiff =  lround(difftime(NetGuard_ModuleLoader_Base::GetNow(),last_stats));

		if (secsdiff > 0) {
			ng_logout("seen %llu MByte and %llu Packages in %d seconds",(unsigned long long)(diffsize/1024/1024),diffpkg,secsdiff);

			long long int pkssec =  llround(diffpkg/secsdiff);
			long long int sizesec =  llround(diffsize/secsdiff);
			ng_logout("seen %lld MByte/second and %lld Packages/second",(long long)(sizesec/1024/1024),pkssec);

			pkt_count_l = pkt_count;
			pkt_size_l = pkt_size;
			last_stats = NetGuard_ModuleLoader_Base::GetNow();
		}
	}

	GlobalCFG::GetPointer()->got_input(params,intparams,command);	
	NetGuard_Global_IP_Filter::GetPointer()->got_input(params,intparams,command);
	modules->broadcast_input(params,intparams,command);
}

int main (int argc, char *argv[]) {
	//ng_slog("NetGuard","netguard starting ...");

	//init global config -> create instance
	GlobalCFG::Get().loaddata();

	NetGuard_Main _netguard = NetGuard_Main(argc,argv);
	try
	{
		_netguard.do_init(argc,argv);
		_netguard.main_loop();

		ng_slog("NetGuard","netguard closing ...");
		return 0;
	} catch (int err) {
		ng_slogerror("main","major error on init of the main object");
		return err;
	}

	return -1;
}

