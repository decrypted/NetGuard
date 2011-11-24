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

#ifndef NETGuard_MAIN
#define NETGuard_MAIN

#include <time.h>
#include <signal.h>

#include "../includes/tools.h"
#include "../includes/types.hpp"
#include "../includes/modules/general_module.hpp"
#include "module_loader.hpp"
#include "../includes/ip_filter.hpp"
#include <sys/time.h>
#include "../includes/state/state_handling.hpp"

class NetGuard_Main : public NetGuard_General_Module
{
	private:
		FILE * logfile_spam;
		string logfile_name_save;
		string logfile_spamname_save;

		bool isdaemon;
		unsigned int alarm_seconds;

		int alarm_raised;
		bool alarm_raised_s;

	public:
		#ifndef no_input_timer
		timer_t timer;
		#endif
		std::vector<std::string> do_onexit;
		std::vector<std::string> do_onsave;

		int main_pid;

		NetGuard_Main(int argc, char *argv[]);
		~NetGuard_Main();
		
		void do_init(int argc, char *argv[]);
		void main_loop();
		
		static void SigHandler(int sig_num);
		static void TimerHandler(union sigval sigval);

		#ifndef no_input_timer
		void start_timer();
		void stop_timer();
		#else
		unsigned int alarm(unsigned int mseconds);
		#endif
		void check_inputs();
		void save_data();

		void timer_tick() {};

		void parse_line(std::vector<std::string>& params, std::vector<int>& intparams, std::string& command);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);

		void packet_in(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		
		unsigned long long int pkt_count;
		unsigned long long int pkt_size;

		unsigned long long int pkt_count_l;
		unsigned long long int pkt_size_l;
		time_t last_stats;

		unsigned long long int pkt_count_l5;
		unsigned long long int pkt_size_l5;
		time_t last_stats5;

		int is_running;

		NetGuard_ModuleLoader *modules;
		NetGuard_State_Handler *state_handler;

		void loaddata() {};
		void savedata() {};
		void shutdown() {};

		void *get_data(void *data) {return NULL;};

};

#endif

