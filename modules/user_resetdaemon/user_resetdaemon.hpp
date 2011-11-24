/***************************************************************************
 *   NetGuard User RST Daemon Module                                       *
 *                                                                         *
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

#ifndef NETGUARD_USER_RESETDAEMON
#define NETGUARD_USER_RESETDAEMON

#include "time.h"
#include "../../includes/tools.h"
#include "../../includes/types.hpp"
#include "../../includes/config.hpp"
#include "../../includes/modules/user_module.hpp"

typedef struct rst_d_entry{
		u_int32_t s_ip;
		u_int32_t d_ip;
		int syn_only;
		char device[255];
		char comment[255];
} rst_d_entry;

class  NetGuard_ResetDaemon : public NetGuard_User_Module
{
	private:
		std::vector<rst_d_entry *> rst_ips;
		std::string db_filename;

		int socket_fd;
		u_int16_t g_ip_id; 
		int ipv4_checksum_add(const void *data, size_t len);
		u_int16_t ipv4_checksum_final(int s);
		void send_reset(u_int32_t saddr,u_int32_t daddr, u_int32_t sport,u_int32_t dport, u_int32_t seq_ack, u_int32_t id = 0, u_int32_t seq = 0, u_int32_t window = 0);

	public:
		NetGuard_ResetDaemon();
		~NetGuard_ResetDaemon();

		void loaddata();
		void savedata();
		void clear();

		int init(NetGuard_Config *data);

		void shutdown();
		void timer_tick();
		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		void user_init(struct user_data *u_data);
		void user_shutdown(struct user_data *u_data);
		void user_data_forgetday(int day);

		void *get_data(void *data) {return NULL;};


};

#endif

