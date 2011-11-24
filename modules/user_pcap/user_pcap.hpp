/***************************************************************************
 *   NetGuard Pcap Module                                                  *
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

#ifndef NETGUARD_USER_PCAP
#define NETGUARD_USER_PCAP

#include "../../includes/tools.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/mac_filter.hpp"
#include "../../includes/types.hpp"
#include "../../includes/config.hpp"
#include "../../includes/modules/user_module.hpp"
#include "../../includes/modules/general_module.hpp"


#ifdef __cplusplus

class NetGuard_Pcap : public NetGuard_User_Module
{
    private:
	    bool pcapInProg;
	    struct in_addr *filter_ipaddr;
	    mac_addr *filter_macaddr;
	    FILE *logFile;
	    
	    
	    void stop_pckgcapture();
	    void start_pckgcapture(struct in_addr *ipaddr, mac_addr *macaddr);
    public:
	    NetGuard_Pcap();
	    ~NetGuard_Pcap();
	    
	    int init(NetGuard_Config *data);
	    void shutdown();
	    void clear();
	    void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
	    
	    void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid,
		struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);
		
	    
	    void timer_tick() {};
	    void loaddata() {};
	    void savedata() {};
	    void *get_data(void *data) { return NULL; };

            void user_init(struct user_data *u_data) {};
            void user_shutdown(struct user_data *u_data) {};
            void user_data_forgetday(int day) {};
};
#endif

#endif

