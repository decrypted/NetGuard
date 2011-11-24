/***************************************************************************
 *   NetGuard Special Accounting Module                                    *
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

#ifndef NETGUARD_USER_SPECIAL_ACCOUNTING
#define NETGUARD_USER_SPECIAL_ACCOUNTING

#ifdef __cplusplus

#include "time.h"
#include "../../includes/tools.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/mac_filter.hpp"
#include "../../includes/types.hpp"
#include "../../includes/modules/user_module.hpp"
#include "../../includes/modules/general_module.hpp"



#define user_special_module_number 40

class NetGuard_Special_Accounting : public NetGuard_User_Module
{
	private:
		std::string db_filename;
		int htons_ETHERTYPE_IPV6;


		NetGuard_General_Module *general_acccounting;
		User_Data_Tools *muser_data;
		NetGuard_User_Module *security;

		struct user_special_accounting_data *load_accouning_data(struct user_data *u_data, int rename_onfail);
		struct user_special_accounting_data *my_user_init(struct user_data *u_data);
		void doaccount_package(user_data * u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);
		void account_package(user_data * u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);

		void do_sum_timeslot_data(struct user_data_special_timeslot_data *counter,struct user_data_special_timeslot_data data);
		void do_sum_timeslot(struct user_data_special_timeslot *counter,struct user_data_special_timeslot data);

		int htons_ETHERTYPE_IP;
		int htons_ETHERTYPE_ARP;

		mac_addr	null_hw_addr;
		mac_addr	bcast_hw_addr;
	
	public:
		NetGuard_Mac_Filter *Mac_IgnoreSpecial; //add switches etc

		NetGuard_Special_Accounting();
		~NetGuard_Special_Accounting();
		
		void loaddata();
		void savedata();
		int init(NetGuard_Config *data);
		void shutdown();
		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
		
		void user_init(struct user_data *u_data);
		void user_shutdown(struct user_data *u_data);
		void user_data_forgetday(int day);

		void timer_tick();

		void packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data);
		
		void *get_data(void *data) {return NULL;};


};

extern "C" {
#endif

//storage of the user special accounting data
typedef struct user_data_special_timeslot_data
{
	unsigned long long int   nonip_bytes;
	unsigned long long int   nonip_pkts;

} user_data_special_timeslot_data;

typedef struct user_data_special_timeslot
{
	user_data_special_timeslot_data send;
	user_data_special_timeslot_data resv;
} user_data_special_timeslot;

typedef struct user_data_special_traffic
{
	user_data_special_timeslot  over_all;
	user_data_special_timeslot  days[7];
	user_data_special_timeslot  week;
} user_data_special_traffic;

typedef struct user_special_accounting_data
{
	user_data_special_traffic internal;
	user_data_special_traffic external;
} user_special_accounting_data;

#ifdef __cplusplus
}
#endif

#endif

