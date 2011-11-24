/***************************************************************************
 *   NetGuard Data Storage definition for the accounting module            *
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

#ifndef ACCOUTING_DATA
#define ACCOUTING_DATA

#include "../defines.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MODULES 254
#include "../tools.h"

#define  def_log_str "User_Data_Tools"

//storage of the user data ip based
typedef struct user_data_timeslot_data
{
	unsigned long long int   bytes;
	unsigned long long int   pkts;

	unsigned long long int   ip_bytes;
	unsigned long long int   ip_pkts;

	unsigned long long int   tcpip_bytes;
	unsigned long long int   tcpip_pkts;

	unsigned long long int   udp_bytes;
	unsigned long long int   udp_pkts;

	unsigned long long int   icmp_bytes;
	unsigned long long int   icmp_pkts;

	unsigned long long int   arp_bytes;
	unsigned long long int   arp_pkts;
	
	unsigned long long int   connects;
} user_data_timeslot_data;

typedef struct user_data_timeslot
{
	user_data_timeslot_data send;
	user_data_timeslot_data resv;
} user_data_timeslot;

typedef struct user_data_traffic
{
	user_data_timeslot  over_all;
	user_data_timeslot  days[7];
	user_data_timeslot  week;
} user_data_traffic;

typedef struct user_data
{
	u_int32_t          saddr;
	unsigned int       vlan_id;

	mac_addr           hw_addr;
	time_t             last_activity;

	user_data_traffic  external;
	user_data_traffic  internal;

	void              *module_data[MAX_MODULES];

} user_data;


#ifndef userlist_own
//single list to keep track of all entrys
typedef struct user_list *list_pointer;
typedef struct user_list
{
	struct user_data *data;
	list_pointer     next;
} user_list;

#ifdef __cplusplus
}
#endif
#endif



#ifndef __cplusplus
#ifndef userlist_own
#error can not compile with not using own list but not CPP
#endif
#endif

#ifdef __cplusplus

#include <string>
#include <ext/hash_map>
#include <vector>
#include <values.h>


#ifndef userlist_own
struct user_data_idx
{
   	u_int32_t          saddr;
    unsigned int       vlan_id;
};

using namespace std;
using namespace __gnu_cxx; 

struct eq_user_data_idx
{
  bool operator()(const struct user_data_idx* s1, const struct user_data_idx* s2) const
  {
    return (s1->saddr == s2->saddr) && (s1->vlan_id == s2->vlan_id);
  }
};

struct hash_user_data_idx
{
	size_t operator()(const struct user_data_idx* t) const
	{
		return (t->vlan_id * MAXINT) + t->saddr;
	}
};

typedef hash_map<const struct user_data_idx*, struct user_data* , hash_user_data_idx, eq_user_data_idx> ip_storage_hash;
typedef std::vector<const struct user_data_idx*> user_data_list_idx;

#endif

typedef std::vector<struct  user_data *> user_data_list;

class User_Data_Tools
{
	private:
		#ifdef userlist_use_simple
		void* user_index[256];  //simple index based on last byte of ip
		struct user_list *user_list_head;
		#else
		ip_storage_hash user_index;

		FILE *save_file;
		int save_index;
		bool save_in_progress;
		user_data_list_idx save_index_data;
		#endif
	public:
		std::string log_str;
		#ifndef userlist_use_simple
		int savejunk;
		#endif
		User_Data_Tools(std::string inlog_str = def_log_str);
		~User_Data_Tools();
		
		void list_clear();

		struct user_data *get_user(u_int32_t *search_saddr, unsigned int *vlan_id);

		int add_user(struct user_data *u_data, unsigned int vlan_id);
		struct user_data *get_or_add_user(u_int32_t *search_saddr, unsigned int *vlan_id);

		void free_user(struct user_data *u_data);

		void loaddata(std::string filename, int rename_onfail=0);
		void savedata(std::string filename, bool allatonce=true);

		#ifdef userlist_use_simple
		struct user_list *get_list();
		#else
		ip_storage_hash *get_list();
		user_data_list_idx get_list_idx();
		#endif

		user_data_list get_vector_list();

};
#endif

#endif

