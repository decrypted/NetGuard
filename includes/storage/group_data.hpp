/***************************************************************************
 *   NetGuard Data Storage definition for the group accounting module      *
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

#ifndef GACCOUTING_DATA
#define GACCOUTING_DATA

#include "../defines.h"
#include "user_data.hpp"
#include "user_limits.hpp"

#include <string>
#include <ext/hash_map>
#include <vector>
#include <values.h>
#include "../types.hpp"


struct guser_data_idx
{
   	u_int32_t          saddr;
    unsigned int       vlan_id;
};

using namespace std;
using namespace __gnu_cxx; 	
struct eq_guser_data_idx
{
  bool operator()(const struct guser_data_idx s1, const struct guser_data_idx s2) const
  {
    return (s1.saddr == s2.saddr) && (s1.vlan_id == s2.vlan_id);
  }
};

struct hash_guser_data_idx
{
	size_t operator()(const struct guser_data_idx t) const
	{
		return (t.vlan_id+MAXLONG) + t.saddr;
	}
};

typedef std::vector<struct guser_data_idx> guser_data_list_idx;

class GUser_Data_Tools;

class Group_Data
{
	private:
		struct user_data data;
		struct user_limit_data limits;
		guser_data_list_idx members;
		std::string log_str;
		GUser_Data_Tools *tools; //needed to update index etc
	public:
		std::string name;		

		Group_Data(GUser_Data_Tools *intools, std::string inname);
		~Group_Data();

		guser_data_list_idx *get_members();

		struct user_data *GetData();
		struct user_limit_data *GetLimits();
		bool member_present(u_int32_t search_saddr, unsigned int vlan_id);

		void clear();

		bool add_member(u_int32_t saddr, unsigned int vlan_id);
		bool del_member(u_int32_t saddr, unsigned int vlan_id);
};

typedef vector<class Group_Data*> guser_data_list_vector;
typedef hash_map<struct guser_data_idx, guser_data_list_vector *, hash_guser_data_idx, eq_guser_data_idx> gip_storage_hash;
typedef hash_map<std::string, class Group_Data*,string_hash> guser_data_list;

class GUser_Data_Tools
{
	private:
		gip_storage_hash group_index;
		guser_data_list groups;

		FILE *save_file;
	public:
		std::string log_str;
		GUser_Data_Tools(std::string inlog_str = def_log_str);
		~GUser_Data_Tools();
		
		void clear();

		//use fast when ever you can - its like x00% faster
		guser_data_list_vector *get_groups(u_int32_t *search_saddr, unsigned int *vlan_id);


		void loaddata(std::string filename, int rename_onfail=0);
		void savedata(std::string filename, bool junks=false);

		bool reindex_group(std::string name);
		bool reindex_group(Group_Data *group);

		Group_Data *get_group(std::string name);
		Group_Data *get_group(u_int32_t *search_saddr, unsigned int *vlan_id);

		Group_Data *create_group(std::string name);
		bool del_group(std::string name);

		gip_storage_hash *get_list();
		guser_data_list_vector get_vector_list();
};
#endif

