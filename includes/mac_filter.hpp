/***************************************************************************
 *   NetGuard Mac Filter                                                   *
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

#ifndef NETGUARD_MAC_FILTER
#define NETGUARD_MAC_FILTER

#include "defines.h"
#include "tools.h"
#include "stdio.h"
#include <values.h>
#include "types.hpp"


#ifdef hash_security
//we use std:: hases and maps and not selfmade things
//general types

#include <string>
#include <ext/hash_map>
#include <vector>
#include <values.h>

//#define mac_hash_calc(mac) mac[0]+(mac[1]*16^2)+(mac[2]*32^2)+(mac[3]*48^2)+(mac[4]*64^2)+(mac[5]*96^2)
#define mac_hash_calc(mac) mac[0]+mac[4]+mac[5];

struct eq_sec_data_idx
{
	bool operator()(struct sec_data_idx s1, struct sec_data_idx s2) const
	{
		return compare_mac(&s1.hw_addr,&s2.hw_addr) && (s1.vlan_id == s2.vlan_id);
	}
};

struct hash_sec_data_idx
{
	size_t operator()(const struct sec_data_idx t) const
	{
		return (t.vlan_id * MAXINT ) + mac_hash_calc(t.hw_addr);
	}
};

using namespace std;
using namespace __gnu_cxx; 

typedef std::vector<const struct sec_data_idx> sec_list_idx;

#else

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mac_hash_entry *mac_hash_level[UCHAR_MAX+1]; //+1 to also add FF and 00

//mac hashing entrys
typedef struct mac_hash_entry
{
	mac_addr		hw_addr;   //all users with a mac address that matched the hash
	int mac_set;
	char comment[255];
	mac_hash_level	next_level;
} mac_hash_entry;

#ifdef __cplusplus
}
#endif

#endif


#ifdef hash_security
//private types
typedef hash_map<const struct sec_data_idx, std::string, hash_sec_data_idx, eq_sec_data_idx> mac_hash_map;

#endif

class NetGuard_Mac_Filter
{
	private:
		#ifndef hash_security
		mac_hash_level macs;
		void addmac_hash(mac_addr *hw_addr,char comment[255], mac_hash_level *hash_data, int lev = 0);
		int delmac_hash(mac_addr *hw_addr,mac_hash_level *hash_data, int lev = 0);
		void clearhash(mac_hash_level level,int lev  = 0);
		int  mac_present(mac_addr *hw_addr, mac_hash_level hash_data, int lev = 0);
		void dosave_hash(FILE *myfile, mac_hash_level level,int lev  = 0);
		void doprint_hash(mac_hash_level level,int lev = 0);
		#else
		mac_hash_map mac_data;
		#endif

	public:
		std::string name;
		NetGuard_Mac_Filter();
		~NetGuard_Mac_Filter();
	
		int match(mac_addr *hw_addr, unsigned int *vlan_id);
		void add(mac_addr *hw_addr, unsigned int *vlan_id, char comment[255]);
		void add(int m0, int m1, int m2, int m3, int m4, int m5, unsigned int *vlan_id, char comment[255]);
		void del(mac_addr *hw_addr, unsigned int *vlan_id);
		void del(int m0, int m1, int m2, int m3, int m4, int m5, unsigned int *vlan_id);

		void clear();

		int loadfile(const char *filename);
		int savefile(const char *filename);
		void print();

};

#endif

