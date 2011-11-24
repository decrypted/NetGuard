/***************************************************************************
 *   NetGuard Mac Filter                                                   *
 *   Class to fast matching a list of mac addresses                        *
 *   working with a 5 level (dynamic depth hash)                           *
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
#include <sys/stat.h>
#include <fstream>
#include "../includes/types.hpp"
#include "../includes/mac_filter.hpp"
#include "../includes/logging.h"
#include "../includes/config.hpp"

NetGuard_Mac_Filter::NetGuard_Mac_Filter()
{
	ng_slogdebug_spam("NetGuard_Mac_Filter","constructor");
	name = "default";
	#ifndef hash_security
	memset(&macs,0,sizeof(mac_hash_level));
	#endif
}

NetGuard_Mac_Filter::~NetGuard_Mac_Filter()
{
	ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' destructor",name.c_str());
	clear();
}

#ifndef hash_security
void NetGuard_Mac_Filter::addmac_hash(mac_addr *hw_addr,char comment[255], mac_hash_level *hash_data, int lev)
{
	ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' adding mac %02x:%02x:%02x:%02x:%02x:%02x to hash level: %d", name.c_str(), printf_mac_params((*hw_addr)),lev);
	struct mac_hash_entry *level_data;
	int pos = 5 - lev;
	level_data = (*hash_data)[(*hw_addr)[pos]];
	if (level_data == NULL)
	{
		//we need a new level
		level_data = (struct mac_hash_entry *)malloc(sizeof(struct mac_hash_entry));
		memset(level_data,0,sizeof(struct mac_hash_entry));
		(*hash_data)[(*hw_addr)[pos]] = level_data;
		level_data->mac_set = 1;
		memcpy(&level_data->hw_addr,hw_addr,sizeof(mac_addr));
		memcpy(&level_data->comment,comment,sizeof(level_data->comment));
		ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' added on - index %x - lev %d - index pos %d comment %s", name.c_str(),(*hw_addr)[pos],lev,pos,level_data->comment);
	} else {
		if (lev == 5)
		{
			memcpy(&level_data->hw_addr,hw_addr,sizeof(mac_addr));
			memcpy(&level_data->comment,comment,sizeof(level_data->comment));
		} else {
			if (compare_mac(&(level_data->hw_addr),hw_addr))
			{
				ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' not adding mac - user present at level %d - index %x", name.c_str(), lev +1 , (*hw_addr)[pos]);
				memcpy(&level_data->comment,comment,sizeof(level_data->comment));
				return;
			}
			ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' forard to level %d - index %x", name.c_str(), lev +1 , (*hw_addr)[pos]);
			ng_slogdebug_spam("NetGuard_Mac_Filter","NetGuard_Mac_Filter: '%s' forward new address", name.c_str());
			addmac_hash(hw_addr,comment,&level_data->next_level,lev+1);
			
	
			if (level_data->mac_set)
			{
				ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' forward old address lev %d ", name.c_str(),lev);
				level_data->mac_set = 0;
				addmac_hash(&level_data->hw_addr, level_data->comment, &level_data->next_level,lev+1);
				memset(&level_data->hw_addr,0,sizeof(mac_addr));
			}
		}
	}

}

int NetGuard_Mac_Filter::delmac_hash(mac_addr *hw_addr, mac_hash_level *hash_data, int lev)
{
	struct mac_hash_entry *level_data;
	int pos = 5 - lev;
	level_data = (*hash_data)[(*hw_addr)[pos]];
	if (level_data == NULL) return 0;
	ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' delmac_hash %02x:%02x:%02x:%02x:%02x:%02x to hash level: %d", name.c_str(), printf_mac_params((level_data->hw_addr)),lev);
	if (level_data)
	{
		if (level_data->mac_set)
		{
			if (compare_mac(&(level_data->hw_addr),hw_addr)) {
				ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' delmac_hash hash found for mac %02x:%02x:%02x:%02x:%02x:%02x level: %d", name.c_str() , printf_mac_params((level_data->hw_addr)),lev);
				delete level_data;
				(*hash_data)[(*hw_addr)[pos]] = NULL;
				return 1;
			}
		};
		ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' delmac_hash %02x:%02x:%02x:%02x:%02x:%02x jump to hash level: %d", name.c_str(), printf_mac_params((level_data->hw_addr)),lev);
		int found = delmac_hash(hw_addr,&level_data->next_level,lev+1);
		if (found) return 1;
	}
	return 0;
}

void NetGuard_Mac_Filter::clearhash(mac_hash_level level,int lev)
{
	if (lev > 6 ) return;
	ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' cleering hash - depth %d", name.c_str(), lev);
	struct mac_hash_entry *level_data;
	for(int index=0;index<UCHAR_MAX;index++) {
		level_data = level[index];
		if (level_data)
		{
			ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' level: %d - cleering hash index %x", name.c_str(),lev,index);
			clearhash(level_data->next_level,lev+1);
			delete level_data;
		}
		level[index] = NULL;
	}
}

int NetGuard_Mac_Filter::mac_present(mac_addr *hw_addr, mac_hash_level hash_data, int lev)
{
	struct mac_hash_entry *level_data;
	int pos = 5 - lev;
	level_data = hash_data[(*hw_addr)[pos]];
	if (level_data == NULL) return 0;

	int found = mac_present(hw_addr,level_data->next_level,lev+1);
	if (found) return 1;

	if (level_data->mac_set)
	{
		if (compare_mac(&(level_data->hw_addr),hw_addr)) {
			ng_slogdebug_spam_spam("NetGuard_Mac_Filter","NetGuard_Mac_Filter: '%s' hash found for mac %02x:%02x:%02x:%02x:%02x:%02x level: %d", name.c_str() , printf_mac_params((*hw_addr)),lev);
			return 1;
		}
	}
	
	#ifdef debug_hash_search_fail
		if (!lev)
		{
			ng_slogdebug_spam_spam("NetGuard_Mac_Filter","'%s' NOT FOUNT mac %02x:%02x:%02x:%02x:%02x:%02x", name.c_str() , printf_mac_params((*hw_addr)));
		}
	#endif
	return 0;
}
#endif

int NetGuard_Mac_Filter::match(mac_addr *hw_addr, unsigned int *vlan_id)
{
	#ifdef hash_security
    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = (*vlan_id);
	mac_hash_map::iterator it;
	it=mac_data.find(idx);
	if (it != mac_data.end()) {
		ng_slogdebug_spam_spam("NetGuard_Mac_Filter","NetGuard_Mac_Filter: '%s' hash found for mac %02x:%02x:%02x:%02x:%02x:%02x vlan: %u", name.c_str(), printf_mac_params((*hw_addr)),(*vlan_id));
		return 1;
	} else return 0;
	#else
	return mac_present(hw_addr, macs);
	#endif
}

void NetGuard_Mac_Filter::add(mac_addr *hw_addr, unsigned int *vlan_id,char comment[255]) 
{
	#ifdef hash_security
	ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' adding mac %02x:%02x:%02x:%02x:%02x:%02x", name.c_str(), printf_mac_params((*hw_addr)));
	if (match(hw_addr,vlan_id)) {
		ng_slogdebug_spam("NetGuard_Mac_Filter","'%s' not adding mac - present", name.c_str());
		return;
	}
    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = (*vlan_id);
	std::string mycomment = comment;
	mac_data.insert(pair<const struct sec_data_idx, std::string>(idx, mycomment));

	if (!match(hw_addr,vlan_id))
	{
		ng_slogerror("NetGuard_Mac_Filter","'%s' error on adding mac %02x:%02x:%02x:%02x:%02x:%02x", name.c_str(), printf_mac_params((*hw_addr)));
	}

	#else
	addmac_hash(hw_addr,comment,&macs);
	#endif
}

void NetGuard_Mac_Filter::add(int m0, int m1, int m2, int m3, int m4, int m5, unsigned int *vlan_id,char comment[255])
{
	mac_addr hw_addr;
	hw_addr[0] = m0;
	hw_addr[1] = m1;
	hw_addr[2] = m2;
	hw_addr[3] = m3;
	hw_addr[4] = m4;
	hw_addr[5] = m5;
	add(&hw_addr,vlan_id,comment);
}

void NetGuard_Mac_Filter::del(mac_addr *hw_addr, unsigned int *vlan_id) 
{
	#ifdef hash_security
    sec_data_idx idx;
	memcpy(&idx.hw_addr,hw_addr,sizeof(mac_addr));
	idx.vlan_id = (*vlan_id);
	mac_hash_map::iterator it;
	it=mac_data.find(idx);
	if (it != mac_data.end()) {
		ng_slogdebug_spam_spam("NetGuard_Mac_Filter","'%s' delmac_hash %02x:%02x:%02x:%02x:%02x:%02x", name.c_str(), printf_mac_params((*hw_addr)));
		mac_data.erase(it);
	}
	#else
	delmac_hash(hw_addr,&macs);
	#endif
}

void NetGuard_Mac_Filter::del(int m0, int m1, int m2, int m3, int m4, int m5, unsigned int *vlan_id)
{
	mac_addr hw_addr;
	hw_addr[0] = m0;
	hw_addr[1] = m1;
	hw_addr[2] = m2;
	hw_addr[3] = m3;
	hw_addr[4] = m4;
	hw_addr[5] = m5;
	del(&hw_addr,vlan_id);
}

int NetGuard_Mac_Filter::loadfile(const char *filename)
{
	FILE *myfile;
	struct stat fileinfo;

	if (GlobalCFG::GetStr("config_path") == "") {
		ng_slogerror("NetGuard_Mac_Filter","'%s' missing global cfg str config_path",name.c_str());
		return -1;
	}

	if (filename == NULL) return -1;
	std::string file_name;
	file_name.assign(GlobalCFG::GetStr("config_path").c_str());
	file_name.append("/");
	file_name += filename;
	if (stat(file_name.c_str(),&fileinfo))
	{
		ng_slogerror("NetGuard_Mac_Filter","'%s' can not load %s",name.c_str(),file_name.c_str());
		return -1;
	}

	clear();

	ng_slogdebug_spam_spam("NetGuard_Mac_Filter","'%s' loading data from %s",name.c_str(),file_name.c_str());	
	myfile = fopen(file_name.c_str(), "r");
	if (!myfile) {
		ng_slogerror("NetGuard_Mac_Filter","'%s' cant open data file %s",name.c_str(),file_name.c_str());
		return -1;
	}

	mac_addr hw_addr;
	char str[2000];
	char tmp_comment[255];
	char tmp_mac[255];
	unsigned int vlan_id;

	std::fstream file_op(file_name.c_str(),std::ios::in);
	int counter = 0;
	while(!file_op.eof())
	{
		file_op.getline(str,2000);
		if (sscanf (str,"%17s %d %[^\n\r]255s",tmp_mac,&vlan_id,tmp_comment) == 3)
		{
			if (getmacfromchar(tmp_mac, &hw_addr))
			{
				counter++;
				add(&hw_addr,&vlan_id,tmp_comment);
			}
		}
	}
	file_op.close();

	ng_slogdebug_spam("NetGuard_Mac_Filter","%s loaded %d macs",name.c_str(),counter);

	fclose(myfile);

	return 0;
}

#ifndef hash_security
void NetGuard_Mac_Filter::dosave_hash(FILE *myfile, mac_hash_level level,int lev)
{
	if (lev > 6 ) return;
	ng_slogdebug_spam("NetGuard_Mac_Filter","%s: dosave_hash cleering hash - depth %d", name.c_str(), lev);
	struct mac_hash_entry *level_data;
	for(int index=0;index<UCHAR_MAX;index++) {
		level_data = level[index];
		if (level_data)
		{
			if (level_data->mac_set)
			{
				fprintf(myfile,"%02x:%02x:%02x:%02x:%02x:%02x 0 %s\n", printf_mac_params((level_data->hw_addr)),level_data->comment);
				ng_slogdebug_spam("NetGuard_Mac_Filter","%s: dosave_hash save mac %02x:%02x:%02x:%02x:%02x:%02x level: %d index %x", name.c_str(), printf_mac_params((level_data->hw_addr)),lev,index);
			}
			ng_slogdebug_spam("NetGuard_Mac_Filter","%s: dosave_hash jump to hash level: %d - index %x", name.c_str(),lev + 1,index);
			dosave_hash(myfile,level_data->next_level,lev+1);
		}
	}
}
#endif

int NetGuard_Mac_Filter::savefile(const char *filename)
{
	FILE *myfile;
	if (filename == NULL) return -1;

	if (GlobalCFG::GetStr("config_path") == "") {
		ng_slogerror("NetGuard_Mac_Filter","'%s' missing global cfg str config_path",name.c_str());
		return -1;
	}

	std::string file_name;
	file_name.assign(GlobalCFG::GetStr("config_path").c_str());
	file_name.append("/");
	file_name += filename;

	ng_slogdebug_spam("NetGuard_Mac_Filter","%s saving data to %s",name.c_str(),file_name.c_str());

	myfile = fopen(file_name.c_str(), "w+");
	if (!myfile) {
		ng_slogerror("NetGuard_Mac_Filter","%s cant save data to %s - %s",name.c_str(),file_name.c_str(),strerror(errno));
		return -1;
	}

	#ifdef hash_security
	mac_hash_map::iterator it;
	for (it=mac_data.begin(); it != mac_data.end(); it++) {
		fprintf(myfile,"%02x:%02x:%02x:%02x:%02x:%02x %u %s\n", printf_mac_params((*it).first.hw_addr),(*it).first.vlan_id,(*it).second.c_str());
	}
	#else
	dosave_hash(myfile,macs);
	#endif

	fclose(myfile);

	return 0;
}

#ifndef hash_security
void NetGuard_Mac_Filter::doprint_hash(mac_hash_level level,int lev)
{
	if (lev > 6 ) return;
	struct mac_hash_entry *level_data;
	for(int index=0;index<UCHAR_MAX;index++) {
		level_data = level[index];
		if (level_data)
		{
			if (level_data->mac_set)
			{
				ng_slogout("NetGuard_Mac_Filter","'%s' %02x:%02x:%02x:%02x:%02x:%02x Comment: %s", name.c_str() , printf_mac_params((level_data->hw_addr)),level_data->comment);
			}
			doprint_hash(level_data->next_level,lev+1);
		}
	}
}
#endif

void NetGuard_Mac_Filter::print()
{
	#ifdef hash_security
	mac_hash_map::iterator it;
	for (it=mac_data.begin(); it != mac_data.end(); it++) {
		ng_slogout("NetGuard_Mac_Filter","'%s' %02x:%02x:%02x:%02x:%02x:%02x vlan: %u Comment: %s", name.c_str() , printf_mac_params((*it).first.hw_addr),(*it).first.vlan_id,(*it).second.c_str());
	}
	#else
	doprint_hash(macs);
	#endif
}

void NetGuard_Mac_Filter::clear()
{
	#ifdef hash_security	
	#else
	clearhash(macs);
	#endif
}

