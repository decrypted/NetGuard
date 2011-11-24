/***************************************************************************
 *   NetGuard IP Filter                                                    *
 *   Class to fast matching a list of ip addresses                         *
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
#include "../includes/ip_filter.hpp"

NetGuard_IP_Filter::NetGuard_IP_Filter(std::string inprefix,std::string inname)
{
	fprefix = inprefix;
	fname = inname;
	ng_slogdebug_spam(GetFullName().c_str(),"constructor");
}

NetGuard_IP_Filter::~NetGuard_IP_Filter()
{
	ng_slogdebug_spam(GetFullName().c_str(),"destructor");
	clear();
}

std::string NetGuard_IP_Filter::GetFullName()
{
	std::string tmpstr;
	tmpstr = "IPFilter_";
	tmpstr.append(GetPrefixName());
	return tmpstr;
}

std::string NetGuard_IP_Filter::GetPrefixName()
{
	std::string tmpstr;
	tmpstr = fprefix;
	if (tmpstr != "")
		tmpstr.append(".");
	tmpstr.append(fname);
	return tmpstr;
}

void NetGuard_IP_Filter::clear()
{  
	ng_slogdebug_spam(GetFullName().c_str(),"clearing");
	IP_FILTER_MAP::iterator it;
	int found = 1;
	while (found)
	{
		found = 0;
		for (it=filter_filters.begin(); it != filter_filters.end(); it++) {
			NetGuard_IP_Filter *entry =  (*it).second;
			if (!entry) continue;
			found = 1;
			delete entry;
			(*it).second = NULL;
		}
	}
	filter_filters.clear();

	std::vector<filter_d_entry *>::iterator it2;
	found = 1;
	while (found)
	{
		found = 0;
		for (it2=filter_ips.begin(); it2 != filter_ips.end(); it2++) {
			filter_d_entry *entry = (*it2);
			if (!entry) continue;
			found = 1;
			delete entry;
			(*it2) = NULL;
		}
	}
    filter_ips.clear();

	ng_slogdebug(GetFullName().c_str(),"cleared");
}

bool NetGuard_IP_Filter::addrange(u_int32_t min_ip, u_int32_t max_ip)
{
	delrange(min_ip,max_ip);
	filter_d_entry *entry = new filter_d_entry;
	
	entry->min_ip = min_ip;
	entry->max_ip = max_ip;
	entry->min_ip_hl = ntohl(min_ip);
	entry->max_ip_hl = ntohl(max_ip);
	filter_ips.push_back(entry);
	char *min_ip_s = get_ip_char(entry->min_ip);
	char *max_ip_s = get_ip_char(entry->max_ip);
	ng_slogdebug(GetFullName().c_str(),"added - from %s to %s",min_ip_s,max_ip_s);
	free(min_ip_s);
	free(max_ip_s);
	return true;
}

bool NetGuard_IP_Filter::delrange(u_int32_t min_ip, u_int32_t max_ip)
{
	char *min_ip_s = NULL;
	char *max_ip_s = NULL;
	std::vector<filter_d_entry *>::iterator it2;
	for (it2=filter_ips.begin(); it2 != filter_ips.end(); it2++) {	
		filter_d_entry *entry = (*it2);
		if (!entry) continue;
		if ( entry->min_ip == min_ip && entry->max_ip == max_ip) {
			min_ip_s = get_ip_char(entry->min_ip);
			max_ip_s = get_ip_char(entry->max_ip);
			ng_slogdebug(GetFullName().c_str(),"deleted - from %s to %s",min_ip_s,max_ip_s);
			free(min_ip_s);
			free(max_ip_s);
			delete (*it2);
			filter_ips.erase(it2);
			return true;
		}
	}
	min_ip_s = get_ip_char(min_ip);
	max_ip_s = get_ip_char(max_ip);
	ng_slogdebug_spam(GetFullName().c_str(),"delete - did not find - from %s to %s",min_ip_s,max_ip_s);
	free(min_ip_s);
	free(max_ip_s);
	return false;
}

bool NetGuard_IP_Filter::delrange_id(u_int32_t id)
{
	std::vector<filter_d_entry *>::iterator it2 = filter_ips.begin();
	it2 += id;
	if (it2 == filter_ips.end()) {
		ng_slogdebug_spam(GetFullName().c_str(),"delete - did not find id - %d",id);
		return false;
	}
	filter_d_entry *entry = (*it2);
	if (!entry) return false;
	char *min_ip_s = get_ip_char(entry->min_ip);
	char *max_ip_s = get_ip_char(entry->max_ip);
	ng_slogdebug(GetFullName().c_str(),"deleted (id)- from %s to %s",min_ip_s,max_ip_s);
	free(min_ip_s);
	free(max_ip_s);
	delete (*it2);
    filter_ips.erase(it2);
	return true;
}

void NetGuard_IP_Filter::listranges(int level)
{
	int i = -1;
	std::vector<filter_d_entry *>::iterator it2;
	for (it2=filter_ips.begin(); it2 != filter_ips.end(); it2++) {	
		filter_d_entry *entry = (*it2);
		i++;
		if (!entry) continue;

		char *min_ip_s = get_ip_char(entry->min_ip);
		char *max_ip_s = get_ip_char(entry->max_ip);
		ng_slogdebug("ip_filter","%s (%d): from %s to %s",GetPrefixName().c_str(),i,min_ip_s,max_ip_s);
		free(min_ip_s);
		free(max_ip_s);
	}

	if (filter_ips.empty())
	{
		ng_slogdebug("ip_filter","%s: --empty--",GetPrefixName().c_str());
	}
	
	IP_FILTER_MAP::iterator it;
	for (it=filter_filters.begin(); it != filter_filters.end(); it++) {
		NetGuard_IP_Filter *entry =  (*it).second;
		if (!entry) continue;
		entry->listranges(level+1);
	}

}

NetGuard_IP_Filter* NetGuard_IP_Filter::add_filter(std::string inname)
{
	ng_slogdebug(GetFullName().c_str(),"adding filter %s ",inname.c_str());
	del_filter(inname);
	NetGuard_IP_Filter *myfilter = new NetGuard_IP_Filter(GetPrefixName(),inname);
	filter_filters[inname] = myfilter;
	return myfilter;
}

bool NetGuard_IP_Filter::del_filter(std::string inname)
{
	IP_FILTER_MAP::iterator it = filter_filters.find(inname);
	if (it == filter_filters.end()) {		// not in map.
		return false;
	} else {
		delete filter_filters[inname];
		filter_filters.erase(inname);
	}	
	return false;
}

int NetGuard_IP_Filter::filtercount(){
	return filter_filters.size();
}

std::string NetGuard_IP_Filter::name()
{
	return fname;
}

NetGuard_Global_IP_Filter* NetGuard_Global_IP_Filter::onlyInstance=NULL;


NetGuard_Global_IP_Filter::NetGuard_Global_IP_Filter() : NetGuard_IP_Filter("","BasicFilter")
{
	ng_slogdebug_spam("ip_filter","constructor");
	onlyInstance = this;
}

NetGuard_Global_IP_Filter::~NetGuard_Global_IP_Filter()
{	
	onlyInstance = NULL; //make sure the print dont fail as the object goes down
	ng_slogdebug_spam("ip_filter","destructor");
}

NetGuard_IP_Filter* NetGuard_Global_IP_Filter::add_filter(std::string inname)
{
	ng_slogdebug("ip_filter","adding main filter %s",inname.c_str());
	del_filter(inname);
	NetGuard_IP_Filter *myfilter = new NetGuard_IP_Filter("",inname);
	filter_filters[inname] = myfilter;
	return myfilter;
}

void NetGuard_Global_IP_Filter::listranges(int level)
{
	IP_FILTER_MAP::iterator it;
	for (it=filter_filters.begin(); it != filter_filters.end(); it++) {
		NetGuard_IP_Filter *entry =  (*it).second;
		if (!entry) continue;
		entry->listranges(level+1);
	}
}



