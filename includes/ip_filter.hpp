/***************************************************************************
 *   NetGuard IP Filter                                                    *
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

#ifndef NETGUARD_IP_FILTER_INCLUDE
#define NETGUARD_IP_FILTER_INCLUDE

#include "defines.h"
#include <string>
#include <map>
#include "../includes/logging.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct filter_d_entry{
		u_int32_t min_ip;
		u_int32_t max_ip;
		u_int32_t min_ip_hl;
		u_int32_t max_ip_hl;
} filter_d_entry;

#ifdef __cplusplus
}
#endif

class NetGuard_IP_Filter;

typedef std::map<std::string, NetGuard_IP_Filter*> IP_FILTER_MAP;

class NetGuard_IP_Filter
{
	protected:
		std::vector<filter_d_entry *> filter_ips;
        IP_FILTER_MAP filter_filters;
		std::string fname;
		std::string fprefix;



	public:
		NetGuard_IP_Filter(std::string inprefix,std::string inname);
		virtual ~NetGuard_IP_Filter();

		inline bool in_range(u_int32_t *ip);

		bool addrange(u_int32_t min_ip, u_int32_t max_ip);
		bool delrange(u_int32_t min_ip, u_int32_t max_ip);
		bool delrange_id(u_int32_t id);
		virtual void listranges(int level);

		virtual NetGuard_IP_Filter* add_filter(std::string inname);
		inline virtual NetGuard_IP_Filter* get_filter(std::string inname);
		bool del_filter(std::string inname);

		std::string name();
		std::string GetFullName();
		std::string GetPrefixName();

		void clear();
		int filtercount();

		inline bool operator==(u_int32_t *ip) { return in_range(ip); };
};


class NetGuard_Global_IP_Filter: public NetGuard_IP_Filter
{
	protected:
		static class NetGuard_Global_IP_Filter *onlyInstance;

		bool in_range(u_int32_t ip) { return false;};
		bool addrange(u_int32_t min_ip, u_int32_t max_ip) { return false;};
		bool delrange(u_int32_t min_ip, u_int32_t max_ip) { return false;};
		bool delrange_id(u_int32_t id) { return false;};

		std::string name() { return NetGuard_IP_Filter::name();};

		void clear() { NetGuard_IP_Filter::clear();};
	public:

		inline static NetGuard_Global_IP_Filter& Get()
		{
			if(!onlyInstance)
				onlyInstance=new NetGuard_Global_IP_Filter; 
			return *onlyInstance;
		}

		inline static NetGuard_Global_IP_Filter* GetPointer()
		{
			if(!onlyInstance)
				onlyInstance=new NetGuard_Global_IP_Filter; 
			return onlyInstance;
		}

		static void InitPointer(NetGuard_Global_IP_Filter* data) {
			onlyInstance = data;
		}

		static void Delete(){delete onlyInstance;}

		NetGuard_Global_IP_Filter();
		~NetGuard_Global_IP_Filter();

		inline static NetGuard_IP_Filter* Filter(std::string inname) {
			if (onlyInstance) {
				return onlyInstance->get_filter(inname,false,0);
			} else return NULL;
		};

        NetGuard_IP_Filter* add_filter(std::string inname);
		inline NetGuard_IP_Filter* get_filter(std::string inname,bool do_create=false,int parent=0);

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);		

		void listranges(int level);
};

//inline functions

//empty filter = true
inline bool NetGuard_IP_Filter::in_range(u_int32_t *ip) 
{		
	bool match = false;
	bool ishl = true;
	if (filter_ips.size() > 0)
	{
		std::vector<filter_d_entry *>::iterator it2;
		for (it2=filter_ips.begin(); it2 != filter_ips.end(); it2++) {	
			filter_d_entry *entry = (*it2);
			if (!entry) continue;
			if (ishl)
			{
				if ( (*ip) >= entry->min_ip_hl  && (*ip) <= entry->max_ip_hl) {
					match = true;
					break;
				}
			} else {
				if ( (*ip) >= entry->min_ip  && (*ip) <= entry->max_ip) {
					match = true;
					break;
				}
			}
		}
	} else match = true;

	if (!match) return false;

	if (filter_filters.size() > 0)
	{
		IP_FILTER_MAP::iterator it;
		for (it=filter_filters.begin(); it != filter_filters.end(); it++) {
			NetGuard_IP_Filter *entry =  (*it).second;
			if (!entry) continue;
			if (!entry->in_range(ip)) {
				return false;
			}
		}
	}
	return true;
}

inline NetGuard_IP_Filter* NetGuard_IP_Filter::get_filter(std::string inname)
{
	IP_FILTER_MAP::iterator it = filter_filters.find(inname);
	if (it == filter_filters.end()) {		// not in map.
		return NULL;
	} else {
		return filter_filters[inname];
	}	
	return NULL;
}

inline NetGuard_IP_Filter* NetGuard_Global_IP_Filter::get_filter(std::string inname, bool do_create,int parent) {
	//we need to parse the name here now
	std::vector<std::string> params;
	split(inname.c_str(),".",params, false);

	NetGuard_IP_Filter* tmpConfig = this;
	NetGuard_IP_Filter* tmpConfig2 = this;
	for( unsigned int i=0; i+parent < params.size(); i++ )
	{		 
		 tmpConfig2 = tmpConfig->get_filter(params[i]);
		 if ((tmpConfig2 == NULL) && do_create)
			 tmpConfig2 = tmpConfig->add_filter(params[i]);		 
		 tmpConfig = tmpConfig2;
		 if (tmpConfig == NULL) {
			 //missing link
			 ng_slogerror("ip_filter","can not find filter %s in chain %s",params[i].c_str(),inname.c_str());
			 return NULL;
		 }
	}
	return tmpConfig;
}

#endif

