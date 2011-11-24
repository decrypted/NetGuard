/***************************************************************************
 *   NetGuard Config Object                                                *
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


#ifndef NETGUARD_CONFIGHPP
#define NETGUARD_CONFIGHPP

#include "defines.h"
#include "types.hpp"
#include <string>
#include <map>
#include <string>
#include <vector>
#include <ext/hash_map>
#include <set>
#include <values.h>

#define CONFIG_VER_MAGIC "ngc0.2"

using namespace std;
using namespace __gnu_cxx;

class NetGuard_Module;
class NetGuard_Config;

enum {
	NG_CFG_INT = 0,
	NG_CFG_STR = 1,
	NG_CFG_POINTER = 2,
	NG_CFG_MAC = 3,
	NG_CFG_IP = 4,
	NG_CFG_TIME = 5,
	NG_CFG_CONFIG = 6,
};

class ConfigData
{	

	private:
		std::string name;
		int type;

		//values
		int int_val;
		void* p_val;
		mac_addr hw_addr;
		u_int32_t  addr;
		time_t time;
		std::string str_val;
		NetGuard_Config *config;
	public:
		ConfigData();
		~ConfigData();

		void clear();

		std::string get_string(bool addtypeinfo=true);

		int GetInt();
		void SetInt(int value);

		std::string GetStr();
		void SetStr(std::string value);
		
		mac_addr *GetMac();
		void SetMac(mac_addr value);

		time_t GetTime();
		void SetTime(time_t value);

		u_int32_t GetIP();
		void SetIP(u_int32_t value);

		NetGuard_Module* GetModule();
		void SetModule(NetGuard_Module* value);

		NetGuard_Config* GetConfig();
		void SetConfig(NetGuard_Config *value);

		void* GetPointer();
		void SetPointer(void* value);

		void assign(ConfigData *data);

		int GetType() {return type;};

		bool savedata(FILE *myfile);
		bool loaddata(FILE *myfile);
		bool saveable();

};


typedef hash_map<std::string, ConfigData*, string_hash> ConfigMap;


class NetGuard_Config
{
	protected:
		ConfigMap data;
		mac_addr zero_hw_addr;

	public:
		std::string config_path;	

		NetGuard_Config();
		virtual ~NetGuard_Config();

		void clear();

        std::string get_string(bool addtypeinfo=true);

		//load/save general config date
		virtual void loaddata() {};
		virtual void savedata() {};

		ConfigData *GetItem(std::string name);

		bool ItemExists(std::string name) {return GetItem(name)!=NULL;};

		bool AddItem(std::string name, ConfigData* indata);

		int GetInt(std::string name, int def=MININT);
		void SetInt(std::string name, int value);

		std::string GetStr(std::string name, std::string def="");
		void SetStr(std::string name, std::string value);

		mac_addr *GetMac(std::string name, mac_addr *def=NULL);
		void SetMac(std::string name, mac_addr value);

		time_t GetTime(std::string name, time_t def=MININT);
		void SetTime(std::string name, time_t value);

		u_int32_t GetIP(std::string name, u_int32_t def=0);
		void SetIP(std::string name, u_int32_t value);

		NetGuard_Module* GetModule(std::string name, NetGuard_Module* def=NULL);
		void SetModule(std::string name, NetGuard_Module* value);

		NetGuard_Config* GetConfig(std::string name, NetGuard_Config* def=NULL);
		void SetConfig(std::string name, NetGuard_Config *value);

		void* GetPointer(std::string name, void* def = NULL);
		void SetPointer(std::string name, void* value);

		void assign(NetGuard_Config *indata);
		void add(NetGuard_Config *indata);
		bool remove(std::string name);
		
		ConfigMap *GetData() {return &data;};

		bool savedata(FILE *myfile);
		bool loaddata(FILE *myfile);

};

#include "modules/module.hpp"

class NetGuard_Config_Static: public NetGuard_Config
{
	void loaddata() {};
	void savedata() {};
};

class GlobalCFG: public NetGuard_Config
{
	public:
		static class GlobalCFG *onlyInstance;
		//static int GlobalCFG_CNT;

		inline static GlobalCFG& Get()
		{
			if(!onlyInstance)
				onlyInstance=new GlobalCFG; 
			return *onlyInstance;
		}

		inline static GlobalCFG* GetPointer()
		{
			if(!onlyInstance)
				onlyInstance=new GlobalCFG; 
			return onlyInstance;
		}

		static void InitPointer(GlobalCFG* data) {
			onlyInstance = data;
		}

		static void Delete() {
			if(onlyInstance)
				delete onlyInstance; 
			onlyInstance=NULL;
		}

		void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);

		inline static ConfigData *GetItem(std::string name) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetItem(name); 
			return NULL;
		};

		inline static bool ItemExists(std::string name) {return GetItem(name)!=NULL;};

		inline static int GetInt(std::string name, int def=MININT) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetInt(name,def); 
			return def;
		};

		inline static std::string GetStr(std::string name, std::string def="") {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetStr(name,def); 
			return def;
		};

		inline static mac_addr *GetMac(std::string name, mac_addr *def=NULL) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetMac(name,def); 
			return def;
		};

		inline static time_t GetTime(std::string name, time_t def=MININT) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetTime(name,def); 
			return def;
		};

		inline static u_int32_t GetIP(std::string name, u_int32_t def=0) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetIP(name,def); 
			return def;
		};

		inline static NetGuard_Module* GetModule(std::string name, NetGuard_Module* def=NULL) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetModule(name,def); 
			return def;
		};

		inline static NetGuard_Config* GetConfig(std::string name, NetGuard_Config* def=NULL) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetConfig(name,def); 
			return def;
		};

		inline static void* GetPointer(std::string name, void* def = NULL) {
			if(onlyInstance)
				return ((NetGuard_Config*)onlyInstance)->GetPointer(name,def); 
			return def;
		};

};

#endif

