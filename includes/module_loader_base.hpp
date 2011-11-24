/***************************************************************************
 *   NetGuard Module Loader Base                                           *
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
 *   This program is distributed in the hope that it will be useful,        *
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

#ifndef NETGUARD_MODULE_LOADER_BASE
#define NETGUARD_MODULE_LOADER_BASE

#include "defines.h"

#include <dlfcn.h>
#include "../includes/tools.h"
#include "../includes/modules/module.hpp"
#include "../includes/modules/general_module.hpp"

enum {
	NETGUARD_MODULE_STATE_INIT = 0,
	NETGUARD_MODULE_STATE_LOADED = 1,
	NETGUARD_MODULE_STATE_STARTING = 2,
	NETGUARD_MODULE_STATE_STARTED = 3,
};

class NetGuard_ModuleLoader_Entry
{
	protected:
		void *handle_;
		int state_;
		int type_;
		int do_delete;
		int do_reload;
		int can_delete;
		std::string name_;
		std::string version_;
		std::string filename_;
		NetGuard_Module *module_;
		NetGuard_ModuleLoader_Entry() {};

		void* load_symbol(const char *symbol);

	public:
		virtual NetGuard_Module *module() { return module_;};

		NetGuard_ModuleLoader_Entry(void *handle);
		virtual ~NetGuard_ModuleLoader_Entry();

		virtual int loadmodule() = 0;
		virtual int unloadmodule() = 0;
		void setVersion(std::string value);
		void setName(std::string value);
		void SetFileName(std::string value);

		std::string Version() { return version_;};
		std::string Name() { return name_;};
		std::string FileName() { return filename_;};

		void CanDelete();
		int GetCanDelete() {return can_delete;};
		void DoDelete();
		int GetDoDelete() {return do_delete;};
		void DoReload();
		int GetDoReload() {return do_reload;};

};

typedef std::map<std::string, NetGuard_ModuleLoader_Entry*> ModuleLoader_Map;

class NetGuard_ModuleLoader_Base
{
	protected:

		ModuleLoader_Map modules;

		NetGuard_General_Module *main_module_;

		struct tm my_time;
		time_t now;
		unsigned int timer_counter;

		static class NetGuard_ModuleLoader_Base *onlyInstance;

	public:
		static int basic_loglevel;

		static sigset_t MaskSignals();
		static void UnMaskSignals();
		static void UnMaskSignals(sigset_t old_sigset);

		static NetGuard_ModuleLoader_Base& Get()
		{
			return *onlyInstance;
		}

		static NetGuard_ModuleLoader_Base* GetPointer()
		{
			return onlyInstance;
		}

		static void InitPointer(NetGuard_ModuleLoader_Base* data) {
			onlyInstance = data;
		}

		int do_broadcasting_input;

		NetGuard_ModuleLoader_Base();
		virtual ~NetGuard_ModuleLoader_Base();

		inline static NetGuard_General_Module& Get_Main_Module()
		{
			if (onlyInstance)
				return *((*onlyInstance).main_module_);
			NetGuard_General_Module *tmp_ = NULL;
			return *tmp_;
		}

		inline static NetGuard_General_Module* Get_Main_ModulePointer()
		{
			if (onlyInstance)
				return (*onlyInstance).main_module_;
			return NULL;
		}

		inline static void *send_cmsg(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) {
			if (onlyInstance)
				return onlyInstance->broadcast_control_message(sender,command,params,data);
			return NULL;
		};

		virtual void *broadcast_control_message(NetGuard_Module *sender, std::string command, ConfigData *params, void *data) {
			return NULL;
		};

		inline static void send_cmd(std::vector<std::string> params, std::vector<int> intparams, std::string command) {
			if (onlyInstance)
				onlyInstance->broadcast_input(params,intparams, command);
		};

		virtual void broadcast_input(std::vector<std::string> params, std::vector<int> intparams, std::string command) = 0;

		static int flog(std::string sender, int level, const char *fmt, ...);
		static int flog(NetGuard_Module *sender, int level, const char *fmt, ...);

		//log error code
		static int flog_code(std::string sender, int code, int level, const char *fmt, ...);
		static int flog_code(NetGuard_Module *sender, int code, int level, const char *fmt, ...);

		//ignore the next ingore count log entrys! (as long as we are not threaded that is no issue //TODO better ideas?
		static int flog_buff(std::string sender, int ingore, int level, const char *fmt, ...);
		static int flog_buff(NetGuard_Module *sender, int ingore, int level, const char *fmt, ...);

		static void log(NetGuard_Module *sender, char *message, int level = 0) {
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message(sender,message,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				if (sender) {
					printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
				} else  printf("%s - Log_Base (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};

		static void log(std::string sender, char *message, int level = 0)
		{
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message(sender,message,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};

		//buffers the log -> ignores duplicates for some time and ingores the ingore next messages also //TODO threadsave
		//buffer only works if the instance is there
		static void log_buff(NetGuard_Module *sender, char *message, int ingore, int level) {
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message_buff(sender,message,ingore,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				if (sender) {
					printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
				} else  printf("%s - Log_Base (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};

		//buffers the log -> ignores duplicates for some time and ingores the ingore next messages also //TODO threadsave
		//buffer only works if the instance is there
		static void log_buff(std::string sender, char *message, int ingore, int level)
		{
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message_buff(sender,message,ingore,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};

		//return code logging -> reports a result code
		static void log_code(NetGuard_Module *sender, char *message, int code, int level) {
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message_code(sender,message,code,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				if (sender) {
					printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender->GetName().c_str(),level,message);
				} else  printf("%s - Log_Base (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};

		//return code logging -> reports a result code
		static void log_code(std::string sender, char *message, int code, int level)
		{
			if (onlyInstance) {
				//printf("going to object\n");
				onlyInstance->log_message_code(sender,message,code,level);
			} else {
				if (basic_loglevel < level) return;
				sigset_t myset = NetGuard_ModuleLoader_Base::MaskSignals();
				printf("%s - Log_Base \"%s\" (%d): %s\n",NetGuard_ModuleLoader_Base::GetLogDateStr().c_str(),sender.c_str(),level,message);
				NetGuard_ModuleLoader_Base::UnMaskSignals(myset);
			}
		};



		virtual void log_message(NetGuard_Module *sender, char *message, int level = 0) = 0;
		virtual void log_message(std::string sender, char *message, int level = 0) = 0;

		virtual void log_message_buff(NetGuard_Module *sender, char *message, int ingore, int level) = 0;
		virtual void log_message_buff(std::string sender, char *message, int ingore, int level) = 0;

		virtual void log_message_code(NetGuard_Module *sender, char *message, int retcode, int level) = 0;
		virtual void log_message_code(std::string sender, char *message, int retcode, int level) = 0;

		inline static std::string GetLogDateStr() {
			char buffer [120];
			const struct tm * timeinfo = NetGuard_ModuleLoader_Base::GetTime();
			strftime (buffer,120,GlobalCFG::GetStr("log_time_format","%s %T").c_str(),timeinfo);
			return buffer;
		}

		inline static const tm* GetTime() {
			if (onlyInstance) {
				return &(onlyInstance->my_time);
			} else {
				time_t now;
				time(&now);
				return localtime(&now); 
			}
		}

		inline static time_t GetNow() {
			if (onlyInstance) {
				return onlyInstance->now;
			} else {
				time_t now;
				time(&now);
				return now;
			}
		}

		static unsigned int GetCounter() {
			if (onlyInstance) {
				return onlyInstance->timer_counter;
			} else return 0;
		}

		virtual void broadcast_packet(unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) = 0; 
		virtual void broadcast_user_packet(struct user_data *u_data, int *mode, unsigned int *vlanid, struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data) = 0;


};

#endif

