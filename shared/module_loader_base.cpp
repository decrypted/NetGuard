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


#include "../includes/tools.h"
#include "../includes/module_loader_base.hpp"
#include "../includes/modules/module.hpp"
#include "../includes/logging.h"
#include "compile.h"
#include <stdarg.h>
#include <signal.h>

//NetGuard_ModuleLoader_Entry
NetGuard_ModuleLoader_Entry::NetGuard_ModuleLoader_Entry(void *handle) {
	handle_ = handle;
	version_ = "";
	name_ = "";
	module_ = NULL;
	filename_ = "";
	do_delete = 0;
	can_delete = 0;
	do_reload = 0;
	ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","constructor - handle %x",(int)handle_);
}

NetGuard_ModuleLoader_Entry::~NetGuard_ModuleLoader_Entry() {	
	version_.clear();
	name_.clear();
	filename_.clear();
	ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","destructor - handle %x",(int)handle_);
	if (handle_)
	{
		ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","closing library... %x",(int)handle_);	
		dlclose(handle_);
	}
}

void NetGuard_ModuleLoader_Entry::setVersion(std::string value) {
	ng_slogdebug("NetGuard_ModuleLoader_Entry","setVersion - handle %x - \"%s\"",(int)handle_,value.c_str());
	version_ = value;
}
void NetGuard_ModuleLoader_Entry::setName(std::string value) {
	ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","setName - handle %x - \"%s\"",(int)handle_,value.c_str());
	name_ = value;
	if (module_)
		module_->SetName(value);
}

void NetGuard_ModuleLoader_Entry::SetFileName(std::string value) {
	ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","SetFileName - handle %x - \"%s\"",(int)handle_,value.c_str());
	filename_ = value;
}

void* NetGuard_ModuleLoader_Entry::load_symbol(const char *symbol) {
	ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","Loading symbol \"%s\" ...",symbol);
	void *result = dlsym(handle_, symbol);
	if (!result) {
		ng_slogerror("NetGuard_ModuleLoader_Entry","Cannot load symbol %s - %s ",symbol, dlerror());
		//dlclose(handle);
		return NULL;
	} else {
		ng_slogdebug_spam("NetGuard_ModuleLoader_Entry","done.");
		return result;
	}
}

void NetGuard_ModuleLoader_Entry::DoDelete() {
	do_delete = 1;
}

void NetGuard_ModuleLoader_Entry::DoReload() {
	do_reload = 1;
}

NetGuard_ModuleLoader_Base* NetGuard_ModuleLoader_Base::onlyInstance=NULL;
int NetGuard_ModuleLoader_Base::basic_loglevel=0;

NetGuard_ModuleLoader_Base::NetGuard_ModuleLoader_Base()
{
	ng_slogdebug_spam("NetGuard_ModuleLoader_Base","constructor");
	onlyInstance = this;
}

NetGuard_ModuleLoader_Base::~NetGuard_ModuleLoader_Base()
{	
	onlyInstance = NULL; //make sure the print dont fail as the object goes down
	ng_slogdebug_spam("NetGuard_ModuleLoader_Base","destructor");
}


void NetGuard_ModuleLoader_Base::broadcast_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params.size() != 0)
		if (params[0] == "version")
		{
			ng_slogext("NetGuard_ModuleLoader_Base",100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
		}
}


sigset_t NetGuard_ModuleLoader_Base::MaskSignals()
{
  sigset_t old_sigset;
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGUSR1);
  sigaddset(&sigset, SIGUSR2);
  sigaddset(&sigset, SIGHUP);
  sigaddset(&sigset, SIGINT);
  sigaddset(&sigset, SIGTERM);
  sigaddset(&sigset, SIGALRM);  
  sigprocmask(SIG_BLOCK, &sigset, &old_sigset);
  return old_sigset;
}

void NetGuard_ModuleLoader_Base::UnMaskSignals()
{
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGUSR1);
	sigaddset(&sigset, SIGUSR2);
	sigaddset(&sigset, SIGHUP);
	sigaddset(&sigset, SIGTERM);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &sigset, 0);
}

void NetGuard_ModuleLoader_Base::UnMaskSignals(sigset_t old_sigset)
{
	sigprocmask(SIG_SETMASK, &old_sigset, 0);
}


int NetGuard_ModuleLoader_Base::flog(std::string sender, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log(sender,p,level);
	delete p;
	return 0;
}

int NetGuard_ModuleLoader_Base::flog(NetGuard_Module *sender, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log(sender,p,level);
	delete p;
	return 0;
}

int NetGuard_ModuleLoader_Base::flog_buff(std::string sender, int ignore, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log_buff(sender,p,ignore,level);
	delete p;
	return 0;
}

int NetGuard_ModuleLoader_Base::flog_buff(NetGuard_Module *sender, int ignore, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log_buff(sender,p,ignore,level);
	delete p;
	return 0;
}

int NetGuard_ModuleLoader_Base::flog_code(std::string sender, int retcode, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log_code(sender,p,retcode,level);
	delete p;
	return 0;
}

int NetGuard_ModuleLoader_Base::flog_code(NetGuard_Module *sender, int retcode, int level, const char *fmt, ...) {
	/* Guess we need no more than 1024 bytes. */
	int n, size = 1024;
	char *p;
	va_list ap;
	if ((p = (char*)malloc(size)) == NULL)
		return -1;
	sigset_t mysig = MaskSignals();
	while (1) {
		/* Try to print in the allocated space. */
		va_start(ap, fmt);
		n = vsnprintf (p, size, fmt, ap);
		va_end(ap);
		/* If that worked, return the string. */
		if (n > -1 && n < size)
			break;
		/* Else try again with more space. */
		if (n > -1)		/* glibc 2.1 */
			size = n+1; /* precisely what is needed */
		else			/* glibc 2.0 */
			size *= 2;  /* twice the old size */
		if ((p = (char*)realloc (p, size)) == NULL) {
			delete p;
			p = NULL;
			break;
		}
	}
	UnMaskSignals(mysig);
	
	if (!p) return -1;
	NetGuard_ModuleLoader_Base::log_code(sender,p,retcode,level);
	delete p;
	return 0;
}
