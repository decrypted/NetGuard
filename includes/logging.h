/***************************************************************************
 *   NetGuard Module Loggin Includes                                       *
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

#ifndef NETGUARD_LOGGING_INC
#define NETGUARD_LOGGING_INC

#include "defines.h"
#include "module_loader_base.hpp"

#define RET_WRONG_SYNTAX -10
#define RET_NOT_FOUND -404

//this are wrapper functions for the logging - only them should be used 
//or the NetGuard_ModuleLoader_Base directly to send log messages to somewhere
#define ng_logdebug(...) NetGuard_ModuleLoader_Base::flog(this,1000,__VA_ARGS__)
#define ng_logdebug_spam(...) NetGuard_ModuleLoader_Base::flog(this,2000,__VA_ARGS__)
#define ng_logdebug_spam_spam(...) 

//use this define to dont compile with DEBUG messages
//#define ng_logdebug_spam(...) 
//#define ng_logdebug(...)

#define ng_logext(level,...) NetGuard_ModuleLoader_Base::flog(this,level,__VA_ARGS__)
#define ng_log(...) NetGuard_ModuleLoader_Base::flog(this,0,__VA_ARGS__)
#define ng_logout(...) NetGuard_ModuleLoader_Base::flog(this,100,__VA_ARGS__)
#define ng_logerror(...) NetGuard_ModuleLoader_Base::flog_code(this,-1,-1,__VA_ARGS__)

#define ng_logout_code(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,100,__VA_ARGS__)
#define ng_logout_retcode(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,100,__VA_ARGS__)
#define ng_logout_ret(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,100,__VA_ARGS__)
#define ng_logout_ok(...) NetGuard_ModuleLoader_Base::flog_code(this,0,100,__VA_ARGS__)
#define ng_logout_not_found(...) NetGuard_ModuleLoader_Base::flog_code(this,RET_NOT_FOUND,100,__VA_ARGS__)

#define ng_logerror_code(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,-1,__VA_ARGS__)
#define ng_logerror_retcode(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,-1,__VA_ARGS__)
#define ng_logerror_ret(code,...) NetGuard_ModuleLoader_Base::flog_code(this,code,-1,__VA_ARGS__)


#define ng_log_ext_buff(ignore,level,...) NetGuard_ModuleLoader_Base::flog_buff(this,ignore,level,__VA_ARGS__)
#define ng_log_buff(ignore,...) NetGuard_ModuleLoader_Base::flog_buff(this,ignore,0,__VA_ARGS__)
#define ng_logout_buff(ignore,...) NetGuard_ModuleLoader_Base::flog_buff(this,ignore,100,__VA_ARGS__)
#define ng_logdebug_buff(ignore,...) NetGuard_ModuleLoader_Base::flog_buff(this,ignore,1000,__VA_ARGS__)
#define ng_logerror_buff(ignore,...) NetGuard_ModuleLoader_Base::flog_buff(this,ignore,-1,__VA_ARGS__)



//ng_s... can be used if log is written outside from a NetGuard Module object
#define ng_slogdebug(source,...) NetGuard_ModuleLoader_Base::flog(source,1000,__VA_ARGS__)
#define ng_slogdebug_spam(source,...) NetGuard_ModuleLoader_Base::flog(source,2000,__VA_ARGS__)
#define ng_slogdebug_spam_spam(source,...) 

//use this define to dont compile with DEBUG messages
//#define ng_slogdebug(...)
//#define ng_slogdebug_spam(source,...) 

#define ng_slogext(source,level,...) NetGuard_ModuleLoader_Base::flog(source,level,__VA_ARGS__)
#define ng_slog(source,...) NetGuard_ModuleLoader_Base::flog(source,0,__VA_ARGS__)
#define ng_slogout(source,...) NetGuard_ModuleLoader_Base::flog(source,100,__VA_ARGS__)
#define ng_slogout_ok(source,...) NetGuard_ModuleLoader_Base::flog_code(source,0,100,__VA_ARGS__)
#define ng_slogout_not_found(source,...) NetGuard_ModuleLoader_Base::flog_code(source,RET_NOT_FOUND,100,__VA_ARGS__)
#define ng_slogerror(source,...) NetGuard_ModuleLoader_Base::flog_code(source,-1,-1,__VA_ARGS__)

#define ng_slogout_code(source,code,...) NetGuard_ModuleLoader_Base::flog_code(source,code,100,__VA_ARGS__)
#define ng_slogout_retcode(source,code,...) NetGuard_ModuleLoader_Base::flog_code(source,code,100,__VA_ARGS__)
#define ng_slogout_ret(source,code,...) NetGuard_ModuleLoader_Base::flog_code(source,code,100,__VA_ARGS__)

#define ng_slogerror_code(code,source,...) NetGuard_ModuleLoader_Base::flog_code(source,code,-1,__VA_ARGS__)
#define ng_slogerror_retcode(code,source,...) NetGuard_ModuleLoader_Base::flog_code(source,code,-1,__VA_ARGS__)
#define ng_slogerror_ret(code,source,...) NetGuard_ModuleLoader_Base::flog_code(source,code,-1,__VA_ARGS__)


#define ng_slogext_buff(source,ignore,level,...) NetGuard_ModuleLoader_Base::flog_buff(source,ignore,level,__VA_ARGS__)
#define ng_slog_buff(source,ignore,...) NetGuard_ModuleLoader_Base::flog_buff(source,ignore,0,__VA_ARGS__)
#define ng_slogout_buff(source,ignore,...) NetGuard_ModuleLoader_Base::flog_buff(source,ignore,100,__VA_ARGS__)
#define ng_slogerror_buff(source,ignore,...) NetGuard_ModuleLoader_Base::flog_buff(source,ignore,-1,__VA_ARGS__)



#endif

