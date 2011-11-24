/***************************************************************************
 *   NetGuard Module Main                                                  *
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

//include the object that need to be exported
#include "group_accounting.hpp"

#include "module_main.hpp"
#include "compile.h"

#ifdef __cplusplus
extern "C" {
#endif

	const char* net_guard_module() {
		return NETGUARD_GENERAL_MODULE_IDENT;
	}

	const char* get_module_name() {
		return NetGuard_NAME;
	}

	const char* get_module_version() {
		return NetGuard_VERSION;
	}

	const char* get_interface_version() {
		return NETGUARD_MODULE_INTERFACE_VERSION;
	}

	NetGuard_General_Module* create_general_module() {
		return new NetGuard_GAccounting();
	}

	void destroy_general_module(NetGuard_General_Module* p) {
		delete p;
	}

#ifdef __cplusplus
}
#endif

//executed if module get loaded
void __attribute__ ((constructor)) my_init(void) {
}

//executed if module get unloaded
void __attribute__ ((destructor)) my_fini(void) {
}

