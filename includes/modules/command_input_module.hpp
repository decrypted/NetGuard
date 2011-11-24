/***************************************************************************
 *   NetGuard Module Definitions                                           *
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


#ifndef NETGUARD_COMMANDINPUTMODULE_HPP
#define NETGUARD_COMMANDINPUTMODULE_HPP

#include "module.hpp"

class NetGuard_Command_Input_Module: public NetGuard_Module
{
	public:
		//Callback Object - the object that this module can send the commands to with  got_input or  get_control_message
		class NetGuard_Module *CallBack_;

		NetGuard_Command_Input_Module() { CallBack_=NULL; name_ = ("default_command_input_module"); type = NETGUARD_COMMAND_INPUT_MODULE_TYPE; };

		virtual ~NetGuard_Command_Input_Module() {};

};

// the types of the class factories
typedef NetGuard_Command_Input_Module* (*create_command_input_module_t)();
typedef void (*destroy_command_input_module_t) (NetGuard_Command_Input_Module* p);

#endif

