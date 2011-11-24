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


#ifndef NETGUARD_INPUTMODULE_HPP
#define NETGUARD_INPUTMODULE_HPP

#include "module.hpp"

class NetGuard_Input_Module: public NetGuard_Module
{
	protected:
		unsigned int do_break;	//if set true the poll function break on next run	

		//Callback Object - to that object the packages are send with packet_in
		//this has to be an General Module for now
		class NetGuard_General_Module *CallBack_;
	
	public:
		NetGuard_Input_Module() 
			:do_break(0)	{ name_ = ("default_input_module"); type = NETGUARD_INPUT_MODULE_TYPE; };

		virtual ~NetGuard_Input_Module() {};

		//poll this import module
		virtual int poll() = 0;

		//break the polling
		virtual void stop_poll()  = 0;

		//check the input source - 0 - its all fine
		virtual int check()  = 0;


};

// the types of the class factories
typedef NetGuard_Input_Module* (*create_input_module_t) ();
typedef void (*destroy_input_module_t)(NetGuard_Input_Module* p);

#endif

