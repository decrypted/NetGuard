/***************************************************************************
 *   NetGuard Module                                                       *
 *                                                                         *
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


#include "../includes/modules/module.hpp"
#include "../includes/logging.h"
#include "../includes/config.hpp"
#include "../includes/ip_filter.hpp"
#include "../includes/state/state_handling.hpp"

int NetGuard_Module::init(NetGuard_Config *data) {
	if (!data) return -1;
	data_ = new NetGuard_Config();
	data_->assign(data);
	NetGuard_ModuleLoader_Base::InitPointer((NetGuard_ModuleLoader_Base*)data_->GetPointer("module_loader"));
	ng_slogdebug_spam("NetGuard_Module","init module instance");

	NetGuard_Global_IP_Filter::InitPointer((NetGuard_Global_IP_Filter*)data_->GetPointer("global_ip_filter"));
	GlobalCFG::InitPointer((GlobalCFG*)data_->GetPointer("global_cfg"));
	NetGuard_State_Handler::InitPointer((NetGuard_State_Handler*)data_->GetPointer("state_handler"));

	return 0;
};

void NetGuard_Module::got_input_out(std::vector<std::string> params, std::vector<int> intparams, std::string command) {
		if (NetGuard_ModuleLoader_Base::GetPointer())
		{
			NetGuard_ModuleLoader_Base::GetPointer()->do_broadcasting_input = 1;
 			got_input(params, intparams, command);
			NetGuard_ModuleLoader_Base::GetPointer()->do_broadcasting_input = 0;
		} else  got_input(params, intparams, command);
};



NetGuard_Module::~NetGuard_Module() {
	ng_slogdebug_spam("NetGuard_Module","destructor");
	if (data_)
	{
		delete data_;
		data_ = NULL;
	}
}

