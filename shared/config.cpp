/***************************************************************************
 *   NetGuard Config Objects                                               *
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

#include "../includes/config.hpp"
#include "../includes/logging.h"
#include "../includes/tools.h"
#include <values.h>
#include <sstream>

std::string int2string(const int& number) 
{ 
	std::ostringstream oss; 
	oss << number; 
	return oss.str(); 
}


GlobalCFG* GlobalCFG::onlyInstance=NULL;
//int GlobalCFG::GlobalCFG_CNT = 0;

//ConfigData
ConfigData::ConfigData()
{
	config = NULL;
	clear();
	//GlobalCFG::GlobalCFG_CNT++;
}

ConfigData::~ConfigData()
{
	type = -1;
	clear();
	str_val.clear();
	//GlobalCFG::GlobalCFG_CNT--;
}

void ConfigData::clear()
{
	if (config) {
		delete config;
		config = NULL;
	}
	type = MININT;
	int_val = MININT;
	p_val = NULL;
	setNULL_HW_ADDR(hw_addr);
	addr = 0;
	str_val = "";
	time = 0;
}

int ConfigData::GetInt() { 
	switch (type)
	{
	case NG_CFG_INT:
			return int_val;	
	}
	return MININT;
};

void ConfigData::SetInt(int value) {
	clear();
	type = NG_CFG_INT;
	int_val = value;
};

std::string ConfigData::GetStr() {
	switch (type)
	{
	case NG_CFG_STR:
			return str_val;	
	}
	return "";
};

void ConfigData::SetStr(std::string value) {
	clear();
	type = NG_CFG_STR;
	str_val = value;
};

mac_addr *ConfigData::GetMac() {
	switch (type)
	{
	case NG_CFG_MAC:
			return &hw_addr;	
	}
	setNULL_HW_ADDR(hw_addr);
	return &hw_addr;
};

void ConfigData::SetMac(mac_addr value){
	clear();
	type = NG_CFG_MAC;
	memcpy(hw_addr,value,sizeof(mac_addr));
};

time_t ConfigData::GetTime() {
	switch (type)
	{
	case NG_CFG_TIME:
			return time;
	}
	return MININT;
};

void ConfigData::SetTime(time_t value) {
	clear();
	type = NG_CFG_TIME;
	time = value;
};

u_int32_t ConfigData::GetIP(){
	switch (type)
	{
	case NG_CFG_IP:
			return addr;	
	}
	return 0;
};

void ConfigData::SetIP(u_int32_t value){
	clear();
	type = NG_CFG_IP;
	str_val = value;
};


NetGuard_Module* ConfigData::GetModule() { 
	switch (type)
	{
	case NG_CFG_POINTER:
			return (NetGuard_Module*)p_val;
	}
	return NULL;
};

void ConfigData::SetModule(NetGuard_Module* value) {
	clear();
	type = NG_CFG_POINTER;
	p_val = value;
};

NetGuard_Config* ConfigData::GetConfig() { 
	switch (type)
	{
	case NG_CFG_CONFIG:
			return (NetGuard_Config*)&config;
	}
	return NULL;
};

void ConfigData::SetConfig(NetGuard_Config *value) {
	clear();
	type = NG_CFG_CONFIG;
	config = new NetGuard_Config();
	config->assign(value);
};

void* ConfigData::GetPointer() { 
	switch (type)
	{
	case NG_CFG_POINTER:
			return p_val;
	}
	return NULL;
};

void ConfigData::SetPointer(void* value) {
	clear();
	type = NG_CFG_POINTER;
	p_val = value;
};

void ConfigData::assign(ConfigData *data) {
	type = 0;
	if (!data) return;
	clear();
	type = data->type;
	p_val = data->p_val;
	str_val = data->str_val;
	int_val = data->int_val;
	memcpy(&hw_addr,&data->hw_addr,sizeof(mac_addr));
	addr = data->addr;
	if (data->config)
	{
		config = new NetGuard_Config();
		config->assign(data->config);
	}
}

std::string ConfigData::get_string(bool addtypeinfo) 
{
	std::string tmp_str = "";
	std::string my_str;
	std::string my_str_2;
	char *ip = get_ip_char(addr);
	my_str = ip;
	free(ip);

	ip = (char*)malloc(sizeof(unsigned char)*20);
	sprintmac(ip,hw_addr);
	my_str_2 = ip;
	free(ip);


	switch (type)
	{
	case NG_CFG_INT:
		if (addtypeinfo) tmp_str.append("[i]='");
		tmp_str.append(int2string(int_val));
		if (addtypeinfo) tmp_str.append("'");
		break;
	case NG_CFG_TIME:
		if (addtypeinfo) tmp_str.append("[t]='");
		tmp_str.append(int2string(time));
		if (addtypeinfo) tmp_str.append("'");
		break;
	case NG_CFG_STR:
		if (addtypeinfo) tmp_str.append("[s]='");
		tmp_str.append(str_val);
		if (addtypeinfo) tmp_str.append("'");
		break;
	case NG_CFG_MAC:
		if (addtypeinfo) tmp_str.append("[m]='");
		tmp_str.append(my_str_2);
		if (addtypeinfo) tmp_str.append("'");
		break;
	case NG_CFG_IP:
		if (addtypeinfo) tmp_str.append("[a]='");
		tmp_str.append(my_str_2);
		if (addtypeinfo) tmp_str.append("'");
		break;
	case NG_CFG_CONFIG:	
		if (addtypeinfo) tmp_str.append("[c]='");
		tmp_str.append(config->get_string(addtypeinfo));
		if (addtypeinfo) tmp_str.append("'");
		break;
	}

	return tmp_str;
}


bool ConfigData::savedata(FILE *myfile) {
	fwrite(CONFIG_VER_MAGIC,strlen(CONFIG_VER_MAGIC),1,myfile);
	fwrite(&type,sizeof(type),1, myfile);

	size_t statelen = 0;
	switch (type)
	{
	case NG_CFG_INT:
			fwrite(&int_val,sizeof(int_val),1, myfile);
			break;
	case NG_CFG_TIME:
			fwrite(&time,sizeof(time),1, myfile);
			break;
	case NG_CFG_STR:
			statelen = str_val.length();
			fwrite(&statelen,sizeof(statelen),1, myfile);
			fwrite(str_val.c_str(),statelen,1, myfile);
			break;
	case NG_CFG_MAC:
			fwrite(&hw_addr,sizeof(mac_addr),1, myfile);
			break;
	case NG_CFG_IP:
			fwrite(&addr,sizeof(addr),1, myfile);
			break;
	case NG_CFG_CONFIG:	
			assert(config!=NULL);
			config->savedata(myfile);
	}
	return true;
}

bool ConfigData::loaddata(FILE *myfile) {

	clear();

	char * tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(CONFIG_VER_MAGIC)+1));
	tmpdata[strlen(CONFIG_VER_MAGIC)] = 0;
	int count = fread(&tmpdata[0],strlen(CONFIG_VER_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,CONFIG_VER_MAGIC) ) {
		free(tmpdata);
		return false;
	} else free(tmpdata);
	
	fread(&type,sizeof(type),1, myfile);
	size_t statelen = 0;
	char *tmpstate_d = NULL;
	switch (type)
	{
	case NG_CFG_INT:
			fread(&int_val,sizeof(int_val),1, myfile);
			break;
	case NG_CFG_TIME:
			fread(&time,sizeof(time),1, myfile);
			break;
	case NG_CFG_STR:
			fread(&statelen,sizeof(statelen),1, myfile);
			if (statelen > 500) return false;
			tmpstate_d = (char*)malloc(sizeof(unsigned char)*(statelen+1));
			memset(tmpstate_d,0,sizeof(unsigned char)*(statelen+1));
			fread(tmpstate_d,statelen,1, myfile);
			str_val = tmpstate_d;
			free(tmpstate_d);
			break;
	case NG_CFG_MAC:
			fread(&hw_addr,sizeof(mac_addr),1, myfile);
			break;
	case NG_CFG_IP:
			fread(&addr,sizeof(addr),1, myfile);
			break;
	case NG_CFG_CONFIG:
			config = new NetGuard_Config();
			if (!config->loaddata(myfile))
			{
			  delete config;
			  return false;
			} return true;
			break;
	}
	return true;
}

bool ConfigData::saveable(){
	switch (type)
	{
	case NG_CFG_INT:
	case NG_CFG_TIME:
	case NG_CFG_STR:
	case NG_CFG_MAC:
	case NG_CFG_IP:
	case NG_CFG_CONFIG:
		return true;
	}
	return false;
}

//NetGuard_Config
NetGuard_Config::NetGuard_Config(){
	setNULL_HW_ADDR(zero_hw_addr);
	clear();
};

NetGuard_Config::~NetGuard_Config() {
	clear();
};

void NetGuard_Config::clear() {
	map_delete(data.begin(), data.end());
	data.erase(data.begin(), data.end());
	data.clear();
}

ConfigData *NetGuard_Config::GetItem(std::string name) {
	ConfigMap::iterator it = data.find(name);
	if (it == data.end()) {		// not in map.
		return NULL;
	} else return (*it).second;
}

bool NetGuard_Config::AddItem(std::string name, ConfigData *indata) {
	if (ItemExists(name)) return false;
	data.insert(pair<std::string, ConfigData *>(name, indata));
	return true;
}

bool NetGuard_Config::remove(std::string name) {
	ConfigMap::iterator it = data.find(name);
	if (!(it == data.end())) 
	{
		delete (*it).second;
		data.erase(it);
		return true;
	}
	return false;
}

int NetGuard_Config::GetInt(std::string name,int def) { 
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetInt();
	return def;
};

void NetGuard_Config::SetInt(std::string name, int value) {
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetInt(value);
};

std::string NetGuard_Config::GetStr(std::string name,std::string def) { 
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetStr();
	return def;
};

void NetGuard_Config::SetStr(std::string name, std::string value) {
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetStr(value);
};

mac_addr *NetGuard_Config::GetMac(std::string name, mac_addr *def) {
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetMac();
	if (def == NULL) {
		return &zero_hw_addr;
	} else return def;
}

void NetGuard_Config::SetMac(std::string name, mac_addr value){
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetMac(value);
}

time_t NetGuard_Config::GetTime(std::string name,time_t def) {
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetTime();
	return def;
}

void NetGuard_Config::SetTime(std::string name, time_t value){
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetTime(value);
}

u_int32_t NetGuard_Config::GetIP(std::string name,u_int32_t def){
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetIP();
	return def;
}

void NetGuard_Config::SetIP(std::string name, u_int32_t value){
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetIP(value);
}

NetGuard_Module* NetGuard_Config::GetModule(std::string name, NetGuard_Module* def) { 
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetModule();
	return def;
};

void NetGuard_Config::SetModule(std::string name, NetGuard_Module* value) {
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetModule(value);
};

NetGuard_Config* NetGuard_Config::GetConfig(std::string name, NetGuard_Config* def) {
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetConfig();
	return def;
};

void NetGuard_Config::SetConfig(std::string name, NetGuard_Config *value) {
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetConfig(value);
}

void* NetGuard_Config::GetPointer(std::string name, void* def) { 
	ConfigData *mydata = GetItem(name);
	if (mydata != NULL) return mydata->GetPointer();
	return def;
};

void NetGuard_Config::SetPointer(std::string name, void* value) {
	ConfigData *mydata = GetItem(name);
	if (mydata == NULL) {
		mydata = new ConfigData;
		if (!AddItem(name,mydata))
		{
			delete mydata;
			return;
		}
	}
	mydata->SetPointer(value);
};

void NetGuard_Config::assign(NetGuard_Config *indata) {
	clear();
	add(indata);
}

void NetGuard_Config::add(NetGuard_Config *indata) {
	if (!indata) return;
	ConfigMap::iterator it;
	for (it=indata->data.begin(); it != indata->data.end(); it++) {
		ConfigData *mydata = (*it).second;
		ConfigData *mydata_new = new ConfigData();
		mydata_new->assign(mydata);
		if (!AddItem((*it).first,mydata_new))
			delete mydata_new;
	}
}

std::string NetGuard_Config::get_string(bool addtypeinfo) {	
	std::string my_data = "{ ";

	ConfigMap::iterator it;
	for (it=data.begin(); it != data.end(); it++) {
		my_data.append("(");
		my_data.append((*it).first);
		my_data.append(((*it).second)->get_string(addtypeinfo));
		my_data.append(") ");
	}
	my_data.append("} ");
	return my_data;
}

bool NetGuard_Config::savedata(FILE *myfile) {
	ConfigMap::iterator it;
	unsigned int counter = 0;
	for (it=data.begin(); it != data.end(); it++)
		if ((*it).second->saveable()) counter++;

	fwrite(CONFIG_VER_MAGIC,strlen(CONFIG_VER_MAGIC),1,myfile);
	fwrite(&counter,sizeof(counter),1, myfile);
	for (it=data.begin(); it != data.end(); it++) {
		size_t statelen = (*it).first.length();
		fwrite(&statelen,sizeof(statelen),1, myfile);
		fwrite((*it).first.c_str(),statelen,1, myfile);
		(*it).second->savedata(myfile);
	}
	return true;
}

bool NetGuard_Config::loaddata(FILE *myfile) {
	clear();
	unsigned int counter = 0;
	ConfigData *new_data;

	char * tmpdata = (char *)malloc(sizeof(unsigned char)*(strlen(CONFIG_VER_MAGIC)+1));
	tmpdata[strlen(CONFIG_VER_MAGIC)] = 0;
	int count = fread(&tmpdata[0],strlen(CONFIG_VER_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,CONFIG_VER_MAGIC) ) {
		free(tmpdata);
		return false;
	} else free(tmpdata);
	
	fread(&counter,sizeof(counter),1, myfile);
	for (unsigned int i = 1; i <= counter ; i++) {
		size_t statelen = 0;
		fread(&statelen,sizeof(statelen),1, myfile);
		if (statelen > 500) return false;
		char *tmpstate_d = (char*)malloc(sizeof(unsigned char)*(statelen+1));
		memset(tmpstate_d,0,sizeof(unsigned char)*(statelen+1));
		fread(tmpstate_d,statelen,1, myfile);
		std::string myname = tmpstate_d;
		free(tmpstate_d);
		new_data = new ConfigData();
		if (new_data->loaddata(myfile))
		{
		  if (!AddItem(myname,new_data)) {
			  delete new_data;
			  return false;
		  }
		} else {
			delete new_data;
			return false;
		}
	}
	return true;
}

