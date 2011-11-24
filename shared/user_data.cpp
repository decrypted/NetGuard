/***************************************************************************
 *   NetGuard Data Storage definition for the accounting module            *
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

#include "../includes/storage/user_data.hpp"
#include "../includes/module_loader_base.hpp"

#include "../includes/tools.h"
#include "../includes/logging.h"
#include <math.h>

static const char *ACC_DATA_VERSION_MAGIC = "netguard_accounting_db_v0.3";

User_Data_Tools::User_Data_Tools(std::string inlog_str)
{
	log_str = inlog_str;
	ng_slogdebug_spam(log_str,"constructor");
	#ifdef userlist_use_simple
	user_list_head = NULL;
	#else
	save_file = NULL;
	save_index = 0;
	save_in_progress = false;
	savejunk = 10000;
	#endif
}

User_Data_Tools::~User_Data_Tools()
{
	ng_slogdebug_spam(log_str,"destructor");
	list_clear();
	#ifdef userlist_use_simple
	user_list_head = NULL;
	#endif
}

void User_Data_Tools::loaddata(std::string filename, int rename_onfail)
{
	struct user_data * u_data;
	char *tmpdata;
	int count = 0;
	FILE *myfile;
	struct stat fileinfo;

	list_clear();

	if (!filename.length()) {
		ng_slogerror(log_str,0,"can not load - got emtpy filename");
		return;
	}
	
	ng_slogdebug_spam(log_str,"loading data from %s",filename.c_str());	

	if (stat(filename.c_str(),&fileinfo)) {
		ng_slogerror(log_str,"cant stat data file %s",filename.c_str());
		return;
	}
	myfile = fopen(filename.c_str(), "r");
	if (!myfile) {
		ng_slogerror(log_str,"cant open data file %s",filename.c_str());
		return;
	}

	tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(ACC_DATA_VERSION_MAGIC)+1));
	tmpdata[strlen(ACC_DATA_VERSION_MAGIC)] = 0;

	count = fread(&tmpdata[0],strlen(ACC_DATA_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_DATA_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant read traffic data from %s - illegal format (%s <> %s)",filename.c_str(),(char *)tmpdata,ACC_DATA_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogext(log_str,0,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}
		free(tmpdata);
		return;
	}

	ng_slogdebug_spam(log_str,"loading %lu bytes data",fileinfo.st_size);

	off_t f_pos =  ftell(myfile);
	int counter = 0;
	while ( (unsigned int)(fileinfo.st_size - f_pos - strlen(ACC_DATA_VERSION_MAGIC)) >= sizeof(struct user_data) ) {
		u_data = (struct user_data*) malloc(sizeof(struct user_data));
		memset(u_data,0,sizeof(struct user_data));

		fread(u_data,sizeof(struct user_data),1, myfile);
		
		//loaded module data is not assigned yet modules have to take care about this
		memset(&u_data->module_data,0,MAX_MODULES * sizeof(void *));

		ng_slogdebug_spam(log_str,"loaded %-15s - %u",inet_ntoa(*(struct in_addr *)&u_data->saddr),u_data->saddr);

		add_user(u_data,u_data->vlan_id);
		counter++;

		f_pos =  ftell(myfile);
	}

	count = fread(tmpdata,strlen(ACC_DATA_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,ACC_DATA_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant traffic data file (end) from %s - illegal format - renaming file",filename.c_str());

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogext(log_str,0,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}

		list_clear();
		free(tmpdata);
		return;
	}

	ng_slogdebug(log_str,"loaded %d users",counter);

	fclose(myfile);
	free(tmpdata);
}

void User_Data_Tools::savedata(std::string filename,bool allatonce)
{
	#ifdef userlist_use_simple
	struct  user_list * m_users;
	m_users = user_list_head;
	#endif
	struct  user_data * u_data;
	void    *t_module_data[MAX_MODULES];
	int     i;
	FILE *myfile;
	
	ng_slogdebug_spam(log_str,"saving ....");

	#ifndef userlist_use_simple
	bool was_reset = false;
	if (allatonce && save_in_progress)
	{
		ng_slogerror(log_str,"save was in progress but no progress save was requested -> cleanup");
		save_in_progress = false;
		fclose(save_file);
		was_reset = true;
	}

	if (!save_in_progress)
	{
		ng_slogdebug_spam(log_str,"enter new save");

		if (!filename.length()) {
			ng_slogerror(log_str,0,"can not save - got emtpy filename");
			return;
		}

		if (!allatonce)
		{
			ng_slogdebug_spam(log_str,"save junk steps %d",savejunk);
		}

		if (!was_reset)
		{
			string rename_file = filename;
			rename_file.append(".old");
			if (rename(filename.c_str(), rename_file.c_str()))
			{
				ng_slogerror(log_str,0,"rename accounting data from %s to %s",filename.c_str(),rename_file.c_str());
			}
		}

		ng_slogext(log_str,2000,"saving users to %s",filename.c_str());

		myfile = fopen(filename.c_str(), "w+");
		if (!myfile) {
			ng_slogerror(log_str,0,"can not save users to %s",filename.c_str());
			return;
		}

		fwrite(ACC_DATA_VERSION_MAGIC,strlen(ACC_DATA_VERSION_MAGIC),1,myfile);

		save_index = 0;
		save_file = myfile;
		save_index_data = get_list_idx();

	} else {
		if (!save_index)
		{
			save_index_data.clear();
			save_in_progress = false;
			fclose(save_file);
			ng_slogerror(log_str,0,"resume old saving .... save_index is zero");
			return;
		}
		myfile = save_file;	
		ng_slogdebug_spam(log_str,"resume old saving ....at %d",save_index);
	}
	save_in_progress = true;	
	#endif

	#ifdef userlist_use_simple
	while (m_users != NULL) {
		u_data = m_users->data;
	#else
	ip_storage_hash::iterator it;

	it = user_index.begin();
	int counter = 0;
	if (save_index)
	{
		for (; it != user_index.end(); it++) {
			if (save_index > counter)
			{
				counter++;
			} else {
				ng_slogdebug_spam(log_str,"skipped users on save resume - position %d",counter);
				break;
			}
		}
	}

	for (; it != user_index.end(); it++) {
		u_data =  (*it).second;
	#endif
		counter++;
		
		//backup module data addr
		//memcpy(&u_data->module_data,t_module_data, MAX_MODULES * sizeof(void *));
		for(i=0; i<MAX_MODULES; i++) t_module_data[i] = u_data->module_data[i];
		memset(&u_data->module_data,0,MAX_MODULES * sizeof(void *));

		fwrite(u_data,sizeof(struct user_data),1, myfile);

		//restore module data addr
		//memcpy(t_module_data, u_data->module_data, MAX_MODULES * sizeof(void *));
		for(i=0; i<MAX_MODULES; i++) u_data->module_data[i] = t_module_data[i];

		#ifdef userlist_use_simple
		m_users = m_users->next;
		#else
		if (!allatonce)
		{
			//did we save savejunk items and are more then 10% of savejunk away from the end ? lets have a break
			if ((counter-save_index >= savejunk) && (user_index.size() >= counter + round(savejunk*0.1) ) )
			{				
				ng_slogdebug_spam(log_str,"break save loop - on counter %d",counter);				
				//save_index = counter; //done later now
				break;
			}
		}
		#endif
	}

	#ifndef userlist_use_simple
	if (!allatonce && (counter-save_index > savejunk))
		ng_slogdebug_spam(log_str,"extented junk size - saved %d users this run",counter-save_index);
	#endif

	if (it == user_index.end())
	{
		ng_slogdebug_spam(log_str,"saved %d users",counter);

		#ifndef userlist_use_simple
		save_in_progress = false;
		save_index = 0;
		save_index_data.clear();
		save_file = NULL;
		#endif

		fwrite(ACC_DATA_VERSION_MAGIC,strlen(ACC_DATA_VERSION_MAGIC),1,myfile);
		fclose(myfile);
	} else {
		#ifndef userlist_use_simple
		save_index = counter;
		ng_slogdebug_spam(log_str,"pause saving on %d",save_index);
		#endif
	}
}

void User_Data_Tools::list_clear()
{
	ng_slogdebug_spam(log_str,"clearing user list");
	#ifdef userlist_use_simple
	user_list *p, *q;
	p = user_list_head;
	while ( p != NULL )
	{
		q = p->next;
		free_user((struct user_data*)p->data);
		free(p);
		p = q;
	}
	user_list_head = NULL;
	#else
 	ip_storage_hash::iterator it;
	for (it=user_index.begin(); it != user_index.end(); it++) {
		free_user((*it).second);
		//TODO does STD lib really free it ?!
		//delete (*it).first; 
	}
	user_index.clear();
	#endif
	ng_slogdebug_spam(log_str,"cleared user list");
}

struct user_data *User_Data_Tools::get_user(u_int32_t *search_saddr, unsigned int *vlan_id)
{
	#ifdef userlist_use_simple
	//index for 255.255.255.0 simple index
	u_int32_t hl_saddr = ntohl((*search_saddr));
	u_int8_t * last_ip_byte;
	last_ip_byte = (u_int8_t*) ((void*)&hl_saddr);
	return (struct user_data *)user_index[*last_ip_byte];
	#else	
    user_data_idx idx;
	idx.saddr = (*search_saddr);
	idx.vlan_id = (*vlan_id);
	ip_storage_hash::iterator it;
	it=user_index.find(&idx);
	if (it != user_index.end()) return (*it).second;
	return NULL;
	#endif
}

void User_Data_Tools::free_user(struct user_data *u_data)
{
	ng_slogdebug_spam(log_str,"free data for %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	NetGuard_ModuleLoader_Base::send_cmsg(NULL,"user_shutdown",NULL,u_data);
	//TODO listen to the broadcast
	//user_shutdown(u_data);
	delete u_data;
}

int User_Data_Tools::add_user(struct user_data *u_data, unsigned int vlan_id)
{
	#ifdef userlist_use_simple
	user_list *neu, *p;
	if (user_list_head == NULL)
	{
		user_list_head = (struct user_list *)malloc(sizeof(struct user_list));
		user_list_head->data = u_data;
		user_list_head->next = NULL;

		//init index
		memset(user_index,0,sizeof(void*) * 256);

	}	else	{
		if (get_user(&u_data->saddr,&u_data->vlan_id) != NULL) {
			ng_slogdebug(log_str,"not adding user - already found");
			return -1;
		}
		p = user_list_head;
		neu = (struct user_list *)malloc(sizeof(struct user_list));
		while( p->next != NULL) p = p->next;
		neu->data = u_data;
		neu->next = NULL;
		p->next = neu;
	}
	ng_slogdebug_spam(log_str,"added user %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));

	//fill index for 255.255.255.0 simple index
	u_int32_t hl_saddr = ntohl(u_data->saddr);
	u_int8_t * last_ip_byte;
	last_ip_byte = (u_int8_t*) ((void*)&hl_saddr );
	user_index[*last_ip_byte] = u_data;
	#else
	if (get_user(&u_data->saddr,&u_data->vlan_id) != NULL) {
		ng_slogdebug(log_str,"not adding user - already found");
		return -1;
	}
    user_data_idx* idx = new user_data_idx;
	idx->saddr = u_data->saddr;
	idx->vlan_id = u_data->vlan_id;
	user_index.insert(pair<const struct user_data_idx*, struct user_data*>(idx, u_data));
	ng_slogdebug_spam(log_str,"added user %-15s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
	#endif

	//init other modules data
	NetGuard_ModuleLoader_Base::send_cmsg(NULL,"user_init",NULL,u_data);
	//TODO listen to the broadcast
	//user_init(u_data);
	return 0;
}

struct user_data *User_Data_Tools::get_or_add_user(u_int32_t *search_saddr, unsigned int *vlan_id) {
	struct user_data *u_data;
	u_data = get_user(search_saddr,vlan_id);
	if (u_data == NULL) {
		u_data = (struct user_data*)malloc(sizeof(struct user_data));
		memset(u_data,0,sizeof(struct user_data));
		u_data->saddr = (*search_saddr);
		u_data->vlan_id = (*vlan_id);
		add_user(u_data,(*vlan_id));
	};
	return u_data;
}

#ifdef userlist_use_simple
struct user_list *User_Data_Tools::get_list()
{
	return user_list_head;
}
#else
ip_storage_hash *User_Data_Tools::get_list() 
{
	return &user_index;
}

user_data_list_idx User_Data_Tools::get_list_idx()
{
	user_data_list_idx user_data;
	ip_storage_hash::iterator it;
	for (it=get_list()->begin(); it != get_list()->end(); it++)
		user_data.push_back((*it).first);
	return user_data;
}
#endif

user_data_list User_Data_Tools::get_vector_list()
{
	user_data_list my_vector;
	#ifdef userlist_use_simple
	struct	user_list * m_users = NULL;
	m_users = get_list();
	//fill vector
	while (m_users != NULL) {
		struct  user_data *u_data = m_users->data;
		my_vector.push_back(u_data);
		m_users = m_users->next;
	}
	#else
	ip_storage_hash::iterator it;
	for (it=get_list()->begin(); it != get_list()->end(); it++)
		my_vector.push_back((*it).second);
	#endif
	return my_vector;
}

