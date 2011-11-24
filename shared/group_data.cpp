/***************************************************************************
 *   NetGuard Data Storage definition for the group accounting module      *
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
#include "../includes/storage/group_data.hpp"
#include "../includes/module_loader_base.hpp"

#include "../includes/tools.h"
#include "../includes/logging.h"
#include "../includes/crc32.h"
#include <math.h>


static const char *GACC_DATA_VERSION_MAGIC = "netguard_gaccounting_db_v0.3";



Group_Data::Group_Data(GUser_Data_Tools *intools, std::string inname) {
	tools = intools;
	name = inname;
	log_str = "group_";
	log_str.append(name);
	ng_slogext(log_str,2500,"constructor");
	memset(&data,0,sizeof(struct user_data));
	data.saddr = crc32(log_str.c_str(),strlen(log_str.c_str()));
	data.vlan_id = 999999; //make sure we have unique states
	ng_slogext(log_str,2500,"init group crc %u",data.saddr);
	ng_slogext(log_str,2500,"group would collide with ip:%s",inet_ntoa(*(struct in_addr *)&data.saddr));
	memset(&limits,0,sizeof(struct user_limit_data));

}

Group_Data::~Group_Data() 
{
	ng_slogext(log_str,2500,"destructor");
}

struct user_data *Group_Data::GetData()
{
	return &data;
}

struct user_limit_data *Group_Data::GetLimits()
{
	return &limits;
}

guser_data_list_idx *Group_Data::get_members()
{
	return &members;
};

void Group_Data::clear()
{
	members.clear();
	tools->reindex_group(this);
}


bool Group_Data::member_present(u_int32_t search_saddr, unsigned int vlan_id)
{
 	guser_data_list_idx::iterator it;
	for (it=members.begin(); it != members.end(); it++) {
		if ((search_saddr == (*it).saddr) && (vlan_id == (*it).vlan_id))
			return true;
	}
	return false;
}

bool Group_Data::add_member(u_int32_t saddr, unsigned int vlan_id)
{
    if (member_present(saddr,vlan_id)) return false;
	ng_slogext(log_str,2200,"adding member with ip:%s vlan:%d to group with name %s",inet_ntoa(*(struct in_addr *)&saddr),vlan_id,name.c_str());

	guser_data_idx idx;
	idx.saddr = saddr;
	idx.vlan_id = vlan_id;
	members.push_back(idx);
	tools->reindex_group(this);
	return true;
}

bool Group_Data::del_member(u_int32_t saddr, unsigned int vlan_id)
{
 	guser_data_list_idx::iterator it;
	for (it=members.begin(); it != members.end(); it++) {
		if ((saddr == (*it).saddr) && (vlan_id == (*it).vlan_id)) {
			members.erase(it);
			tools->reindex_group(this);
			return true;
		}
	}
	return false;
}

GUser_Data_Tools::GUser_Data_Tools(std::string inlog_str)
{
	log_str = inlog_str;
	ng_slogext(log_str,2500,"constructor");
}

GUser_Data_Tools::~GUser_Data_Tools()
{
	ng_slogext(log_str,2500,"destructor");
	clear();
}

void GUser_Data_Tools::loaddata(std::string filename, int rename_onfail)
{
	struct user_data * u_data;
	char *tmpdata;
	int count = 0;
	FILE *myfile;
	struct stat fileinfo;

	clear();

	if (!filename.length()) {
		ng_slogerror(log_str,"can not load - got emtpy filename");
		return;
	}
	
	ng_slogext(log_str,2500,"loading data from %s",filename.c_str());	

	if (stat(filename.c_str(),&fileinfo)) {
		ng_slogerror(log_str,"cant stat data file %s",filename.c_str());
		return;
	}
	myfile = fopen(filename.c_str(), "r");
	if (!myfile) {
		ng_slogerror(log_str,"cant open data file %s",filename.c_str());
		return;
	}

	tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(GACC_DATA_VERSION_MAGIC)+1));
	tmpdata[strlen(GACC_DATA_VERSION_MAGIC)] = 0;

	count = fread(&tmpdata[0],strlen(GACC_DATA_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,GACC_DATA_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant read group data from %s - illegal format (%s <> %s)",filename.c_str(),(char *)tmpdata,GACC_DATA_VERSION_MAGIC);

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogerror(log_str,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}
		free(tmpdata);
		return;
	}

	ng_slogext(log_str,2500,"loading %lu bytes data",fileinfo.st_size);

	off_t f_pos =  ftell(myfile);
	int counter = 0;
	while ( (unsigned int)(fileinfo.st_size - f_pos - strlen(GACC_DATA_VERSION_MAGIC)) >= sizeof(struct user_data) ) {
		NetGuard_Config mydata;

		if (!mydata.loaddata(myfile)) {
			ng_slogerror(log_str,"cant group data file from %s - illegal format - additonal data - renaming file",filename.c_str());
			clear();
			free(tmpdata);
			return;
		};

		Group_Data *gdata = create_group(mydata.GetStr("name"));
		unsigned int mc;
		fread(&mc,sizeof(unsigned int),1, myfile);

		for(unsigned int i=1;i<=mc;i++) {
			struct guser_data_idx myudata;
			fread(&myudata,sizeof(struct guser_data_idx),1, myfile);
			gdata->add_member(myudata.saddr,myudata.vlan_id);
		}

		//load traffic data
		u_data = gdata->GetData();
		fread(u_data,sizeof(struct user_data),1, myfile);		
		//loaded module data is not assigned yet modules have to take care about this
		memset(&u_data->module_data,0,MAX_MODULES * sizeof(void *));

		//load limits
		user_limit_data *ldata=  gdata->GetLimits();
		fread(ldata,sizeof(struct user_limit_data),1, myfile);

		ng_slogext(log_str,2500,"loaded group s%",gdata->name.c_str());

		counter++;
		f_pos =  ftell(myfile);
	}

	count = fread(tmpdata,strlen(GACC_DATA_VERSION_MAGIC),1,myfile);
	if ((count != 1) || strcmp(tmpdata,GACC_DATA_VERSION_MAGIC) ) {
		ng_slogerror(log_str,"cant traffic data file (end) from %s - illegal format - renaming file",filename.c_str());

		if (rename_onfail)
		{
			free(tmpdata);
			tmpdata = (char*)malloc(sizeof(unsigned char)*(strlen(filename.c_str())+20));
			time_t now;
			time(&now);		/* get the current time */
			sprintf(tmpdata,"%s_%d",filename.c_str(),(int)now);
			ng_slogerror(log_str,"renaming file to %s",tmpdata);
			rename(filename.c_str(),tmpdata);
		}

		clear();
		free(tmpdata);
		return;
	}

	ng_slogext(log_str,2100,"loaded %d groups",counter);

	fclose(myfile);
	free(tmpdata);
}

void GUser_Data_Tools::savedata(std::string filename,bool allatonce)
{
	struct  user_data * u_data;
	void    *t_module_data[MAX_MODULES];
	int     i;
	FILE *myfile;
	
	ng_slogext(log_str,2500,"saving ....");

	if (!filename.length()) {
		ng_slogerror(log_str,"can not save - got emtpy filename");
		return;
	}

	string rename_file = filename;
	rename_file.append(".old");
	if (rename(filename.c_str(), rename_file.c_str()))
	{
			ng_slogerror(log_str,"rename accounting data from %s to %s",filename.c_str(),rename_file.c_str());
	}

	ng_slogext(log_str,2500,"saving groups to %s",filename.c_str());
	myfile = fopen(filename.c_str(), "w+");
	if (!myfile) {
		ng_slogerror(log_str,"can not save groups to %s",filename.c_str());
		return;
	}

	fwrite(GACC_DATA_VERSION_MAGIC,strlen(GACC_DATA_VERSION_MAGIC),1,myfile);

	guser_data_list::iterator it;

	it = groups.begin();
	int counter = 0;
	for (; it != groups.end(); it++) {
		u_data =  (*it).second->GetData();
		counter++;
		NetGuard_Config mydata;
		//save stuff
		mydata.SetStr("name",(*it).second->name);
		mydata.savedata(myfile);

		//save members
		guser_data_list_idx *members = (*it).second->get_members();
		unsigned int mc = members->size();
		fwrite(&mc,sizeof(unsigned int),1, myfile);

		guser_data_list_idx::iterator it2;
		for (it2=members->begin(); it2 != members->end(); it2++) {
			struct guser_data_idx *myudata = &(*it2);
			fwrite(myudata,sizeof(struct guser_data_idx),1, myfile);
		}

		//save traffic data
		//backup module data addr
		//memcpy(&u_data->module_data,t_module_data, MAX_MODULES * sizeof(void *));
		for(i=0; i<MAX_MODULES; i++) t_module_data[i] = u_data->module_data[i];
		memset(&u_data->module_data,0,MAX_MODULES * sizeof(void *));

		fwrite(u_data,sizeof(struct user_data),1, myfile);

		//restore module data addr
		//memcpy(t_module_data, u_data->module_data, MAX_MODULES * sizeof(void *));
		for(i=0; i<MAX_MODULES; i++) u_data->module_data[i] = t_module_data[i];
		
		//save limit details
		user_limit_data *ldata=  (*it).second->GetLimits();
		fwrite(ldata,sizeof(struct user_limit_data),1, myfile);
	}

	ng_slogext(log_str,2100,"saved %d groups",counter);
	fwrite(GACC_DATA_VERSION_MAGIC,strlen(GACC_DATA_VERSION_MAGIC),1,myfile);
	fclose(myfile);
}

void GUser_Data_Tools::clear()
{
	ng_slogext(log_str,2500,"clearing group list");

	gip_storage_hash::iterator it;
	for (it=group_index.begin(); it != group_index.end(); it++) {
		delete (*it).second;	
	}
	group_index.clear();

	guser_data_list::iterator it2;
	for (it2=groups.begin(); it2 != groups.end(); it2++) {
		delete (*it2).second;
	}
	groups.clear();
	ng_slogext(log_str,2500,"cleared group list");
}

guser_data_list_vector *GUser_Data_Tools::get_groups(u_int32_t *search_saddr, unsigned int *vlan_id)
{
	//ng_slogdebug_spam(log_str,"looking for member with ip:%s vlan:%d",inet_ntoa(*(struct in_addr *)search_saddr),*vlan_id);
    guser_data_idx idx;
	idx.saddr = *search_saddr;
	idx.vlan_id = *vlan_id;
	gip_storage_hash::iterator it;
	it=group_index.find(idx);
	if (it != group_index.end()) return ((*it).second);
	return NULL;
}

gip_storage_hash *GUser_Data_Tools::get_list() 
{
	return &group_index;
}

guser_data_list_vector GUser_Data_Tools::get_vector_list()
{
	guser_data_list_vector data;
	guser_data_list::iterator it;
	for (it = groups.begin(); it != groups.end(); it++) 
		data.push_back((*it).second);
	return data;
}

Group_Data *GUser_Data_Tools::get_group(std::string name)
{
	guser_data_list::iterator it;
	it=groups.find(name);
	if (it != groups.end()) {
		return (*it).second;
	} else return NULL;
}

Group_Data *GUser_Data_Tools::get_group(u_int32_t *search_saddr, unsigned int *vlan_id) 
{
	guser_data_list::iterator it;
	for (it = groups.begin(); it != groups.end(); it++) 
	{
		//data.saddr = crc32(log_str.c_str(),strlen(log_str.c_str()));
		//data.vlan_id = 999999; //make sure we have unique states
		if ( ((*it).second->GetData()->saddr==(*search_saddr)) && ((*it).second->GetData()->vlan_id==(*vlan_id)) )
			return (*it).second;
	}
	return NULL;
}

Group_Data *GUser_Data_Tools::create_group(std::string name)
{
	if (get_group(name)) return NULL;
	Group_Data *group = new Group_Data(this,name);
	groups.insert(pair<std::string, Group_Data *>(name, group));
	return group;
}

bool GUser_Data_Tools::del_group(std::string name)
{
	guser_data_list::iterator it;
	it=groups.find(name);
	if (it != groups.end()) {
		delete (*it).second;
		groups.erase(it);
		return true;
	} else return false;
}

bool GUser_Data_Tools::reindex_group(std::string name)
{
	Group_Data *group = get_group(name);
	if (group) return reindex_group(group);
	return false;
}

bool GUser_Data_Tools::reindex_group(Group_Data * group)
{
	//remove all "old" index values for that group
	gip_storage_hash::iterator it;
	for (it=group_index.begin(); it != group_index.end(); it++) {
		guser_data_list_vector *mylist = (*it).second;
		guser_data_list_vector::iterator it2;
		//(*mylist).clear(); ?! we can simply drop all
		for (it2=(*mylist).begin(); it2 != (*mylist).end(); it2++) {
			if ((*it2) == group) {
				(*it2) = NULL; //we dont want the erase to handle something dirty here
				(*mylist).erase(it2);
				break;
			}
		}
	}

	//readd them all
	guser_data_list_idx *members = group->get_members();
	guser_data_list_idx::iterator it2;
	for (it2=members->begin(); it2 != members->end(); it2++) {
		guser_data_idx member = (*it2);
		guser_data_list_vector *mylist = get_groups(&member.saddr,&member.vlan_id);
		if (mylist) {
			//add in old vector
			(*mylist).push_back(group);
		} else {
			//we need to add a new vector to the hash
			guser_data_list_vector *newlist = new guser_data_list_vector;
			(*newlist).push_back(group);
			group_index.insert(pair<struct guser_data_idx, guser_data_list_vector*>(member, newlist));
		}
	}

	return true;	
}


