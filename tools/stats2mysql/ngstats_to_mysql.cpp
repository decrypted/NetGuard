/***************************************************************************
 *   NetGuard MySql Stats Generator                                        *
 *                                                                         *
 *   Copyright (c) 2011 Ronny Hillmann <ronny at net-guard net>            *
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


#include <arpa/inet.h>
#include "../../includes/storage/user_data.hpp"
#include "../../includes/storage/group_data.hpp"
#include "../../includes/storage/user_limits.hpp"
#include "../../includes/state/state_handling.hpp"
#include "../../includes/tools.h"
#include "../../modules/user_limit/user_limit.hpp"
#include "../../includes/modules/general_module.hpp"
#include "../../includes/modules/user_module.hpp"
#include "../../includes/modules/module.hpp"
#include <net/ethernet.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>

#define NG_FILENAME "./accounting.dat"
#define NG_GFILENAME "./gaccounting.dat"
#define NG_SFILENAME "./states.dat"
#define NG_LFILENAME "./limit.dat"
//#define debug


MYSQL_RES *runquery(MYSQL *mysql, char* query, bool wantres = false ) {

    #ifdef debug
	printf("running query %s",query);
    #endif
	int res = mysql_real_query(mysql,query,(unsigned int) strlen(query));
    if (res)
    {
    	printf("Error making query %s: - %s\n",query,mysql_error(mysql));
		
		exit(1);
    }
    #ifdef debug
	    else printf("Query made...\n");
    #endif
	MYSQL_RES *mres = mysql_store_result(mysql);
	if (wantres)
	{
		return mres;
	} else { 
		mysql_free_result(mres);
	}
	return NULL;
}

int write_traffic(MYSQL *mysql,std::string tablename, std::string indexfield, std::string indexvalue,struct user_data *u_data) 
{
    const char *type = NULL;
	struct user_data_traffic *traffic_type = &u_data->external;
    char* tmpdata = (char*)malloc(sizeof(unsigned char)*10000);
    int day,i;

	for(i=0;i<=1;i++)
	{		
		switch(i)
		{
			case 0:     traffic_type = &u_data->external;
				type="extern";
				break;
			case 1:     traffic_type = &u_data->internal;
				type="intern";
				break;
		}


		for(day=0;day<=6;day++)
		{
			//INSERT Anfrage auf traffic
			sprintf(tmpdata,"delete from %s where %s=\"%s\" and type=\"%s\" and day=\"%i\";",tablename.c_str(),indexfield.c_str(),	indexvalue.c_str(),type,day);
			runquery(mysql,tmpdata);

			sprintf(tmpdata,"insert into %s (%s,type,day,send_bytes,resv_bytes,send_pkts,resv_pkts,send_ipbytes,resv_ipbytes,send_ippkts,resv_ippkts,send_tcpipbytes,resv_tcpipbytes,send_tcpippkts,resv_tcpippkts,send_udpbytes,resv_udpbytes,send_udppkts,resv_udppkts,send_icmpbytes,resv_icmpbytes,send_icmppkts,resv_icmppkts,send_arpbytes,resv_arpbytes,send_arppkts,resv_arppkts,send_connects,resv_connects) values (\"%s\",\"%s\",\"%i\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\");",
			tablename.c_str(),
			indexfield.c_str(),	indexvalue.c_str(),
			type,day,
			*(&traffic_type->days[day].send.bytes),*(&traffic_type->days[day].resv.bytes),
			*(&traffic_type->days[day].send.pkts),*(&traffic_type->days[day].resv.pkts),
			*(&traffic_type->days[day].send.ip_bytes),*(&traffic_type->days[day].resv.ip_bytes),
			*(&traffic_type->days[day].send.ip_pkts),*(&traffic_type->days[day].resv.ip_pkts),
			*(&traffic_type->days[day].send.tcpip_bytes),*(&traffic_type->days[day].resv.tcpip_bytes),
			*(&traffic_type->days[day].send.tcpip_pkts),*(&traffic_type->days[day].resv.tcpip_pkts),
			*(&traffic_type->days[day].send.udp_bytes),*(&traffic_type->days[day].resv.udp_bytes),
			*(&traffic_type->days[day].send.udp_pkts),*(&traffic_type->days[day].resv.udp_pkts),
			*(&traffic_type->days[day].send.icmp_bytes),*(&traffic_type->days[day].resv.icmp_bytes),
			*(&traffic_type->days[day].send.icmp_pkts),*(&traffic_type->days[day].resv.icmp_pkts),
			*(&traffic_type->days[day].send.arp_bytes),*(&traffic_type->days[day].resv.arp_bytes),
			*(&traffic_type->days[day].send.arp_pkts),*(&traffic_type->days[day].resv.arp_pkts),
			*(&traffic_type->days[day].send.connects),*(&traffic_type->days[day].resv.connects));
			runquery(mysql,tmpdata);
		}

		//week
		day=7;
		sprintf(tmpdata,"delete from %s where %s=\"%s\" and type=\"%s\" and day=\"%i\";",tablename.c_str(),indexfield.c_str(),	indexvalue.c_str(),type,day);
		runquery(mysql,tmpdata);

		sprintf(tmpdata,"insert into %s (%s,type,day,send_bytes,resv_bytes,send_pkts,resv_pkts,send_ipbytes,resv_ipbytes,send_ippkts,resv_ippkts,send_tcpipbytes,resv_tcpipbytes,send_tcpippkts,resv_tcpippkts,send_udpbytes,resv_udpbytes,send_udppkts,resv_udppkts,send_icmpbytes,resv_icmpbytes,send_icmppkts,resv_icmppkts,send_arpbytes,resv_arpbytes,send_arppkts,resv_arppkts,send_connects,resv_connects) values (\"%s\",\"%s\",\"%i\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\");",
		tablename.c_str(),
		indexfield.c_str(),	indexvalue.c_str(),
		type,day,
		*(&traffic_type->week.send.bytes),*(&traffic_type->week.resv.bytes),
		*(&traffic_type->week.send.pkts),*(&traffic_type->week.resv.pkts),
		*(&traffic_type->week.send.ip_bytes),*(&traffic_type->week.resv.ip_bytes),
		*(&traffic_type->week.send.ip_pkts),*(&traffic_type->week.resv.ip_pkts),
		*(&traffic_type->week.send.tcpip_bytes),*(&traffic_type->week.resv.tcpip_bytes),
		*(&traffic_type->week.send.tcpip_pkts),*(&traffic_type->week.resv.tcpip_pkts),
		*(&traffic_type->week.send.udp_bytes),*(&traffic_type->week.resv.udp_bytes),
		*(&traffic_type->week.send.udp_pkts),*(&traffic_type->week.resv.udp_pkts),
		*(&traffic_type->week.send.icmp_bytes),*(&traffic_type->week.resv.icmp_bytes),
		*(&traffic_type->week.send.icmp_pkts),*(&traffic_type->week.resv.icmp_pkts),
		*(&traffic_type->week.send.arp_bytes),*(&traffic_type->week.resv.arp_bytes),
		*(&traffic_type->week.send.arp_pkts),*(&traffic_type->week.resv.arp_pkts),
		*(&traffic_type->week.send.connects),*(&traffic_type->week.resv.connects));
		runquery(mysql,tmpdata);

		//overall
		day=8; 
		sprintf(tmpdata,"delete from %s where %s=\"%s\" and type=\"%s\" and day=\"%i\";",tablename.c_str(),indexfield.c_str(),	indexvalue.c_str(),type,day);
		runquery(mysql,tmpdata);

		sprintf(tmpdata,"insert into %s (%s,type,day,send_bytes,resv_bytes,send_pkts,resv_pkts,send_ipbytes,resv_ipbytes,send_ippkts,resv_ippkts,send_tcpipbytes,resv_tcpipbytes,send_tcpippkts,resv_tcpippkts,send_udpbytes,resv_udpbytes,send_udppkts,resv_udppkts,send_icmpbytes,resv_icmpbytes,send_icmppkts,resv_icmppkts,send_arpbytes,resv_arpbytes,send_arppkts,resv_arppkts,send_connects,resv_connects) values (\"%s\",\"%s\",\"%i\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%llu\");",
		tablename.c_str(),
		indexfield.c_str(),	indexvalue.c_str(),
		type,day,
		*(&traffic_type->over_all.send.bytes),*(&traffic_type->over_all.resv.bytes),
		*(&traffic_type->over_all.send.pkts),*(&traffic_type->over_all.resv.pkts),
		*(&traffic_type->over_all.send.ip_bytes),*(&traffic_type->over_all.resv.ip_bytes),
		*(&traffic_type->over_all.send.ip_pkts),*(&traffic_type->over_all.resv.ip_pkts),
		*(&traffic_type->over_all.send.tcpip_bytes),*(&traffic_type->over_all.resv.tcpip_bytes),
		*(&traffic_type->over_all.send.tcpip_pkts),*(&traffic_type->over_all.resv.tcpip_pkts),
		*(&traffic_type->over_all.send.udp_bytes),*(&traffic_type->over_all.resv.udp_bytes),
		*(&traffic_type->over_all.send.udp_pkts),*(&traffic_type->over_all.resv.udp_pkts),
		*(&traffic_type->over_all.send.icmp_bytes),*(&traffic_type->over_all.resv.icmp_bytes),
		*(&traffic_type->over_all.send.icmp_pkts),*(&traffic_type->over_all.resv.icmp_pkts),
		*(&traffic_type->over_all.send.arp_bytes),*(&traffic_type->over_all.resv.arp_bytes),
		*(&traffic_type->over_all.send.arp_pkts),*(&traffic_type->over_all.resv.arp_pkts),
		*(&traffic_type->over_all.send.connects),*(&traffic_type->over_all.resv.connects));
		runquery(mysql,tmpdata);

    }
	free(tmpdata);

	return 0;
}


int write_limit(MYSQL *mysql,std::string tablename, std::string indexfield, std::string indexvalue,struct user_data *u_data, struct user_limit_data *inlimit_data) 
{
    const char *type = NULL;
	struct user_limit_data_type *traffic_type = NULL;
    char* tmpdata = (char*)malloc(sizeof(unsigned char)*10000);
    int i;


	struct user_limit_data *limit_data;
	if (!inlimit_data)
	{
		limit_data = (struct user_limit_data *)u_data->module_data[user_limit_module_number];
	} else limit_data = inlimit_data;
	if ( limit_data == NULL ) return 1;

	for(i=0;i<=1;i++)
	{		
		switch(i)
		{
			case 0:     traffic_type = &limit_data->external;
				type="extern";
				break;
			case 1:     traffic_type = &limit_data->internal;
				type="intern";
				break;
		}


		sprintf(tmpdata,"delete from %s where %s=\"%s\" and type=\"%s\" ;",
		tablename.c_str(),
		indexfield.c_str(),	indexvalue.c_str(),
		type);
		runquery(mysql,tmpdata);

		char l_a_time[50];		
		strftime(l_a_time, 80,"%Y-%m-%d %H:%M:%S",localtime(&traffic_type->max_week_date));
		char l_a_time2[50];		
		strftime(l_a_time2, 80,"%Y-%m-%d %H:%M:%S",localtime(&traffic_type->max_day_date));

		sprintf(tmpdata,"insert into %s (%s,type,day,week,over_all,max_week,max_week_date,max_day,max_day_date) values (\"%s\",\"%s\",\"%llu\",\"%llu\",\"%llu\",\"%llu\",\"%s\",\"%llu\",\"%s\");",
		tablename.c_str(),
		indexfield.c_str(),	indexvalue.c_str(),
		type,
		*(&traffic_type->limit_day),
		*(&traffic_type->limit_week),
		*(&traffic_type->limit_overall),
		*(&traffic_type->max_week),
		l_a_time,
		*(&traffic_type->max_day),
		l_a_time2);
		runquery(mysql,tmpdata);

	}
	free(tmpdata);

	return 0;
}

int main()
{
    MYSQL mysql;
    MYSQL_RES *res;
    char* tmpdata = (char*)malloc(sizeof(unsigned char)*10000);
    char l_a_time[50];
	//,max_week_date[50],max_day_date[50];
    struct tm *time;
    
    struct user_data *u_data = NULL;

    //NetGuard initialisieren
	User_Data_Tools data = User_Data_Tools();
	data.loaddata(NG_FILENAME,false);

    GUser_Data_Tools gdata = GUser_Data_Tools();
	gdata.loaddata(NG_GFILENAME,false);

    NetGuard_Limit nglimit = NetGuard_Limit();
	nglimit.set_user_data(&data);
	nglimit.db_filename = NG_LFILENAME;
	nglimit.loaddata();

	NetGuard_State_Handler state_handler = NetGuard_State_Handler();
	state_handler.loaddata(NG_SFILENAME);
    
    //Verbindung aufbauen	           
	if (!mysql_init(&mysql))
	{
		printf( "Error init mysql: %s\n",mysql_error(&mysql));
		exit(-1);
	}
	//TODO read from config file
    if (!mysql_real_connect(&mysql,"127.0.0.1","netguard","statsdump!","ng",3306,NULL,0))
    {
		printf( "Error connectin ot database: %s\n",mysql_error(&mysql));
		exit(-1);
    }
	#ifdef debug
	    else printf("Connected...\n");
	#endif    
    
	sprintf(tmpdata,"TRUNCATE TABLE `global_states`"); 
	runquery(&mysql,tmpdata);

	sprintf(tmpdata,"TRUNCATE TABLE `global_states_data`"); 
	runquery(&mysql,tmpdata);

	sprintf(tmpdata,"TRUNCATE TABLE `group_states`"); 
	runquery(&mysql,tmpdata);

	sprintf(tmpdata,"TRUNCATE TABLE `group_states_data`"); 
	runquery(&mysql,tmpdata);

	//LOCK TABLES
    sprintf(tmpdata,"lock tables global write, global_states write, global_states_data write, group_states write, group_states_data write,limits write, groups_members write, glimits write, traffic write, groups write, gtraffic write;"); 
	runquery(&mysql,tmpdata);   

    user_data_list user_list = data.get_vector_list();

	int current_state = 0;
	user_data_list::iterator it;
	for (it=user_list.begin(); it != user_list.end(); it++) {
		u_data = (*it);

		NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(u_data);
		if (!user_state) continue;
	
		sprintf(tmpdata,"delete from global where ip=\"%s\";",inet_ntoa(*(struct in_addr *)&u_data->saddr)); 
		runquery(&mysql,tmpdata);

 		time_t ttime = user_state->params()->GetTime("timeenter",0);
		time = localtime(&ttime);
		strftime(l_a_time, 80, "%Y-%m-%d %H:%M:%S",time);
		sprintf(tmpdata,"insert into global_states (ip,vlan,state,reason,datetime) values (\"%s\",%d,\"%s\",\"%s\",\"%s\");",
					inet_ntoa(*(struct in_addr *)&u_data->saddr),
					u_data->vlan_id,
					user_state->state()->GetName().c_str(),
					user_state->params()->GetStr("reason","").c_str(),
					l_a_time
		); 			
		res = runquery(&mysql,tmpdata,true);
		current_state = mysql_insert_id(&mysql);
		mysql_free_result(res);
		
		ConfigMap *mydata2 = user_state->params()->GetData();
		ConfigMap::iterator cit2;
		for (cit2=(*mydata2).begin(); cit2 != (*mydata2).end(); cit2++) {
			sprintf(tmpdata,"insert into global_states_data (state_id,name,value) values (%d,\"%s\",\"%s\");",
					current_state,
					(*cit2).first.c_str(),
					((*cit2).second)->get_string(false).c_str()
			); 		
			runquery(&mysql,tmpdata);
		}

		std::vector<NetGuard_Config*> history = user_state->GetHistory();
		std::vector<NetGuard_Config*>::iterator hit;
		for (hit=history.begin(); hit != history.end(); hit++)
		{
			ttime = (*hit)->GetTime("time",0);
			time = localtime(&ttime);
			strftime(l_a_time, 80, "%Y-%m-%d %H:%M:%S",time);
			sprintf(tmpdata,"insert into global_states (ip,vlan,state,reason,datetime) values (\"%s\",%d,\"%s\",\"%s\",\"%s\");",
						inet_ntoa(*(struct in_addr *)&u_data->saddr),
						u_data->vlan_id,
						(*hit)->GetStr("to").c_str(),
						(*hit)->GetStr("reason").c_str(),
						l_a_time
			); 			
			res = runquery(&mysql,tmpdata,true);

			int tmp_state = mysql_insert_id(&mysql);
			mysql_free_result(res);

			ConfigMap *mydata = (*hit)->GetData();
			ConfigMap::iterator cit;
			for (cit=(*mydata).begin(); cit != (*mydata).end(); cit++) {
				sprintf(tmpdata,"insert into global_states_data (state_id,name,value) values (%d,\"%s\",\"%s\");",
						tmp_state,
						(*cit).first.c_str(),
						((*cit).second)->get_string(false).c_str()
				); 		
				runquery(&mysql,tmpdata);
			}
		}


		time = localtime(&(u_data->last_activity));
		strftime(l_a_time, 80, "%Y-%m-%d %H:%M:%S",time);
 		sprintf(tmpdata,"insert into global (ip,vlan,mac,last_active,room,login,current_state,disable_count) values (\"%s\",%d,\"%02x:%02x:%02x:%02x:%02x:%02x\",\"%s\",\"%s\",\"%s\",%d,%d);",
 					inet_ntoa(*(struct in_addr *)&u_data->saddr),
 					u_data->vlan_id,
 					u_data->hw_addr[0],u_data->hw_addr[1],u_data->hw_addr[2],u_data->hw_addr[3],u_data->hw_addr[4],u_data->hw_addr[5],
 					l_a_time,
 					user_state->params()->GetStr("room").c_str(),
 					user_state->params()->GetStr("login").c_str(),
					current_state,
					user_state->params()->GetInt("external_week_exceeded",0)
 		); 
		runquery(&mysql,tmpdata);

		sprintf(tmpdata,"%s",inet_ntoa(*(struct in_addr *)&u_data->saddr));
		std::string mvalue = tmpdata;
	    write_traffic(&mysql,"traffic","ip",mvalue,u_data);
		write_limit(&mysql,"limits","ip",mvalue,u_data,NULL);
		user_state = NULL;
	}

	sprintf(tmpdata,"delete from groups"); 
	runquery(&mysql,tmpdata);

	sprintf(tmpdata,"delete from groups_members"); 
	runquery(&mysql,tmpdata);

	int g_counter = 0;
	guser_data_list_vector mylist = gdata.get_vector_list();
	guser_data_list_vector::iterator it2;
	for (it2=mylist.begin(); it2 != mylist.end(); it2++) {
		g_counter++;
		u_data =  (*it2)->GetData();

		NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(&u_data->saddr,&u_data->vlan_id); //hack but should also be here the data
		if (user_state) 
		{	
			time_t ttime = user_state->params()->GetTime("timeenter",0);
			time = localtime(&ttime);
			strftime(l_a_time, 80, "%Y-%m-%d %H:%M:%S",time);
			sprintf(tmpdata,"insert into group_states (ip,vlan,state,reason,datetime) values (\"%s\",%d,\"%s\",\"%s\",\"%s\");",
						inet_ntoa(*(struct in_addr *)&u_data->saddr),
						u_data->vlan_id,
						user_state->state()->GetName().c_str(),
						user_state->params()->GetStr("reason","").c_str(),
						l_a_time
			); 			
			res = runquery(&mysql,tmpdata,true);
			current_state = mysql_insert_id(&mysql);
			mysql_free_result(res);
			
			ConfigMap *mydata2 = user_state->params()->GetData();
			ConfigMap::iterator cit2;
			for (cit2=(*mydata2).begin(); cit2 != (*mydata2).end(); cit2++) {
				sprintf(tmpdata,"insert into group_states_data (state_id,name,value) values (%d,\"%s\",\"%s\");",
						current_state,
						(*cit2).first.c_str(),
						((*cit2).second)->get_string(false).c_str()
				); 		
				runquery(&mysql,tmpdata);
			}


			std::vector<NetGuard_Config*> history = user_state->GetHistory();
			std::vector<NetGuard_Config*>::iterator hit;
			for (hit=history.begin(); hit != history.end(); hit++)
			{
			
				ttime = (*hit)->GetTime("time",0);
				time = localtime(&ttime);
				strftime(l_a_time, 80, "%Y-%m-%d %H:%M:%S",time);
				sprintf(tmpdata,"insert into group_states (ip,vlan,state,reason,datetime) values (\"%s\",%d,\"%s\",\"%s\",\"%s\");",
							inet_ntoa(*(struct in_addr *)&u_data->saddr),
							u_data->vlan_id,
							(*hit)->GetStr("to").c_str(),
							(*hit)->GetStr("reason").c_str(),
							l_a_time
				); 			
				res = runquery(&mysql,tmpdata,true);
				int tmpstate = mysql_insert_id(&mysql);
				mysql_free_result(res);

				ConfigMap *mydata = (*hit)->GetData();
				ConfigMap::iterator cit;
				for (cit=(*mydata).begin(); cit != (*mydata).end(); cit++) {
					sprintf(tmpdata,"insert into group_states_data (state_id,name,value) values (%d,\"%s\",\"%s\");",
							tmpstate,
							(*cit).first.c_str(),
							((*cit).second)->get_string(false).c_str()
					); 		
					runquery(&mysql,tmpdata);
				}
			}
		}

		sprintf(tmpdata,"insert into groups set name=\"%s\", id=%d, current_state=%d",(*it2)->name.c_str(),g_counter,current_state); 
		runquery(&mysql,tmpdata);

		#ifdef debug
		printf("writing group %s\n",(*it2)->name.c_str());
		#endif
		std::string mvalue = any2string(g_counter);
		write_traffic(&mysql,"gtraffic","group_id",mvalue,u_data);
		write_limit(&mysql,"glimits","group_id",mvalue,u_data,(*it2)->GetLimits());


		guser_data_list_idx *members = (*it2)->get_members();
		guser_data_list_idx::iterator git;
		for (git=members->begin(); git != members->end(); git++) {
			struct guser_data_idx mdata = (*git);
			//ng_logout("member ip:%s vlan %d",inet_ntoa(*(struct in_addr *)&data.saddr),data.vlan_id);
			sprintf(tmpdata,"insert into groups_members set group_id=%d, ip=\"%s\", vlan=%d ",g_counter,inet_ntoa(*(struct in_addr *)&mdata.saddr),mdata.vlan_id); 
			runquery(&mysql,tmpdata);
		}
	}

    //UNLOCK TABLES
    sprintf(tmpdata,"unlock tables;"); 
	runquery(&mysql,tmpdata);
    
    //Verbindung trennen
	#ifdef debug
    printf("DONE\n");    
	#endif
    mysql_close(&mysql);

    free(tmpdata);

    return 0;
}
