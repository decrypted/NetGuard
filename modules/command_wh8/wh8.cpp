/***************************************************************************
 *                                                                         *
 *   NetGuard Command Input WH8State Module                                *
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


/* 
	parts of the code are a copy from MacOnOff,
	only features used in this module are imported and moved to cpp
	for now only with a very limited featureset
*/

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>
#include <fstream>

#include "wh8.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/storage/user_data.hpp"
#include "../../includes/state/state_handling.hpp"


//static char *nullmac   = "00:00:00:00:00:00";
const char *q_portname = "enterprises.9.2.2.1.1.28.%d";
const char* switches[]={"172.17.1.1","172.17.1.2","172.17.1.3","172.17.1.4",
                        "172.17.2.1","172.17.2.2","172.17.2.3",
                        "172.17.3.1","172.17.3.2","172.17.3.3","172.17.3.4",
            			"172.17.0.1",
						NULL};

void NetGuard_User_SCE_WH8::done_state_change(NetGuard_User_State *user, NetGuard_State **from, NetGuard_State *to,std::string reason)
{
	ng_slogdebug_spam("NetGuard_User_SCE_WH8","seeing done state change from <%s> to <%s> (user: %s vlan: %d) - reason %s",(*from)->GetName().c_str(),to->GetName().c_str(),inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id,reason.c_str());

	if (user->Getuser().vlan_id > 1000)
	{
		//group
	} else {
		//user
		//char* tmpdata = (char*)malloc(sizeof(unsigned char)*10000);

		//NetGuard_User_State *user_state = user;
		//if (!user_state) continue;
	
		//sprintf(tmpdata,"delete global_states_data from global_states_data inner join  global_states on (global_states_data.state_id=global_states.id) where global_states.ip=\"%s\" and global_states.vlan=\"%d\";",inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id); 
		//sprintf(tmpdata,"delete from global_states where ip=\"%s\" and vlan=\"%d\";",inet_ntoa(*(struct in_addr *)&user->Getuser().saddr),user->Getuser().vlan_id); 
		//runquery(&mysql,tmpdata);
	}

	return;
}

NetGuard_Command_Input_WH8::NetGuard_Command_Input_WH8()
{
	general_acccounting = NULL;
	muser_data = NULL;
	ng_logdebug_spam("constructor");
	CallBack_ = NULL;
}

NetGuard_Command_Input_WH8::~NetGuard_Command_Input_WH8()
{
	ng_logdebug_spam("destructor");
}

int NetGuard_Command_Input_WH8::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	//thats defined for all command modules
	CallBack_ = data_->GetModule("root_module");

	general_acccounting = (NetGuard_General_Module*)data_->GetModule("module_general_accounting");
	muser_data = (User_Data_Tools*)general_acccounting->get_data(NULL);

	if (data_->GetStr("community") == "")
	{
		ng_logerror("need an community in config data");
		return -2;
	}
	community = data_->GetStr("community");

	NetGuard_State_Handler::GetPointer()->register_exec(new NetGuard_User_SCE_WH8(this));

	return 0;
}

unsigned char *NetGuard_Command_Input_WH8::getmacfrommac_addr(mac_addr mac) {
    unsigned char *tmpmac;
    tmpmac = (unsigned char*)malloc(sizeof(unsigned char)*6);
    for (int i=0;i<=5;i++) tmpmac[i]=mac[i];
    return tmpmac;	
}

char *NetGuard_Command_Input_WH8::doquery(char *ip, char* oid){
    struct snmp_session *snmp_sess;
    char *buffer, *tmpresult;
    char *result;
    struct snmp_pdu *pdu;


    buffer = NULL;
    result = NULL;
    snmp_sess = session_open(ip, community.c_str());

	#ifdef debug
    printf("query: %s\n",oid);
    #endif

    pdu = (struct snmp_pdu*)session_create_pdu(SNMP_MSG_GET);
    session_add_null_var(pdu,oid);
    buffer = session_query(snmp_sess,pdu);
    session_free_pdu(pdu);

	#ifdef debug
	printf("query Result: %s\n",buffer);
	#endif
    if (buffer != NULL){
	    if (strstr(buffer,": ") != NULL) {
		    //suche in der Antwort nach dem AntwortString
		    tmpresult = buffer;
		    while (tmpresult[0] != ':') {
			    tmpresult++;
		    }
		    tmpresult++;
		    tmpresult++;
			#ifdef debug
			printf("query Result: %s\n",buffer);
		    #endif
	    } else tmpresult = buffer;

	    result = strdup(tmpresult);
	    free(buffer);
		#ifdef debug
	    printf("Result: %s \n", result);
	    #endif
	} else {
		#ifdef debug
	    printf("Cant Exec Command got null reply\n");
	    #endif
    };
    session_close(snmp_sess);
    return result;
}

void NetGuard_Command_Input_WH8::dowalkquery(char *ip, char* oid, char *results[]) {
    struct snmp_session *snmp_sess;
    char *buffer;
    int  pos = 0;

    buffer = NULL;
    snmp_sess = session_open(ip, community.c_str());

	#ifdef debug
    printf("query: %s\n",oid);
    #endif

    session_walk(snmp_sess,oid,results);
    buffer = results[pos];
    session_close(snmp_sess);
}

char *NetGuard_Command_Input_WH8::doset(char *ip, char* oid, char *value){
    struct snmp_session *snmp_sess;
    char *buffer, *tmpresult;
    char *result;

    buffer = NULL;
    result = NULL;
    snmp_sess = session_open(ip, community.c_str());

	#ifdef debug
    printf("query: %s\n",oid);
    printf("value: %s\n",value);
    #endif
    buffer = session_set(snmp_sess,oid,value);
	#ifdef debug
    printf("query Result: %s\n",buffer);
    #endif
    if (buffer != NULL){
	    if (strstr(buffer,": ") != NULL) {
	    	//suche in der Antwort nach dem AntwortString
	    	tmpresult = buffer;
	    	while (tmpresult[0] != ':') {
	    		tmpresult++;
		    }
		    tmpresult++;
	    	tmpresult++;
			#ifdef debug
	    	printf("query Result: %s\n",buffer);
	    	#endif
	    } else tmpresult = buffer;

	    result = strdup(tmpresult);
	    free(buffer);
		#ifdef debug
	    printf("Result: %s \n", result);
	    #endif
    } else {
		#ifdef debug
	    printf("Cant Exec Command got null reply\n");
	    #endif
    };
    session_close(snmp_sess);
    return result;
}

char *NetGuard_Command_Input_WH8::doportquery(char *ip,char *oid, int port) {
    char *query;
    char *tmpresult;

    query = (char*)calloc(strlen(oid)+10,sizeof(char));
    sprintf(query,oid,port);
    tmpresult = doquery(ip,query);
    free(query);
    return tmpresult;
}

char *NetGuard_Command_Input_WH8::doportset(char *ip,char *oid, int port, char *value) {
    char *query;
    char *tmpresult;

    query = (char*)calloc(strlen(oid)+10,sizeof(char));
    sprintf(query,oid,port);
    tmpresult = doset(ip,query,value);
    free(query);
    return tmpresult;
}

int NetGuard_Command_Input_WH8::getmaxmacs(u_int32_t ip, int port){
    const char *maxmacs = "iso.3.6.1.4.1.9.9.315.1.2.1.1.3.%d";
    char *query, *tmpresult;
    int count;

	#ifdef debug
    printf("entering inc mac part\n");
    #endif
    query = (char*)calloc(strlen(maxmacs)+10,sizeof(char));
    sprintf(query,maxmacs,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

	char *myip = inet_ntoa(*(struct in_addr *)&ip);
    tmpresult = doquery(myip,query);
	//delete myip;
    if (tmpresult)
    {
    	count = atoi(tmpresult);
	    free(tmpresult);
		#ifdef debug
	    printf("max mac count found:  %d\n",count);
	    #endif
	    return count;
    } else {
	    free(query);
	    printf("Error cant get max mac count\n");
	    return -1;
    }
}

int NetGuard_Command_Input_WH8::getmacslearned(u_int32_t ip, int port){
    const char *macsl = "enterprises.9.9.315.1.2.1.1.4.%i";
    char *query, *tmpresult;
    int count;
	#ifdef debug
    printf("entering get getmacslearned\n");
    #endif
    query = (char*)calloc(strlen(macsl)+10,sizeof(char));
    sprintf(query,macsl,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif


	char *myip = inet_ntoa(*(struct in_addr *)&ip);
    tmpresult = doquery(myip,query);
	//delete myip;
    if (tmpresult)
    {
	    count = atoi(tmpresult);
	    free(tmpresult);
		#ifdef debug
	    printf("getmacslearned count found:  %d\n",count);
	    #endif
	    return count;
    } else {
	    free(query);
	    printf("Error cant get getmacslearned count\n");
	    return -1;
    }
}

unsigned char *NetGuard_Command_Input_WH8::getmacfromoid(char *input) {
    unsigned char *tmpmac;
    char *tmpparse;
    int i=0, decoctet;
    const char *div;
    char *myinput;

    if (strstr(input,".") != NULL) {div = ".";} 
	else return NULL;

    tmpparse = strsep(&input,"=");
    myinput = tmpparse;
    tmpmac = (unsigned char *)malloc(sizeof(unsigned char)*6);
    for (i=0;i<5;i++) tmpmac[i]=0;
    tmpparse = strsep(&myinput,div);
    while (tmpparse != NULL) {
		sscanf(tmpparse,"%d", &decoctet);
    	tmpmac[0] = (int)tmpmac[1];
    	tmpmac[1] = (int)tmpmac[2];
    	tmpmac[2] = (int)tmpmac[3];
    	tmpmac[3] = (int)tmpmac[4];
    	tmpmac[4] = (int)tmpmac[5];
    	tmpmac[5] = decoctet;
    	tmpparse = strsep(&myinput,div);
    }
    return tmpmac;
}

bool NetGuard_Command_Input_WH8::find_mac(mac_addr mac,u_int32_t *ip, int *port, string *name) {
    int x,y,i = 0;
    char *tmp;
    const char* namequery = "enterprises.9.2.2.1.1.28.%d";
    const char *macquery = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d";

    char  *query, *myresult,*tmpresult;
    unsigned char *mymac, *hwa;
    char *results[MAXDUMPQUERRYLENGTH];
    int found = FALSE;

    mymac = getmacfrommac_addr(mac);

	#ifdef debug
    printf("entering search mac part\n");
    printf("need to find Mac Address at \t %02x:%02x:%02x:%02x:%02x:%02x\n",
		mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);
    #endif
    query = (char*)calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
    myresult = (char*)calloc(MAXDUMPQUERRYLENGTH,sizeof(char));

    i = 0;
    while ( switches[i] != NULL && !found)
    {
	    tmp = (char*)switches[i];
	    for (x=1;x<=24;x++){

		    query = (char*)calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
		    sprintf(query,macquery,x);
		    dowalkquery(tmp,query,results);
		    y = 0;
		    myresult = results[y];
		    while (myresult != NULL){
			    hwa = getmacfromoid(myresult);
				if (hwa != NULL) {
					#ifdef debug
					printf("Mac Address at \t%s \t%i \t %02x:%02x:%02x:%02x:%02x:%02x\n", tmp, x,
							hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
					#endif
					if (hwa[5] == mymac[5] && hwa[4] == mymac[4] &&
						hwa[3] == mymac[3] && hwa[2] == mymac[2] &&
						hwa[1] == mymac[1] && hwa[0] == mymac[0]) {
						found = 1;
						struct in_addr m_ip;
						inet_aton(switches[i],&m_ip);
						*ip = m_ip.s_addr;
						*port = x;
						free(query);
						query = (char*)calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
						sprintf(query,namequery,x);
						tmpresult = doquery(tmp,query);
						#ifdef debug
						printf("Switch: %s (%s) Port: %d\n",tmpresult,*ip,*port);
						#endif
						*name = strdup(tmpresult);
						free(tmpresult);
					}
					free(hwa);
				}
				free(myresult);
			    y++;
			    myresult = results[y];
		    }
		    free(query);
		    if (found) break;
	    }
	    i++;
    }
    free(mymac);
    return found;
}

int NetGuard_Command_Input_WH8::getadminstatus(u_int32_t ip, int port) {
    const char *getstatus = "interfaces.2.1.7.%d";
    char *query, *tmpresult;
    int count;

	#ifdef debug
    printf("entering get admin status\n");
    #endif
    query = (char*)calloc(strlen(getstatus)+10,sizeof(char));
    sprintf(query,getstatus,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

	char *myip = inet_ntoa(*(struct in_addr *)&ip);
    tmpresult = doquery(myip,query);
	//delete myip;

	if (tmpresult)
    {
	    count = atoi(tmpresult);
	    switch (count)
	    { 	case 1:
		    	return 1;
		    default:
			    return 0;
	    };

    } else {
	    free(query);
	    printf("Error cant get admin status\n");
	    return 0;
    }
}


string NetGuard_Command_Input_WH8::get_room_from_mac(mac_addr mac) {
	u_int32_t ip;
	int port;
	string name;
	if (find_mac(mac,&ip,&port,&name)) {
		return name;
	}
	return "";
}

mac_vector NetGuard_Command_Input_WH8::getmacs(u_int32_t ip, int port) {
	const char *macquery = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d";
	char  *query, *myresult;
	unsigned char *hwa;
	int i;
	char *results[MAXDUMPQUERRYLENGTH];
    query = (char*)calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
    sprintf(query,macquery,port);

	mac_vector res_v;

	char *myip = inet_ntoa(*(struct in_addr *)&ip);
    dowalkquery(myip,query,results);
    i = 0;
    myresult = results[i];
    while (myresult != NULL){
	    hwa = getmacfromoid(myresult);
		mac_addr *mymac = (mac_addr*)malloc(sizeof(mac_addr));
		(*mymac)[0] = hwa[0];
		(*mymac)[1] = hwa[1];
		(*mymac)[2] = hwa[2];
		(*mymac)[3] = hwa[3];
		(*mymac)[4] = hwa[4];
		(*mymac)[5] = hwa[5];
	    //printf("Mac Address %d : \t\t %02x:%02x:%02x:%02x:%02x:%02x\n", i+1, hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
		res_v.push_back(mymac);
	    free(myresult);
	    free(hwa);
	    i++;
	    myresult = results[i];
    }
    free(query);

	return res_v;
}


int NetGuard_Command_Input_WH8::resolve_room(in_addr_t *addr, u_int32_t *swip, int *swport) {
    struct hostent *host;
    char *ptr;
    struct stat fileinfo;

    char str[255];
    char room[100];
    char tmpswip[100];
    int  tmpswport;
    int check=0;
    	
	host = gethostbyaddr((char *)addr, sizeof(addr), AF_INET);
    if (host)
	{
		//get only the room number
		ng_logdebug("Found full Hostname:%s", host->h_name);
		ptr = strtok(host->h_name,".");
    	ptr[strlen(ptr)+1] = '\0';
		ng_logdebug("Check for Hostname:%s in db file", ptr);		
	    
		if (stat(GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),&fileinfo))
   		{
			ng_logerror("can not load %s",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str());
			return 0;
   		}

   		std::fstream file_op(GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),std::ios::in);
    
        while(!file_op.eof())
   		{
			file_op.getline(str,2000);
			if (sscanf (str,"%100s %100s %d",room,tmpswip,&tmpswport) == 3)
			{
				//ng_logdebug("check if :%s", room);
				int tmpval = strncasecmp(room,host->h_name,100);
				//ng_logdebug("check if :%s %i", room,tmpval);
				if(tmpval<=GlobalCFG::GetInt("mof.roomcheckboundry",-80))
				{
					ng_logdebug("checked %s and room found... matched line (%i):\"%s\"",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str(),tmpval,str);
					struct in_addr m_ip;
					inet_aton(tmpswip,&m_ip);
					*swip = m_ip.s_addr;
					*swport=*(&tmpswport);
					check=1;
					break;
				}		                		
			}
    	}
		if(check==0)
		    ng_logerror("checked %s - room *not* found...",GlobalCFG::GetStr("mof.dbfile","./db.txt").c_str());
		file_op.close();
		return check;		
	} else {
		ng_logerror("can *not* resolve hostname!");
		return 0;
	}
}


int NetGuard_Command_Input_WH8::user_state_load_logins() {
    struct stat fileinfo;

    char str[255];
    char user_login[100];
    char userip[100];
    	

	if (stat(GlobalCFG::GetStr("wh8.user_ip_db","./db_user-ip.txt").c_str(),&fileinfo))
	{
		ng_logerror("can not load %s",GlobalCFG::GetStr("wh8.user_ip_db","./db_user-ip.txt").c_str());
		return 0;
	}

	ng_logdebug("loading logins from file %s",GlobalCFG::GetStr("wh8.user_ip_db","./db_user-ip.txt").c_str());

	std::fstream file_op(GlobalCFG::GetStr("wh8.user_ip_db","./db_user-ip.txt").c_str(),std::ios::in);

	while(!file_op.eof())
	{
		file_op.getline(str,2000);
		if (sscanf (str,"%100s %100s",user_login,userip) == 2)
		{
			struct in_addr m_ip;
			inet_aton(userip,&m_ip);
			unsigned int tmpvlan = (GlobalCFG::GetInt("wh8.user_vlan",0));
			struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlan);
			if (!u_data) continue;
			if (u_data->saddr != m_ip.s_addr) continue;
			NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(u_data);
			if (!user_state) continue;
			user_state->params()->SetStr("login",user_login);
		}
	}
	file_op.close();

	ng_logdebug("loading logins done");

	return 0;
}


int NetGuard_Command_Input_WH8::user_state_load_rooms() {
    struct stat fileinfo;

    char str[255];
    char user_room[100];
    char userip[100];
    	

	if (stat(GlobalCFG::GetStr("wh8.ip_room_db","./db_ip-room.txt").c_str(),&fileinfo))
	{
		ng_logerror("can not load %s",GlobalCFG::GetStr("wh8.ip_room_db","./db_ip-room.txt").c_str());
		return 0;
	}

	ng_logdebug("loading rooms from file %s",GlobalCFG::GetStr("wh8.ip_room_db","./db_ip-room.txt").c_str());

	std::fstream file_op(GlobalCFG::GetStr("wh8.ip_room_db","./db_ip-room.txt").c_str(),std::ios::in);

	while(!file_op.eof())
	{
		file_op.getline(str,2000);
		if (sscanf (str,"%100s %100s",userip,user_room) == 2)
		{
			struct in_addr m_ip;
			inet_aton(userip,&m_ip);
			unsigned int tmpvlan = (GlobalCFG::GetInt("wh8.user_vlan",0));
			struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlan);
			if (!u_data) continue;
			if (u_data->saddr != m_ip.s_addr) continue;
			NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(u_data);
			if (!user_state) continue;
			user_state->params()->SetStr("room",user_room);
		}
	}
	file_op.close();

	ng_logdebug("loading rooms done");
	return 0;
}


void NetGuard_Command_Input_WH8::shutdown() {	
	NetGuard_State_Handler::GetPointer()->do_clear_registered_exec("wh8");
}

void NetGuard_Command_Input_WH8::timer_tick() {
}

void NetGuard_Command_Input_WH8::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	//here you get all commands send to netguard
	//in params you see the commands - intparams get filled if the param is an int and in command you see the unparsed input
	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "help")
	{
		ng_logout("wh8_mac <mac> - search for an mac in the hostel");
		ng_logout("wh8_mac_dump <mac> - search for an mac in the hostel - and display the status of the port where it was found");
		ng_logout("wh8_ip <ip> - show status of a port based on a given hostel ip");
		ng_logout("wh8_loaduser - load all logins from a db containing login -> ip");
		ng_logout("wh8_loadrooms - load all rooms from a db containing ip -> room");
		ng_logout("wh8_set_login <ip> <login> - set hostel login - like loadusers");
	}

	if (params[0] == "wh8_loaduser")
	{
		user_state_load_logins();
	}

	if (params[0] == "wh8_loadrooms")
	{
		user_state_load_rooms();
	}


	if (params[0] == "wh8_mac")
	{
		if (params.size() < 1)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_mac <mac>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_mac <mac>");
			return;
		}
		string room;
		u_int32_t ip;
		int port;
		if (find_mac(mac,&ip,&port,&room)) {
			ng_logout_ok("found room: %s \t\t-ip %s -port %d",room.c_str(),inet_ntoa(*(struct in_addr *)&ip),port);
		} else ng_logout_not_found("room not found!");
	}

	if (params[0] == "wh8_mac_dump")
	{
		if (params.size() < 1)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_mac <mac>");
			return;
		}
		mac_addr mac;
		if (!getmacfromchar(params[1].c_str(), &mac))
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_mac <mac>");
			return;
		}
		string room;
		u_int32_t ip;
		int port;
		if (find_mac(mac,&ip,&port,&room)) {
			ng_logout("found room: %s \t\t-ip %s -port %d",room.c_str(),inet_ntoa(*(struct in_addr *)&ip),port);
			ng_logout("port details - admin status:[%d] max macs:[%d] learned macs:[%d]",getadminstatus(ip,port),getmaxmacs(ip,port),getmacslearned(ip,port));

			mac_vector macs = getmacs(ip,port);
			mac_vector::iterator it;
			for (it=macs.begin(); it != macs.end(); it++) {
				mac_addr *mymac = (*it);
				ng_logout("port learned mac: %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params((*mymac)));
			}
			macs.clear();
		} else ng_logout_not_found("room not found!");
	}

	if (params[0] == "wh8_ip")
	{
		if (params.size() < 1)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_ip <ip>");
			return;
		}

		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: %s <ip>",params[0].c_str());
			return;
		}
		string room;
		u_int32_t ip;
		int port;
		if (resolve_room(&(m_ip.s_addr),&ip,&port)) {
			ng_logout("found room: %s \t\t-ip %s -port %d",room.c_str(),inet_ntoa(*(struct in_addr *)&ip),port);
			ng_logout("port details - admin status:[%d] max macs:[%d] learned macs:[%d]",getadminstatus(ip,port),getmaxmacs(ip,port),getmacslearned(ip,port));

			mac_vector macs = getmacs(ip,port);
			mac_vector::iterator it;
			for (it=macs.begin(); it != macs.end(); it++) {
				mac_addr *mymac = (*it);
				ng_logout("port learned mac: %02x:%02x:%02x:%02x:%02x:%02x", printf_mac_params((*mymac)));
			}
			macs.clear();
		} else ng_logout_not_found("room not found!");
	}

	if (params[0] == "wh8_set_login")
	{
		if (params.size() < 2)
		{
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_set_login <ip> <login>");
			return;
		}

		struct in_addr m_ip;
		if (!inet_aton(params[1].c_str(),&m_ip ))
		{	
			ng_logout_ret(RET_WRONG_SYNTAX,"usage: wh8_set_login <ip> <login>",params[0].c_str());
			return;
		}

		unsigned int tmpvlan = (GlobalCFG::GetInt("wh8.user_vlan",0));
		struct user_data *u_data = muser_data->get_user(&m_ip.s_addr,&tmpvlan);
		if (!u_data) {
			ng_logout_not_found("user not found!");
			return;
		}
		if (u_data->saddr != m_ip.s_addr) {
			ng_logout_not_found("user not found!");
			return;
		}
		NetGuard_User_State *user_state = NetGuard_State_Handler::user_state(u_data);
		if (!user_state) return;
		user_state->params()->SetStr("login",params[2]);
		ng_logout_ok("user updated");

	}

}

