/***************************************************************************
 *   NetGuard CGI Stats                                                    *
 *                                                                         *
 *   Copyright (c) 2011 Ronny Hillmann <ronny at net-guard net>            *
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



//include für gethostbyaddr
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
//#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

#include <stdio.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <time.h>
#include <string.h>

#include "../../includes/storage/user_data.hpp"
#include "../../includes/tools.h"

#include <vector>
#include <algorithm>
#include <functional>

#define MESSAGE "Trafficübersicht des WH8"
#define CSSFILE "'/style.css'"
#define EINHEIT 1024/1024
#define NG_FILENAME "accounting.dat"
#define VLAN 0


User_Data_Tools data;

struct sortByUser_extern_traffic : public std::binary_function< struct  user_data *, struct  user_data *, bool > 
{
	bool operator()(struct  user_data * r1, struct  user_data * r2) const 
	{
		unsigned long long int v1 = r1->external.week.send.bytes + r1->external.week.resv.bytes;
		unsigned long long int v2 = r2->external.week.send.bytes + r2->external.week.resv.bytes;
		return ( v1 > v2 );
	}
};

struct sortByUser_intern_traffic : public std::binary_function< struct  user_data *, struct  user_data *, bool > 
{
	bool operator()(struct  user_data * r1, struct  user_data * r2) const 
	{
		unsigned long long int v1 = r1->internal.week.send.bytes + r1->internal.week.resv.bytes;
		unsigned long long int v2 = r2->internal.week.send.bytes + r2->internal.week.resv.bytes;
		return ( v1 > v2 );
	}
};

int gethostname(struct in_addr ip)
{
    int shift;
    struct hostent *host;
        
    host = gethostbyaddr((const void *)&ip, sizeof(ip),AF_INET);
    if(host == NULL)
    {
		herror("Rechner nicht gefunden");
		return EXIT_FAILURE;
    }
    
    //show only the room
    shift=0;
    while(host->h_name[shift] != '.' && host->h_name[shift] != '\0') shift++;
	    host->h_name[shift]='\0';
    
    printf("%s\n", host->h_name);
    return 0;
}

int mainpage(int traffictypselect)
{
    int userid = 1;
	int day = 0;
    long double traffic_usage;
    const char *trafficcolor;
    char l_a_time[50];
    
    struct tm *last_activity_time;
    struct user_data *u_data;
    //CONTENT
    printf("<div align=right>"
    "<b>Netguard CGI Stats 0.1</b><br>"
    "Daniel Rudolph<br>"
    "Ronny Hillmann"
    "</div>");
    
    printf("<center><h1>%s</h1></center>",MESSAGE);    
    printf("<DIV align=center>");
    printf("<a href='?traffictyp=extern'>extern</a>\n");
    printf("<a href='?traffictyp=intern'>intern</a>\n");
    printf("<br><br>");
    printf("</DIV>");
    
    printf("<table border='0'\n");
    printf(
    
    "<tr bgcolor=#0E377C>"
    "<th colspan='4'>"
    "</th>"
    "<th colspan='8' >"
    "externer Traffic in MB  (send/resv)"
    "</th>"    
    "<th colspan='1'>"
    "</th>"
    "</tr>"
    
    "<tr bgcolor=#0E377C>"
    "<th width='30'>"
	"Nr."
    "</th>"
    
    "<th width='75'>"
	"User"
    "</th>"
    
    "<th width='150'>"
	"IP"
    "</th>"
    
    "<th width='100'>"
	"Status"
    "</th>"
    
    "<th width='50'>"
	"Mo"
    "</th>"
    
    "<th width='50'>"
	"Di"
    "</th>"
    
    "<th width='50'>"
	"Mi"
    "</th>"
    
    "<th width='50'>"
	"Do"
    "</th>"
    
    "<th width='50'>"
	"Fr"
    "</th>"
    
    "<th width='50'>"
	"Sa"
    "</th>"
    
    "<th width='50'>"
	"So"
    "</th>"
    
    "<th width='100'>"
	"Woche"
    "</th>"
    
    "<th width='100'>"
	"Limit"
    "</th>");
    
    user_data_list user_list = data.get_vector_list();
    if(traffictypselect==0) {
		std::sort( user_list.begin(), user_list.end(), sortByUser_extern_traffic() );
    } else std::sort( user_list.begin(), user_list.end(), sortByUser_intern_traffic() );
    
	user_data_list::iterator it;
	for (it=user_list.begin(); it != user_list.end(); it++) {
		u_data = (*it);
	
		struct user_data_traffic *traffic_type = &u_data->external;
		//struct user_limit_data_type *traffic_type_limit = &((user_limit_data *)&u_data->module_data[10])->external;
		switch(traffictypselect)
		{
				case 0: traffic_type = &u_data->external;
				//traffic_type_limit = &((user_limit_data *)u_data->module_data[10])->external;
				break;
			case 1: traffic_type = &u_data->internal;
					//traffic_type_limit = &((user_limit_data *)u_data->module_data[10])->internal;
				break;
		}
		
		
		printf("<tr>\n");
		
		printf("<td align='center' valign='top'>\n");
		printf("%i\n",userid);
		printf("</td>\n");
		
		printf("<td align='center'>\n");
		printf("testuser");
		printf("<br>");
		printf("<font size=1>");
		gethostname(*(struct in_addr *)&u_data->saddr);
		printf("</font>");
		printf("</td>\n");
		
		printf("<td align='center' style='color:#C0C0C0'\n");
		printf("<a href='?hostip=%s'>%s</a>",inet_ntoa(*(struct in_addr *)&u_data->saddr),inet_ntoa(*(struct in_addr *)&u_data->saddr));
		printf("<br>");
		printf("%02x:%02x:%02x:%02x:%02x:%02x",u_data->hw_addr[0],u_data->hw_addr[1],u_data->hw_addr[2],u_data->hw_addr[3],u_data->hw_addr[4],u_data->hw_addr[5]);
		//printf("<br>");
		printf("</td>\n");
		
		printf("<td align='center'>\n");
		last_activity_time = localtime(&(u_data->last_activity));
		strftime(l_a_time, 80,"%d.%m.%Y <br> %X",last_activity_time);
		printf("%s",l_a_time);
		printf("</td>\n");
		
		if(userid%2==0)
			trafficcolor="style='color:#00CCFF'";
		else
			trafficcolor="style='color:#0099CC'";
		
		for(day=0;day<=6;day++)
		{    
			printf("<td align='center' %s\n>",trafficcolor);
			printf("%llu",traffic_type->days[(day+1)%7].send.bytes/EINHEIT);
			printf("<br>");
			printf("%llu",traffic_type->days[(day+1)%7].resv.bytes/EINHEIT);
			printf("</td>\n");
		}	
		
		if(userid%2==0)
			trafficcolor="style='color:#33FFCC'";
		else
			trafficcolor="style='color:#00CC99'";

		printf("<td align='center' %s>\n",trafficcolor);
		printf("%llu",traffic_type->week.send.bytes/EINHEIT);
		printf("<br>");
		printf("%llu",traffic_type->week.resv.bytes/EINHEIT);
		printf("</td>\n");
		
		//TODO buildin the limit stuff again
	//	if(((long double)traffic_type_limit->limit_week)!=0)
	//	    traffic_usage=100*((long double)(traffic_type->week.send.bytes+traffic_type->week.resv.bytes))/((long double)traffic_type_limit->limit_week);
	//	else
			traffic_usage=0;
			
	/*	printf(
		"<td align='center'>"
		"<font color='#FFCC66'>%llu</font>"
		"<br>"
		"<font color='#CC6600'>%.2Lf %%</font>"
		"</td>",traffic_type_limit->limit_week/EINHEIT,traffic_usage);*/

		printf(
		"<td align='center'>"
		"<font color='#FFCC66'>0</font>"
		"<br>"
		"<font color='#CC6600'>0</font>"
		"</td>");
		
		
		printf("</tr>");
		userid++;
    }
    
    printf("</table>\n");
    return 0;
}


int detailpage(struct user_data *u_data_host)
{
    int day,i,z;
    const char *trafficcolor_days,*trafficcolor_week,*trafficcolor_overall,*trafficcolor_name;
    const char *strings[]={"send-bytes","resv-bytes","send-pkts","resv-pkts","sendip-bytes","resvip-bytes","sendip-pkts","resvip-pkts",
		    "sendtcpip-bytes","resvtcpip-bytes","sendtcpip-pktes","resvtcpip-pktes","sendudp-bytes","resvudp-bytes",
		    "sendudp-pkts","resvudp-pkts","sendicmp-bytes","resvicmp-bytes","sendicmp-pkts","resvicmp-pkts",
		    "sendarp-bytes","resvarp-bytes","sendarp-pkts","resvarp-pkts"};

    printf("<center><h2>%s</h2></center>",inet_ntoa(*(struct in_addr *)&u_data_host->saddr));
    
    printf("<tr>IP-Adresse: %s </tr>",inet_ntoa(*(struct in_addr *)&u_data_host->saddr));   
    printf("<br>");
    printf("<tr>VLAN-ID: %u </tr>",u_data_host->vlan_id);
    printf("<br>");
    printf("<tr>MAC-Adresse: %02x:%02x:%02x:%02x:%02x:%02x</tr>",u_data_host->hw_addr[0],u_data_host->hw_addr[1],u_data_host->hw_addr[2],u_data_host->hw_addr[3],u_data_host->hw_addr[4],u_data_host->hw_addr[5]);
    printf("<br>");
    printf("<tr>Letzte Aktivität: %.24s</tr>",ctime(&(u_data_host->last_activity)));
    printf("<br><br>");    
    
	//TODO buildin the limit stuff again
	/*
    printf("<b>Limits:</b><br>");
    printf("<tr>limit-day-bytes(extern): %llu </tr>",((user_limit_data *)u_data_host->module_data[10])->external.limit_day);   
    printf("<br>");
    printf("<tr>limit-week-bytes(extern): %llu </tr>",((user_limit_data *)u_data_host->module_data[10])->external.limit_week);
    printf("<br>");
    printf("<tr>limit-day-bytes(intern): %llu </tr>",((user_limit_data *)u_data_host->module_data[10])->internal.limit_day);   
    printf("<br>");
    printf("<tr>limit-week-bytes(intern): %llu </tr>",((user_limit_data *)u_data_host->module_data[10])->internal.limit_week);
    printf("<br>");
	*/
    
    
    struct user_data_traffic *traffic_type = &u_data_host->external;
    for(i=0;i<=1;i++)
    {
	printf("<br><br>");
    
	switch(i)
	{
	    case 0:	traffic_type = &u_data_host->external;
			printf("<h3>Externer Traffic</h3>");
		    break;
	    case 1:	traffic_type = &u_data_host->internal;
			printf("<h3>Interner Traffic</h3>");
		    break;
	}
    
	printf("<table border='0'>"
	"<tr bgcolor=#0E377C>"
	"<th width='100'>"
	"</th>"
    
	"<th width='100'>"
	    "Mo"
	"</th>"
    
	"<th width='100'>"
	    "Di"
	"</th>"
    
	"<th width='100'>"
	    "Mi"
	"</th>"
    
	"<th width='100'>"
	    "Do"
	"</th>"
    
	"<th width='100'>"
	    "Fr"
	"</th>"
    
	"<th width='100'>"
	    "Sa"
	"</th>"
    
	"<th width='100'>"
	    "So"
	"</th>"
    
	"<th width='100'>"
	    "Woche"
	"</th>"
    
	"<th width='100'>"
	    "Gesamt"
	"</th>"
	"</tr>");
    
	////
	
	
	for(z=0; z<(int)(sizeof(strings)/4)/2; z++)
	{    
	
	    if(z%2==0)
	    {
		trafficcolor_days="style='color:#0099CC'";
		trafficcolor_week="style='color:#00CC99'";
		trafficcolor_overall="style='color:#00CC00'";
		trafficcolor_name="style='color:#C0C0C0'";
	    }
	    else
	    {
		trafficcolor_days="style='color:#00CCFF'";
		trafficcolor_week="style='color:#33FFCC'";
		trafficcolor_overall="style='color:#33FF00'";
		trafficcolor_name="style='color:#FFFFFF'";
	    }
	
	
	    printf("<tr>");    
	    printf("<td %s>%s</td>",trafficcolor_name,strings[2*z]);
	    for(day=0; day<=6; day++)
	    {
		printf("<td align='right' %s>%llu</td>",trafficcolor_days,*(&traffic_type->days[(day+1)%7].send.bytes+z));
	    }
	    printf("<td align='right' %s>%llu</td>",trafficcolor_week,*(&traffic_type->week.send.bytes+z));
	    printf("<td align='right' %s>%llu</td>",trafficcolor_overall,*(&traffic_type->over_all.send.bytes+z));
	    printf("</tr>");
    
	    printf("<tr>");    
	    printf("<td %s>%s</td>",trafficcolor_name,strings[2*z+1]);
	    for(day=0; day<=6; day++)
	    {
		printf("<td align='right' %s>%llu</td>",trafficcolor_days,*(&traffic_type->days[(day+1)%7].resv.bytes+z));
	    }
	    printf("<td align='right' %s>%llu</td>",trafficcolor_week,*(&traffic_type->week.resv.bytes+z));
	    printf("<td align='right' %s>%llu</td>",trafficcolor_overall,*(&traffic_type->over_all.resv.bytes+z));
	    printf("</tr>");
	}
	
	trafficcolor_days="style='color:#0099CC'";
	trafficcolor_week="style='color:#00CC99'";
	trafficcolor_overall="style='color:#00CC00'";
	trafficcolor_name="style='color:#C0C0C0'";
        
	printf("<tr>");    
	printf("<td %s>Outgoing Connects</td>",trafficcolor_name);
	for(day=0; day<=6; day++)
	{
	    printf("<td align='right' %s>%llu</td>",trafficcolor_days,traffic_type->days[(day+1)%7].send.connects);
	}
	printf("<td align='right' %s>%llu</td>",trafficcolor_week,traffic_type->week.send.connects);
	printf("<td align='right' %s>%llu</td>",trafficcolor_overall,traffic_type->over_all.send.connects);
	printf("</tr>");

	printf("<tr>");    
	printf("<td %s>Incomming Connects</td>",trafficcolor_name);
	for(day=0; day<=6; day++)
	{
	    printf("<td align='right' %s>%llu</td>",trafficcolor_days,traffic_type->days[(day+1)%7].resv.connects);
	}
	printf("<td align='right' %s>%llu</td>",trafficcolor_week,traffic_type->week.resv.connects);
	printf("<td align='right' %s>%llu</td>",trafficcolor_overall,traffic_type->over_all.resv.connects);
	printf("</tr>");


	printf("</table>");
    }
    
    return 0;
}

int main()
{
    int shift,pageselect,traffictypselect;
    char query[512],hostipparam[512],traffictypparam[512],*poi;
    
    struct user_data *u_data_host = NULL;

    
    //HEAD///////////////////////////////////////////////////
    printf("Content-type: text/html\n\n");
    printf("<html><head><title>%s</title><link rel='stylesheet' type='text/css' href=%s></head>\n",MESSAGE,CSSFILE);
    printf("<body>\n");
    /////////////////////////////////////////////////////////
    
    if(getenv("QUERY_STRING") == NULL) 
    {
        /* das sollte eigentlich nicht vorkommen */
        printf("QUERY_STRING nicht definiert\n");
    } 
    else 
    {
	 strncpy(query,getenv("QUERY_STRING"),512);
    }
   
    data = User_Data_Tools();
    data.loaddata(NG_FILENAME,true);

    pageselect=0;
    traffictypselect=0;
    if(getenv("QUERY_STRING") != NULL) 
    {
		if((poi=strstr(query,"hostip=")) != NULL) 
		{
			strcpy(hostipparam,poi+7);
			shift=0;
			while(hostipparam[shift] != '&' && hostipparam[shift] != '\0') shift++;
			hostipparam[shift]='\0';
			in_addr_t myaddr = inet_addr(hostipparam);
			unsigned int tmpvlan = VLAN;
			u_data_host = data.get_user(&myaddr,&tmpvlan);
		}
		
		if((poi=strstr(query,"traffictyp=")) != NULL) 
		{
			strcpy(traffictypparam,poi+11);
			shift=0;
			while(traffictypparam[shift] != '&' && traffictypparam[shift] != '\0') shift++;
			traffictypparam[shift]='\0';

			if(strcmp(traffictypparam,"intern")==0)
			traffictypselect=1;
		}	 
    }
   
	if (u_data_host != NULL)
	{
		detailpage(u_data_host);
	} else mainpage(traffictypselect);
   

   //END////////////////////////////////////////////////////
    printf("</body></html>\n");
    /////////////////////////////////////////////////////////

    return 0;
}
