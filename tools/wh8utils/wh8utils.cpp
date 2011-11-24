/***************************************************************************
 *   NetGuard CGI Stats                                                    *
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

#include <fstream>
#include "dns.h"



char *getroomname(char *host)
{
	if (!host) return NULL;
    char *roomname = host;    
    int shift=0;
    while(roomname[shift] != '.' && roomname[shift] != '\0') shift++;
	    roomname[shift]='\0';
	if (roomname[strlen(roomname)-1] == 'a')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	if (roomname[strlen(roomname)-1] == 'b')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	if (roomname[strlen(roomname)-1] == 'c')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	if (roomname[strlen(roomname)-1] == 'd')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	if (roomname[strlen(roomname)-1] == 'e')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	if (roomname[strlen(roomname)-1] == 'f')
	{
		 roomname[strlen(roomname)-1] ='\0';
	}
	return roomname;
}

int main(int argc, char **argv)
{
	//std::string tmproom = getroomname(myaddr.addr);
    FILE *db;
	FILE *db2;

	db = fopen("db_ip-room.txt","w");
	if(db == NULL) {
		printf("Can not open file!\n");
		return -1;
    }
	db2 = fopen("db_user-ip.txt","w");
	if(db2 == NULL) {
		printf("Can not open file!\n");
		return -1;
    }

	for (int i=1;i<256;i++) {
		char *buffer = (char*)malloc(5000);
		char *buffer2 = (char*)malloc(5000);
		sprintf(buffer,"141.30.225.%d",i);

		in_addr myaddr;
		myaddr.s_addr = inet_addr(buffer);
		
		dns_t *ptr;
		int count1=dns_ptr(&myaddr,&ptr);

		sprintf(buffer2,"%s",ptr->name);
		
		dns_t *txt;
		int count2=dns_txt(ptr->name,&txt);		
		if ((count1>0) && (count2>0))
		{
			getroomname(buffer2);
			printf("%s %s %s %s\n",buffer,ptr->name,buffer2,txt->name);

			fprintf(db,"%s\t%s\n",buffer,buffer2);
			fprintf(db2,"%s\t%s\n",txt->name,buffer);
		}

		free(buffer);
		free(buffer2);
	}

	fclose(db);
	fclose(db2);

	return 0;
}
