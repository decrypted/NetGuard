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


#include "../../modules/command_input_socket/input.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>

#define SOCK_PATH2  "/var/run/netguard_socket"

int getresults(int s) 
{
	int t, len;
	char str[1024];
	pollfd myp;
	myp.fd = s;
	myp.events = POLLIN;

	t = 1;
	int w = 5000;
	while (t>0)
	{
		t = poll(&myp,1, w);
		if (t > 0)
		{
			w = 1;
			len = recv(s, str, sizeof(str),MSG_DONTWAIT);
			if (len == -1) exit(1);
			if (len) {
				str[len]=0;
				printf("%s", str);
			} else t=0;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	int s, len;
	struct sockaddr_un remote;
	char str[1024];

	if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}

	//printf("Trying to connect...\n");

	remote.sun_family = AF_UNIX;
	if (access(SOCK_PATH2, F_OK) == 0) {
		strcpy(remote.sun_path, SOCK_PATH2);
	} else strcpy(remote.sun_path, SOCK_PATH); //use home path if its not in the current path
	
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);
	if (connect(s, (struct sockaddr *)&remote, len) == -1) {
		perror("connect");
		exit(1);
	}


	//printf("Connected.");

	if (argc>1)
	{
		std::string args;

		for (int i=1;i<argc;i++) 
		{
			if (i>1)
				args.append(" ");
			args.append(argv[i]);
		}

		if (send(s, args.c_str(), strlen(args.c_str()), 0) == -1) {
			perror("send");
			exit(1);
		}

		getresults(s);
	} else {

		while(printf("\n> "), fgets(str, sizeof(str), stdin), !feof(stdin)) {
			if (send(s, str, strlen(str), 0) == -1) {
				perror("send");
				exit(1);
			}
			getresults(s);
		}
	}

	close(s);

	return 0;
}
