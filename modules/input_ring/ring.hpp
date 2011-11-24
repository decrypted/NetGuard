/***************************************************************************
 *   NetGuard Packet Capture Ring                                          *
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

#ifndef NETGUARD_RING_H
#define NETGUARD_RING_H 1

#ifndef SOL_PACKET /* */
#  define SOL_PACKET  263 /* */
#endif /* SOL_PACKET */

#define SNAPLENGTH 	 1514
#define DEFAULT_RINGSIZE 8129
//#define DEFAULT_RINGSIZE 10

#include "ring_mb.h"	//mb() c call

#ifdef __cplusplus

#include "../../includes/tools.h"	//include NetGuard Tools	
#include "../../includes/types.hpp"
#include "../../includes/modules/input_module.hpp"
#include "../../includes/modules/general_module.hpp"

using namespace std;
using namespace __gnu_cxx; 

typedef hash_map<int, bool> vlan_ignore_set;

class NetGuard_Ring: public NetGuard_Input_Module
{
private:
	unsigned int	buffersize;	
	unsigned int	_RingLength;	//stored RingLength to avoid timing problems 
	unsigned int	iovmax;		//ring end
	unsigned int	iovhead;	//actual head to ring
	char 		*buf;		//pointer to the mapped buffer
	struct iovec    *ring;		//pointer to ioved struct to access the ring data

	int sock_fd, device_id;

	int got_package;
	unsigned int ring_alloc_size;

	unsigned long long int pkt_count;
	unsigned long long int pkt_size;

	unsigned long long int pkt_kernel_count;
	unsigned long long int pkt_kernel_count_dropped;


	int open_ring();	//open the ring
	unsigned flush_ring();	//flush all packages from the ring
	void close_ring();		//close the ring (unmap the memory)

	struct tpacket_stats get_stats();

	vlan_ignore_set vignore;	

public:  
	NetGuard_Ring();
	~NetGuard_Ring();


	//poll this import module
	int poll();

	//break the polling
	void stop_poll();

	//check the input source - 0 - its all fine
	int check();

	int init(NetGuard_Config *data);
	void got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command);
	void shutdown();

	void loaddata() {};
	void savedata() {};
	void timer_tick()  {};

	void *get_data(void *data) {return NULL;};

};
#endif

#endif /* !NETGUARD_RING_H */
