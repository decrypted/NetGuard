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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <values.h>

#include "ring.hpp"
#include "compile.h"
#include "../../includes/logging.h"



NetGuard_Ring::NetGuard_Ring()
{
	ng_logdebug_spam("constructor");	
	do_break = 0;
	_RingLength = (unsigned int)DEFAULT_RINGSIZE;
	CallBack_ = NULL;

	//device stuff
	sock_fd = -1;
	device_id = -1;

	got_package =0 ;

	pkt_kernel_count = 0;
	pkt_kernel_count_dropped = 0;
	ring_alloc_size = 0;

}

NetGuard_Ring::~NetGuard_Ring() 
{
	ng_logdebug_spam("destructor");	
	close_ring();
}

void NetGuard_Ring::stop_poll()
{
	do_break = 1;
}

int NetGuard_Ring::open_ring()
{
	int i, k, idx;
	int framesz = TPACKET_ALIGN(TPACKET_HDRLEN)+TPACKET_ALIGN(SNAPLENGTH);
	int page_size = getpagesize();
	int frames_per_pg = page_size/framesz;
	int pgs;
	struct tpacket_req req;

	ng_logdebug("setting up ring ..");
	close_ring();

	if (!frames_per_pg)
		return -1;

	got_package = 0;
	pkt_count  = 0;
	pkt_size = 0;

	pgs = (_RingLength + frames_per_pg - 1) / frames_per_pg;
	_RingLength = frames_per_pg * pgs;

	req.tp_frame_nr = _RingLength;
	req.tp_frame_size = framesz;
	req.tp_block_nr = pgs;
	req.tp_block_size = page_size;

	ng_logdebug("setting up ring - sockopt ..");

	if (setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, (void*)&req, sizeof(req))) {
		ng_logerror("Error: setsockopt(PACKET_RX_RING)");
		return -2;
	}

	ng_logdebug("setting up ring - malloc ..");
	ring = (struct iovec *) malloc(_RingLength * sizeof(struct iovec));
	if (!ring)
	{
		ng_logerror("Error: Ring setup failure, malloc");
		return -2;
	}

    ring_alloc_size = pgs*page_size;
	ng_logdebug("setting up ring - mmap ..");
	buf = (char*)mmap(0, pgs*page_size, PROT_READ|PROT_WRITE,MAP_SHARED, sock_fd, 0);
	if ((long)buf == -1L) {
		ng_logerror("Error: Could not allocate shared memory");
		memset(&req, 0, sizeof(req));
		buf=NULL;
		if (setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, (void*)&req,
		    sizeof(req)))
		{
			ng_logerror("Error: Failed to destroy ring");
		}
		free (ring);
		ring = NULL;
		return -2;
	}

	ng_logdebug("setting up ring - init ..");
	idx=0;
	for (i=0; i<pgs; i++) {
		for (k=0; k<frames_per_pg; k++) {
			ring[idx].iov_base = buf + page_size*i + k*framesz;
			ring[idx].iov_len = framesz;
			//we dont init the init base as we can not predict how far the kernel already is
			//*(unsigned long*)ring[idx].iov_base = 0;
			idx++;
		}
	}

	ng_logdebug("setting up ring - reset ..");
	buffersize = pgs * page_size;
	iovhead = 0;
	iovmax = _RingLength - 1;

	check();

	ng_logdebug("ring running");

	return 0;
}

int NetGuard_Ring::poll()
{
	//do we have a ring running ?
	if (!ring) return -1;

	if (do_break) {
		//terminated
		do_break = 0;
		return 1;
	}

	int read_cnt = 0;

	if (iovhead!=0)
	{
		if ((*(unsigned long*)ring[iovhead-1].iov_base))
		{
			ng_log("ring buffer to small - lost packages");
		}
	}

	while ((*(unsigned long*)ring[iovhead].iov_base))
	{
		/*	
		int iovhead_front = (iovhead == 0) ? iovmax : iovhead-1;
		if ((*(unsigned long*)ring[iovhead_front].iov_base))
		{
			ng_logdebug_spam("ring buffer to small - lost packages");
		}			
		*/
		//much LESS cpu usage but fails in one case .... we can take this i guess


		if (do_break) {
			//terminated
			do_break = 0;
			return 1;
		}
		struct tpacket_hdr *h = NULL;
		vlan_ignore_set::const_iterator it;

		h = (struct tpacket_hdr *)ring[iovhead].iov_base;
		//(void*)h = ring[iovhead].iov_base;
		struct ether_header *eth = (struct ether_header *) ((int)h + h->tp_mac);
		struct iphdr *ip = (struct iphdr *) (void*)((int)eth + sizeof(struct ether_header));
		struct tcphdr *tcp = (struct tcphdr *) (void*)((int)ip + sizeof(struct iphdr));
		void *rawdata  = (void *)((int)tcp + sizeof(struct tcphdr));
		
		unsigned int vlanid = 0;
		if (ETHERTYPE_8021Q == ntohs(eth->ether_type)) {
			struct vlan_hdr *vhdr = (struct vlan_hdr *)ip;
			ip = (struct iphdr *) ((int)eth + sizeof(struct ether_header) + sizeof(struct vlan_hdr));
			tcp = (struct tcphdr *) ((int)ip + sizeof(struct iphdr));
			rawdata  = (void *) ((int)tcp + sizeof(struct tcphdr));

			eth->ether_type = vhdr->h_vlan_encapsulated_proto;
			vlanid = VLAN_ID(vhdr);
		};

		if (!got_package)
		{
			got_package = 1;
			ng_logdebug("got the first package ...");
		}

		pkt_count ++;
		pkt_size += h->tp_len;

		it = vignore.find(vlanid);
		if (it == vignore.end())
			CallBack_->packet_in(&vlanid,h,eth, ip, tcp, rawdata);

		read_cnt ++;
		h->tp_status = 0; // mark package as read
		my_mb();

		iovhead = (iovhead == iovmax) ? 0 : iovhead+1;
	}

	//OOOK this whole looking if there is another package thing is overrated
	//there will be soon - so soon that sleeping short until wont fix it - as it will happen always again
	//if we want realtime we should not do the return - but that will cause a lot of cs and other things
	//return 0 signals hey - i got some packages but nothing im busy with so lets sleep some time
	return read_cnt;

	/*if (read_cnt > 10 ) 
	{	
		usleep(10000);
		return 1;
	}*/

	//skip empty ring entrys 
	//wait for entrys
	while (!(*(unsigned long*)ring[iovhead].iov_base))
	{
		//ng_log("nothing in buffer %d",iovhead);
//			return 0;
/*		struct pollfd 	pfd;
		pfd.fd = fd;
		pfd.revents = 0;
		pfd.events = POLLIN|POLLRDNORM|POLLERR;
		int pres = poll(&pfd, 1, 1000); 
		if (pres < 0) {
			printf("error on poll: %s", strerror(errno));
		}
		if (pfd.revents & POLLERR) {
			int err;
			socklen_t elen = sizeof(err);
			if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen)) {
				printf("getsockopt(SO_ERROR): %s", strerror(errno));
			}
		}*/

/*
		read_cnt ++;
		if (maxcnt >= read_cnt || read_cnt>1000) do_break = 1;
		if (do_break) {
			//terminated
			//ng_log("nothing in buffer %d",iovhead);
			do_break = 0;
			return 1;
		}

		//sleep(1);*/

		if (do_break) {
			do_break = 0;
			return 1;
		}
		int pres;
		struct pollfd pfd;
		pfd.fd = sock_fd;
		pfd.revents = 0;
		pfd.events = POLLIN;
		pres = ::poll(&pfd, 1, 10);
		if ((pres > 0) && (pfd.revents&POLLIN)) {
			//if (pres <= 5) return 1;
			//ng_logerror("polling got package %d",pres);
			break;
		} else {
			if (pres == 0) {
				//timeout
				ng_logerror("polling got timeout %d",pres);
				return 1; //1 -> dont sleep and call us again asap
			}
			if (errno == EINTR) {
				do_break = 0;
				return 1; //1 -> dont sleep and call us again asap
				//continue; //lets try that again
			}
			ng_logerror("error polling the ring fd %d",errno);
		}
		ng_logerror("strange error polling the ring fd %d",errno);
		return 0; //0 -> sleep and call us again 
	} 
	return 0;
}

void NetGuard_Ring::close_ring()
{
	if (ring != NULL)
	{
		free (ring);
	}
	ring = NULL;
	if (buf != NULL)
	{
		munmap (buf, buffersize);
		buf = NULL;
	}
}

int NetGuard_Ring::check()
{
	unsigned int i, head;
	ng_logdebug("run check");

	for (head = iovhead, i = 0; i < _RingLength; i++ )
	{
		if (*(unsigned long *)ring[head].iov_base)
		{
			iovhead = head;
			ng_logdebug("Set iovhead to %d!", head);
			return head;
		}
		head = (head == iovmax) ? 0 : head + 1;
	}
	return -1;
}

unsigned int NetGuard_Ring::flush_ring()
{
	unsigned int    i, head;
	unsigned int discarded = 0;

	if (!ring) return 0;
	for (head = iovhead, i = 0; i < _RingLength; i++ )
	{

		if (*(unsigned long *)ring[head].iov_base)
		{
			*(unsigned long *)ring[head].iov_base = 0;
			discarded++;
		}
		head = (head == iovmax) ? 0 : head + 1;
	}
	iovhead = head;

	return discarded;
}


int NetGuard_Ring::init(NetGuard_Config *data) {
	if (!data) return -1;
	int ret = NetGuard_Module::init(data); //important to get needed links
	if (ret) return ret;

	CallBack_ = NULL;
	ring = NULL;
	sock_fd = -1;
	device_id = -1;
	int err;

	data_ = new NetGuard_Config();
	data_->assign(data);

	CallBack_ = (NetGuard_General_Module*)data->GetModule("root_module");
	if (!CallBack_)
	{
		ng_logerror("need an root_module in config data");
		return -2;
	}

	if (data_->GetStr("interface") == "")
	{
		ng_logerror("need an interface in config data");
		return -2;
	}

	if (data_->GetInt("ringsize") != MININT)
	{
		if (data_->GetInt("ringsize")> 2 )
		{
			_RingLength = data_->GetInt("ringsize");
			ng_logdebug("set ringsize to %d",_RingLength);
		} else  ng_log("dont set ringsize to %d (must be >2)",data_->GetInt("ringsize"));
	}

	ng_logdebug("starting on: %s",data_->GetStr("interface").c_str());

	//open raw socket
	sock_fd = socket(PF_PACKET, SOCK_RAW,htons(ETH_P_ALL));
	if (sock_fd == -1) {
		ng_logerror("Error on open socket: %s",strerror(errno));
		return -2;
	}

	device_id = iface_get_id(sock_fd, data->GetStr("interface").c_str());
	if (device_id == -1) {
		ng_logerror("Error cant get device id for: %s",data->GetStr("interface").c_str());
		return -2;
	}

	if ((err = iface_bind(sock_fd, device_id)) < 0) {
		if (err == -2) {
			ng_logerror("Error critical Error on iface_bind");
			return -2;
		}
	}

	ng_logdebug("open ring on: %s",data_->GetStr("interface").c_str());

	return open_ring();
}

struct tpacket_stats NetGuard_Ring::get_stats() {
    struct tpacket_stats stats;
	stats.tp_packets = pkt_kernel_count;
	stats.tp_drops = pkt_kernel_count_dropped;
	if (sock_fd == -1) return stats;
    socklen_t l = sizeof (struct tpacket_stats);
    getsockopt(sock_fd, SOL_PACKET, PACKET_STATISTICS,&stats, &l);
	stats.tp_packets += pkt_kernel_count;
	stats.tp_drops += pkt_kernel_count_dropped;
	pkt_kernel_count = stats.tp_packets;
	pkt_kernel_count_dropped = stats.tp_drops;
	return stats;
}

void NetGuard_Ring::shutdown() {
	close_ring();
	if (sock_fd) close(sock_fd);
}

void NetGuard_Ring::got_input(std::vector<std::string> params, std::vector<int> intparams, std::string command)
{
	if (params[0] == "help") 
	{
		ng_logout("stats - show ring stats");
		ng_logout("ring_stats - show some ring specific stats");
		ng_logout("ring_stats_reset - reset kernel stats");
		ng_logout("ring_vignore_add <vlan> - add ignored vlan");
		ng_logout("ring_vignore_list - list all ignored vlans");
		ng_logout("ring_vignore_clean - clear all ignored vlans");
		//ng_log("ringsize <size> - set new ringsize");
	}

	if (params[0] == "version")
	{
		ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);
	}

	if (params[0] == "stats")
	{	
		ng_logout("%llu MByte in %llu Packages ",(unsigned long long)(pkt_size/1024/1024),pkt_count);
	}

	if (params[0] == "ring_stats")
	{	
		ng_logout("%llu MByte in %llu Packages ",(unsigned long long)(pkt_size/1024/1024),pkt_count);
		ng_logout("Ring size - items: %u size: %u KByte",_RingLength,(unsigned long long)(ring_alloc_size/1024));
		struct tpacket_stats  stats = get_stats();
		ng_logout("Kernel Stats packages: %u dropped: %u",stats.tp_packets,stats.tp_drops);
	}
	if (params[0] == "ring_stats_reset")
	{	
		struct tpacket_stats  stats = get_stats();
		pkt_kernel_count = 0;
		pkt_kernel_count_dropped = 0;
		ng_logout_ok("kernel stats resetted");
	}

	if (params[0] == "ring_vignore_add")
	{	
		if (params.size() == 2 && intparams[1]>2)
		{
			vignore.insert(pair<int,bool>(intparams[1], true));
			ng_logout_ok("ring_vignore_add added %d",intparams[1]);
		} else {
			ng_logout_ok("ring_vignore_add <vlan> - add ignored vlan");
			return;
		}
	}

	if (params[0] == "ring_vignore_clean")
	{	
		vignore.clear();
		ng_logout_ok("ring_vignore cleared");
	}


	if (params[0] == "ring_vignore_list")
	{	
		ng_logout("ring_vignore list:");
		vlan_ignore_set::iterator it;
		for (it=vignore.begin(); it != vignore.end(); it++)
				ng_logout("ignore vlan: %d",(*it).first);
	}


/*  TODO not working right now - need to unmap memory first etc
	if (params[0] == "ringsize")
	{	
		if (params.size() == 2 && intparams[1]>2)
		{
			close_ring();
			_RingLength = intparams[1];
			open_ring();			
			ng_log("ringsize set to %d",_RingLength);
		} else {
			ng_log("usage: ringsize <size> - set new ringsize (size >2)");
			return;
		}
	}*/

}


