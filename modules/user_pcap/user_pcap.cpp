/***************************************************************************
 *   NetGuard Pcap Module                                                  *
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

#include "user_pcap.hpp"
#include "compile.h"
#include "../../includes/logging.h"
#include "../../includes/storage/user_data.hpp"
#include "pcap.h"


NetGuard_Pcap::NetGuard_Pcap()
{
    ng_logdebug_spam("constructor");
    pcapInProg = false;
}

NetGuard_Pcap::~NetGuard_Pcap()
{
    ng_logdebug_spam("destructor");
}

int NetGuard_Pcap::init(NetGuard_Config *data)
{
    return 0;
}

void NetGuard_Pcap::shutdown()
{

}

void NetGuard_Pcap::clear()
{
}

void NetGuard_Pcap::stop_pckgcapture()
{
    if(!pcapInProg)
	return;
    pcapInProg = false;
    if(filter_macaddr)
	delete filter_macaddr;
    if(logFile)
	fclose(logFile);
}

void NetGuard_Pcap::start_pckgcapture(struct in_addr *ipaddr, mac_addr *macaddr)
{
    if((!ipaddr)&&(!macaddr))
	return;
    if(pcapInProg)
	stop_pckgcapture();
    std::string file_name;
    filter_ipaddr = ipaddr;
    if(filter_ipaddr){
	file_name.append(inet_ntoa((*ipaddr)));
    }
    if(macaddr)
    {
	filter_macaddr = (mac_addr *)malloc(sizeof(mac_addr));
        memcpy(filter_macaddr,macaddr,sizeof(mac_addr));
        char *buffer2 = (char*)malloc(17);
        sprintmac(buffer2, *macaddr);
        file_name.append(buffer2);
    }
    file_name = GlobalCFG::GetStr("pcap_path", "/tmp")+"/"+file_name;

    logFile = fopen(file_name.c_str(), "wb");
    if(!logFile) {
	ng_logerror("cant not create pcap file %s",file_name.c_str());
	return;
    }
    struct pcap_file_header pfh;
    pfh.magic = TCPDUMP_MAGIC;
    pfh.version_major = PCAP_VERSION_MAJOR;
    pfh.version_minor = PCAP_VERSION_MINOR;
    pfh.thiszone = 0;
    pfh.sigfigs = 0;
    pfh.snaplen = 65535;
    pfh.linktype = LINKTYPE_ETHERNET;
    
    if( fwrite(&pfh, 1, sizeof( pfh ), logFile) != (size_t) sizeof( pfh )) 
    {
	ng_logerror("cant write pcap header");
	return;
    };
    pcapInProg = true;
}

void NetGuard_Pcap::got_input(std::vector<std::string> params, std::vector<int> inparams, std::string command)
{
    if(params.size()==0)
	return;
    if(params[0]=="version")
    {
	ng_logext(100,"%s - Version: %s build: %s from %s at %s with %s",NetGuard_NAME, NetGuard_VERSION,NetGuard_COMPILE_DATE,NetGuard_COMPILE_BY,NetGuard_COMPILE_HOST,NetGuard_COMPILER);;
    }
    if(params[0]=="pcap") 
    {
	if(params.size() > 1 ) 
	{
	    if(params[1]=="stop"){
		stop_pckgcapture();
		ng_logout(0, "Pckg capture stopped");
	    } else if(!pcapInProg) {
		struct in_addr m_ip;
		mac_addr mac;
		if(inet_aton(params[1].c_str(), &m_ip))
		{
		    start_pckgcapture(&m_ip, NULL);
		} else
		if(getmacfromchar(params[1].c_str(), &mac))
		{
		    start_pckgcapture(NULL, &mac);
		} else
		    ng_logout_ret(RET_WRONG_SYNTAX, "pcap <ip> or <mac>");
	    } else
		ng_logout(0, "Pckg capture allready running");
	}
	if(pcapInProg)
	    ng_logout(0, "Pckg capture is running");
	else
	    ng_logout(0, "Pckg capture is NOT running");
    }
}

void NetGuard_Pcap::packet_in(struct user_data *u_data, int *mode, unsigned int *vlanid,
    struct tpacket_hdr *h, struct ether_header *eth, struct iphdr *ip, struct tcphdr *tcp, void *data)
{
    if(!pcapInProg)
	return;
    bool capturePckg = false;

    if(filter_macaddr) 
    {
	capturePckg = compare_mac(&eth->ether_shost, filter_macaddr) ||
	    compare_mac(&eth->ether_shost, filter_macaddr);
    }
    
    if((!capturePckg) && filter_ipaddr && (htons(eth->ether_type)==ETHERTYPE_IP))
    {
	capturePckg = (ip->saddr == filter_ipaddr->s_addr) || (ip->daddr == filter_ipaddr->s_addr);
    }
    
    if(!capturePckg)
	return;

    struct pcap_pkthdr pkh;
    
    pkh.caplen = h->tp_len; 
    pkh.tv_sec = h->tp_sec;
    pkh.tv_usec = h->tp_usec;

    fwrite(&pkh, 1, sizeof(pkh), logFile);
    fwrite(&data, 1, h->tp_len, logFile);
}












