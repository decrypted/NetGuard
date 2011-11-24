#ifndef NETGUARD_PCAP_H
#define NETGUARD_PCAP_H

#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4
#define TCPDUMP_MAGIC           0xA1B2C3D4 
#define LINKTYPE_ETHERNET       1


struct pcap_file_header
{
    uint magic;
    ushort version_major;
    ushort version_minor;
    int thiszone;
    uint sigfigs;
    uint snaplen;
    uint linktype;
};

struct pcap_pkthdr
{
    int tv_sec;
    int tv_usec;
    uint caplen;
    uint len;
}; 


#endif
