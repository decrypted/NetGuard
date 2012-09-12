/***************************************************************************
 *   MacOnOff                                                              *
 *                                                                         *
 *   Copyright (c) 2003-2012 Daniel Rudolph <daniel at net-guard net>      *
 *                                                                         *
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
 ***************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/in.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <linux/socket.h>
#include "snmp_layer.h"
#include "nsnmp_layer.h"
#include "compile.h"

#define MAXDUMPQUERRYLENGTH 1024
#define AUTHOR  "Daniel Rudolph 200[3,4,5,6,7,12] (maconoff@bsolut.com)\nsnmp code based on code from: Gregor Jasny"

//define passwdfile means get password from a file
//#define passwdfile

//#define debug
#define debugmode

#define do_setuid 1000

void usage(char *progname,char *error);

#ifdef passwdfile
static char *community;
const char * defaultfilename = "maconoff.conf";
#else
static char *community = "$ecUr1T4+3";
#endif

//set this to 1 if you want to have the wh8 mode in which disable changes the vlan of a port
int wh8mode = 1;
#define wh8_enable_vlan 2
#define wh8_disable_vlan 5

static char *nullmac   = "00:00:00:00:00:00";
const char *q_portname = "enterprises.9.2.2.1.1.28.%d";
const char* switches[]={"172.17.1.1","172.17.1.2","172.17.1.3","172.17.1.4",
                        "172.17.2.1","172.17.2.2","172.17.2.3",
                        "172.17.3.1","172.17.3.2","172.17.3.3","172.17.3.4",
            			"172.17.0.1",
						NULL};

//ronny...added WRITEDB
typedef enum { UNKOWN, DUMP, SET , FIND, VALUE, DOWRITE, WRITEDB,INFO} pmode_t;
typedef enum { DISABLE, ENABLE, LEARN, FORGET, REENABLE, CLEARMACS, VOICE, VLAN} state_t;
typedef enum { DUMPPORT, DUMPMACS} dumpstate_t;


typedef enum { qtype_string,qtype_int,qtype_typ,qtype_macaddr,qtype_voipvlan} qtype_t;
typedef struct {
	const char *   name;
	const char *   oid;
	qtype_t        val_typ;
	const char *   values[12];
} t_query_a_entry;

const t_query_a_entry s_queries[] =
{
	{ "Port Name\t", "enterprises.9.2.2.1.1.28.%d", qtype_string, {NULL} },
	{ "Admin Status\t", "interfaces.2.1.7.%d", qtype_typ, {"","up","down",NULL} },
	{ "Link Status\t","enterprises.9.9.87.1.4.1.1.18.0.%d", qtype_typ, {"","","link","nolink",NULL} },
	{ "Operation Status","interfaces.2.1.8.%d", qtype_typ, {"","up","down",NULL} },
	{ "May Learn Address","enterprises.9.9.87.1.4.1.1.5.0.%d", qtype_typ, {"","yes","no",NULL} },
	{ "PortSecurity\t","enterprises.9.9.315.1.2.1.1.1.%d", qtype_typ, {"","enabled","disabled",NULL} },
	{ "Voice VLAN ID\t","enterprises.9.9.87.1.4.1.1.37.0.%d", qtype_voipvlan, {NULL} },
	{ "VLAN ID\t\t","enterprises.9.9.68.1.2.2.1.2.%d", qtype_int, {NULL} },
	{ "PS (Status)\t","enterprises.9.9.315.1.2.1.1.2.%d", qtype_typ, {"","secureup","securedown", "shutdown",NULL}  },
	{ "PS (Max Macs)\t","enterprises.9.9.315.1.2.1.1.3.%d", qtype_int, { NULL} },
	{ "PS (Macs learned)","enterprises.9.9.315.1.2.1.1.4.%d", qtype_int, { NULL} },
	{ "PS (Violation Action)","enterprises.9.9.315.1.2.1.1.8.%d", qtype_typ, {"","shutdown","dropNotify", "drop",NULL} },
	{ "PS (Violation Count)","enterprises.9.9.315.1.2.1.1.9.%d", qtype_int, { NULL} },
	{ "PS (Last Mac)","enterprises.9.9.315.1.2.1.1.10.%d", qtype_macaddr, { NULL} },
	{ NULL,NULL,0,{NULL}}
};

void exit_w_error(int error){
	#ifdef debug
	printf("exit with error %d\n",error);
	#endif
	exit (error);
}

void usage(char *progname,char *error) {
	fprintf(stderr,"%s %s Usage\n",NetGuard_NAME,NetGuard_VERSION);
	#ifdef passwdfile
	fprintf(stderr," %s -c filename (set password file - default: maconoff.conf)\n", progname);
	#endif
	if (wh8mode)
	fprintf(stderr,"\n**Running in WH Mode! Enable/Disable will set the vlan - but not the alias commands (ydisable, xdisable) **\n\n");

	fprintf(stderr,"select mode %s  -m set|dump|find|value|write|info \n\n", progname);
	fprintf(stderr,"set: \n");
	fprintf(stderr,"  %s -m set -s disable|xdisable|enable|yenable|learn|forget|reenable|clearmacs|voice|svlan\n\n", progname);
	fprintf(stderr,"  reenable|clearmacs:\n");
	fprintf(stderr,"	%s -m set (-i ip -p port | -a macadress | -r room) -s reenable|clearmacs\n", progname);
	fprintf(stderr," 		reenable: shut down port and enable it again\n");
	fprintf(stderr," 		clearmacs: forget all learned macs (dont change maxmacs !!)\n\n");
	fprintf(stderr,"  disable|forget:\n");
	fprintf(stderr,"	%s -m set [(-i ip -p port) | -r room] -s disable|forget -a macadress\n", progname);
	fprintf(stderr," 		remove the mac from the port\n\n");
	fprintf(stderr,"	%s -m set ((-i ip -p port) | -a macadress | -r room) -s disable|forget\n", progname);
	fprintf(stderr," 		set adminstate down on port\n\n");
	fprintf(stderr,"  enable|learn:\n");
	fprintf(stderr,"	%s -m set ((-i ip -p port) | -a macadress | -r room) -s enable|learn [-a macadress]\n", progname);
	fprintf(stderr," 		enable|learn: no mac given -> enable port else learn this mac on port \n\n");
	fprintf(stderr," 		learn: mac given -> forget the mac given - keep state\n\n");
	fprintf(stderr,"  voice:\n");
	fprintf(stderr,"	%s -m set ( (-i ip -p port) | -a macadress | -r room ) -s voice -v value\n", progname);
	fprintf(stderr,"		value: VLan ID [0-4096|off|on] off=4096 on=602\n\n" );
	fprintf(stderr,"  svlan:\n");
	fprintf(stderr,"	%s -m set ( (-i ip -p port) | -a macadress | -r room ) -s vlan -v value\n", progname);
	fprintf(stderr,"		value: VLan ID [0-4096]\n\n" );
	fprintf(stderr,"value:\n");
	fprintf(stderr,"	%s -m value [-i ip [-p port]] -o oid without port -v value\n", progname);
	fprintf(stderr," 		use with CAUTION !! set a value to an given snmp oid\n\n");
	fprintf(stderr,"write:\n");
	fprintf(stderr,"	%s -m write (-i ip | -f)\n", progname);
	fprintf(stderr," 		copy running config to startup config\n\n");
	fprintf(stderr,"dump:\n");
	fprintf(stderr,"	%s -m dump (-i ip [-p port] | -f) [-s dumpmacs]\n", progname);
	fprintf(stderr,"	%s -m dump (-r room | -a macaddress) [-s dumpmacs]\n", progname);
	fprintf(stderr," 		show port details\n\n");
	fprintf(stderr,"find:\n");
	fprintf(stderr,"	%s -m find (-a macadress | -r room) \n", progname);
	fprintf(stderr," 		find a port based on the given data\n\n");

	//ronny
	fprintf(stderr,"writedb:\n");
	fprintf(stderr,"	%s -m x \n", progname);
	fprintf(stderr,"		write database to file (portname,switchip,port)\n" );

	fprintf(stderr,"info:\n");
	fprintf(stderr,"	%s -m info \n", progname);
	fprintf(stderr,"		show some author info\n" );

	if (error)
		fprintf(stderr,"\n\nERROR (check your params): %s\n",error);

	exit_w_error (EXIT_FAILURE);
}

unsigned char *getmacfromchar_ng(char *input){
    unsigned char *tmpmac;
    const char *tmpparse;
    int i=0, decoctet;
    const char *mdiv;
    char *myinput;
    myinput = strdup(input);
    if (strstr(myinput,":") != NULL) {mdiv = ":";} else {mdiv = " ";};

    tmpmac = malloc(sizeof(unsigned char)*6);

    for (i=0;i<=5;i++) tmpmac[i]=0;

    i=0;
    tmpparse = strsep((char **)&myinput,(const char *)mdiv);
    while (tmpparse != NULL) {
        sscanf(tmpparse,"%x", &decoctet);
        tmpmac[i] = (int)decoctet;
        i++;
        tmpparse = strsep(&myinput,mdiv);
    }

    free(myinput);

    return tmpmac;
}

unsigned char *getmacfromoid(char *input){
    unsigned char *tmpmac;
    char *tmpparse;
    int i=0, decoctet;
    char *mdiv;
    char *myinput;

    if (strstr(input,".") != NULL) {mdiv = ".";}
    else {
    	printf("Error cant parse MAC OID %s,\n",input);
    	exit_w_error (EXIT_FAILURE);
    }

    tmpparse = strsep(&input,"=");
    myinput = tmpparse;
    tmpmac = malloc(sizeof(unsigned char)*6);
    for (i=0;i<5;i++) tmpmac[i]=0;
    tmpparse = strsep(&myinput,mdiv);
    while (tmpparse != NULL) {
		sscanf(tmpparse,"%d", &decoctet);
    	tmpmac[0] = (int)tmpmac[1];
    	tmpmac[1] = (int)tmpmac[2];
    	tmpmac[2] = (int)tmpmac[3];
    	tmpmac[3] = (int)tmpmac[4];
    	tmpmac[4] = (int)tmpmac[5];
    	tmpmac[5] = decoctet;
    	tmpparse = strsep(&myinput,mdiv);
    }
    return tmpmac;
}

char *doquery(char *ip, char* moid){
    struct snmp_session *snmp_sess;
    char *buffer, *tmpresult;
    char *result;
    struct snmp_pdu *pdu;


    buffer = NULL;
    result = NULL;
    snmp_sess = session_open(ip, community);

	#ifdef debug
    printf("query: %s\n",moid);
    #endif

    pdu = (struct snmp_pdu*)session_create_pdu(SNMP_MSG_GET);
    session_add_null_var(pdu,moid);
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

void dowalkquery(char *ip, char* moid, char *results[]){
    struct snmp_session *snmp_sess;
    char *buffer;
    int  pos = 0;

    buffer = NULL;
    snmp_sess = session_open(ip, community);

	#ifdef debug
    printf("query: %s\n",moid);
    #endif

    session_walk(snmp_sess,moid,results);
    buffer = results[pos];
    session_close(snmp_sess);
}

char *doset(char *ip, char* moid, char *value){
    struct snmp_session *snmp_sess;
    char *buffer, *tmpresult;
    char *result;

    buffer = NULL;
    result = NULL;
    snmp_sess = session_open(ip, community);

	#ifdef debug
    printf("query: %s\n",moid);
    printf("value: %s\n",value);
    #endif
    buffer = session_set(snmp_sess,moid,value);
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

char *doportquery(char *ip,char *moid, int port) {
    char *query;
    char *tmpresult;

    query = calloc(strlen(moid)+10,sizeof(char));
    sprintf(query,moid,port);
    tmpresult = doquery(ip,query);
    free(query);
    return tmpresult;
}

char *doportset(char *ip,char *moid, int port, char *value) {
    char *query;
    char *tmpresult;

    query = calloc(strlen(moid)+10,sizeof(char));
    sprintf(query,moid,port);
    tmpresult = doset(ip,query,value);
    free(query);
    return tmpresult;
}

int getmaxmacs(char *ip, int port){
    char *maxmacs = "iso.3.6.1.4.1.9.9.315.1.2.1.1.3.%d";
    char *query, *tmpresult;
    int count;

	#ifdef debug
    printf("entering inc mac part\n");
    #endif
    query = calloc(strlen(maxmacs)+10,sizeof(char));
    sprintf(query,maxmacs,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

    tmpresult = doquery(ip,query);
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

int getmacslearned(char *ip, int port){
    char *macsl = "enterprises.9.9.315.1.2.1.1.4.%i";
    char *query, *tmpresult;
    int count;
	#ifdef debug
    printf("entering get getmacslearned\n");
    #endif
    query = calloc(strlen(macsl)+10,sizeof(char));
    sprintf(query,macsl,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

    tmpresult = doquery(ip,query);
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

void incmaxmacs(char *ip, int port){
	char *maxmacs = "iso.3.6.1.4.1.9.9.315.1.2.1.1.3.%d";
	char *query, *tmpresult, *value;
	int count;

	#ifdef debug
	printf("entering inc mac part\n");
	#endif
	query = calloc(strlen(maxmacs)+10,sizeof(char));
	sprintf(query,maxmacs,port);
	#ifdef debug
	printf("query:  %s\n",query);
	#endif

	tmpresult = doquery(ip,query);
	if (tmpresult)
	{
		count = atoi(tmpresult);
		free(tmpresult);
		#ifdef debug
		printf("max mac count found:  %d\n",count);
		#endif
		count++;
		value = calloc(2,sizeof(char));
		sprintf(value,"%d",count);
		tmpresult = doset(ip,query,value);
		if (tmpresult) free(tmpresult);
			else exit_w_error(EXIT_FAILURE);
		free(value);
		free(query);
	} else {
		free(query);
		printf("Error cant get max mac count\n");
	}
}

void decmaxmacs(char *ip, int port){
    char *maxmacs = "iso.3.6.1.4.1.9.9.315.1.2.1.1.3.%d";
    char *query, *tmpresult, *value;
    int count;

	#ifdef debug
    printf("entering dec mac part\n");
    #endif
    query = calloc(strlen(maxmacs)+10,sizeof(char));
    sprintf(query,maxmacs,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

    tmpresult = doquery(ip,query);
    if (tmpresult)
    {
	    count = atoi(tmpresult);
	    free(tmpresult);
		#ifdef debug
	    printf("max mac count found:  %d\n",count);
	    #endif
	    if (count >= 1)
	    {
		    count--;
		    value = calloc(2,sizeof(char));
		    sprintf(value,"%d",count);
		    tmpresult = doset(ip,query,value);
		    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
		    free(value);
	    } else {
		    printf("Error cant dec max mac count it is already 0\n");
		    exit_w_error (EXIT_FAILURE);
	    }
	    free(query);
    } else {
	    free(query);
    	printf("Error cant get max mac count\n");
	    exit_w_error (EXIT_FAILURE);
    }
}

int getadminstatus(char *ip, int port){
    char *getstatus = "interfaces.2.1.7.%d";
    char *query, *tmpresult;
    int count;

	#ifdef debug
    printf("entering get admin status\n");
    #endif
    query = calloc(strlen(getstatus)+10,sizeof(char));
    sprintf(query,getstatus,port);
	#ifdef debug
    printf("query:  %s\n",query);
    #endif

    tmpresult = doquery(ip,query);
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

void enable(char *ip, int port, char *mac){
    unsigned char *hwa = NULL;
    char *tmpquery;
    char *rowstatus = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d.%i.%i.%i.%i.%i.%i";
    char *query;
    char *createAndGo = "4";
    char *enablePort = "1";


	#ifdef debug
    printf("entering enable part\n");
    #endif
    if (mac)
    {

	    if (getmacslearned(ip,port)==0 && getmaxmacs(ip,port)==1 && !getadminstatus(ip,port))
		{
			enable(ip,port,NULL);
		} else incmaxmacs(ip,port);

	    hwa = getmacfromchar_ng(mac);
		#ifdef debug
	    printf ("eth hw address: %02x:%02x:%02x:%02x:%02x:%02x\n", hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
	    #endif

    	if (!(hwa[0]==0 && hwa[1]==0 && hwa[2]==0 && hwa[3]==0 && hwa[4]==0 && hwa[5]==0))
	    {
		    query = calloc(strlen(rowstatus)+25,sizeof(char));
		    sprintf(query,rowstatus,port,hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
			#ifdef debug
		    printf("query:  %s\n",query);
		    #endif
		    tmpquery = doset(ip,query,createAndGo);
		    if (tmpquery) free(tmpquery); else exit_w_error (EXIT_FAILURE);
		    free(query);
	    }

    } else {
	    tmpquery = doportset(ip,"iso.3.6.1.2.1.2.2.1.7.%d",port,enablePort);
    	if (tmpquery) free(tmpquery); else exit_w_error (EXIT_FAILURE);
    }
}

void disable(char *ip, int port, char *mac){
    unsigned char *hwa = NULL;
    char *tmpquery;
    char *rowstatus = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d.%i.%i.%i.%i.%i.%i";
    char *query;
    char *destroy = "6";
    char *disablePort = "2";
	int dodec = 0;
	int adminstate = 0;


	#ifdef debug
    printf("entering disable part\n");
    #endif
    if (mac)
    {
	    hwa = getmacfromchar_ng(mac);
		#ifdef debug
		printf ("eth hw address: %02x:%02x:%02x:%02x:%02x:%02x\n", hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
		#endif


		adminstate = getadminstatus(ip,port);

		if (adminstate)
	    {
			//if the port is enabled disable it to prevent conditions
			disable(ip,port,NULL);
	    }
		if (getmaxmacs(ip,port) > 1)
	    {
			//remember to dec the max macs
			dodec = 1;
	    } else {
			//we dont call disable if we want to learn the 0 mac so no check needed 
			adminstate = 0;
		}

		if (!(hwa[0]==0 && hwa[1]==0 && hwa[2]==0 && hwa[3]==0 && hwa[4]==0 && hwa[5]==0))
		{
			#ifdef debug
			printf("mac != Null Mac try to forget mac\n");
			#endif
			query = calloc(strlen(rowstatus)+25,sizeof(char));
			sprintf(query,rowstatus,port,hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
			#ifdef debug
			printf("query:  %s\n",query);
			#endif
			tmpquery = doset(ip,query,destroy);
			if (tmpquery) free(tmpquery); else exit_w_error(EXIT_FAILURE);
			free(query);
		}
		if (dodec) decmaxmacs(ip,port);

		if (adminstate)
		{
			//port was enabled so enable it again
			enable(ip,port,NULL);
		}

    } else {
	    tmpquery = doportset(ip,"iso.3.6.1.2.1.2.2.1.7.%d",port,disablePort);
	    if (tmpquery) free(tmpquery) ; else exit_w_error (EXIT_FAILURE);
    }
}

void dumpswitchport(char *ip, int port,int maconly) {
	char *tmpresult;

	const char* namequery = "system.sysName.0";
	char *macquery = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d";

	char  *query, *myresult;
	unsigned char *hwa;
	int i;
	char *results[MAXDUMPQUERRYLENGTH];
	t_query_a_entry entry;

	query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
	myresult = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));

    strcpy(query,namequery);
    tmpresult = doquery(ip,query);
    printf("Switch: %s (%s) Port: %d\n",tmpresult,ip,port);
    free(tmpresult);

    i = 0;
    if (!maconly)
    {
	    entry = s_queries[i];
	    while (entry.name!=NULL)
	    {
		    sprintf(query,entry.oid,port);
		    tmpresult = doportquery(ip,query,port);
		    if (tmpresult)
		    {
			    switch ((int)entry.val_typ) {
				    case qtype_string:
					    printf("%s \t\t %s\n",entry.name,tmpresult);
					    break;
				    case qtype_voipvlan:
                    	if (!strcmp(tmpresult,"602"))  strcpy(tmpresult,"on");
                    	if (!strcmp(tmpresult,"4096")) strcpy(tmpresult,"off");
					    printf("%s \t\t %s\n",entry.name,tmpresult);
					    break;
				    case qtype_int:
					    printf("%s \t\t %d\n",entry.name,atoi(tmpresult));
					    break;
				    case qtype_typ:
					    if (entry.values[atoi(tmpresult)] != NULL)
					    {
						    printf("%s \t\t %s\n",entry.name,entry.values[atoi(tmpresult)]);
					    } else printf("Error please redefine arrays (%s) wanted typ %d\n",entry.values[atoi(tmpresult)],atoi(tmpresult));
					    break;
				    case qtype_macaddr:
					    hwa = getmacfromchar_ng(tmpresult);
					    printf ("%s: \t\t\t %02x:%02x:%02x:%02x:%02x:%02x\n",entry.name, hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
					    free(hwa);
					    break;
				    default:
					    printf("Error please redefine arrays");
					    break;
		    	}
		    }
		    i++;
		    entry = s_queries[i];
	    }
    }
    free(myresult);
    free(query);

    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
    sprintf(query,macquery,port);
    dowalkquery(ip,query,results);
    i = 0;
    myresult = results[i];
    while (myresult != NULL){
	    hwa = getmacfromoid(myresult);
	    printf("Mac Address %d : \t\t %02x:%02x:%02x:%02x:%02x:%02x\n", i+1, hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
	    free(myresult);
	    free(hwa);
	    i++;
	    myresult = results[i];
    }
    free(query);
}

void dumpswitch(char *ip, int maconly){
    int i;
    for (i=1;i<=24;i++){
	    printf("\n");
	    dumpswitchport(ip,i,maconly);
	    printf("\n\n");
    }
}

void dumpall(int maconly){
    int i = 0;
    char *tmp;
    tmp = calloc(255,sizeof(char));
    while ( switches[i] != NULL)
    {
	    tmp = (char*)switches[i];
	    dumpswitch(tmp,maconly);
	    i++;
    }
    free(tmp);
}

int findmac(char *mac,char **ip, int *port, char **name){
    int x,y,i = 0;
    char *tmp;
    const char* namequery = "enterprises.9.2.2.1.1.28.%d";
    char *macquery = "iso.3.6.1.4.1.9.9.315.1.2.2.1.4.%d";

    char  *query, *myresult,*tmpresult;
    unsigned char *mymac, *hwa;
    char *results[MAXDUMPQUERRYLENGTH];
    int found = FALSE;

    mymac = getmacfromchar_ng(mac);

	#ifdef debug
    printf("entering search mac part\n");
    printf("need to find Mac Address at \t %02x:%02x:%02x:%02x:%02x:%02x\n",
		mymac[0],mymac[1],mymac[2],mymac[3],mymac[4],mymac[5]);
    #endif
    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
    myresult = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));

    i = 0;
    while ( switches[i] != NULL && !found)
    {
	    tmp = (char*)switches[i];
	    for (x=1;x<=24;x++){

		    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
		    sprintf(query,macquery,x);
		    dowalkquery(tmp,query,results);
		    y = 0;
		    myresult = results[y];
		    while (myresult != NULL){
			    hwa = getmacfromoid(myresult);
				#ifdef debug
			    printf("Mac Address at \t%s \t%i \t %02x:%02x:%02x:%02x:%02x:%02x\n", tmp, x,
						hwa[0],hwa[1],hwa[2],hwa[3],hwa[4],hwa[5]);
			    #endif
			    if (hwa[5] == mymac[5] && hwa[4] == mymac[4] &&
			    	hwa[3] == mymac[3] && hwa[2] == mymac[2] &&
			    	hwa[1] == mymac[1] && hwa[0] == mymac[0]) {
				    found = 1;
					*ip = strdup(switches[i]);
					*port = x;
                    free(query);
                    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
                    sprintf(query,namequery,x);
                    tmpresult = doquery(tmp,query);
					#ifdef debug
                    printf("Switch: %s (%s) Port: %d\n",tmpresult,*ip,*port);
                    #endif
                    *name = strdup(tmpresult);
                    free(tmpresult);
                }
    			free(myresult);
			    free(hwa);
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

int findroom(char *room,char **ip, int *port, char **name){
    int x,i = 0;
    char *tmp;
    const char* namequery = "enterprises.9.2.2.1.1.28.%d";
    char  * myroom = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));

    char  *query, *tmpresult;
    int found = FALSE;

    sprintf(myroom,"\"%s\"",room);
	#ifdef debug
    printf("entering search room part\n");
    printf("need to find room %s\n", myroom);
    #endif

    i = 0;
    while ( switches[i] != NULL && !found)
    {
	    tmp = (char*)switches[i];
	    for (x=1;x<=24;x++){
            query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
            sprintf(query,namequery,x);
            tmpresult = doquery(tmp,query);
            *ip = strdup(switches[i]);
            *port = x;
			#ifdef debug
            	printf("Switch: %s (%s) Port: %d\n",tmpresult,*ip,*port);
            #endif
            if (!strcmp(tmpresult,myroom)) found=1;
			*name = tmpresult;
		    free(query);
		    if (found) break;
		    free(tmpresult);
	    }
	    i++;
    }
    free(myroom);
    return found;
}

int setvalue(char *ip, int port, char *moid,char *value){
    int x,i = 0;
    char *tmp;

    char  *query, *myresult,*tmpresult;
    int found = FALSE;

	#ifdef debug
    printf("entering setvalue\n");
    printf("oid %s value %s\n", moid,value);
    #endif

    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
    myresult = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));

    i = 0;
    while ( switches[i] != NULL && !found)
    {
	    tmp = (char*)switches[i];
	    if (ip!=NULL) tmp = strdup(ip);
	    for (x=1;x<=24;x++){

		    if (port>0) x=port;

		    query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
		    strcpy(query,moid);
		    strcat(query,".%d");
			#ifdef debug
		    printf("ip [%s] port[%d] query [%s] value [%s]\n", tmp,x,query,value);
		    #endif

		    tmpresult = doportset(tmp,query,x,value);
		    if (tmpresult) free(tmpresult);
			    else printf("Error on Setting ip [%s] port[%d] query [%s] value [%s]\n", tmp,x,query,value);

		    free(query);
		    if (port>0) return 1;
	    }
    	if (ip!=NULL) return 1;
	    i++;
    }
	return 0;
}

void setvoicevlan(char *ip, int port, char *value) {
    char *voicev_q = "enterprises.9.9.87.1.4.1.1.37.0.%d";
    char *query;
    char *tmpresult;

    query = calloc(strlen(voicev_q)+10,sizeof(char));
    sprintf(query,voicev_q,port);
    tmpresult = doset(ip,query,value);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    free(query);
}

void setvlan(char *ip, int port, char *value) {
    char *voicev_q = "enterprises.9.9.68.1.2.2.1.2.%d";
    char *query;
    char *tmpresult;

    query = calloc(strlen(voicev_q)+10,sizeof(char));
    sprintf(query,voicev_q,port);
    tmpresult = doset(ip,query,value);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    free(query);
}

void dodisable(char *ip, int port, char *mac){
  if (wh8mode) {
    char *q = "%d";
    char *tmp;
    tmp = calloc(10,sizeof(char));
    sprintf(tmp,q,wh8_disable_vlan);
    setvlan(ip,port,tmp);
  } else disable(ip,port,mac);
}

void doenable(char *ip, int port, char *mac){
  if (wh8mode) {
    char *q = "%d";
    char *tmp;
    tmp = calloc(10,sizeof(char));
    sprintf(tmp,q,wh8_enable_vlan);
    setvlan(ip,port,tmp);
  } else enable(ip,port,mac);
}

void reenable(char *ip, int port) {
    char *admin_q = "interfaces.2.1.7.%d";
    char *ports_q = "enterprises.9.9.315.1.2.1.1.1.%d";

    char *query, *query2;
    char *tmpresult,*tmpresult2;
    char *value_on = "1";
    char *value_off = "2";

    query = calloc(strlen(admin_q)+10,sizeof(char));
    sprintf(query,admin_q,port);
    tmpresult = doset(ip,query,value_off);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);

    query2 = calloc(strlen(ports_q)+10,sizeof(char));
    sprintf(query2,ports_q,port);
    tmpresult2 = doset(ip,query2,value_off);
    if (tmpresult2) free(tmpresult2); else exit_w_error(EXIT_FAILURE);

    tmpresult2 = doset(ip,query2,value_on);
    if (tmpresult2) free(tmpresult2); else exit_w_error(EXIT_FAILURE);
    free(query2);

    tmpresult = doset(ip,query,value_on);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    free(query);
}

void clearmac(char *ip, int port) {
    char *clear_q = "enterprises.9.9.315.1.2.1.1.11.%d";

    char *query;
    char *tmpresult;
    char *value_on = "1";

    query = calloc(strlen(clear_q)+10,sizeof(char));
    sprintf(query,clear_q,port);
    tmpresult = doset(ip,query,value_on);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    free(query);
}

void writeconfig(char *ip) {
    char *save_from = "enterprises.9.9.96.1.1.1.1.3.1";
    char *save_to = "enterprises.9.9.96.1.1.1.1.4.1";
    char *save_do = "enterprises.9.9.96.1.1.1.1.14.1";

    char *value_from = "4";
    char *value_to = "3";
    char *value_do = "1";
    char *value_destroy = "6";
    char *tmpresult;

    tmpresult = doset(ip,save_do,value_destroy);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    tmpresult = doset(ip,save_from,value_from);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    tmpresult = doset(ip,save_to,value_to);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
    tmpresult = doset(ip,save_do,value_do);
    if (tmpresult) free(tmpresult); else exit_w_error(EXIT_FAILURE);
}

void writeconfigall(){
    int i = 0;
    char *tmp;
    tmp = calloc(255,sizeof(char));
    while ( switches[i] != NULL)
    {
	    tmp = (char*)switches[i];
    	writeconfig(tmp);
	    i++;
    }
    free(tmp);
}

//ronny
void write_db(){
    int x,i = 0;

    char *tmp,*tmp2;
    const char* namequery = "enterprises.9.2.2.1.1.28.%d";
    char  *query, *tmpresult;
    int port;
    char *ip;
    int shift;
	char * pch; 
    FILE *db;
    
    i = 0;
    db = fopen("db.txt","w");
    if(db == NULL) {
	printf("Can not open file!\n");
    }
    else
    {
	while ( switches[i] != NULL)
	{
	    tmp = (char*)switches[i];
	    for (x=1;x<=24;x++){
        	query = calloc(MAXDUMPQUERRYLENGTH,sizeof(char));
        	sprintf(query,namequery,x);
        	tmpresult = doquery(tmp,query);
        	ip = strdup(switches[i]);
        	port = x;

		//string formatieren
		tmp2 = strchr(tmpresult,(int)'"')+1;
		shift=0;
		while(tmp2[shift] != '"') shift++;
		tmp2[shift]='\0';
		if(tmp2[0]!='\0') {
			pch=strchr(tmp2,'.'); 
			if (pch!=NULL) { strncpy(pch,"-",1);}; //replace first . with - to transform A315.1 -> A315-1 for example
		  fprintf(db,"%s %s %d\n",tmp2,ip,port);
		}
		free(query);
		free(tmpresult);
	    }
	    i++;
	}
    fclose(db);
    }
}

int main (int argc, char *argv[]) {
    char *ip=NULL, *port=NULL, *mac=NULL, *status=NULL, *moid= NULL, *value= NULL;
    char option;
    int  portNum;
    char *room=NULL;
    #ifdef passwdfile
    char *configfile=NULL;
    int freeconfig= 0;
    FILE *filehandle;
    #endif


    state_t mode = UNKOWN;
    dumpstate_t dmode = DUMPPORT;
    pmode_t newState = UNKOWN;
    int dodumpall = FALSE;
    char *tmp,*tmp2;

    opterr = 0;
    portNum = -1;

    while ( (option = getopt( argc, argv, "fi:p:m:r:s:a:o:v:c:" )) != EOF) {
	    switch (tolower(option)) {
		    case 'c':
                #ifdef passwdfile
                    configfile = optarg;
                    #ifdef debugmode
                    printf("Config File Found: %s\n",configfile);
                    #endif
                #else
                  usage( argv[0],"Config file not supported by this version");
                #endif
                break;
		    case 'i':
			    ip = optarg;
				#ifdef debugmode
			    printf("Backbone Switch %s found.\n",ip);
			    #endif
			    break;
		    case 'p':
				port=optarg;
			    portNum=atoi(port);
				#ifdef debugmode
			    printf("Port %d found.\n",portNum);
			    #endif
			    break;
		    case 'f':
			    dodumpall = 1;
			    #ifdef debugmode
			    printf("Mode Dumpall found.\n");
			    #endif
			    break;
		    case 'm':
			    status=optarg;
			    switch (tolower(status[0])) {
				    case 'd':
					    mode = DUMP;
					    #ifdef debugmode
					    printf("Mode %s found.\n","dump");
					    #endif
	                    break;
                    case 's':
    	                mode = SET;
    	                #ifdef debugmode
        	            printf("Mode %s found.\n","set");
        	            #endif
            	        break;
                    case 'f':
                	    mode = FIND;
                	    #ifdef debugmode
	                    printf("Mode %s found.\n","find");
	                    #endif
    	                break;
                    case 'v':
	                    mode = VALUE;
	                    #ifdef debugmode
    	                printf("Mode %s found.\n","value");
    	                #endif
        	            break;
					case 'w':
	                    mode = DOWRITE;
	                    #ifdef debugmode
	                    printf("Mode %s found.\n","write");
	                    #endif
	                    break;

					//ronny
					case 'x':
						mode = WRITEDB;
						#ifdef debugmode
						printf("Mode %s found.\n","writedb");
						#endif
						break;

					case 'i':
	                    mode = INFO;
	                    #ifdef debugmode
	                    printf("Mode %s found.\n","info");
	                    #endif
	                    break;
                    default:
	                    usage( argv[0],NULL);
                }
			    break;
		    case 'r':
			    room = optarg;
			    #ifdef debugmode
			    printf("Room %s found.\n",room);
			    #endif
				break;
		    case 's':
			    status=optarg;
			    if (mode == SET){
			    	#ifdef debugmode
				    printf("Checking Set Params\n");
				    #endif
				    switch (tolower(status[0])) {
                        case 'n':
                        case 'l':
                        	#ifdef debugmode
	                        printf("NewState %s found.\n","LEARN");
	                        #endif
	                        newState = LEARN;
	                        break;
                        case 'f':
                        	#ifdef debugmode
    	                    printf("NewState %s found.\n","FORGET");
    	                    #endif
	                        newState = FORGET;
    	                    break;
	                    case 'y':
	                	//we want the normal enable!
	                	wh8mode = 0;
	                    	#ifdef debugmode
	                        printf("NewState %s found.\n","ENABLE - WH8 MODE OVERRIDE");
	                        #endif
	                    case 'e':
	                    	#ifdef debugmode
	                        printf("NewState %s found.\n","ENABLE");
	                        #endif
	                        newState = ENABLE;
	                        break;
                        case 'x':
                    		//we want the normal disable command!
	                	wh8mode = 0;
	                    	#ifdef debugmode
	                        printf("NewState %s found.\n","DISABLE - WH8 MODE OVERRIDE");
	                        #endif
                        case 'd':
                            #ifdef debugmode
    	                    printf("NewState %s found.\n","DISABLE");
    	                    #endif
	                        newState = DISABLE;
                	        break;
	                    case 'v':
	                    	#ifdef debugmode
	                        printf("NewState %s found.\n","VOICE");
	                        #endif
	                        newState = VOICE;
                        	break;
	                    case 's':
	                    	#ifdef debugmode
	                        printf("NewState %s found.\n","SVLAN");
	                        #endif
	                        newState = VLAN;
                        	break;
    	                case 'r':
        	                if (strlen(status) < 3) usage( argv[0], NULL);
            	            switch (tolower(status[2])) {
		                        case 'e':
		                        	#ifdef debugmode
        			                printf("NewState %s found.\n","REENABLE");
        			                #endif
			                        newState = REENABLE;
            			            break;
                        		default:
			                        usage( argv[0], NULL);
            		        }
						    break;
					    case 'c':
						    newState = CLEARMACS;
						    break;
					    default:
						    usage( argv[0],NULL);
					}
				    break;
			    }

			    if (mode == DUMP)
			    {
			    	#ifdef debugmode
			    	printf("Checking Dump Params\n");
			    	#endif
				    switch (tolower(status[0])) {
					    case 'd':
					    	#ifdef debugmode
						    printf("NewdumpState  %s found.\n","DUMPMACS");
						    #endif
    						dmode = DUMPMACS;
						    break;
					    default:
						    usage( argv[0],NULL);
					}
				    break;
			    }
			    break;
		    case 'a':
			    mac = optarg;
			    #ifdef debugmode
			    printf("mac %s found.\n",mac);
			    #endif
		    	break;
			case 'o':
			    moid = optarg;
			    #ifdef debugmode
			    printf("oid %s found.\n",moid);
			    #endif
			    break;
    		case 'v':
			    value = optarg;
			    #ifdef debugmode
			    printf("value %s found.\n",value);
			    #endif
			    break;
		    default:
		    	usage(argv[0],NULL);
				break;
	    }
    }

    #ifdef passwdfile
    if (!configfile) {
        freeconfig = 1;
    	configfile = calloc(strlen(defaultfilename),sizeof(char));
    	strcpy(configfile,defaultfilename);
    }
    filehandle = fopen(configfile,"r");
    community = calloc(255,sizeof(char));
    if (filehandle <= 0) {
		sprintf(community,"\nError opening config file: %s - %s\n",configfile,strerror(errno));
    	usage(argv[0],community);
    };
    fscanf(filehandle,"%254s", community);
        #ifdef debug
        printf("community: %s\n",community);
        #endif
    #endif

	#ifdef do_setuid
	if (getuid()==0)
		setuid(do_setuid);
	#ifdef debug
	printf("setuid: %d\n",getuid());
	#endif
	#endif

    //lets start
    switch (mode) {
	    case DUMP: {
	    	if (!ip)
                if ((mac != NULL)  || (room != NULL))
                {
                    dmode = DUMPPORT;
                    if (mac) {
                        if (findmac(mac,&tmp,&portNum,&tmp2) ==1) {
                            printf("Mac found at  -i %s -p %i  \tname: %s\n",tmp,portNum,tmp2);
                            printf("Setting new ip (%s) and port (%i)\n",tmp,portNum);
                            ip = tmp;
                            free(tmp2);
                        } else {
                              printf("Mac not found \n");
                              exit(1);
                        }
                    } else {
                        if (findroom(room,&tmp,&portNum,&tmp2) ==1) {
                            printf("Room found at  -i %s -p %i  \tname: %s\n",tmp,portNum,tmp2);
                            printf("Setting new ip (%s) and port (%i)\n",tmp,portNum);
                            ip = tmp;
                            free(tmp2);
                        } else {
                            printf("Room not found \n");
                            exit(1);
                        }
                    }
                }
		    switch (dmode)
		    {
			    case DUMPPORT:
				    if (dodumpall) dumpall(0); else
				    {  	if (!ip)
						    usage(argv[0],"ip missing\n");
					    if (portNum ==-1)  dumpswitch(ip,0);
						    else dumpswitchport(ip,portNum,0);
				    }
				    break;
			    case DUMPMACS:
                    if (dodumpall) dumpall(1); else
                    { 	if (!ip)
		                    usage(argv[0],"ip missing\n");
                    	if (portNum ==-1)  dumpswitch(ip,1);
                    		else dumpswitchport(ip,portNum,1);
                    }
            }
    		break;
    	}
	    case DOWRITE:
             if (dodumpall) writeconfigall(); else
             {  	if (!ip)
                		usage(argv[0],"ip missing\n");
                	writeconfig(ip);
             }
             break;

		 //ronny
	    case WRITEDB:
			write_db();
			printf("Wrote Database...\n"); 
			break;

		case INFO:
	    	 printf("Usecase: Cisco Switch Administration (2950/3950/xxxx)\n");
	    	 printf("Feel free to send bug reports\n\nAuthor:	%s\n",AUTHOR);
	    	 exit(0);
             break;
        case VALUE:
        	if (!moid)
                usage(argv[0],"oid missing\n");
            if (value == NULL)
                usage(argv[0],"value missing\n");

            setvalue(ip,portNum,moid,value);
            break;
    	case FIND:
		    if ((mac == NULL) && (room == NULL))
			    usage(argv[0],"mac or room missing\n");
		    if (mac) {
                if (findmac(mac,&tmp,&portNum,&tmp2) ==1) {
                    printf("Mac found at\t-i %s -p %i\tname: %s\n",tmp,portNum,tmp2);
                    free(tmp);
                    free(tmp2);
                } else {
                	 printf("Mac not found \n");
                	 return 1;
                }
            } else {
                if (findroom(room,&tmp,&portNum,&tmp2) ==1) {
                    printf("Room found at\t-i %s -p %i\tname: %s\n",tmp,portNum,tmp2);
                    free(tmp);
                    free(tmp2);
                } else	{
                  	printf("Room not found \n");
                  	return 1;
                }
            }
		    break;
	    case SET: {
	    	if ((!ip) && (room)) {
                if (findroom(room,&tmp,&portNum,&tmp2) ==1) {
                    printf("Room found at  -i %s -p %i  \tname: %s\n",tmp,portNum,tmp2);
                    printf("Setting new ip (%s) and port (%i)\n",tmp,portNum);
                    ip = tmp;
                    port = (char*)&portNum;
                    free(tmp2);
                } else {
                    printf("Room not found \n");
                    exit(1);
                }
            };
		    switch (newState) {
			    case ENABLE:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    doenable(ip,portNum,mac);
                    break;
                case DISABLE:
                    if (!ip ||!port)
                    {
                        if (mac == NULL)
                            usage(argv[0],"mac missing\n");
                        if (findmac(mac,&tmp,&portNum,&tmp2) ==1) {
                            printf("Mac found at  -i %s -p %i  \tname: %s\n",tmp,portNum,tmp2);
                            printf("Setting new ip (%s) and port (%i)\n",tmp,portNum);
                            dodisable(tmp,portNum,mac);
                            free(tmp);
                            free(tmp2);
                        } else {
                            printf("Mac not found \n");
                            exit(1);
                        }
                    } else dodisable(ip,portNum,mac);
                    break;
                case FORGET:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    if (mac == NULL)
					{
                       mac = nullmac;
                    }
                    disable(ip,portNum,mac);
                    break;
                case LEARN:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    if (	getmacslearned(ip,portNum)==0 &&
                        	getmaxmacs(ip,portNum)==1 &&
                        	!getadminstatus(ip,portNum) ) {
                        //port was not used
                        enable(ip,portNum,NULL);
                    } else {
                        //port was used
						if (mac)
						{
							unsigned char *hwa = NULL;
							hwa = getmacfromchar_ng(mac);
							if (!(hwa[0]==0 && hwa[1]==0 && hwa[2]==0 && hwa[3]==0 && hwa[4]==0 && hwa[5]==0))
							{
								//remove old mac given
								disable(ip,portNum,mac);
							}
							
                    		if (	getmacslearned(ip,portNum)==0 &&
                        			getmaxmacs(ip,portNum)==1 &&
                        			!getadminstatus(ip,portNum) ) {
                        	   //it was the last mac -> normal enable will do as port is clean
								enable(ip,portNum,NULL);
							} else {
							   //that was a port that is not clean so here we inc max macs and enable it
							   //the enable dont inc max macs
                              incmaxmacs(ip,portNum);
                              enable(ip,portNum,NULL);
							}
						} else  {
						  incmaxmacs(ip,portNum);
						  enable(ip,portNum,NULL);
						}
                    }
                    break;
                case REENABLE:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    reenable(ip,portNum);
                    break;
                case CLEARMACS:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    clearmac(ip,portNum);
                    break;
                case VOICE:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    if (value==NULL)
                        usage(argv[0],"value missing\n");
                    if (!strcmp(value,"on"))  strcpy(value,"602");
                    if (!strcmp(value,"off")) strcpy(value,"4096");
                    setvoicevlan(ip,portNum,value);
                    break;
                case VLAN:
                    if (!ip)
                        usage(argv[0],"ip missing\n");
                    if (!port)
                        usage(argv[0],"port missing\n");
                    if (value==NULL)
                        usage(argv[0],"value missing\n");
                    setvlan(ip,portNum,value);
                    break;
        		default:
            		usage(argv[0],NULL);
            		break;
    		}
    		break;
    	}
    	default:
    		usage(argv[0],NULL);
    		break;
    }

    #ifdef passwdfile
    if (freeconfig) free(configfile);
    free(community);
    #endif
    exit_w_error (EXIT_SUCCESS);
	return 0;
}

