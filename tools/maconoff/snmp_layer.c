/***************************************************************************
 *   MacOnOff                                                              *
 *                                                                         *
 *   Copyright (c) 2003-2011 Daniel Rudolph <daniel at net-guard net>      *
 *                                          Gregor Jasny                   *
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

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "snmp_layer.h"

struct snmp_session *session_open(const char *chost, const char *ccommunity) {
  struct snmp_session *ss, session;

  char *host, *community;

  host=calloc(strlen(chost)+1, sizeof(char));
  strcpy(host, chost);

  community=calloc(strlen(ccommunity)+1, sizeof(char));
  strcpy(community, ccommunity);

  /* Initialize the SNMP library */
  init_snmp("snmpapp");

  /* Initialize the session */
  snmp_sess_init( &session );
  session.version = SNMP_VERSION_2c;
  session.peername = host;
  session.community = (u_char*)community;
  session.community_len = strlen(community);                                                                                                  

  netsnmp_ds_set_int( NETSNMP_DS_LIBRARY_ID,
		NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
		NETSNMP_OID_OUTPUT_UCD );
//                NETSNMP_OID_OUTPUT_NONE);
  SOCK_STARTUP

  /* open the SNMP session */
  ss = snmp_open(&session);
  if (ss == NULL) {
    perror("Cant snmp_open");
    exit(-1);
  }

  netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT,
                                                      NETSNMP_OID_OUTPUT_NUMERIC);


  return ss;
}

int session_close(struct snmp_session *ss) {
  int r = snmp_close(ss);
  SOCK_CLEANUP
  return r;
}

struct snmp_pdu *session_create_pdu(int type){
  struct snmp_pdu *pdu;

  /* create PDU for request */
  pdu = snmp_pdu_create(type);  
  return pdu;
}

void session_add_null_var(struct snmp_pdu *pdu, const char *name) {
  oid anOID[MAX_OID_LEN+1];
  size_t anOID_len = MAX_OID_LEN;

  get_node(name, anOID, &anOID_len);
  snmp_add_null_var(pdu, anOID, anOID_len);
}

struct snmp_pdu *session_free_pdu(struct snmp_pdu *pdu){
  //TODO memory leak ?
  //snmp_free_pdu(pdu);
  return NULL;
}

char *session_query(struct snmp_session *ss, struct snmp_pdu *pdu) {

  struct snmp_pdu *response;
  struct variable_list *vars;
  int status;
  char buf[SPRINT_MAX_LEN];
  char *rbuffer=NULL;
    
  /* Send the Request */
  status = snmp_synch_response(ss, pdu, &response);

  /* Process the response */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR )
 {
    /* Success: Print the results */
    /* for (vars=response->variables; vars; vars=vars->next_variable) { */
    vars=response->variables;
    
    if (vars!=NULL && vars->type <ASN_LONG_LEN) {
      if (vars->type == ASN_INTEGER) {
         sprintf(buf,"%ld",*vars->val.integer);
		 rbuffer=malloc(sizeof(char)*(strlen(buf)+1));
     	 memset(rbuffer,'\0',strlen(buf)+1);
         strncpy(rbuffer,buf,strlen(buf));
      } else {
         snprint_variable(buf, sizeof (buf), vars->name, vars->name_length, vars);
         rbuffer=malloc(sizeof(char)*(strlen(buf)+1));
     	 memset(rbuffer,'\0',strlen(buf)+1);
         strncpy(rbuffer,buf,strlen(buf));
	  }
    } else rbuffer = NULL;     

  } else {
    /* Failure: print what went wrong */
    if (status == STAT_SUCCESS)
      fprintf(stderr,"Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
    else
      snmp_sess_perror("snmpget ", ss);
  }

  /* Clean up */
  if (response) snmp_free_pdu(response);

//  printf("Result : %s\n",rbuffer);
  return rbuffer;
}

char *session_set( struct snmp_session *ss,const char *name, const char *value ) {
  struct snmp_pdu *pdu, *response;
  oid anOID[MAX_OID_LEN];
  size_t anOID_len = MAX_OID_LEN;
  struct variable_list *vars;
  int status;
  char buf[SPRINT_MAX_LEN];
  char *rbuffer=NULL;

  /* create PDU for request */
  pdu = snmp_pdu_create(SNMP_MSG_SET);
  get_node(name, anOID, &anOID_len);
  snmp_add_var(pdu, anOID, anOID_len,'i',value);
//  snmp_add_null_var(pdu, anOID, anOID_len);

  /* Send the Request */
  status = snmp_synch_response(ss, pdu, &response);

  /* Process the response */
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {
    /* Success: Print the results */

    /* for (vars=response->variables; vars; vars=vars->next_variable) { */
    vars=response->variables;
	if (vars!=NULL) {
      snprint_variable(buf, sizeof (buf), vars->name, vars->name_length, vars);
      rbuffer=malloc(sizeof(char)*(strlen(buf)+1));
      memset(rbuffer,'\0',strlen(buf)+1);
      strncpy(rbuffer,buf,strlen(buf));
    } else rbuffer = NULL;     

  } else {
    /* Failure: print what went wrong */
    if (status == STAT_SUCCESS)
       fprintf(stderr,"Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
    else
      snmp_sess_perror("snmpset", ss);
  }

  /* Clean up */
  /*  if (pdu) snmp_free_pdu(pdu); */
  if (response) snmp_free_pdu(response);

  return rbuffer;
}

