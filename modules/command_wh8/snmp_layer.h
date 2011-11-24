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

#ifndef HUB_SNMP_H
#define HUB_SNMP_H

#ifdef __cplusplus
extern "C" {
#endif

struct snmp_session *session_open(const char *host, const char *community);
int session_close(struct snmp_session *ss);

char *session_query(struct snmp_session *ss, struct snmp_pdu *pdu);
char *session_set( struct snmp_session *ss, const char *name, const char *value );

struct snmp_pdu *session_create_pdu(int type);
void session_add_null_var(struct snmp_pdu *pdu, const char *name);
struct snmp_pdu *session_free_pdu(struct snmp_pdu *pdu);

#ifdef __cplusplus
}
#endif

#endif /* HUB_SNMP_H */
