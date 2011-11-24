/***************************************************************************
 *   NetGuard FileSharing Detection Module                                 *
 *                                                                         *
 *   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
 *                                                                         *
 *   This program module is released under        .                        *
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
 *                                                                         *
 *   Detection taken from   http://www.ipp2p.org/                          *
 *                                                                         *
 ***************************************************************************/

#ifndef __IPT_IPP2P_H
#define __IPT_IPP2P_H
#define IPP2P_VERSION "0.8.0"

struct ipt_p2p_info {
    int cmd;
    int debug;
};


#endif //__IPT_IPP2P_H

#define SHORT_HAND_IPP2P	1 /* --ipp2p switch*/
//#define SHORT_HAND_DATA		4 /* --ipp2p-data switch*/
#define SHORT_HAND_NONE		5 /* no short hand*/

#define IPP2P_EDK		2
#define IPP2P_DATA_KAZAA	8
#define IPP2P_DATA_EDK		16
#define IPP2P_DATA_DC		32
#define IPP2P_DC		64
#define IPP2P_DATA_GNU		128
#define IPP2P_GNU		256
#define IPP2P_KAZAA		512
#define IPP2P_BIT		1024
#define IPP2P_APPLE		2048
#define IPP2P_SOUL		4096
#define IPP2P_WINMX		8192
#define IPP2P_ARES		16384

