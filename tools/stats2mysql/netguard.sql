#***************************************************************************
#*   NetGuard Accounting Project Makefile                                  *
#*                                                                         *
#*   Copyright (c) 2011 Ronny Hillmann <ronny at net-guard net>            *
#*                                                                         *
#*                                                                         *
#*   This program is released under a dual license.                        *
#*   GNU General Public License for open source and educational use and    *
#*   the Net-Guard Professional License for commercial use.                *
#*   Details: http://www.net-guard.net/licence                             *
#*                                                                         *
#*   For open source and educational use:                                  *
#*   This program is free software; you can redistribute it and/or modify  *
#*   it under the terms of the GNU General Public License as published by  *
#*   the Free Software Foundation; either version 2 of the License, or     *
#*   (at your option) any later version.                                   *
#*                                                                         *
#*   This program is distributed in the hope that it will be useful,       *
#*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
#*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
#*   GNU General Public License for more details.                          *
#*                                                                         *
#*   You should have received a copy of the GNU General Public License     *
#*   along with this program; if not, write to the                         *
#*   Free Software Foundation, Inc.,                                       *
#*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
#*                                                                         *
#*   For commercal use:                                                    *
#*   visit http://www.net-guard.net for details if you need a commercal    *
#*   license or not. All conditions are listed here:                       *
#*                 http://www.net-guard.net/licence                        *
#*                                                                         *
#*   If you are unsure what licence you can use you should take            *
#*   the Net-Guard Professional License.                                   *
#*                                                                         *
#***************************************************************************
# Generation Time: Oct 31, 2011 at 10:20 PM

# --------------------------------------------------------

#
# Table structure for table `global`
#

CREATE TABLE `global` (
  `ip` varchar(15) NOT NULL default '',
  `mac` varchar(18) NOT NULL default '',
  `last_active` datetime NOT NULL default '0000-00-00 00:00:00',
  `vlan` int(4) NOT NULL default '0',
  PRIMARY KEY  (`ip`)
) TYPE=MyISAM;

# --------------------------------------------------------

#
# Table structure for table `limits`
#

CREATE TABLE `limits` (
  `ip` varchar(15) NOT NULL default '',
  `type` enum('intern','extern') NOT NULL default 'intern',
  `day` bigint(20) NOT NULL default '0',
  `week` bigint(20) NOT NULL default '0',
  `over_all` bigint(20) NOT NULL default '0',
  `max_week` bigint(20) NOT NULL default '0',
  `max_week_date` date NOT NULL default '0000-00-00',
  `max_day` bigint(20) NOT NULL default '0',
  `max_day_date` date NOT NULL default '0000-00-00',
  PRIMARY KEY  (`ip`,`type`)
) TYPE=MyISAM;

# --------------------------------------------------------

#
# Table structure for table `traffic`
#

CREATE TABLE `traffic` (
  `ip` varchar(15) NOT NULL default '',
  `type` enum('intern','extern') NOT NULL default 'intern',
  `day` int(1) unsigned NOT NULL default '0',
  `send_bytes` bigint(20) unsigned NOT NULL default '0',
  `resv_bytes` bigint(20) unsigned NOT NULL default '0',
  `send_pkts` bigint(20) unsigned NOT NULL default '0',
  `resv_pkts` bigint(20) unsigned NOT NULL default '0',
  `send_ipbytes` bigint(20) unsigned NOT NULL default '0',
  `resv_ipbytes` bigint(20) unsigned NOT NULL default '0',
  `send_ippkts` bigint(20) unsigned NOT NULL default '0',
  `resv_ippkts` bigint(20) unsigned NOT NULL default '0',
  `send_tcpipbytes` bigint(20) unsigned NOT NULL default '0',
  `resv_tcpipbytes` bigint(20) unsigned NOT NULL default '0',
  `send_tcpippkts` bigint(20) unsigned NOT NULL default '0',
  `resv_tcpippkts` bigint(20) unsigned NOT NULL default '0',
  `send_udpbytes` bigint(20) unsigned NOT NULL default '0',
  `resv_udpbytes` bigint(20) unsigned NOT NULL default '0',
  `send_udppkts` bigint(20) unsigned NOT NULL default '0',
  `resv_udppkts` bigint(20) unsigned NOT NULL default '0',
  `send_icmpbytes` bigint(20) unsigned NOT NULL default '0',
  `resv_icmpbytes` bigint(20) unsigned NOT NULL default '0',
  `send_icmppkts` bigint(20) unsigned NOT NULL default '0',
  `resv_icmppkts` bigint(20) unsigned NOT NULL default '0',
  `send_arpbytes` bigint(20) unsigned NOT NULL default '0',
  `resv_arpbytes` bigint(20) unsigned NOT NULL default '0',
  `send_arppkts` bigint(20) unsigned NOT NULL default '0',
  `resv_arppkts` bigint(20) unsigned NOT NULL default '0',
  `send_connects` bigint(20) unsigned NOT NULL default '0',
  `resv_connects` bigint(20) unsigned NOT NULL default '0',
  PRIMARY KEY  (`ip`,`type`,`day`)
) TYPE=MyISAM;
