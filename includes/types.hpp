/***************************************************************************
 *   NetGuard Global Type Defs and Templates                               *
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


#ifndef NETGUARD_TYPESHPP
#define NETGUARD_TYPESHPP

#include "defines.h"
#include "tools.h"

#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <iostream>
#include <sstream>
#include <deque>
#include <ext/hash_map>
#include <map>
#include <set>
#include <values.h>

using namespace std;
using namespace __gnu_cxx;


//-----------------------------------------------------------
// StrT:    Type of string to be constructed
//          Must have char* ctor.
// str:     String to be parsed.
// delim:   Pointer to delimiter.
// results: Vector of StrT for strings between delimiter.
// empties: Include empty strings in the results. 
//-----------------------------------------------------------
template<typename StrT>
int split(const char* str, const char* delim, std::vector<StrT>& results, bool empties = true)
{
	char* pstr = const_cast<char*>(str);
	char* r = NULL;
	r = strstr(pstr, delim);
	int dlen = strlen(delim);
	while( r != NULL )
	{
		char* cp = new char[(r-pstr)+1];
		memcpy(cp, pstr, (r-pstr));
		cp[(r-pstr)] = '\0';
		if( strlen(cp) > 0 || empties )
		{
			StrT s(cp);
			results.push_back(s);
		}
		delete[] cp;
		pstr = r + dlen;
		r = strstr(pstr, delim);
	}
	if( strlen(pstr) > 0 || empties )
	{
		results.push_back(StrT(pstr));
	}
	return results.size();
}

template <class ForwardIterator>
void map_delete(ForwardIterator first, ForwardIterator last) {
	while (first != last)
		delete (*first++).second;
}


//user_security module information to use getdata(sec_data_idx *data)
//user security index data
struct sec_data_idx
{
	mac_addr		hw_addr;
    unsigned int	vlan_id;
};


struct string_hash
{
		size_t operator()( const std::string& x ) const
		{
				return hash< const char* >()( x.c_str() );
		}
};


template<class T>
std::string any2string(T i) {
	std::ostringstream buffer;
	buffer << i;
	return buffer.str();
}


#endif




