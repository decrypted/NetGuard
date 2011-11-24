#***************************************************************************
#*   NetGuard Makefile                                                     *
#*                                                                         *
#*   Copyright (c) 2011 Daniel Rudolph <daniel at net-guard net>           *
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
#*                                                                         *
#*************************************************************************** 

NGDIR ?= ../
include $(NGDIR)/mk/Makeconf

COMPILEHGEN = ${NGDIR}scripts/mkcompile_h compile.h  "netguard" "$(UTS_MACHINE)" "$(CONFIG_SMP)" "$(CC) $(CFLAGS)" "$(STATIC_LIB)"

all:	netguard

include $(NGDIR)/mk/MakeAutoDepHeader


#also build compile h when module compiles not only if deps get created
compile.h::
		@$(SHELL) ${COMPILEHGEN}

ifeq "$(STATIC_LIB)" "1"

$(NGDIR)shared/libnetguard.a: 
	@echo -e $(EMPHSTART)"Building libnetguard.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/shared

netguard: $(NGDIR)shared/libnetguard.a compile.h  $(AUTODEP_CFiles:.c=.o) $(AUTODEP_CPPFiles:.cpp=.o) 
	@echo -e $(EMPHSTART)"Building $@"$(EMPHSTOP)
	$(CPPL) -o $@ $(AUTODEP_CFiles_Objects) $(AUTODEP_CPPFiles_Objects) $(NGDIR)shared/libnetguard.a -lrt -ldl -L$(NGDIR) 
	@echo -e $(EMPHSTART)"-->Softlink $@ to $(call absfilename,$(NGDIR)) "$(EMPHSTOP)
	@$(call INSTALLFILE,$@,$(NGDIR)) 
else

$(NGDIR)shared/libnetguard.so.0:
	@echo -e $(EMPHSTART)"Building libnetguard.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/shared

netguard: $(NGDIR)shared/libnetguard.so.0 compile.h  $(AUTODEP_CFiles:.c=.o) $(AUTODEP_CPPFiles:.cpp=.o) 
	@echo -e $(EMPHSTART)"Building $@"$(EMPHSTOP)
	$(CPPL) -o $@ $(AUTODEP_CFiles_Objects) $(AUTODEP_CPPFiles_Objects) -lrt -ldl -L$(NGDIR) -lnetguard
	@echo -e $(EMPHSTART)"-->Softlink $@ to $(call absfilename,$(NGDIR)) "$(EMPHSTOP)
	@$(call INSTALLFILE,$@,$(NGDIR)) 
endif

clean:
	@echo -e $(EMPHSTART)"Cleaning up netguard.."$(EMPHSTOP)
	${RM} *.o *.bak *.d compile.h netguard $(NGDIR)netguard

include $(NGDIR)/mk/MakeAutoDepFooter
