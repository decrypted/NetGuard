#***************************************************************************
#*   NetGuard Accounting Project Makefile                                  *
#*                                                                         *
#*   Copyright (c) 2011       Daniel Rudolph <daniel at net-guard net>     *
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

NGDIR ?= .
NGSSH_USER ?= daniel
NGSSH_HOST ?= 141.30.225.1
NGSSH_PATH ?= /home/netguard/
NGSSH_SOURCEPATH ?= /home/netguard/source
NGSSH_DIR ?= ${NGSSH_USER}@${NGSSH_HOST}:${NGSSH_PATH}
NGSSH_SOURCEDIR ?= ${NGSSH_USER}@${NGSSH_HOST}:${NGSSH_SOURCEPATH}
include $(NGDIR)/mk/Makeconf

ifdef GCC_ERROR
$(error $(GCC_ERROR))
endif
ifdef GCC_WARN
$(warning $(GCC_WARN))
endif

debug::	libnetguard modules netguard tools do_copy dorelease

all:: libnetguard modules netguard tools

stripped:: libnetguard modules netguard strip

clean-release::	clean release
clean-debug::	clean debug

dorelease::
	@$(MAKE) -C $(NGDIR)/tools $@

release:: libnetguard modules netguard tools do_copy dorelease strip_release

install:: release do_remote_copy
clean-install:: clean-release do_remote_copy

install_debug:: debug do_remote_copy
clean-install_debug:: clean-debug do_remote_copy

leak_check: leak_detect
leak_test: leak_detect
leak_detect:: leaktracer debug
	@echo -e $(EMPHSTART)"starting leak detect.."$(EMPHSTOP)
	@echo -e $(EMPHSTART)"!!!!!you have to kill netguard with kill or quit on the messure run!!!!!"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"!!!!!you have to kill netguard with kill or quit on the messure run!!!!!"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"!!!!!you have to kill netguard with kill or quit on the messure run!!!!!"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"!!!!!you have to kill netguard with kill or quit on the messure run!!!!!"$(EMPHSTOP)
	@sleep 5
	@export LD_LIBRARY_PATH=./ && export LEAKTRACE_FILE=ngleak.out && $(NGDIR)/leaktracer/leakcheck $(NGDIR)/netguard || true	
	@echo -e $(EMPHSTART)"messure run done - results (copy in leak_results.txt):"$(EMPHSTOP)
	@sleep 2
#	@export LD_LIBRARY_PATH=./ && $(NGDIR)/leaktracer/leak-analyze $(NGDIR)/netguard ngleak.out main.cpp:`grep -n "while(is_running)" src/main.cpp | grep -o "[1-9]*"` > $(NGDIR)/leak_results.txt || true 
	@export LD_LIBRARY_PATH=./ && $(NGDIR)/leaktracer/leak-analyze $(NGDIR)/netguard ngleak.out main.cpp:`grep -n "netguard starting ..." src/main.cpp | grep -o "[1-9]*"` > $(NGDIR)/leak_results.txt || true 
	@cat $(NGDIR)/leak_results.txt

test::	debug
	@echo -e $(EMPHSTART)"starting netguard.."$(EMPHSTOP)
	@export LD_LIBRARY_PATH=./ && $(NGDIR)/netguard || true

netguard:: 
	@echo -e $(EMPHSTART)"Building netguard.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/src $@

shared: libnetguard
libnetguard:: 
	@echo -e $(EMPHSTART)"Building libnetguard.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/shared $@
	
modules:: 
	@echo -e $(EMPHSTART)"Building modules.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/modules $@

tools:: libnetguard
	@echo -e $(EMPHSTART)"Building tools.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/tools $@

netguard_clean:
	@$(MAKE) -C $(NGDIR)/src clean

modules_clean:
	@echo -e $(EMPHSTART)"Cleaning modules.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/modules clean

tools_clean:
	@echo -e $(EMPHSTART)"Cleaning tools.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/tools clean

shared_clean: libnetguard_clean

libnetguard_clean::
	@$(MAKE) -C $(NGDIR)/shared clean

leaktracer_clean::
	@echo -e $(EMPHSTART)"Cleaning up.. leak detect"$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/leaktracer clean
	${RM} $(NGDIR)/leaktracer/LeakTracer.so
	${RM} $(NGDIR)/ngleak.out $(NGDIR)/leak_results.txt

clean::	libnetguard_clean modules_clean tools_clean netguard_clean leaktracer_clean
	@echo -e $(EMPHSTART)"Cleaning up.."$(EMPHSTOP)
	@find $(NGDIR) -name "*.bak" ! -type d -exec echo -e "deleting.. {}" \; -exec ${RM} {} \;
	@find $(NGDIR) -name "*.d" ! -type d -exec echo -e "deleting.. {}" \; -exec ${RM} {} \;

strip::
	@echo -e $(EMPHSTART)"Striping files"$(EMPHSTOP)
	@find $(NGDIR) -maxdepth 1 -perm +3 ! -type d ! -name "*.a"  -exec echo -e "stripping.. {}" \; -exec strip {} \;

strip_release::
	@echo -e $(EMPHSTART)"Striping files"$(EMPHSTOP)
	@find $(NGDIR)/release -maxdepth 1 -perm +3 ! -type d ! -name "*.a"  -exec echo -e "stripping.. {}" \; -exec strip {} \;

release_clean:
	@echo -e $(EMPHSTART)"clean release dir.."$(EMPHSTOP)
	${RM} $(NGDIR)/release/*.so
	${RM} $(NGDIR)/release/netguard
	
do_copy:: release_clean
	@echo -e $(EMPHSTART)"copy files .."$(EMPHSTOP)
	@cp $(NGDIR)/*.so netguard start restart runtop debug .gdbinit $(NGDIR)/release
	@echo -e $(EMPHSTART)"copy done"$(EMPHSTOP)

do_remote_copy::
	@echo -e $(EMPHSTART)"remote copy files to "$(NGSSH_DIR)" .."$(EMPHSTOP)
	@rsync -avz --exclude 'CVS'  $(NGDIR)/release/* $(NGDIR)/release/.gdbinit $(NGSSH_DIR)
	@#scp $(NGDIR)/release/* $(NGSSH_DIR)

do_rsync::
	@echo -e $(EMPHSTART)"remote rsync source files to "$(NGSSH_SOURCEDIR)" .."$(EMPHSTOP)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/includes $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/mk $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/modules $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/shared $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/src $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/scripts $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/Makefile $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/tools $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/runtop $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/start $(NGSSH_SOURCEDIR)
	@rsync -avz --exclude-from=./source_sync.rignore $(NGDIR)/restart $(NGSSH_SOURCEDIR)

leaktracer:: 
	@echo -e $(EMPHSTART)"Building leaktracer.."$(EMPHSTOP)
	@$(MAKE) -C $(NGDIR)/leaktracer

stats::
	@echo -e $(EMPHSTART)"running sloccount.."$(EMPHSTOP)
	@sloccount --wide $(NGDIR)

r_shutdown::
	@echo -e $(EMPHSTART)"remote shutdown netguard.."$(EMPHSTOP)
	@ssh ${NGSSH_USER}@${NGSSH_HOST} "/bin/bash -c 'echo quit >> /netguard'"
	@sleep 2

r_start::
	@echo -e $(EMPHSTART)"remote start netguard.."$(EMPHSTOP)
	@ssh ${NGSSH_USER}@${NGSSH_HOST} "screen -dmS netguard /bin/bash -c 'cd ${NGSSH_PATH} && ./start'"

r_restart::
	@echo -e $(EMPHSTART)"remote restart netguard.."$(EMPHSTOP)
	@ssh ${NGSSH_USER}@${NGSSH_HOST} "/bin/bash -c 'cd ${NGSSH_PATH} && sudo ./restart'"


restart :: all install r_restart
restart_debug :: all install_debug r_restart

help:
	@echo -e Net-Guard.net - contact@net-guard.net
	@echo -e $(EMPHSTART)"targets:"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\tdebug\t\t"$(EMPHSTOP)"- build a debug version of netguard "netguard libnetguard modules"  (*default)"
	@echo -e $(EMPHSTART)"\tnetguard\t"$(EMPHSTOP)"- build netguard only"
	@echo -e $(EMPHSTART)"\tmodules\t\t"$(EMPHSTOP)"- build all netguard modules"
	@echo -e $(EMPHSTART)"\tlibnetguard\t"$(EMPHSTOP)"- build netguard library only"	
	@echo -e $(EMPHSTART)"\ttools\t\t"$(EMPHSTOP)"- build the tools"
	@echo -e $(EMPHSTART)"\ttest\t\t"$(EMPHSTOP)"- build debug and start netguard"
	@echo -e $(EMPHSTART)"\tstrip\t\t"$(EMPHSTOP)"- strip all bins"
	@echo -e $(EMPHSTART)"\tdo_copy\t\t"$(EMPHSTOP)"- copy netguard and libs to the release dir"
	@echo -e $(EMPHSTART)"\tleak_detect\t"$(EMPHSTOP)"- build debug version and start it using the leaktracer tool"
	@echo -e $(EMPHSTART)"\trelease\t\t"$(EMPHSTOP)"- build netguard copy it to the release dir and finally strip it"
	@echo -e $(EMPHSTART)"\tinstall\t\t"$(EMPHSTOP)"- build a release and then copy it to the remote computer"
	@echo
	@echo -e $(EMPHSTART)"\tstats\t\t"$(EMPHSTOP)"- show source stats using sloccount"
	@echo
	@echo -e $(EMPHSTART)"\tclean\t\t"$(EMPHSTOP)"- clean the build dirs"
	@echo -e $(EMPHSTART)"\tdist-clean\t\t"$(EMPHSTOP)"- clean all dirs"
	@echo
	@echo -e $(EMPHSTART)"\tclean commands:\t"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\tlibnetguard_clean"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\tmodules_clean"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\ttools_clean"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\tnetguard_clean"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\tleaktracer_clean"$(EMPHSTOP)
	@echo
	@echo -e $(EMPHSTART)"\tparams:\t"$(EMPHSTOP)
	@echo -e $(EMPHSTART)"\t\tNGDIR="$(EMPHSTOP)$(NGDIR)
	@echo -e $(EMPHSTART)"\t\tNGSSH_USER="$(EMPHSTOP)$(NGSSH_USER)
	@echo -e $(EMPHSTART)"\t\tNGSSH_HOST="$(EMPHSTOP)$(NGSSH_HOST)
	@echo -e $(EMPHSTART)"\t\tNGSSH_DIR="$(EMPHSTOP)$(NGSSH_DIR)
	@echo -e $(EMPHSTART)"\t\tOPT="$(EMPHSTOP)$(OPT)" - set it to 1 to compile optimized version"
	@echo
	@echo -e $(EMPHSTART)"\texamples:\t"$(EMPHSTOP)
	@echo -e "\t\tmake clean release OPT=1"
	@echo -e "\t\tmake clean install"
	@echo

	
dist-clean: clean release_clean

.PHONY: help all debug stripped clan-release clean tools stop release test leak_detect shared libnetguard modules_clean netguard_clean tools_clean shared_clean libnetguard_clean leak_detect_clean leaktracer dist_clean


	
