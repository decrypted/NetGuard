# Compiler Options
#CMP=ppcx64
CMP=fpc
CMPOPT=-S2cdgi -OG1 -gl -vewni -dUseCThreads 
# -vp -vv

# Search Paths
# Shared
INC=-Fisrc/
SEARCH += -Fusrc/
SEARCH += -Fusrc/synapse
SEARCH += -Fusrc/linux

all:
	@$(CMP) $(CMPOPT) $(INC) $(SEARCH) -FUdcu -oout/traffgen src/traffgen.dpr
