########################################################################
# TGEN makefile
#
# Requires GNU make, errors will occur if the path: /usr/local/bin
# is not before paths to other make programs.
# 
# Same makefile for DEC and Linux native compilation
#
# ENV VARIABLES REQUIRED:
#	- CLEARCASE_ROOT
#
########################################################################

TARGET_ARCH = $(shell uname)

ROOT_DIR = /home/test/tgen-local
#ROOT_DIR = .
PROJECT_DIR = $(ROOT_DIR)/mds_tests/Common/Tgen
OPENLDAP_INST = $(ROOT_DIR)/mds_tests/Common/Openldap/x86_64
OPENLDAP_SRC = $(ROOT_DIR)/openldap
#OPENLDAP_SRC = /local/anthoin1/src/openldap-2.4.23
#64 CYRUS_SASL_INST = /hss_openldap/cyrus-sasl
#64 CYRUS_SASL_SRC = /hss_openldap/src/cyrus-sasl
RADIUS = $(ROOT_DIR)/hss_freeradius
SUPPLICANT = $(ROOT_DIR)/mds_tests/uma/Common/WpaSupplicant


# directories definitions
SOURCE_DIR = $(PROJECT_DIR)/Src
OBJECT_DIR = $(PROJECT_DIR)/Obj64
BIN_DIR = $(PROJECT_DIR)/Bin64
SHLIB_DIR = $(PROJECT_DIR)/Shlib64
TOP_DIR = $(PROJECT_DIR)/Src/top-3.5beta9
#IOSTAT_DIR = $(PROJECT_DIR)/Src/sysstat-5.0.5
IOSTAT_DIR = $(PROJECT_DIR)/Src/sysstat-9.1.7
LIBRARY_DIR = $(PROJECT_DIR)/Obj64

#hss_openldap/src/openldap/libraries/libldap needed to include ldap_int.h in tldap.c
#hss_openldap/src/openldap/libraries/liblber needed to include lber-int.h in tldap.c

INCLUDE_DIR = -I$(PROJECT_DIR)/Inc \
              -I$(OPENLDAP_SRC)/include \
              -I$(OPENLDAP_SRC)/libraries/libldap_r \
              -I$(OPENLDAP_SRC)/libraries/libldap \
              -I$(OPENLDAP_SRC)/libraries/liblber \
              -I$(RADIUS)/src/include \
              -I$(RADIUS)/src/modules/rlm_eap \
              -I$(RADIUS)/src/modules/rlm_eap/libeap \
	      -I$(SUPPLICANT)


#64	      -I$(CYRUS_SASL_SRC)/include \

##################################################################
#
CC = gcc
#CC = insure
# compiler command used to generate dependencies
CCDEPEND = $(CC) -M 

# optimized and debug
#DEC:    			CDEBUGFLAGS = -g3 -O4 -w -pthread
#SOL:    			CDEBUGFLAGS = -g -w -xCC -pthread
#Linux:
# forcer le 32bits sur un PC 64b: CDEBUGFLAGS = -g -w -pthread -O3 -m32
				CDEBUGFLAGS = -g -w -pthread -O3
#profiling with cprof:
#				CDEBUGFLAGS = -g -w -pthread -finstrument-functions -pg

#__TGEN_HAS_MUTEX_TIMEOUTS: Compiler support timed mutex acquisitions
#__TGEN_ON_LINUX_TIMESPES:  Linux timespec definition
#__LIMITED_THREAD_NB:	    Thread nb can not exceed req/s nb

# LINUX
# remove -D__TGEN_HAS_MUTEX_TIMEOUTS for valgrind usage
# but statistics are not given without -D__TGEN_HAS_MUTEX_TIMEOUTS
#DEF_FLAGS = -D__TGEN_ON_LINUX_TIMESPEC -DSCE_GENERIC -D_REENTRANT -DCONFIG_DRIVER_HOSTAP -DCONFIG_DRIVER_WEXT -DCONFIG_DRIVER_ATMEL -DCONFIG_DRIVER_WIRED -DEAP_TLS -DEAP_PEAP -DEAP_TTLS -DEAP_MD5 -DEAP_MSCHAPv2 -DEAP_GTC -DEAP_OTP -DEAP_SIM -DEAP_LEAP -DEAP_AKA -DEAP_TLV -DIEEE8021X_EAPOL -DEAP_TLS_FUNCS -DPKCS12_FUNCS -DCONFIG_WIRELESS_EXTENSION
DEF_FLAGS = -D__TGEN_HAS_MUTEX_TIMEOUTS -D__TGEN_ON_LINUX_TIMESPEC -DSCE_GENERIC -D_REENTRANT -DIEEE8021X_EAPOL #-DSUPPLICANT_PAP_CHAP

# -??	Allows double slash comments in C code
CFLAGS = $(CDEBUGFLAGS) $(DEF_FLAGS) $(INCLUDE_DIR)

             
LNKFLAGS = -L$(OPENLDAP_INST)/lib -lldap_r -llber \
	-L$(RADIUS)/x86_64/lib -lradius -leap \
	-L$(SUPPLICANT)/x86_64 -leapolTest \
	-L/usr/lib64 -L/lib64 -L/lib -lrt -lm -lpthread -lsasl2 -lncurses -lssl -lcrypto

#64    	-L/3pp_openssl/x86/lib 
#64     -L$(CYRUS_SASL_INST)/lib -lsasl \

#profiling with cprof:  -L/local/anthoin1/lib -lcprof



########################################################################
# List of objects required (used also for dependancy generation)
#
########################################################################
OBJS = tmain.o tinit.o tconf.o tthread.o tuser.o tsce.o tstat.o tldap.o tradius.o texec.o profile.o taction.o ttimer.o tsupplicant.o tdebug.o tload.o xinuconio.o tselect.o tserver.o

SRC  =  $(OBJS:%.o=%.c)
OBJS_WITH_DIR = $(OBJS:%.o=$(OBJECT_DIR)/%.o)
INC_WITH_DIR = $(OBJS:%.o=$(OBJECT_DIR)/%.o)

OBJS_TOP   = commands.o display.o getopt.o machine.o screen.o username.o utils.o version.o
SRC_TOP =  $(TOP_OBJS:%.o=%.c)
OBJS_TOP_WITH_DIR = $(OBJS_TOP:%.o=$(TOP_DIR)/%.o) 

LIBS  = 


########################################################################
# Specific compilation targets
# First target (all) is default target
#
all: version $(BIN_DIR)/tgen_mas
# $(BIN_DIR)/tgen_hss $(BIN_DIR)/tgen_mms

version:
	@echo "---------------------------------------------------------------------------------------"      
	@echo "Touching for VERSION and BUILT DATE update"
	@echo "---------------------------------------------------------------------------------------"      
	\rm -f $(OBJECT_DIR)/tmain.o

tloadserver: $(BIN_DIR)/tloadserver
	@echo "REMEMBER: Must be compiled on target server architecture !!!"

tgen_mas_newline: $(BIN_DIR)/tgen_mas_newline
	@echo "---------------------------------------------------------------------------------------"      
	@echo " ===>>> Special build for multiple parallel tgen done."
	@echo "---------------------------------------------------------------------------------------"

$(OBJECT_DIR)/%.o: $(SOURCE_DIR)/%.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Compilation of file $^"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) $(CFLAGS) -c -o $@ $^

$(LIBRARY_DIR)/libtgen.a: $(OBJS_WITH_DIR)
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Creating Static lib $@"
	@echo "---------------------------------------------------------------------------------------"
	rm -f $@
	ar -ur $@ $^

$(LIBRARY_DIR)/libtgen.so: $(OBJS_WITH_DIR)
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Creating Dynamic lib $@"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -shared -all -lpthread -lrt -o $@ $^
	

# the - in front of ligne force make to ignore eventual errors
$(BIN_DIR)/tgen_mas: $(OBJS_WITH_DIR) 
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Linking $@"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -o $@ $(CFLAGS) $^ $(LNKFLAGS)

$(BIN_DIR)/tgen_mas_newline: $(OBJS_WITH_DIR) 
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Compilation of file tstat.c"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) $(CFLAGS) -D_ALWAYS_NEWLINE_ -c -o $(OBJECT_DIR)/tstat.o $(SOURCE_DIR)/tstat.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Linking $@"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -o $@ $(CFLAGS) $^ $(LNKFLAGS)

$(BIN_DIR)/tgen_hss: $(OBJS_WITH_DIR) $(OBJECT_DIR)/tuserHss.o $(OBJECT_DIR)/tsceHss.o
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Linking $@"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -o $@ $(CFLAGS) $^ $(LNKFLAGS)

$(BIN_DIR)/tgen_mms: $(OBJS_WITH_DIR) $(OBJECT_DIR)/tuserLdas.o $(OBJECT_DIR)/tsceLdas.o
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Linking $@"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -o $@ $(CFLAGS) $^ $(LNKFLAGS)


$(OBJECT_DIR)/tloadserver.o: $(SOURCE_DIR)/tloadserver.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Special compilation of file $^"
	@echo "---------------------------------------------------------------------------------------"
##	$(CC) -g -w -pthread -D_REENTRANT -c -o $@ $^
	$(CC) -g -w -pthread -c -o $@ $^

$(OBJECT_DIR)/tloadtimer.o: $(SOURCE_DIR)/tloadtimer.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Special compilation of file $^"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -g -w -pthread -c -I$(TOP_DIR) -o $@ $^

$(OBJECT_DIR)/tloadiostat.o: $(SOURCE_DIR)/tloadiostat.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Special compilation of file $^"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -g -w -pthread -c -I$(IOSTAT_DIR) -o $@ $^

$(OBJECT_DIR)/tloadmpstat.o: $(SOURCE_DIR)/tloadmpstat.c
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Special compilation of file $^"
	@echo "---------------------------------------------------------------------------------------"
	$(CC) -g -w -pthread -c -I$(IOSTAT_DIR) -o $@ $^

#tloadserver: $(OBJECT_DIR)/tloadserver.o $(OBJECT_DIR)/tloadtimer.o $(OBJS_TOP_WITH_DIR)
#	@echo "---------------------------------------------------------------------------------------"
#	@echo "- Linking $@"
#	@echo "---------------------------------------------------------------------------------------"
#	$(CC) -ltermcap -lcurses -lpthread -lrt -lm -lmld -lmach -o $@ $^

$(IOSTAT_DIR):
#	tar zxvf sysstat-5.0.5.tar.gz
	tar zxvf sysstat-9.1.7.tar.gz

$(BIN_DIR)/tloadserver: $(OBJECT_DIR)/tloadserver.o $(OBJECT_DIR)/tloadmpstat.o $(IOSTAT_DIR)/librdstats.a $(IOSTAT_DIR)/libsyscom.a
	@echo "---------------------------------------------------------------------------------------"
	@echo "- Linking $@"
	@echo "---------------------------------------------------------------------------------------"
#	$(CC) -lpthread -o $@ $(OBJECT_DIR)/tloadserver.o $(OBJECT_DIR)/tloadiostat.o $(IOSTAT_DIR)/common.o
	$(CC) -lpthread -o $@ $(OBJECT_DIR)/tloadserver.o $(OBJECT_DIR)/tloadmpstat.o $(IOSTAT_DIR)/librdstats.a $(IOSTAT_DIR)/libsyscom.a

########################################################################
# Targets for tidying up
#
# Best run with make DEPEND=NO to avoid dependancy regeneration
#
########################################################################

clean:
	rm -f $(OBJECT_DIR)/*.o $(BIN_DIR)/tgen_*

depend:
	makedepend $(CFLAGS) $(LNKFLAGS) -o .o $(SRC)

# DO NOT DELETE THIS LINE -- make depend depends on it.
