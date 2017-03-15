#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#define WITHOUT_EXPORTED_DATA 1
#include "tconf.h"
#include "tuser.h"
#include "tdebug.h"
#include "tserver.h"

/* This function does not serve a useful purpose in the thread library implementation anymore.
It used to be necessary when then kernel could not shut down "processes" but this is not the case anymore.
We could theoretically provide an equivalent implementation but this is not necessary since the kernel
already does a much better job than we ever could. */
void pthread_kill_other_threads_np (void) {}
//void __pthread_kill_other_threads_np (void) {}
//compat_symbol (libpthread, __pthread_kill_other_threads_np, pthread_kill_other_threads_np, GLIBC_2_0);



int             tcNbOfRequestPerSecond          = -1;
int             tcTrafficProfile				= -1;
int             tcTrafficInfo					;
char *          tcPopulation                    = NULL ;
int             tcLdapSessionPolicy				;
int             tcLdapBindNb     				= 1;
char *          tcServerHost[200]			    = {NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
													NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
int             tcActiveServerId                = 0;
int             tcServerLDAPPort				= -1;
int             tcServerPort[200]			    = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
													0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
int             tcServerRADIUSPort				= -1;
char *          tcClientLDAPPasswd				= NULL ;
char *          tcClientLDAPBindDN				= NULL ;
int             tcWThreadNb					    = -1;
int             tcUserNb					    = 0;
int             tcUserNb1					    = 0;
int             tcUserNb2					    = 0;
int				MaxUsrMemory					= 25000000;
int             tcUserExclusion					= -1;
int             tcUserGetPolicy					= -1;
long            tcTimeToRun						= -1;
int             tcLdapTimeout					;
int             tcRadiusTimeout					;
int             tcRadiusRetries					;
char            tcRadiusCallingStId[32]			;
char            tcRadiusCalledStId[32]			;
int             tcTimeBeforeRebind				;
int             tcRadiusNbNas                   ;
char            tcRadiusNasIdBase[2][32]        ;
char            tcRadiusNasIpAddBase[2][13]     ;
int             tcRadiusNoNasPort       		= -1;
int             tcRadiusSessIdBinary       		= -1;
int             tcNoMattedPair		       		= -1;
int             tcTimeBeforeStats				;
int             tcRadiusAuthTypePolicy			= -1;
char		    tcFullCommandLine[1024] 		= "";
int     	    quietOnError					= -1;
int     	    stopOnError					    = -1;
int     	    sameUserPasswd					= -1;
char *          cpuLoad[2]				    	= {NULL,NULL} ;
int             cpuLoadPortId           		= 3333;
char 		    inifile[1024] 					= "\0";
int             tcRadiusFastReauth              = 0;
int             tcReportPeriod		    		;
int             tcCsvPeriod		        		;
int				tcScenario						= 0;
int				tcLdapWaitResponse				;
char *			tcGroupServer					= 0;
int 			g_option 						= 0;//vérification option g présente
int 			A_option 						= 0;//vérification option A présente
int 			nolog_option 					= 0;//vérification option nolog présente
int 			nbserver						= 1;
int             tcAbortScenario              	= -1;
int             tcSecuredMode	                = 0;
char			tcCaCertFile[128]				= "";

// debug & verbose
int				traficOn = 1;
int             verbose  = 1;
int             debug    = 0;

// files:
FILE *		    tcRptFile 		    			= NULL;
FILE *		    tcCsvFile		    			= NULL;
FILE *		    tcLogFile 		    			= NULL;


// Radius AuthType policy as string
char *	tcRadiusAuthTypePolicyString[3] = {
	"read",
	"popul",
	"distrib"
};

/******************************************************************************/
int tConfInit()
/******************************************************************************/
{
int rc=0;

	TRACE_CORE("tconf init starts with ini-file %s\n", inifile);

    // print warning if .ini files can't be found
    if ( !ProfileIniExist(inifile) )
	    TRACE_CRITICAL("tgen: main: can't read ini-file %s\n", inifile);

    if (tcWThreadNb == -1)
        tcWThreadNb = ProfileGetInt( inifile, "Global", "nb_threads", 1 );

    if (tcNbOfRequestPerSecond == -1)
        tcNbOfRequestPerSecond = ProfileGetInt( inifile, "Global", "req_by_sec", 1 );

#ifdef __LIMITED_THREAD_NB
    if (tcWThreadNb > tcNbOfRequestPerSecond) {
        tcWThreadNb = tcNbOfRequestPerSecond ;
        TRACE_CORE("WARNING: Worker Thread Number (too high), set to %d \n", tcWThreadNb);
    }
#endif

    if (tcTrafficProfile == -1) {
        tcTrafficProfile = ProfileGetInt( inifile, "Global", "traffic", 1 );
    }

    tcLdapSessionPolicy = ProfileGetInt( inifile, "Ldap", "bind_policy", LDAP_SES_POLICY_LOCAL_THR );
    if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
		if (tcLdapBindNb > GLOBAL_MAX_LDAPBIND) {
			tcLdapBindNb = GLOBAL_MAX_LDAPBIND;
			TRACE_CORE("WARNING: Ldap bind Number (too high), set to %d \n", tcLdapBindNb);
		}
	} else
		tcLdapBindNb = tcWThreadNb;
    tcLdapWaitResponse = ProfileGetInt( inifile, "Ldap", "Ldap_wait_response", 1 );

     if ( (!tcServerHost[0]) && (g_option !=1) ) {
        TRACE_CRITICAL("No hostname configured: unresolved ?\n"); 
        exit(1);
    }
    
    if (tcServerLDAPPort == -1 && (g_option !=1))
	    tcServerLDAPPort = ProfileGetInt( inifile, "Ldap", "Ldap_server_port", LDAP_SERVER_HOST_PORT );
    if (tcServerRADIUSPort == -1)
	    tcServerRADIUSPort = ProfileGetInt( inifile, "Radius", "Radius_server_port", RADIUS_SERVER_HOST_PORT );

    tcClientLDAPBindDN = LDAP_CLIENT_BINDDN;
	tcClientLDAPPasswd = LDAP_CLIENT_HOST_PASSWD;
	TRACE_CORE("LDAP bind login/password = (%s/%s)\n", tcClientLDAPBindDN, tcClientLDAPPasswd);

    if (tcUserExclusion == -1)
        tcUserExclusion     = ProfileGetInt( inifile, "Global", "user_exclusion", 1 );
	// tcUserExclusion is not used anymore later in tgen appli... (an exclusion per scenario is used instead)

    if (tcUserGetPolicy == -1)
		tcUserGetPolicy     = ProfileGetInt( inifile, "Global", "user_get_policy", 0 );
	TRACE_CORE("tcUserGetPolicy = %d\n", tcUserGetPolicy );

	if (tcTimeToRun == -1)
		tcTimeToRun     = ProfileGetInt( inifile, "Global", "time_to_run", 0 );
	TRACE_CORE("Tgen will stop after %d seconds running.\n", tcTimeToRun );

    tcLdapTimeout   = ProfileGetInt( inifile, "Ldap", "Ldap_timeout", 10 );
    tcRadiusTimeout = ProfileGetInt( inifile, "Radius", "Radius_timeout", 3 );
    tcRadiusRetries = ProfileGetInt( inifile, "Radius", "Radius_retries", 3 );
    tcRadiusNbNas   = ProfileGetInt( inifile, "Radius", "Radius_nb_nas", 100 );
    tcRadiusFastReauth = ProfileGetInt( inifile, "Radius", "fast_reauth", 0);
	ProfileGetString( inifile, "Radius", "Radius_CallingStationId", "", tcRadiusCallingStId, 32);
	ProfileGetString( inifile, "Radius", "Radius_CalledStationId", "", tcRadiusCalledStId, 32);


    tcTimeBeforeRebind = ProfileGetInt( inifile, "Ldap", "time_before_rebind", 1 );    
    tcTimeBeforeStats  = ProfileGetInt( inifile, "Global", "time_before_stats", 3 );    

    if (quietOnError == -1)
		 quietOnError = ProfileGetInt( inifile, "Global", "quiet_on_error", 0 );
    if (stopOnError == -1)
		 stopOnError = ProfileGetInt( inifile, "Global", "stop_on_error", 0 );

    if (!cpuLoad[0]) {
		char buffer[128];	// by default, initialized to null string
		if ( ProfileGetString( inifile, "Global", "cpu_load", NULL, buffer, 128) )
			cpuLoad[0] = strdup(buffer);
	}
    if (cpuLoad[0] && cpuLoad[0][0]) {
		char *p;
		if ( p=strrchr(cpuLoad[0], ':') ) {
			cpuLoadPortId = atoi(p+1);
			*p = 0;
		}
		if ( p=strchr(cpuLoad[0], '-') ) {
			cpuLoad[1] = p+1;
			*p = 0;
		}
	}
	TRACE_CORE("listen CPU occupation on %s - %s, port=%d\n", cpuLoad[0], cpuLoad[1], cpuLoadPortId );

    if (tcNoMattedPair == -1)
		 tcNoMattedPair = ProfileGetInt( inifile, "Global", "no_matted_pair", 1 );
    if (tcAbortScenario == -1) 
         tcAbortScenario = ProfileGetInt( inifile, "Global", "abort_scenario_on_error", 1 );

	if (tcRadiusAuthTypePolicy == -1)
		 tcRadiusAuthTypePolicy = ProfileGetInt( inifile, "Radius", "authtype_policy", RADIUS_AUTHTYPE_READ );
	if ( (tcRadiusAuthTypePolicy < RADIUS_AUTHTYPE_READ) || (tcRadiusAuthTypePolicy > RADIUS_AUTHTYPE_DISTRIB) )
		tcRadiusAuthTypePolicy = RADIUS_AUTHTYPE_USER;
	TRACE_CORE("    AuthenticationType policy : %s\n", tcRadiusAuthTypePolicyString[tcRadiusAuthTypePolicy]);

	if (sameUserPasswd == -1)
		 sameUserPasswd = ProfileGetInt( inifile, "Radius", "same_passwd", 0 );
    if (tcRadiusNoNasPort == -1)
		 tcRadiusNoNasPort = ProfileGetInt( inifile, "Radius", "no_nas_port", 1 );
	if (tcRadiusSessIdBinary == -1)
		 tcRadiusSessIdBinary = ProfileGetInt( inifile, "Radius", "sessionId_binary", 1 );

    tcReportPeriod   = ProfileGetInt( inifile, "Global", "report_period", 300 );	// default 5 min
    tcCsvPeriod = ProfileGetInt( inifile, "Global", "csv_period", 60);				// default 1 sec

    return rc;
}





#ifdef NOT_USED_ANYMORE

/******************************************************************************/
void tconfStopTrace()
/******************************************************************************/
{
    traficOn = 0 ;
    verbose = 0;
}

/******************************************************************************/
void tconfStartTrace()
/******************************************************************************/
{
static int init=0;
static int verboseS, debugS;

	if (!init) {
		verboseS = verbose;
		init = 1;
	} else {
		verbose = verboseS;
	}
    traficOn = 1 ;
}

/******************************************************************************/
void tconfOnOffTrace()
/******************************************************************************/
{
	traficOn = (traficOn ? 0 : 1);
}


#endif
