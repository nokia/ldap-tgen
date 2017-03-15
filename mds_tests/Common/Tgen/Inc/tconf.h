#include <stdio.h>
#include "ldap.h"
#include "conf.h"
#include "radpaths.h"

#ifdef __i386__
#define __VERSION__	 "v12.22 (i386)"
#define __CCLABEL__	 "ST_SDM_DEV_12_22"
#else
#define __VERSION__	 "v12.26 (x86_64)"
#define __CCLABEL__	 "ST_SDM_DEV_12_26"
#endif


//
// Fixed configuration datas
//

#define INIT_FILE_NAME				"TestU/tgen.ini"
#define CSV_FILE_NAME				"tgen.csv"
#define LOG_FILE_NAME				"tgen.log"
#define TIMER_MAX_WAIT				400				

//
// Default configuration datas (customizable in tgen.ini and cmd-line)
//

/* CONF USER - MIN, MAX included */
/*
User get policy
0: Random
N: take user rank N from Population
*/
#define GLOBAL_MAX_LDAPBIND			50
/* CONF LDAP::SERVER */
#define SERVER_HOST_IP       	    getenv("HSS_IP_CX")
#define LDAP_SERVER_HOST_PORT       389
#define LDAP_CLIENT_HOST_PASSWD   	getenv("LDAP_SECRET")
#define LDAP_CLIENT_BINDDN        	getenv("LDAPBINDDN")
/* CONF RADIUS::SERVER */
#define RADIUS_SERVER_HOST_PORT     1812
#define RADIUS_CLIENT_HOST_PASSWD 	getenv("RAD_SECRET")
#define	RADIUS_CLIENT_NAS_IP_ADD	getenv("MY_IP_ADDRESS")
#define	RADIUS_CLIENT_NAS_ID		getenv("MY_FQDN")

/* CONF LDAP::SESSION POLICY*/
#define LDAP_SES_POLICY_GLOBAL      1		// If defined: secifies the nb of opened LDAP session shared by all scenarios
#define LDAP_SES_POLICY_LOCAL_SCE   2		// If defined: one session per scenario
#define LDAP_SES_POLICY_LOCAL_THR   3		// If defined: one session per Thread
/* CONF RADIUS::AUTHTYPE POLICY*/
#define RADIUS_AUTHTYPE_READ		0
#define RADIUS_AUTHTYPE_USER		1
#define RADIUS_AUTHTYPE_DISTRIB		2

//
// Exported datas
//
// 
#ifndef WITHOUT_EXPORTED_DATA
extern int              tcNbOfRequestPerSecond  ;
extern int              tcTrafficProfile        ;
extern int              tcTrafficInfo           ;
extern char *           tcPopulation            ;
extern int              tcLdapSessionPolicy     ;
extern int              tcLdapBindNb     		;
extern char *           tcServerHost[200]       ;
extern int              tcActiveServerId        ;
extern int              tcServerLDAPPort        ;
extern int	            tcServerPort[200]       ;
extern int              tcServerRADIUSPort      ;
extern char *           tcClientLDAPPasswd      ;
extern char *           tcClientLDAPBindDN	    ;
extern int              tcWThreadNb             ;
extern int              tcUserNb                ;
extern int              tcUserNb1               ;
extern int              tcUserNb2               ;
extern int              MaxUsrMemory            ;
extern int              tcUserExclusion         ;
extern int              tcUserGetPolicy         ;
extern long             tcTimeToRun				;
extern int              tcLdapTimeout           ;
extern int              tcRadiusTimeout         ;
extern int              tcRadiusRetries         ;
extern char        		tcRadiusCallingStId[32]	;
extern char        		tcRadiusCalledStId[32]	;
extern int              tcRadiusNbNas           ;
extern char             tcRadiusNasIdBase[2][32];
extern char             tcRadiusNasIpAddBase[2][13];
extern int              tcTimeBeforeRebind      ;
extern int              tcTimeBeforeStats       ;
extern int              tcRadiusAuthTypePolicy  ;
extern char *		    tcRadiusAuthTypePolicyString[4];
extern int              tcRadiusNoNasPort       ;
extern int              tcRadiusSessIdBinary    ;
extern int              tcNoMattedPair       	;
extern char		        tcFullCommandLine[1024]	;
extern int              tcRadiusFastReauth      ;
extern int              tcReportPeriod		    ;
extern int              tcCsvPeriod		        ;
extern int				tcScenario				;
extern int				tcLdapWaitResponse		;
extern int				g_option				;
extern int				A_option				;
extern int				nolog_option			;
extern char *			tcGroupServer			;
extern int 				nbserver				;
extern int              tcAbortScenario         ;
extern int              tcSecuredMode	        ;

extern int				traficOn				;
extern int				verbose					;
extern int              debug                   ;
extern int              quietOnError            ;
extern int              stopOnError             ;
extern int              sameUserPasswd          ;
extern char *           cpuLoad[2]  	        ;
extern int              cpuLoadPortId           ;
extern char  		    inifile[1024] 		    ;
extern char				tcCaCertFile[128]		;

#endif

int  tConfInit()            ;
void tconfOnOffTrace()      ;


