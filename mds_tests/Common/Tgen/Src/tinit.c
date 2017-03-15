
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "tinit.h"
#include "tconf.h"
#include "tthread.h"
#include "texec.h"
#include "tldap.h"
#include "tstat.h"
#include "tsce.h"
#include "tdebug.h"
#include "tload.h"
#include "tselect.h"


// indicator that all Worker Threads have close all the sessions
extern int			nbSessionsClosed;

int     tInitServerState = SRV_DOWN;

int		  killcalled = 0;

/******************************************************************************/
int tInit()
/* EVOL: secured init by return code assertion */
/******************************************************************************/
{
int i;
    
    TRACE_CORE(" *** starts its initialization ***\n");

    srand((unsigned int)time(NULL));

    if (tConfInit()) 				exit(2) ;
	if (tThreadInit()) 				exit(8) ;
    if (tUserInit(tcPopulation)) 	exit(3) ;
    if (tServerInit(tcGroupServer)) exit(11);
    if (tStatInit()) 				exit(4) ;
    if (tTimerInit(TIMER_MAX_WAIT)) exit(5) ;
    if (tSceInit()) 				exit(6) ;
    if (tSelectInit()) 				exit(6) ;
	if (tExecInit()) 				exit(7) ;
	if (tRadiusInit()) 				exit(9) ;
	if (tSupplicantInit()) 			exit(1) ;  
	if (tLdapInit()) 				exit(10) ;
	    
    if (verbose >= 1) {
        TRACE_CORE("RADIUS ports: Auth(%d), Acct(%d)\n", tcServerRADIUSPort, tcServerRADIUSPort+1);

		if (g_option != 1) {
			TRACE_CORE("LDAP Destination Servers: \tMASTER=%s - SLAVE=%s\n",tcServerHost[0], (tcServerHost[1] ? tcServerHost[1] : "none"));
		} else {
			for(i=0; i<nbserver; i++){
				TRACE_CORE("LDAP Destination Server #%d: \t%s:%d\n", i+1, tcServerHost[i], tcServerPort[i]);
			}
		}
    }
    TRACE_CORE(" *** ends its initialization ***\n" );

    tInitServerState = SRV_RUNNING;
    return 0;
}

/******************************************************************************/
int tReinit()
/* EVOL: secured init by return code assertion */
/******************************************************************************/
{
int rc=0;

    // Ldap
    rc += tLdapReinit();

    // Radius ?

    return rc;
}


/******************************************************************************/
int tReinitIsAlive(int key)
/******************************************************************************/
{
int             rc=1;
LDAPMessage*    res=NULL;

    // is cnx already openned ?
	if (tLdap_getLd(key)) {
	    // is openned cnx still alive ?
		rc = ldap_search_st( tLdap_getLd(key),
						getenv("LDAPBASE"),
						//"NE=MOBILE_DATA_SERVER",         // root DSE is not impacted by UNAVAILABLE
						0,          // scope = base
						NULL,       // no filter
						NULL,       // no attribute
						0,
						&ldaptv,
						&res);
		// print error
		if ( rc != LDAP_SUCCESS ) {
			TRACE_ERROR("Monitoring thread : LDAP search error %d (%s)\n", rc, ldap_err2string(rc));
			//ldap_perror( ld, "ldap_search_s" );
		}
	
		// if cnx crashed, free it
		if (rc == LDAP_SERVER_DOWN) {
			// try once to rebind
			unbindRequest( &tLdap_getLd(key), 1 ) ;
		}
	}

    if ( !tLdap_getLd(key) ) {
        if ( rc = simpleBindRequest( &tLdap_getLd(key), 1, NULL ) ) {   // rc != 0 if ko
            // can not open a new cnx
			TRACE_ERROR("Monitoring thread : LDAP bind error %d (%s)\n", rc, ldap_err2string(rc));
            return 0; // rebind is KO
        }

		// is reopenned cnx working ?
		rc = ldap_search_st( tLdap_getLd(key),
						getenv("LDAPBASE"),
						//"NE=MOBILE_DATA_SERVER",         // root DSE is not impacted by UNAVAILABLE
						0,          // scope = base
						NULL,       // no filter
						NULL,       // no attribute
						0,
						&ldaptv,
						&res);
		// print error
		if ( rc != LDAP_SUCCESS ) {
			TRACE_ERROR("Monitoring thread : LDAP search error on new cnx %d (%s)\n", rc, ldap_err2string(rc));
	//        ldap_perror( ld, "ldap_search_s" );
		}
	}

    if (res) ldap_msgfree( res );
    return (rc == LDAP_SUCCESS);
}

/******************************************************************************/
void tBreak(int sigNum)
/******************************************************************************/
{
int         threadId;
int         rc = 0;     // failure

	if (killcalled) return;

	if (!tcNoMattedPair) {
		// defense is activated

		// suspend worker threads
		tInitServerState = SRV_DOWN;
		for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
			tThread_getState(threadId) = SUSPEND ;
		};
		traficOn = 0;
		
		// server is down
		TRACE_CONSOLE("\n\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		TRACE_CONSOLE("\t\t!!!  tldap: SERVER IS DOWN  !!!   (%dth time)\n", tStatIncrServerMPswitch());
		TRACE_CONSOLE("\t\t!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n");
		
		while ( !rc ) {
			// trying to switch matted-pair server
			if ( tcServerHost[1] ) {
				// if bind succeeded but not the ldapsearch: unbind before switching
				unbindRequest( &tLdap_getLd(tcLdapBindNb), 1 );
		
				tcActiveServerId = (++tcActiveServerId) % 2;
				TRACE_CONSOLE("MATTED-PAIR SWITCH, immediatly testing server %s disponibility... \n", tcServerHost[tcActiveServerId]);
				
				rc = tReinitIsAlive(tcLdapBindNb);
				TRACE_CONSOLE("=> %s\n", (rc ? "Success !" : "Failure !") );
				if (rc) break;
			}
			
			// wait server disponibility
			TRACE_CONSOLE("will test again server %s disponibility in %d sec...\n", tcServerHost[tcActiveServerId], tcTimeBeforeRebind );
		
			// EmA,06/12/2002: keep possibility to use ^C during wait -> tStatWaitFor
			// tStatWaitFor(tcTimeBeforeRebind);
			// EmA,03/01/2003: when returning from sig-handler of SIGURG, thread is defunct -> sleep is OK
			sleep(tcTimeBeforeRebind);
			TRACE_CONSOLE("try now: \n");
		
			rc = tReinitIsAlive(tcLdapBindNb);
			TRACE_CONSOLE("=> %s\n", (rc ? "Success !" : "Failure !") );
			if (rc) break;
		}
		
		tReinit();
		tLoadEnd();
		
		traficOn = 1;
		tInitServerState = SRV_RUNNING;
		// resume worker threads
		for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		   tThread_getState(threadId) = RUNNING ;
		};
		
	} // defense activated
}


/******************************************************************************/
void tStop(int sigNum)
/******************************************************************************/
{
int         threadId;

	if (killcalled) return;

	// switch trafic on/off: counting stats, tracing, and worker threads
	traficOn = (traficOn ? 0 : 1);
	for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
	    tThread_getState(threadId) = ( traficOn ? RUNNING : SUSPEND );
	};
	
	// just suspend trafic: stats are automatically refreshed
	if (!traficOn) {
	    TRACE_CONSOLE("tgen CTRL_Z : trafic suspended (type stop signal again to resume)\n", tThread_getKey());
		sleep(1);
	}
}


/******************************************************************************/
void *tEnd(void *param)
/* EVOL: secured init by return code assertion */
/******************************************************************************/
{
int               threadId;
int				  i;

   if (killcalled) {
	   TRACE_CONSOLE("tgen second CTRL_C : force quick exit (WARNING: DB may be corrupted with sessions) !!!\n");
       TRACE_CORE("tEnd: still waiting for a thread to FINISH... (%d on %d), I am threadid=%d\n", nbSessionsClosed, tcWThreadNb, tThread_getKey() );
	   exit(1);
   }
   killcalled = 1;

   //TRACE_CORE("\ntgen: kill signal received by thread %d , wait a while\n", tThread_getKey());
   TRACE_CONSOLE("tgen CTRL_C : That's all folks, wait a while (5 sec)...\n");

}

