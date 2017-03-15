#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>

/*
#include <ldap.h>

#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"
#include "ldap_log.h"
//#include "ldap_pvt.h"

#include "common.h"
*/

#define AC_INT2_TYPE short
#define AC_INT4_TYPE int

#include "ldap-int.h"
#include "ldap.h"
#include "lber-int.h"


#include "tconf.h"
#include "tthread.h"
#include "tldap.h"
#include "texec.h"
#include "tdebug.h"

#ifdef __TGEN_ON_LINUX_TIMESPEC
#include <time.h>
#else
#include <sys/time.h>
#endif

struct timeval	    ldaptv;

int         attrTypeValue_explode( char * dn, 
                            char *  _attrTypeValue, char ** _attrType, char ** _attrValue )             ;
int         attrs_build(    char * dn,
                            char * _attr_list, 
                            char ***_attrs_type,char ***_attrs_value, int **_attrs_ope, int  *_attrs_nb);
char **     attrsValues_build( char * _attrValue )                                                      ;
char *		strsub (const char *str, const char *replace, const char *with)								;
void        double_free( char ** _toFree )                                                              ;

#define     whatIsValue     1
#define     whatIsType      2

char *      attrTypeValue_getWhat( char * attrTypeValue, char token, int what ) ;

LDAPMod *   get_modlist_element( int mod_op, char *mod_type, char **values )    ;
// From LDAP lib 
LDAPMod **  get_modlist( int mod_op, char *mod_type, char **values )           ;  
void        mods_free( LDAPMod **mods, int freemods )                          ;


//Request Command
#define CMD_GETASBASE		    	((int) 0x0000)

static pthread_mutex_t bindMutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t abandonMutex = PTHREAD_MUTEX_INITIALIZER;
//pthread_mutex_t searchMutex = PTHREAD_MUTEX_INITIALIZER;
//int collision_searchMutex = 0;
//int collision_threadMutex = 0;

tLdapLd*	   		tLdapLdTab;


//中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中
//PUBLIC
//中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中

/******************************************************************************/
int tLdapInit()
// all threads are stopped
// all threads are concerned
/******************************************************************************/
{
int ldId, rc=0;
pthread_mutexattr_t mutattr;


	ldaptv.tv_sec = tcLdapTimeout;
   	ldaptv.tv_usec = 0;

	if ( (tLdapLdTab = malloc( sizeof(tLdapLd) * (tcLdapBindNb+1) ) ) == NULL ) {
		TRACE_CRITICAL("init exit: tLdapLdTab init failed! \n");
		return 1; 
	}
	bzero( tLdapLdTab, sizeof(tLdapLd) * (tcLdapBindNb+1) );

#ifndef __i386__
// 64bits compil only (coredump in openssl in 32bits => use .ldaprc instead with "TLS_CACERT <path to your pem file>")

	// set general LDAP option (before creation of any ld)
	if (tcSecuredMode) {
		if (tcCaCertFile[0]) {
			TRACE_DEBUG("tLdapInit: Secured mode activated with CaCertFile=%s\n", tcCaCertFile );  	
			if ( (rc = ldap_set_option(0, LDAP_OPT_X_TLS_CACERTFILE, tcCaCertFile)) != LDAP_OPT_SUCCESS) {
				TRACE_CRITICAL("tLdapInit: could not set CACERTFILE option, %d\n", rc);
				exit(1);
			}
			
		} else {
			TRACE_CRITICAL("tLdapInit: cacert_file value is not configured. Trying with $HOME/.ldaprc ...\n");
			//exit(1);
		}
	}
#endif

	/* create ld mutex & cond */
	pthread_mutexattr_init( &mutattr );
//	pthread_mutexattr_settype( &mutattr, PTHREAD_MUTEX_ERRORCHECK_NP);
	pthread_mutexattr_settype( &mutattr, PTHREAD_MUTEX_RECURSIVE_NP);
	for (ldId=0 ; ldId<=tcLdapBindNb ; ldId++) {

		tLdapLdTab[ldId].cond = (pthread_cond_t *) malloc ( sizeof (pthread_cond_t) );
		tLdapLdTab[ldId].mutex = (pthread_mutex_t *) malloc ( sizeof (pthread_mutex_t) );
		rc = pthread_cond_init(tLdapLdTab[ldId].cond, NULL); 
		rc += pthread_mutex_init(tLdapLdTab[ldId].mutex, &mutattr);

		TRACE_TRAFIC("tthread: ldid=%d, cond=%d\n", ldId, tLdapLdTab[ldId].cond);
	}

	// Tgen opens its LDAP sessions according to requested policy from tconf
	if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
        //		for (ldId=WORKTHR ; ldId<(WORKTHR+tcLdapBindNb) ; ldId++) {
		for (ldId=0 ; ldId<tcLdapBindNb ; ldId++) {
			simpleBindRequest(&tLdap_getLd(ldId), 1, NULL);
			tStatActionTime(LDAP_Bind_Rq,0,0,0);
			TRACE_DEBUG("tLdap_initialbind ldId=%d, ld=%p\n", ldId, tLdap_getLd( ldId ) );  	
		}
	}

/*
    if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
		if (!tcNoMattedPair) {
			// not supported anymore
			TRACE_CRITICAL("tldap module: one unique global Ldap bind policy not supported in mated-pair !\n" );
			exit (1);
		}

		// Allocates the LDAP structure & make the unique bind
		tcLdapSessionPolicy = LDAP_SES_POLICY_LOCAL_SCE;
		if ( simpleBindRequest( &tLdap_getLd(1) ) ) {
			TRACE_CRITICAL("Check these parameters declared to LDAP server :\n\t- hostname : %s\n\t- password : %s\n\t- LDAP @IP : %s\n\t- LDAP Port Number : %d\n",tcClientLDAPBindDN,tcClientLDAPPasswd,tcServerHost[tcActiveServerId],tcServerPort[tcActiveServerId]);
			exit(1);
		}
		tcLdapSessionPolicy = LDAP_SES_POLICY_GLOBAL;
    }
*/   
    return rc;
}


/******************************************************************************/
int tLdapReinit()
// Only called on Mated-pair defense
// all threads has been stopped, possibly in the middle of a scenario treatment
// some threads have lost their Ldap cnx
/******************************************************************************/
{
int ldId,threadId;
    
	if (!tcNoMattedPair) {
		// defense is activated

		// tLdap_getLd(threadId) == -1       means scenario was in progress & ldap cnx already unbinded => scenario is aborted, nothing to do
		// tLdap_getLd(threadId) == 0        means no scenario was in progress => do not unbind & rebind !
		// tLdap_getLd(threadId) == other    means scenario was in progress & ldap cnx did not crash => unbind & rebind must be done if matted-pair
		if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
			for (ldId=WORKTHR ; ldId<(WORKTHR+tcLdapBindNb) ; ldId++) {

				if ( tLdap_getLd(ldId) ) {
					unbindRequest( &tLdap_getLd(ldId), 1 );                
					simpleBindRequest( &tLdap_getLd(ldId), 1, NULL );
				}
			}
		} else {
			for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {

				if ( tLdap_getLd(threadId) ) {
					unbindRequest( &tLdap_getLd(threadId), 1 );                
					simpleBindRequest( &tLdap_getLd(threadId), 1, NULL );
				}
			}
		}
	}
    return 0;
}

/******************************************************************************/
int tLdapClose()
// all threads are stopped
// all threads are concerned
/******************************************************************************/
{
int threadId;
    
	for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		unbindRequest( &tLdap_getLd(threadId), 1 ) ;                
	}
//	unbindRequest( &tLdap_getLd(1), 1 ) ;                
	unbindRequest( &tLdap_getLd(tcLdapBindNb), 1 ) ;                
    return 0;
}


/******************************************************************************/
int tLdap_abandon(LDAP **ld, char dolock)
// To be used in multi-station server: a KO is detected on an Ldap cnx (one station down)
// Note: we are NOT protected from other WT by a mutex
/******************************************************************************/
{
int     rc;

    pthread_mutex_lock( &abandonMutex );	// avoid treating multiple cnx crash at the same time !

	// one cnx down !
	tStatIncrStationDown();

	// release ld
    unbindRequest( ld, dolock );

    if ( tInitServerState != SRV_DOWN ) {

		// try re-opening ld (which indicate if server is still alive)
		rc = simpleBindRequest(ld, dolock, NULL);

		if ( rc ) {// rebind is KO => server is KO !!!
			// sending break signal
			if (verbose >= 2) TRACE_ERROR("pthread_kill on thread %d\n", tThread_getMainThread());

			if ( (rc=pthread_kill(tThread_getMainThread(), SIGURG)) ) {
				TRACE_CRITICAL("pthread_kill failed with #%d\n", rc);
				exit(1);
			}
		}
    }
    // either cnx is re-established, either srv is down

    pthread_mutex_unlock( &abandonMutex );
    return 0;
}

/******************************************************************************/
int tLdap_Rebind(LDAP **ld, char dolock)
// To be used in multi-station server: a KO is detected on an Ldap cnx (one station down)
// Note: we are NOT protected from other WT by a mutex
/******************************************************************************/
{
int     rc,i,indiceTab;
int version = LDAP_VERSION3;

	if (dolock) pthread_mutex_lock( tLdap_getLdMutex(tThread_getKey()) );
	//pthread_mutex_lock( &bindMutex );	// avoid treating multiple cnx crash at the same time !

	for (i = 0; i<tcWThreadNb;i++){
	    if(tLdapLdTab[i].KeyThead==tThread_getKey()){
	        indiceTab=i;
	    }
	}

	TRACE_ERROR("tLdap_Rebind on keyThread = %d LDAP_SERVER = %s:%d\n",tThread_getKey(), tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
	// one cnx down !
	tStatIncrStationDown();
	TRACE_TRAFIC("tLdapLdTab[%d].ld = %p\n",indiceTab,tLdapLdTab[indiceTab].ld);

	// release ld
	unbindRequest( ld, dolock );
	TRACE_ERROR("Thread suspended T= %d\n",tThread_getKey());
	TRACE_TRAFIC("tLdapLdTab[%d].rebind = %d\n",tLdapLdTab[indiceTab].rebind);
	//while ( tThread_getState(tThread_getKey()) == SUSPEND ) {
	if (tLdapLdTab[indiceTab].rebind == 0){
		while ( !rc == LDAP_SUCCESS ) {
			tLdapLdTab[i].rebind=1;
			sleep(1);
			//tThread_getState(tThread_getKey()) = RUNNING;
			//TRACE_ERROR("Thread suspended T= %d\n",tThread_getKey());
			//rc = tLdapInit();
			if (( *ld = ldap_init( tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort )) == NULL ) {
				TRACE_ERROR("ldap_init error: could not create ld\n");
				return 1;
			}
			if( ldap_set_option( *ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS ) {
				TRACE_ERROR("Could not set LDAP_OPT_PROTOCOL_VERSION %d, error: %d (%s %s:%d)\n", version, (*ld)->ld_errno, ldap_err2string((*ld)->ld_errno), tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
				return 1;
			}

			tStatTimeBegin(0);

			if ( ((rc = ldap_simple_bind_s(*ld, tcClientLDAPBindDN, tcClientLDAPPasswd)) > 0) && !quietOnError) {
				TRACE_ERROR("ldap_simple_bind_s error: %d (%s %s:%d)\n", rc, ldap_err2string(rc), tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
				//		ldap_perror( *ld, "ldap_simple_bind_s");
				if (*ld) {
					ldap_unbind_s( *ld );
					*ld = NULL;
					rc = 1;
				}
			}

			tStatTimeEnd(0);

			if (!rc == LDAP_SUCCESS){
				//tThread_getState(tThread_getKey()) = SUSPEND;
			}
		}
		tLdapLdTab[i].rebind=0;
		TRACE_TRAFIC("Rebind ok thread = %d (%s:%d)\n",tThread_getKey(), tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
		tStatIncrStationRestart();
	}
    //pthread_mutex_unlock( &bindMutex );
    if (dolock) pthread_mutex_unlock( tLdap_getLdMutex(tThread_getKey()) );
    return 0;
}


/******************************************************************************/
int tLdap_BindRequest (int* realBind, LDAPControl **sctrl)
// exclusive usage: within a scenario
/******************************************************************************/
{
int     rc=0;

    TRACE_TRAFIC("tLdap_bindRequest - BEGIN \n");

	if (! tLdap_getLd( tThread_getKey() ) ) {
		rc = simpleBindRequest( &tLdap_getLd( tThread_getKey() ), 1, sctrl );
//		*realBind=(tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL ? 0 : 1);
		*realBind=1;
	} else
		*realBind=0;
    
    TRACE_TRAFIC("tLdap_bindRequest - END (realBind=%d, ld=%p) \n", *realBind, tLdap_getLd( tThread_getKey() ) );  	
	
	return rc;
}

/******************************************************************************/
int tLdap_UnbindRequest (int* realBind)
// exclusive usage: within a scenario
/******************************************************************************/
{
int     rc=0;

    TRACE_TRAFIC("unbindRequest - BEGIN \n"); 
    
    if (tcLdapSessionPolicy == LDAP_SES_POLICY_LOCAL_SCE) {
		rc = unbindRequest( &tLdap_getLd(tThread_getKey()), 1);
		*realBind=1;
    } else   
        *realBind=0;

	TRACE_TRAFIC("unbindRequest - END \n"); 
    
	return rc;
}

/******************************************************************************/
int simpleBindRequest (LDAP** ld, char dolock, LDAPControl **sctrl)
/******************************************************************************/
{
    int rc=0,i;
    int version = LDAP_VERSION3;
	int	outvalue;

    if (verbose >= 2)
    TRACE_TRAFIC("tcActiveServerId :%d\n", tcActiveServerId);
    //TRACE_TRAFIC("simpleBindRequest with %s:%d\n", tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
/*    
	if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
		*ld = tLdap_getLd(1);

	} else {
*/

    if (dolock) pthread_mutex_lock( tLdap_getLdMutex(tThread_getKey()) );
	pthread_mutex_lock( &bindMutex );

	// Allocates the LDAP structure
	if (tcSecuredMode) {
		char ldapuri[128];
		int rc;

		sprintf(ldapuri, "ldaps://%s:%d", tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
		TRACE_DEBUG("secured mode with URI=%s\n", ldapuri);

		rc = ldap_initialize( ld, ldapuri );
		if( rc != LDAP_SUCCESS ) {
			TRACE_ERROR("ldap_init error: could not create ld: rc=%d (%s %s:%d)\n", rc, ldap_err2string(rc), tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
			return 1;
		}
	} else {
		if (( *ld = ldap_init( tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId] )) == NULL ) {
			TRACE_ERROR("ldap_init error: could not create ld\n");
	//		ldap_perror( *ld, "ldap_init" );
			return 1;
		}
	}
	if( ldap_set_option( *ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS ) {
		TRACE_ERROR("Could not set LDAP_OPT_PROTOCOL_VERSION %d, error: %d (%s %s:%d)\n", version, (*ld)->ld_errno, ldap_err2string((*ld)->ld_errno), tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
		return 1;
	}
	if ( sctrl && ldap_set_option( *ld, LDAP_OPT_SERVER_CONTROLS, sctrl ) != LDAP_OPT_SUCCESS ) {
		TRACE_ERROR("Could not set control (%:%d)\n", tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
		return 1;
	}

	tStatTimeBegin(0);

	// Bind with simple authentication
	if ( ((rc = ldap_simple_bind_s( *ld, tcClientLDAPBindDN, tcClientLDAPPasswd)) > 0) && !quietOnError) {
		TRACE_ERROR("ldap_simple_bind_s error: %d (%s %s:%d)\n", rc, ldap_err2string(rc), tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
//		ldap_perror( *ld, "ldap_simple_bind_s");
		if (*ld) {
			ldap_unbind_s( *ld );
			*ld = NULL;
			rc = 1;
		}
	}
	TRACE_DEBUG("simplebind result ld=%p \n", *ld);

	tStatTimeEnd(0);

	if ( sctrl ) {
		TRACE_TRAFIC("unset control \n");
		if( ldap_set_option( *ld, LDAP_OPT_SERVER_CONTROLS, NULL ) != LDAP_OPT_SUCCESS ) {
			TRACE_ERROR("Could not unset control (%s:%d)\n", tcServerHost[tcActiveServerId], tcServerPort[tcActiveServerId]);
		}
		TRACE_TRAFIC("unset control ok\n");
	}


	for (i = 0; i<tcWThreadNb;i++){
		if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey())){
			TRACE_TRAFIC("tLdapLdTab[%d].serverHost = %s\n",i,tLdapLdTab[i].serverHost);
			TRACE_TRAFIC("tLdapLdTab[%d].ld = %p\n",i,tLdapLdTab[i].ld);
			tLdapLdTab[i].serverHost = tcServerHost[tcActiveServerId];
			tLdapLdTab[i].serverPort = tcServerPort[tcActiveServerId];
			tLdapLdTab[i].KeyThead = tThread_getKey();
			tLdapLdTab[i].rebind = 0;
			TRACE_TRAFIC("thread = %d on %s:%d\n",tLdapLdTab[i].KeyThead,tLdapLdTab[i].serverHost,tLdapLdTab[i].serverPort);
		}
	}

	tcActiveServerId = (tcActiveServerId+1) % nbserver;
	pthread_mutex_unlock( &bindMutex );
	if (dolock) pthread_mutex_unlock( tLdap_getLdMutex(tThread_getKey()) );

//		tStatActionTime(LDAP_Bind_Rq,0,0,0);
//	}

    return rc;
}

/******************************************************************************/
int unbindRequest (LDAP** ld, char dolock)
/******************************************************************************/
{   
    int rc=0,i,indiceTab;

    if (verbose >= 2)
    	for (i = 0; i<tcWThreadNb;i++){
    	    if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey() )){
    	    	indiceTab=i;
    	    }
    	   }
        TRACE_TRAFIC("tLdap_unbind with %s:%d \n", tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);

/*
	if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
		*ld = NULL;

	} else {
*/
		if (dolock) pthread_mutex_lock( tLdap_getLdMutex(tThread_getKey()) );
		tStatTimeBegin(0);
		
		if (*ld) {
			TRACE_DEBUG("unbind ld=%p \n", *ld);
			rc = ldap_unbind_s( *ld );
			*ld = NULL;
		}
	
		tStatTimeEnd(0);
		if (dolock) pthread_mutex_unlock( tLdap_getLdMutex(tThread_getKey()) );
	
//		tStatActionTime(LDAP_UnBind_Rq,0,0,0);
//	}
    return rc;
}

/******************************************************************************/
/*
 * tLdap_SearchResult - treat a ldap search result.
 *
/******************************************************************************/
int tLdap_SearchResult(
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
	                    tCmdRes         **cmd_res,
                        long            id,
                        int             waitForRc,
						tLdapReqCtx		*reqCtx
	                    )
{
char 	**result, **attrsIte,**attrsValIte;
LDAP 	*ld;

int indiceTab,i;
//ber_len_t 		msg_len;

pthread_mutex_lock( tLdap_getLdMutex(tThread_getKey()) );
    ld = tLdap_getLd( tThread_getKey() );

    //cmd purpose
    if ( *cmd_list != '\0' && reqCtx->rc == LDAP_SUCCESS ) {
        int     i;
        *cmd_res = tAction_mallocCmdRes();
        for(i=0; i < reqCtx->cmds_nb; i++) {
            if ( reqCtx->cmds_ope[i] == KEYWD_COTF || reqCtx->cmds_ope[i] == KEYWD_SCRUBBING || reqCtx->cmds_ope[i] == KEYWD_DYNAMICSCRUBBING ||
				 reqCtx->cmds_ope[i] == KEYWD_IHLR || reqCtx->cmds_ope[i] == KEYWD_CMOD  ) {
                continue;
            } else if ( reqCtx->cmds_ope[i] == CMD_GETASBASE ) {
                if (reqCtx->res == NULL) {
                    TRACE_ERROR("May be corrupted data in search result...\n");
                    break;
                }    
                result = ldap_get_values(ld, reqCtx->res,  reqCtx->cmds_type[0]);
                //Get first value
                if (result != NULL) {
                    TRACE_TRAFIC("CMD_GETASBASE: type: %s, value: %s \n", reqCtx->cmds_type[i], result[0] );

                    (*cmd_res)->filter = strdup("(objectclass=*)");
                    (*cmd_res)->base   = strdup(result[0]); 
                     
                    ldap_value_free(result);
                } else {
                    TRACE_ERROR("Unable to execute getAsBase command: %s not found\n", reqCtx->cmds_type[0]);
                    reqCtx->rc=LDAP_OPERATIONS_ERROR; 
                }
            }
        } 
    }       

    //Verbose purpose
    if (verbose >= 2 || (reqCtx->rc!=waitForRc && !quietOnError)) {

    	for (i = 0; i<tcWThreadNb;i++){
    		if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey() )){
    			indiceTab=i;
    		}
    	}
        
        if (reqCtx->rc!=waitForRc) {
        		TRACE_ERROR("unexpected response on ldid=%d, ld = %p (expected:%d, had:%d=%s %s:%d)\n"
        		    , tLdap_getLdId(tThread_getKey()), ld, waitForRc, reqCtx->rc, ldap_err2string(reqCtx->rc), tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
             char *error_msg = NULL;
			 ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &error_msg);
			 if ( error_msg != NULL ) {
				 if ( *error_msg != '\0' ) {
					 TRACE_ERROR("\tadditional info: %s\n", error_msg );
				 }
				 ldap_memfree( error_msg );
			 }
        } else {
        	TRACE_TRAFIC("ld = %p, dn=%s (%s:%d)\n", ld, base, tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
        }

        if (verbose >= 3 || (reqCtx->rc!=waitForRc && !quietOnError)) {

            //TODO  suppress id of interface, investigation on going...
//            TRACE_ERROR("\tUSER ID\t= %d \n", id);
        	TRACE_TRAFIC("\tbaseDN\t= %s (%s:%d)\n", base, tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
//            TRACE_ERROR("\tscope\t= %d \n", scope);
//            TRACE_ERROR("\tfilter\t= %s \n", filter);
//            for(attrsIte=reqCtx->attrs_type; *attrsIte != NULL; attrsIte++) {
//                TRACE_ERROR("\tattrs\t= %s \n", *attrsIte);
//            }
        }
    }
    
    //Get attrs if differents from * 
    //TODO  EXC RAISED WHEN ATTRS of ATTRS_TYPE not present in result...
    if ( verbose >= 3 && reqCtx->rc == LDAP_SUCCESS  && strcmp("\*",*reqCtx->attrs_type)) {
        TRACE_TRAFIC("    result:\n");
        for(attrsIte=reqCtx->attrs_type; *attrsIte != NULL; attrsIte++) {
			result = ldap_get_values(ld, reqCtx->res, *attrsIte);
            if (reqCtx->res == NULL) {
                TRACE_ERROR("May be corrupted data in search result...\n");
                break;
            }    
            if (result != NULL) {
                for(attrsValIte=result; *attrsValIte != NULL; attrsValIte++) {
                    TRACE_TRAFIC("\t%s = %s\n", *attrsIte, *attrsValIte);
                }
                ldap_value_free(result);
            } else {
                TRACE_ERROR("\t%s not found in response\n", *attrsIte);                        
            }       
        }
        
        //msg_len = ber_get_io_len( res->lm_ber );
    }

    //Free allocated memory
    if (reqCtx->attrs_type) double_free(reqCtx->attrs_type);
    if (reqCtx->cmds_type) double_free(reqCtx->cmds_type);
    if (reqCtx->attrs_value) double_free(reqCtx->attrs_value);
    if (reqCtx->cmds_value) double_free(reqCtx->cmds_value);
    if (reqCtx->attrs_ope) free(reqCtx->attrs_ope);
    if (reqCtx->cmds_ope) free(reqCtx->cmds_ope);
    //if (reqCtx->c) free( reqCtx->c );

    if (reqCtx->res) ldap_msgfree( reqCtx->res );

	if ( reqCtx->ctrls ) {
		TRACE_TRAFIC("tLdap_SearchResult - unset control \n");
		if( ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, NULL ) != LDAP_OPT_SUCCESS ) {
			TRACE_ERROR("Could not unset control\n" );
		}
		TRACE_TRAFIC("tLdap_SearchResult - unset control ok\n");
	}
    
pthread_mutex_unlock( tLdap_getLdMutex(tThread_getKey()) );

    if (reqCtx->rc!=waitForRc)
        // ldap cnx broken for example...
        return reqCtx->rc;
    else
        // ok or waited error
        return 0;
}


/******************************************************************************/   
void tLdap_freeCtx( tLdapReqCtx *reqCtx )
/******************************************************************************/   
{
LDAP            *ld = tLdap_getLd( tThread_getKey() );   

	if (reqCtx->ctrls) {
		TRACE_DEBUG("begin free reqCtx controls \n");  	
		//ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, NULL);
		//ldap_controls_free(ld->ld_options.ldo_sctrls);
		//ld->ld_options.ldo_sctrls = NULL; // il manque ceci dans la stack...
		ldap_controls_free(reqCtx->ctrls); // on nettoye aussi ceci car la stack a fait une copie
		TRACE_DEBUG("end free reqCtx controls \n");  	
	}
	free(reqCtx);
}


/******************************************************************************/
/*
 * tLdap_SearchRequest - initiate a ldap search operation.
 *
 * Parameters:
 *
 *	ld          LDAP descriptor
 *	base		DN of the base object
 *	filter		a string containing the search filter
 *			    (e.g., "(|(cn=bob)(sn=bob))")
 *	attrs		list of attribute types to return for matches
 *	scope		the search scope - one of LDAP_SCOPE_BASE,
 *			    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE
 *	attrsonly	1 => attributes only 0 => attributes and values
 */
/******************************************************************************/
int tLdap_SearchRequest(
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
	                    tCmdRes         **cmd_res,
                        long            id,
                        LDAPControl		**sctrl,
                        int             waitForRc,
                        int				unLimitSize
	                    )
{
tLdapReqCtx		*reqCtx;
LDAP            *ld = tLdap_getLd( tThread_getKey() );   
int				rc,val=0;

    TRACE_TRAFIC("tLdap_SearchRequest - BEGIN - attr_list: %s, cmd: %s, dn: %s \n", attr_list, cmd_list, base);
	if (!ld) return LDAP_CONNECT_ERROR;
    
	if ( (reqCtx = malloc(sizeof(tLdapReqCtx))) == NULL ) {
		TRACE_ERROR("can not create Ldap request ctx for base %s \n", base);
		return LDAP_NO_MEMORY;
	}
	bzero(reqCtx, sizeof(tLdapReqCtx));

	if ( sctrl ) {
		TRACE_TRAFIC("UnlimitSize = %d \n", unLimitSize);
		if (unLimitSize == 1){
			if( ldap_set_option( ld, LDAP_OPT_SIZELIMIT, &val ) != LDAP_OPT_SUCCESS ) {
				TRACE_ERROR("Could not set new limitSize\n" );
			}
		}
		TRACE_TRAFIC("tLdap_SearchRequest - set control \n");
		// add a Control
		reqCtx->ctrls = sctrl;

		//ld->ld_options.ldo_sctrls = sctrl;
		if( ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, sctrl ) != LDAP_OPT_SUCCESS ) {
			TRACE_ERROR("Could not set control\n" );
		}
		TRACE_TRAFIC("tLdap_SearchRequest - set control ok\n");
		TRACE_TRAFIC("sctrl->ldctl_oid = %s sctrl->ldctl_value.bv_val = %s\n", sctrl[0]->ldctl_oid,sctrl[0]->ldctl_value.bv_val);
	}
    
    //Get attrs for Search Attribute Parameter
    rc = attrs_build( NULL, attr_list, &reqCtx->attrs_type, &reqCtx->attrs_value, &reqCtx->attrs_ope, &reqCtx->attrs_nb);    // duplication de l'original    
    //Get attrs for Search Cmd
    if ( *cmd_list != '\0' )
        rc += attrs_build( NULL, cmd_list, &reqCtx->cmds_type, &reqCtx->cmds_value, &reqCtx->cmds_ope, &reqCtx->cmds_nb);  // duplication de l'original 
	if (rc) TRACE_ERROR("Could not set attributes for base=%s\n", base );

    TRACE_TRAFIC("tLdap_SearchRequest - attrs_build ok \n");

	//Launch LDAP Search Operation
    tStatTimeBegin(0);
    //TRACE_TRAFIC("ldap_search_st - scope = %d  filter = %s \n", scope, filter);
    reqCtx->rc = ldap_search_st( ld, base, scope, filter, reqCtx->attrs_type, 0, &ldaptv, &reqCtx->res);
    //TRACE_TRAFIC("ldap_search_st - reqCtx->rc = %d \n", reqCtx->rc);

	tStatTimeEnd(0);

	//Parse result
	rc = tLdap_SearchResult(base, scope, filter, attr_list, cmd_list, cmd_res, id, waitForRc, reqCtx);

	tLdap_freeCtx(reqCtx);

    TRACE_TRAFIC("tLdap_SearchRequest - END \n");
	return rc;
}


/******************************************************************************/
/*
 * tLdap_SearchRequest_async - initiate a ldap search operation in asynchronous mode.
 *
 * Parameters:
 *
 *	ld          LDAP descriptor
 *	base		DN of the base object
 *	filter		a string containing the search filter
 *			    (e.g., "(|(cn=bob)(sn=bob))")
 *	attrs		list of attribute types to return for matches
 *	scope		the search scope - one of LDAP_SCOPE_BASE,
 *			    LDAP_SCOPE_ONELEVEL, LDAP_SCOPE_SUBTREE
 *	attrsonly	1 => attributes only 0 => attributes and values
 */
/******************************************************************************/
int tLdap_SearchRequest_async(
	                    LDAP_CONST char *base,
	                    int             scope,
	                    LDAP_CONST char *filter,
	                    char            *attr_list,
	                    char            *cmd_list,
//	                    tCmdRes         **cmd_res,
//                        long            id,
                        LDAPControl		**sctrl,
//                        int             waitForRc,
						tSleep			*ctx,
                        int				unLimitSize
	                    )
{
LDAP    		*ld;
int				msgid;
int				rc;
tLdapReqCtx		*reqCtx;

	TRACE_TRAFIC("tLdap_SearchRequest - BEGIN - attr_list: %s, cmd: %s, dn: %s \n", attr_list, cmd_list, base);
	if (!ld) return LDAP_CONNECT_ERROR;
    
	if ( (reqCtx = malloc(sizeof(tLdapReqCtx))) == NULL ) {
		TRACE_ERROR("can not create Ldap request ctx for base %s \n", base);
		return LDAP_NO_MEMORY;
	}
	TRACE_DEBUG("new reqCtx=%d \n", reqCtx);  	

	bzero(reqCtx, sizeof(tLdapReqCtx));
	ctx->req = reqCtx;

pthread_mutex_lock( tLdap_getLdMutex(tThread_getKey()) );
    ld = tLdap_getLd( tThread_getKey() );

    if ( sctrl ) {
    	TRACE_TRAFIC("UnlimitSize = %d \n", unLimitSize);
        // add a Control
        reqCtx->ctrls = sctrl;

		if( ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, reqCtx->ctrls ) != LDAP_OPT_SUCCESS ) {
   			TRACE_ERROR("Could not set control\n" );
		}
    }
    
    //Get attrs for Search Attribute Parameter
    rc = attrs_build( NULL, attr_list, &reqCtx->attrs_type, &reqCtx->attrs_value, &reqCtx->attrs_ope, &reqCtx->attrs_nb);  // duplication de l'original 
    //Get attrs for Search Cmd
    if ( *cmd_list != '\0' )
        rc += attrs_build( NULL, cmd_list, &reqCtx->cmds_type, &reqCtx->cmds_value, &reqCtx->cmds_ope, &reqCtx->cmds_nb);  // duplication de l'original 
	if (rc) TRACE_ERROR("Could not set attributes for base=%s\n", base );


	gettimeofday(&reqCtx->time, NULL);

	msgid = ldap_search( ld, base, scope, filter, reqCtx->attrs_type, 0 );
	if ( msgid == -1 ) {
		rc = ld->ld_errno;
//		ldap_perror( ld, "ldap_search" );
		TRACE_ERROR("LdapSearch async immediate error at sending on ld=%d: %d (%s)\n", ld, rc, ldap_err2string(rc));

// EmA,05/03/2008: let tSelect restart the ld
//		treatError_Ld( tLdap_getLdId(tThread_getKey()), rc );

	} else
		rc = insert_Request( tLdap_getLdId(tThread_getKey()), msgid, ctx);

pthread_mutex_unlock( tLdap_getLdMutex(tThread_getKey()) );

	return rc;
}

/******************************************************************************/
/*
 * tLdap_ModifyRequest - initiate a ldap modify operation.
 *
 * Parameters:
 *
 *	ld          LDAP descriptor
 *	dn  		DN of the base object
 *	mods		List of modifications to make.  This is null-terminated
 *			    array of struct ldapmod's, specifying the modifications
 *			    to perform.
 *
 * Example:
 *	LDAPMod	*mods[] = { 
 *			{ LDAP_MOD_ADD, "cn", { "babs jensen", "babs", 0 } },
 *			{ LDAP_MOD_REPLACE, "sn", { "jensen", 0 } },
 *			0
 *		}
 */
/******************************************************************************/

/******************************************************************************/
// written from ldap_modify_ext_s (file modfy.c in LDAB Lib)
// line with ( ld->ld_errno ) is modified cause include of ldap-int.h is needed
// After ldap_modify_ext was called, ld->errno is returned to get LDAP_SERVER_DOWN error code
// but LDAP_TIMEOUT is supposed to be the right error in all the case
// PB: it appears that when timeout, ldap_result returns 0, and ld->ld_errno is set to 5.
//     In such case res is set to NULL by ldap_result causing ldap_result2error failure:
//     tgen: error.c:221: ldap_parse_result: Assertion `r != ((void *)0)' failed.
// Solution: res is tested
int ldap_modify_st( LDAP *ld, LDAP_CONST char *dn, LDAPMod **mods, LDAPControl **sctrl, LDAPControl **cctrl )
/******************************************************************************/	
{
	int		rc;
	int		msgid;
	LDAPMessage	*res;

	rc = ldap_modify_ext( ld, dn, mods, sctrl, cctrl, &msgid );

	if ( rc != LDAP_SUCCESS ) {
		TRACE_ERROR("ldap_modify_ext: WARNING, error #%d received rc=%d\n",ld->ld_errno,rc);
		ld->ld_errno = LDAP_SERVER_DOWN;
		return( ld->ld_errno) ;
		
    }
    /*Previous code
	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 ) { 
		return ( ld->ld_errno );
    }
    */
    if ( ldap_result( ld, msgid, 1, &ldaptv, &res ) == -1 ) {
		return ( ld->ld_errno );
    }
    
    if ( res == NULL )	{	
        //(void) ldap_abandon( ld, msgid );
		ld->ld_errno = LDAP_TIMEOUT;
		return( ld->ld_errno );
	}

	return( result2error( ld, res, 1 ) );
}


/******************************************************************************/
int tLdap_ModifyRequest(
	                    LDAP_CONST char *dn,
	                    char            *attr_list,
						LDAPControl **sctrl
	                    )
/******************************************************************************/
{
    int         rc,i,attrs_nb=0,indiceTab;
    LDAPMod     **mods;
    int         *attrs_ope=NULL;
    char        **attrs_type=NULL;
    char        **attrs_value=NULL;
	char		**attrs_values=NULL;    
    LDAP        *ld = tLdap_getLd( tThread_getKey() );
  
    TRACE_TRAFIC("tLdap_ModifyRequest - BEGIN \n");
	if (!ld) return LDAP_CONNECT_ERROR;
    
    //Build modification structure
    rc = attrs_build( dn, attr_list, &attrs_type, &attrs_value, &attrs_ope, &attrs_nb);  // duplication de l'original 
    mods = (LDAPMod **) malloc( (attrs_nb+1) * sizeof(LDAPMod *) );
    for(i=0; i < attrs_nb; i++) {
        attrs_values = attrsValues_build(attrs_value[i]); 	// duplication de l'original    
        mods[i] = get_modlist_element( attrs_ope[i], attrs_type[i], attrs_values ); // duplication de types et values

		if (attrs_values) double_free(attrs_values);
    }
    mods[attrs_nb]=NULL;
    
    //Launch LDAP Modification Operation          
    tStatTimeBegin(0);                    
	rc = ldap_modify_st( ld, 
		                 dn, 
		                 mods,
		                 sctrl, NULL ) ;
    tStatTimeEnd(0);

    if (rc == LDAP_STRONG_AUTH_REQUIRED){
    	ld = tLdap_getLd( tThread_getKey() );
        if ( ld ) {
        	unbindRequest( &tLdap_getLd(tThread_getKey()), 1 );
        	rc = simpleBindRequest( &tLdap_getLd( tThread_getKey() ), 1, sctrl );
        	TRACE_ERROR("ld = %d, rc=%d (%s) dn=%s\n", ld, rc, ldap_err2string(rc),dn);
        }
     }else {

    //Verbose purpose
    	 if (verbose >= 2 || (rc!=LDAP_SUCCESS && !quietOnError)) {
    		 for (i = 0; i<tcWThreadNb;i++){
    		     if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey() )){
    		     	indiceTab=i;
    		     }
    		 }
    		 TRACE_ERROR("ld = %d, rc=%d (%s %s:%d)\n", ld, rc, ldap_err2string(rc) , tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);

    		 char *error_msg = NULL;
    		 ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &error_msg);
    		 if ( error_msg != NULL ) {
    			 if ( *error_msg != '\0' ) {
    				 TRACE_ERROR("\tadditional info: %s\n", error_msg );
    			 }
    			 ldap_memfree( error_msg );
    		 }
        
    		 if (verbose >= 3 || rc!=LDAP_SUCCESS) {
    			 register LDAPMod        **modsIter;
    			 register struct berval	**cp;
    			 register int            i, j;

    			 TRACE_ERROR("\tdn\t\t= %s\n", dn);
            
    			 for (modsIter = mods, i = 1; *modsIter != NULL; modsIter++, i++) {
    				 TRACE_ERROR("\tmods[%1d] code\t= %1d\n", i, (*modsIter)->mod_op);
    				 TRACE_ERROR("\tmods[%1d] type\t= %s\n", i, (*modsIter)->mod_type);
    				 if ((*modsIter)->mod_bvalues!=NULL) {
    					 for (cp = (*modsIter)->mod_bvalues, j = 1; *cp != NULL; cp++, j++)
                    	TRACE_ERROR("\tmods[%1d] value[%1d]= %s\n", i, j, (*cp)->bv_val);
    				 }
    			 }
    		 }
    	 }
    }

    //Free allocated memory
    //mods free attrs_values
    mods_free (mods, 1);
    if (attrs_type) double_free(attrs_type);
    if (attrs_value) double_free(attrs_value);
    if (attrs_ope) free(attrs_ope);    
    
	
	TRACE_TRAFIC("tLdap_ModifyRequest - END \n");
	       
    return rc; 

}    

/******************************************************************************/
/*
 * tLdap_AddRequest - initiate a ldap add operation.
 *
 * Parameters:
 *
 *	ld          LDAP descriptor
 *	dn  		DN of the base object
 *	mods		List of modifications to make.  This is null-terminated
 *			    array of struct ldapmod's, specifying the modifications
 *			    to perform.
 *
 * Example:
 *	LDAPMod	*mods[] = { 
 *			{ LDAP_MOD_ADD, "cn", { "babs jensen", "babs", 0 } },
 *			{ LDAP_MOD_REPLACE, "sn", { "jensen", 0 } },
 *			0
 *		}
 */
/******************************************************************************/

/******************************************************************************/	
//see ldap_modify_st comment
//from ldap_add_ext_s
int ldap_add_st( LDAP *ld, LDAP_CONST char *dn, LDAPMod **attrs, LDAPControl **sctrl, LDAPControl **cctrl )
/******************************************************************************/	
{

	int		rc;
	int     msgid;
	LDAPMessage	*res;

    TRACE_TRAFIC("ldap_add_ext - BEGIN \n");
    
	rc = ldap_add_ext( ld, dn, attrs, sctrl, cctrl, &msgid );
    
	if ( rc != LDAP_SUCCESS ) {
		ld->ld_errno = LDAP_SERVER_DOWN;
		return( ld->ld_errno) ;
    }

    /* Previous code    
	if ( ldap_result( ld, msgid, 1, (struct timeval *) NULL, &res ) == -1 )
		return( ld->ld_errno );
		
    return( ldap_result2error( ld, res, 1 ) );		
    */
    
    if ( ldap_result( ld, msgid, 1, &ldaptv, &res ) == -1 ) {
		return ( ld->ld_errno );
    }

    if ( res == NULL )	{	
        //(void) ldap_abandon( ld, msgid );
		ld->ld_errno = LDAP_TIMEOUT;
		return( ld->ld_errno );
	}

    rc = result2error( ld, res, 0 );
    ldap_msgfree( res );
    
    TRACE_TRAFIC("ldap_add_ext - END rc: %d \n", rc);
    
	return( rc  );
}


/******************************************************************************/
int tLdap_AddRequest(
	                    LDAP_CONST char *dn,
	                    char            *attr_list,
						LDAPControl **sctrl
	                    )
/******************************************************************************/
{
    int         rc,i,attrs_nb=0,indiceTab;
    LDAPMod     **mods;
    int         *attrs_ope;
    char        **attrs_value, **attrs_values, **attrs_type;    
    LDAP            *ld = tLdap_getLd( tThread_getKey() );   
  
    TRACE_TRAFIC("tLdap_AddRequest - BEGIN \n");
	if (!ld) return LDAP_CONNECT_ERROR;
    
    //Build modification structure
    rc = attrs_build( dn, attr_list, &attrs_type, &attrs_value, &attrs_ope, &attrs_nb);   // duplication de l'original  
    mods = (LDAPMod **) malloc( (attrs_nb+1) * sizeof(LDAPMod *) );
    for(i=0; i < attrs_nb; i++) {
        attrs_values = attrsValues_build(attrs_value[i]);   // duplication de l'original    
        mods[i] = get_modlist_element( attrs_ope[i], attrs_type[i], attrs_values );  // duplication de types et values
																					  
		if (attrs_values) double_free(attrs_values);
    }
    mods[attrs_nb]=NULL;
    
    //Launch LDAP Add Operation          
    tStatTimeBegin(0);                    
	rc = ldap_add_st(   ld, 
		                dn, 
		                mods,
		                sctrl, NULL) ;
    tStatTimeEnd(0);
    
    if (rc == LDAP_STRONG_AUTH_REQUIRED){
        ld = tLdap_getLd( tThread_getKey() );
        if ( ld ) {
            unbindRequest( &tLdap_getLd(tThread_getKey()), 1 );
            rc = simpleBindRequest( &tLdap_getLd( tThread_getKey() ), 1, sctrl );
            TRACE_ERROR("ld = %d, rc=%d (%s) dn=%s\n", ld, rc, ldap_err2string(rc),dn);
        }
    }else {
    //Verbose purpose
    	if (verbose >= 2 || (rc!=LDAP_SUCCESS && !quietOnError)) {
    		for (i = 0; i<tcWThreadNb;i++){
    		    if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey() )){
    		    	indiceTab=i;
    		    }
    		}
    		TRACE_ERROR("ld = %d, rc=%d (%s %s:%d)\n", ld, rc, ldap_err2string(rc) , tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
    		char *error_msg = NULL;
    		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &error_msg);
    		if ( error_msg != NULL ) {
    			if ( *error_msg != '\0' ) {
    				TRACE_ERROR("\tadditional info: %s\n", error_msg );
    			}
    			ldap_memfree( error_msg );
    		}
        
    		if (verbose >= 3 || rc!=LDAP_SUCCESS) {
    			register LDAPMod        **modsIter;
    			register struct berval	**cp;
    			register int            i, j;

    			TRACE_ERROR("\tdn\t\t= %s\n", dn);
            
    			for (modsIter = mods, i = 1; *modsIter != NULL; modsIter++, i++) {
    				TRACE_ERROR("\tmods[%1d] code\t= %1d\n", i, (*modsIter)->mod_op);
    				TRACE_ERROR("\tmods[%1d] type\t= %s\n", i, (*modsIter)->mod_type);
    				if ((*modsIter)->mod_bvalues!=NULL) {
    					for (cp = (*modsIter)->mod_bvalues, j = 1; *cp != NULL; cp++, j++)
    						TRACE_ERROR("\tmods[%1d] value[%1d]= %s\n", i, j, (*cp)->bv_val);
    				}
    			}
    		}
    	}
    }

    //mods free attrs_values
    mods_free (mods, 1);
    if (attrs_type) double_free(attrs_type);
    if (attrs_value) double_free(attrs_value);
    if (attrs_ope) free(attrs_ope);    

	TRACE_TRAFIC("tLdap_AddRequest - END \n");       
    
    return rc; 

}    

/******************************************************************************/
int tLdap_DeleteRequest(
	                    LDAP_CONST char *dn,
						LDAPControl **sctrl
	                    )                
/******************************************************************************/
{
    int         rc,i,attrs_nb=0,indiceTab;
    LDAPMod     **mods;
    int         *attrs_ope;
    char        **attrs_type, **attrsIte;
    char        **attrs_value, **attrs_values;    
    LDAP            *ld = tLdap_getLd( tThread_getKey() );   
  
    TRACE_TRAFIC("tLdap_DeleteRequest - BEGIN \n");
	if (!ld) return LDAP_CONNECT_ERROR;
    
    //Launch LDAP Delete Operation          
    tStatTimeBegin(0);                    

	rc = ldap_delete_ext_s( ld, dn, sctrl, NULL );
	//rc = ldap_delete_s( ld, dn ) ;
    tStatTimeEnd(0);
    
    if (rc == LDAP_STRONG_AUTH_REQUIRED){
       ld = tLdap_getLd( tThread_getKey() );
       if ( ld ) {
           unbindRequest( &tLdap_getLd(tThread_getKey()), 1 );
           rc = simpleBindRequest( &tLdap_getLd( tThread_getKey() ), 1, sctrl );
           TRACE_ERROR("ld = %d, rc=%d (%s) dn=%s\n", ld, rc, ldap_err2string(rc),dn);
       }
    }else {

    //Verbose purpose
    	if (verbose >= 2 || (rc!=LDAP_SUCCESS && !quietOnError)) {
    		for (i = 0; i<tcWThreadNb;i++){
    		    if(tLdapLdTab[i].ld==tLdap_getLd( tThread_getKey() )){
    		    	indiceTab=i;
    		    }
    		}
    		TRACE_ERROR("ld = %d, rc=%d (%s %s:%d)\n", ld, rc, ldap_err2string(rc) ,tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
    		char *error_msg = NULL;
    		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &error_msg);
    		if ( error_msg != NULL ) {
    			if ( *error_msg != '\0' ) {
    				TRACE_ERROR("\tadditional info: %s\n", error_msg );
    			}
    			ldap_memfree( error_msg );
    		}

    		if (verbose >= 3 || rc!=LDAP_SUCCESS) {
    			TRACE_ERROR("\tdn\t\t= %s\n", dn);
    		}
    	}
    }
	TRACE_TRAFIC("tLdap_DeleteRequest - END \n");       
    
    return rc; 

}    


//中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中
//PRIVATE
//中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中中

/******************************************************************************/
int result2error( LDAP *ld, LDAPMessage *r, int freeit )
/******************************************************************************/
{
	int rc, err;
	char *errmsgp;

	rc = ldap_parse_result( ld, r, &err,
		NULL, NULL, &errmsgp, NULL, freeit );
	if (errmsgp && !quietOnError) {
		TRACE_ERROR("\tadditional info = %s\n", errmsgp);
	}

	return err != LDAP_SUCCESS ? err : rc;
}

/******************************************************************************/
LDAPMod **   get_modlist( int mod_op, char *mod_type, char **values )
/* From LDAP lib */
/* for modifications
typedef struct ldapmod {
	int		mod_op;

#define LDAP_MOD_ADD		((ber_int_t) 0x0000)
#define LDAP_MOD_DELETE		((ber_int_t) 0x0001)
#define LDAP_MOD_REPLACE	((ber_int_t) 0x0002)
#define LDAP_MOD_BVALUES	((ber_int_t) 0x0080)

	char		*mod_type;
	union mod_vals_u {
		char		**modv_strvals;
		struct berval	**modv_bvals;
	} mod_vals;
#define mod_values	mod_vals.modv_strvals
#define mod_bvalues	mod_vals.modv_bvals
} LDAPMod;
*/

/* structure for returning a sequence of octet strings + length 
typedef struct berval {
	ber_len_t	bv_len;
	char		*bv_val;
} BerValue;
*/
/******************************************************************************/
{
	int             num;
	LDAPMod		    tmp;
	LDAPMod		    **result;
	struct berval	**bvals;

    result = NULL;
    tmp.mod_op = mod_op;
    tmp.mod_type = strdup(mod_type);	
    tmp.mod_values = values;
    if ( tmp.mod_values != NULL ) {
        int	i;

        for ( i = 0; tmp.mod_values[i] != NULL; ++i )
				;
        bvals = (struct berval **)calloc( i + 1, sizeof( struct berval *));
        for ( i = 0; tmp.mod_values[i] != NULL; ++i ) {
		    
            bvals[i] = (struct berval *)malloc(sizeof( struct berval ));
            bvals[i]->bv_val = tmp.mod_values[i];
            bvals[i]->bv_len = strlen( tmp.mod_values[i] );
        }
        tmp.mod_bvalues = bvals;
        tmp.mod_op |= LDAP_MOD_BVALUES;
	}
	result = (LDAPMod **) malloc( 2 * sizeof(LDAPMod *) );
	result[0] = (LDAPMod *) malloc( sizeof(LDAPMod) );
	*(result[0]) = tmp;	/* struct copy */
		
	result[1] = NULL;

	return( result );
}

/******************************************************************************/
LDAPMod *   get_modlist_element( int mod_op, char *mod_type, char **values )
// Note that type&values are strdup, U will have to free it
/******************************************************************************/
{
	int             num;
	LDAPMod		    *result;
	struct berval	**bvals;

	result = (LDAPMod *) malloc( sizeof(LDAPMod) );
    result->mod_op = mod_op;
    result->mod_type = strdup(mod_type);	
    result->mod_values = values;
    if ( values ) {
        int	i;

        for ( i = 0; values[i]; ++i )
				;
        bvals = (struct berval **)calloc( i + 1, sizeof( struct berval *));
        for ( i = 0; values[i]; ++i ) {
		    
            bvals[i] = (struct berval *)malloc(sizeof( struct berval ));
            bvals[i]->bv_val = strdup(values[i]);
            bvals[i]->bv_len = strlen( values[i] );
        }
        result->mod_bvalues = bvals;
        result->mod_op |= LDAP_MOD_BVALUES;
	}
	
	return( result );
}

/******************************************************************************/
/*
 * free a null-terminated array of pointers to mod structures. the
 * structures are freed, not the array itself, unless the freemods
 * flag is set.
 */
 /* From LDAP lib */
void  mods_free( LDAPMod **mods, int freemods )
/******************************************************************************/
{
	int	i;

	if ( mods == NULL )
		return;

	for ( i = 0; mods[i] != NULL; i++ ) {
		if ( mods[i]->mod_op & LDAP_MOD_BVALUES ) {
			if( mods[i]->mod_bvalues != NULL )
				ber_bvecfree( mods[i]->mod_bvalues );

		} else if( mods[i]->mod_values != NULL ) {
			free( mods[i]->mod_values );
		}

		if ( mods[i]->mod_type != NULL ) {
			free( mods[i]->mod_type );
		}

		free( (char *) mods[i] );
	}

	if ( freemods ) {
		free( (char *) mods );
	}
}


/**********************************************************************************************/
int  attrs_build(   char * dn,
                    char * _attr_list,
                    char ***_attrs_type,
					char ***_attrs_value,
					int **_attrs_ope,
                    int  * _attrs_nb)
/**********************************************************************************************/
{
    char **attrs_type;
    char **attrs_value;
    int  *attrs_ope;
    int  attrs_size=1, attr_list_size;
    char *attr_list, *str_attr, *str_attr_next, *p;
    int  i,rc;
    
    //Caveat: do not work on original string
    attr_list=strdup(_attr_list);
    
    TRACE_TRAFIC("attrs_build - attribute list: %s \n",attr_list);
      
    //Attrs number = (ATTR_DELIMITER +1) and mind that '\0' is the last one
    attr_list_size=strlen(attr_list);
    for ( p = &attr_list[0]; p < &attr_list[attr_list_size-1]; p++ ) {
        if ( *p == ATTR_DELIMITER)
            attrs_size++;
	} 
	
	//Malloc Attrs type, Attrs value, Attrs ope
    attrs_type = (char **)calloc(attrs_size+1, sizeof(char*));
    attrs_value = (char **)calloc(attrs_size+1, sizeof(char*));
    attrs_ope = (int *)calloc(attrs_size+1, sizeof(int));
    
    //_attrs_type points on the start of the list
    *_attrs_type=attrs_type;
    *_attrs_value=attrs_value;
    *_attrs_ope=attrs_ope;

    //Start at the beginning..
    str_attr=attr_list;
    for( i=0; i< attrs_size; i++) {   
        TRACE_DEBUG("attrs_build works on %s\n", str_attr);
        
	    // skip space between start of string str_attr, str_attr points on current attr
        while ( isspace( (unsigned char) *str_attr ) ) {
            str_attr++;
        }        
        
        //Get next attribute
        str_attr_next = strchr( str_attr, ATTR_DELIMITER );
        if ( str_attr_next == NULL ) {
            //last attr
            str_attr_next=&(attr_list[attr_list_size+1]);
        } else {
            //set it to '\0' and skip it
            *str_attr_next++='\0';
        }       

        //str_attr_next points on next char after ATTR_DELIMITER or on (last char+2) of the original string
        // trim any space between current attr and ; */
        for ( p = &(str_attr_next[-2]); p > str_attr && isspace( * (unsigned char *) p ); p-- ) {
            *p = '\0';                   
	    }    
          
        //Get current ope if it is specified, and skip it
        if ( (p = strchr( str_attr, ATTR_ACTION_SCOPE )) == NULL ) {
            //no current operation, this is an add operation
            attrs_ope[i] = LDAP_MOD_BVALUES;
        } else {
            if ( (strstr( str_attr, "add") ) != NULL) {
               attrs_ope[i] = LDAP_MOD_ADD;
            } else { 
                if ( (strstr( str_attr, "delete") ) != NULL) {
                    attrs_ope[i] = LDAP_MOD_DELETE;
                } else {
                    if ( (strstr( str_attr, "replace") ) != NULL) {
                        attrs_ope[i] = LDAP_MOD_REPLACE;
                    }
                    else { 
                        if ( (strstr( str_attr, KEYWD_GETASBASE) ) != NULL) {
                            attrs_ope[i] = CMD_GETASBASE;
                        }
						//default modify operation
                        attrs_ope[i] = LDAP_MOD_ADD;
                    }
                 } 
            }   
            TRACE_TRAFIC("attrs_build - ope = %s \n", str_attr);
            //str_attr=&(p[1]);
            // trim any space between ATTR_ACTION_SCOPE and next field */
            for ( str_attr = &(p[1]); isspace( * (unsigned char *) str_attr ); str_attr++ ) ;
        }        
                          
        //Get attribute Type and Value, test rc...
        rc = attrTypeValue_explode(dn, str_attr, &attrs_type[i], &attrs_value[i]);  // duplication PUIS substition
        TRACE_TRAFIC("attrs_build - attr[%d]: type = %s, value = %s \n",i, attrs_type[i], attrs_value[i]);
        
        //set current attribute to next one
        str_attr=str_attr_next;   
        
    }
    
    attrs_type[attrs_size] = NULL   ;
    attrs_value[attrs_size] = NULL  ;
    attrs_ope[attrs_size] = NULL    ;
    *_attrs_nb=attrs_size           ;
    
    free (attr_list);
           
    return 0;
	                
} 

/******************************************************************************/
char * attrTypeValue_getWhat( char * attrTypeValue, char token, int what )
/******************************************************************************/
{
    char                    *str_val, *p;
    char                    *l_attrTypeValue, *l_what;
	
	l_attrTypeValue = strdup(attrTypeValue);
	TRACE_TRAFIC("attrTypeValue_getWhat - %s of %s \n", (what == whatIsValue)? "value":"type", attrTypeValue);
	        
    //Get attribute type(s) and attribute value(s) of the attrTypeValue
    str_val = strchr( l_attrTypeValue, token );
	if ( str_val == NULL ) {
	    free (l_attrTypeValue);
	    return NULL;
	}
	
    //Trim any space between type and = 
	for ( p = &str_val[-1]; p > l_attrTypeValue && isspace( * (unsigned char *) p ); p-- ) {
        *p = '\0';
	}
	
	if (what == whatIsType) {
	    l_what = strdup(p);
	} else {   
	    *str_val++ = '\0';

        //Skip space between = and value 
        while ( isspace( (unsigned char) *str_val ) ) {
            str_val++;
        }
	
	    //No Value	        
        if ( *str_val == '\0' ) {
            free (l_attrTypeValue);
            return NULL;
        }
        l_what = strdup(str_val);
	}    
    free (l_attrTypeValue);
    
    TRACE_TRAFIC("attrTypeValue_getWhat - %s is %s \n", (what == whatIsValue)? "value":"type", 
	                                                    (l_what == NULL)? "NULL": l_what)  ;
    return l_what;
}

/******************************************************************************/   
int attrTypeValue_explode( char * dn, char *  _attrTypeValue, char ** _attrType, char ** _attrValue )
//_attrValue is set to NULL if no value
/******************************************************************************/   
{
                                        
    char    *str_val, *p;
    int     noAttrValue=0;
    
	TRACE_TRAFIC("attrTypeValue_explode - %s \n", _attrTypeValue )  ;

    //Get attribute value(s)
    str_val = strchr( _attrTypeValue, ATTR_EQUALITY );
    if ( str_val == NULL )
        noAttrValue=1;      
	
    // trim any space between type and = */
    if (!noAttrValue) {
        for ( p = &str_val[-1]; p > _attrTypeValue && isspace( * (unsigned char *) p ); p-- ) {
            *p = '\0';
        }
        *str_val++ = '\0';

        //str_val point on next char after ATTR_EQUALITY
        //skip space between = and value
        while ( isspace( (unsigned char) *str_val ) ) {
            str_val++;
        }
        
        if ( *str_val == '\0' )
	        noAttrValue=1;   
	}	        
	     
	if ( noAttrValue )     
	    *_attrValue= NULL;     
	else {

		if ( strstr(str_val,KEYWD_RDN) ) {
			//Relace KEYWD_RDN by RDN from DN
			char        **dne;
			char        **rdn;
			char 		*rdnValue;
			dne = ldap_explode_dn( dn, 0 );
			rdn = ldap_explode_rdn( dne[0], 0 );
			//Guess only one RDN value...  
			rdnValue = attrTypeValue_getWhat( rdn[0], '=', whatIsValue );
			  
			*_attrValue = strsub(str_val, KEYWD_RDN, rdnValue);

			double_free(dne);
			double_free(rdn);
			free(rdnValue);

		} else if ( strstr(str_val,KEYWD_DN) ) {
				//Relace KEYWD_DN by DN
				char        **dne;
				char 		*dnValue;
				dne = ldap_explode_dn( dn, 0 );
				//Guess only one DN value...  
				dnValue = attrTypeValue_getWhat( dne[0], '=', whatIsValue );
			  
				*_attrValue = strsub(str_val, KEYWD_DN, dnValue);

				double_free(dne);
				free(dnValue);

		} else {
			// no substitution
			*_attrValue=strdup(str_val);
		}

	}              		 
	*_attrType=strdup(_attrTypeValue);  
	
    return 0;
                               
}   

/******************************************************************************/   
char ** attrsValues_build( char * _attrValue )
//return NULL if no values
/******************************************************************************/   
{
    int     i,valueNb=1;
    char    *attrs_value, *p, *str_val;
    char    **attrs_values;
   
    //case of no value
    if ( _attrValue == NULL ) {
        return NULL;    
    }   
    
    //Evaluate values number
    attrs_value=_attrValue;    
    while (attrs_value) {                           
        attrs_value = strchr( attrs_value, ATTR_VALUE_SEPARATOR );
        if ( attrs_value ) {
            valueNb++;
			// saute les s廧arateurs accol廥
            while ( *attrs_value == ATTR_VALUE_SEPARATOR)
                attrs_value++;
       }   
    }    
    
	//Malloc Attrs values, mind that '\0' is the last one
    attrs_values = (char **)malloc( (valueNb+1) * sizeof(char*) );
    
    //Caveat: do not work on original string
    attrs_value=_attrValue;
    
    //Build attribute valueS, value by value
	TRACE_TRAFIC("attrs_values = %s \n", attrs_value )  ;

    for(i=0; *attrs_value && i<valueNb; i++) {
		p = attrs_value;

		// supprime les blancs de d嶵ut
		while (isspace((unsigned char)*p) || *p==ATTR_VALUE_SEPARATOR) p++ ;
		// marque le d嶵ut de la valeur
        str_val = p;

		// cherche la fin
		while (*p && *p!=ATTR_VALUE_SEPARATOR) p++ ;
		// marque le d嶵ut de la prochaine
		attrs_value = p; // peut etre NULL

		// supprime les blancs de fin
		while (isspace((unsigned char) *--p )) *p = 0 ;

		TRACE_TRAFIC("attrs_values[%d] = %s \n", i, str_val )  ;
        attrs_values[i]=strdup(str_val);
    }
                   
    attrs_values[valueNb]=NULL;
    
    return attrs_values;

}

/******************************************************************************/ 
char *  strsub (const char *str, const char *replace, const char *with)
//string substitute: in "str", "replace" is replaced by "with"
/******************************************************************************/ 
{
  char   *rp;
  char   *pos;
  size_t bufsiz;

  if ((pos = strstr(str, replace)) == NULL)
    return NULL;

  bufsiz = strlen(str) - strlen(replace) + strlen(with);
  if ((rp = calloc(bufsiz + 1, sizeof(char))) == NULL)
    return NULL;

  strncpy(rp, str, pos - str);
  strcat(rp, with);
  strcat(rp, pos + strlen(replace));

  return rp;
}


/******************************************************************************/   
void double_free( char ** _toFree )
/******************************************************************************/   
{
    int i;

    for ( i = 0; _toFree[i] != NULL; i++ ) {
            free( (char *) _toFree[i] );
        }
    free( (char *) _toFree );
}

/******************************************************************************/
void print_list(tLdapList *newresp)
/******************************************************************************/
{
tLdapList   *curr = newresp;

	if (!curr) {
		TRACE_DEBUG("Empty list\n");
		//return;
	}

	TRACE_DEBUG("Last msgid=%d\n", curr->last->msgid);
	while ( curr ) {
		TRACE_DEBUG("-> msgid=%d, sleepCtx=%d, req=%d\n", curr->msgid, curr->sleepCtx, curr->sleepCtx->req);
		curr = curr->next;
	}

}

/******************************************************************************/
int insert_Request(int ldId, int msgid, tSleep *ctx)
/******************************************************************************/
{
tLdapList *newresp;

	TRACE_TRAFIC("Insert request (msgid=%d)\n", msgid);

	if ( (newresp = (tLdapList *)malloc(sizeof(tLdapList))) == NULL) {
		TRACE_ERROR("Could not reserve space for asynchronous LdapSearch response\n");
		return 1;
	} else {
		newresp->next = NULL;
		newresp->msgid = msgid;
		newresp->sleepCtx = ctx;

//		pthread_mutex_lock( tLdapLdTab[ldId].mutex );

		if ( tLdapLdTab[ldId].ldReq ) {
			// chain at the end for perf reasons
			tLdapLdTab[ldId].ldReq->last->next = newresp;
		} else {
			tLdapLdTab[ldId].ldReq = newresp;
		}
		tLdapLdTab[ldId].ldReq->last = newresp;

//		pthread_mutex_unlock( tLdapLdTab[ldId].mutex );
	}

	if (verbose>=3)
		print_list(tLdapLdTab[ldId].ldReq);

	return 0;
}

/******************************************************************************/
static int insert_Response(int ldId, tLdapList *newresp)
/******************************************************************************/
{
	TRACE_TRAFIC("Insert response (msgid=%d)\n", newresp->msgid);

	newresp->next = NULL;

//	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	if ( tLdapLdTab[ldId].ldResp ) {
		// chain at the end for perf reasons
		tLdapLdTab[ldId].ldResp->last->next = newresp;
	} else {
		tLdapLdTab[ldId].ldResp = newresp;
	}
	tLdapLdTab[ldId].ldResp->last = newresp;

//	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

	if (verbose>=3)
		print_list(tLdapLdTab[ldId].ldResp);

	return 0;
}


/******************************************************************************/
tSleep *getAndMove_RequestToResponse(int ldId, int msgid, LDAPMessage *res, int rc, long *tm)
/******************************************************************************/
{
tLdapList   *curr, *first, *pred;
tSleep 			*sleepCtx = NULL;
struct timeval 	end;

	TRACE_TRAFIC("Move a msg from ReqList to RespList (msgid=%d)\n", msgid);

//	TRACE_DEBUG("Lock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	// look for response in request list attached to Ld
	first = curr = tLdapLdTab[ldId].ldReq;
	pred = NULL;
	while ( curr ) {
		if (curr->msgid == msgid) {
			sleepCtx = curr->sleepCtx;

			// delete object
			if (curr == first) {
				//remove first elem
				tLdapLdTab[ldId].ldReq = curr->next;
				// was it the only elem ?
				if (tLdapLdTab[ldId].ldReq) tLdapLdTab[ldId].ldReq->last = first->last;
			} else if (curr == first->last) {
				// remove last elem (which is not the first one!)
				first->last = pred;
				pred->next = NULL;
			} else {
				pred->next = curr->next;
			}

			insert_Response(ldId, curr);

			sleepCtx->req->res = res;
			sleepCtx->req->rc  = rc;

			// calculate response time
			gettimeofday(&end, NULL);
			*tm = 1000000 * (end.tv_sec - sleepCtx->req->time.tv_sec) + (end.tv_usec - sleepCtx->req->time.tv_usec);

			break;
		}
		pred = curr;
		curr = curr->next;
	}

	if (verbose>=3) {
		print_list(tLdapLdTab[ldId].ldReq);
		print_list(tLdapLdTab[ldId].ldResp);
	}

//	TRACE_DEBUG("Unock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

   	return sleepCtx;
}


/******************************************************************************/
tSleep *getAndRemove_firstResponse(int ldId)
/******************************************************************************/
{
tLdapList   *curr, *first, *pred;
tSleep 		*sleepCtx = NULL;

	//TRACE_TRAFIC("Check if a new Response is available\n");

//	TRACE_DEBUG("Lock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	// take first elem
	curr = tLdapLdTab[ldId].ldResp;

	// remove it from list
	if ( curr ) {
		sleepCtx = curr->sleepCtx;
		if (curr->next) curr->next->last = curr->last;
		tLdapLdTab[ldId].ldResp = curr->next;
		free(curr);
	}

	if (verbose>=3)
		print_list(tLdapLdTab[ldId].ldResp);

//	TRACE_DEBUG("Unock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

	return sleepCtx;
}


/******************************************************************************/
void treatError_Ld(int ldId, int myerrno)
/******************************************************************************/
{
tLdapList   	*curr, *first, *pred;
struct timeval 	end;
long 			tm = 0;
LDAP *			oldLd = tLdapLdTab[ldId].ld;
int 			nb;

//	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	// kind of errors that require a ld restart
	switch (myerrno) {
		case LDAP_SERVER_DOWN:
		case LDAP_LOCAL_ERROR:
		case 5:
			tLdap_abandon( &tLdapLdTab[ldId].ld, 0 );
			TRACE_ERROR("Restarted ldid=%d, ld=%p -> %p\n", ldId, oldLd, tLdapLdTab[ldId].ld);

			if (!tLdapLdTab[ldId].ldReq) break;	// no pending requests: is it possible ?

			// set rc to all pending requests on that ld
			curr = tLdapLdTab[ldId].ldReq;
			nb=0;
			while ( curr && curr->sleepCtx && curr->sleepCtx->req) {
				tSleep *sleepCtx = curr->sleepCtx;

				sleepCtx->req->rc = myerrno;

				// calculate response time
				gettimeofday(&end, NULL);
				tm = 1000000 * (end.tv_sec - sleepCtx->req->time.tv_sec) + (end.tv_usec - sleepCtx->req->time.tv_usec);
				tStatActionTime(LDAP_Search_Rq, myerrno, 0, tm);

				curr = curr->next;
				nb++;
			}
			TRACE_ERROR("Marked %d requests with rc=%d\n", nb, myerrno);

			// move all elements of ReqList at the end of RespList
			if (tLdapLdTab[ldId].ldResp) {
				tLdapLdTab[ldId].ldResp->last->next = tLdapLdTab[ldId].ldReq;
				tLdapLdTab[ldId].ldResp->last = tLdapLdTab[ldId].ldReq->last;
			} else {
				tLdapLdTab[ldId].ldResp = tLdapLdTab[ldId].ldReq;
				tLdapLdTab[ldId].ldReq = NULL;
			}
			break;

		case LDAP_TIMEOUT:
			tStatActionTime(LDAP_Search_Rq, myerrno, 1, tcLdapTimeout*1000000);
			break;

		default:
//			TRACE_ERROR("Ldap Search error -> ldId=%d, ld=%d\n", ldId, tLdapLdTab[ldId].ld);
			tStatActionTime(LDAP_Search_Rq, myerrno, 0, 1000);
			break;
	}

//	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );
}

/******************************************************************************/
int getAndRemove_Request(int ldId, tSleep *sleepCtx)
/******************************************************************************/
{
tLdapList   *curr, *first, *pred;
int			rc=0;

//	TRACE_DEBUG("Lock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	// look for response in request list attached to Ld
	TRACE_TRAFIC("Look for a resp msg in list\n");
	first = curr = tLdapLdTab[ldId].ldReq;
	pred = NULL;
	while ( curr ) {
		if (curr->sleepCtx == sleepCtx) {

			// delete object
			if (curr == first) {
				//remove first elem
				tLdapLdTab[ldId].ldReq = curr->next;
				// was it the only elem ?
				if (tLdapLdTab[ldId].ldReq) tLdapLdTab[ldId].ldReq->last = first->last;
			} else if (curr == first->last) {
				// remove last elem (which is not the first one!)
				first->last = pred;
				pred->next = NULL;
			} else {
				pred->next = curr->next;
			}
			free(curr);
			rc = ldap_abandon( tLdapLdTab[ldId].ld, curr->msgid );
			if (rc)
				TRACE_ERROR("ldap_abandon error on ld=%d, rc=%d (%s)\n", tLdapLdTab[ldId].ld, rc, ldap_err2string(rc) );
			break;
		}
		pred = curr;
		curr = curr->next;
	}

//	TRACE_DEBUG("Unlock mutex %d\n", tLdapLdTab[ldId].mutex);
	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

   	return rc;
}







/******************************************************************************/
tSleep *get_Request(int ldId, int msgid)		// NOT USED
/******************************************************************************/
{
tLdapList   *curr;
tSleep 			*sleepCtx = NULL;

	pthread_mutex_lock( tLdapLdTab[ldId].mutex );

	// look for response in request list attached to Ld
	TRACE_TRAFIC("Look for a resp msg in list\n");
	curr = tLdapLdTab[ldId].ldReq;
	while ( curr ) {
		if (curr->msgid == msgid) {
			sleepCtx = curr->sleepCtx;
			break;
		}
		curr = curr->next;
	}

	pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

   	return sleepCtx;
}



