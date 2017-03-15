#include <errno.h>     /* strerror, errno */

#include "tconf.h"
#include "tthread.h"
#include "texec.h"
#include "tdebug.h"
#include "tselect.h"

pthread_key_t       tThreadIdKey = 0;	// (type is unsigned int)
tThreadConf*        tThreadConfTab;
int                 tStatThreadId;


// for pthread_cleanup_push
extern pthread_mutex_t  radomMutex;
extern pthread_mutex_t  eapMutex;
extern pthread_mutex_t  *tTimerMutex;
extern pthread_mutex_t  tUserMutex;
extern pthread_mutex_t  schedulingMutex;
extern pthread_mutex_t  schedulingMutexI;
extern pthread_mutex_t  tstatMutexI;


/******************************************************************************/
void tKeyDestructor(void * param)
/******************************************************************************/
{

}

/******************************************************************************/
void *tThreadCleanUpMutex(void *arg)
/******************************************************************************/
{
    pthread_mutex_unlock(&radomMutex);
    pthread_mutex_unlock(&eapMutex);
    pthread_mutex_unlock(tTimerMutex);
    pthread_mutex_unlock(&tUserMutex);
    pthread_mutex_unlock(&schedulingMutex);
    pthread_mutex_unlock(&schedulingMutexI);
    pthread_mutex_unlock(&tstatMutexI);
}

/******************************************************************************/
int tThreadInit()
// called by Main Thread
/******************************************************************************/
{
    pthread_t         tid;
    int               status;
    int               threadId;
        
    if (verbose >= 1)
        TRACE_CORE("init starts\n" );
          
    if ( pthread_key_create( &tThreadIdKey, NULL) < 0) {
        TRACE_CRITICAL("init exit: pthread_key_create failed! Error=%d", status,"\n");
        return 1; 
    }
    // no need to assign the value of the Key !
    // and the same Key can be used by different threads to store different data !

    /* total thread Nb = Main Thread(1) + Stat Thread(1) + Select Thread(2) + W Threads(tcWThreadNb) */ 
    if ( (tThreadConfTab = malloc( sizeof(tThreadConf) * (tcWThreadNb+WORKTHR) ) ) == NULL ) {
        TRACE_CRITICAL("init exit: tThreadConfTab init failed! \n");
        return 1; 
	}
    bzero( tThreadConfTab, sizeof(tThreadConf) * (tcWThreadNb+WORKTHR) );


    /* Set tThreadConf for Main thread (key=0) */
    tid=pthread_self();
    tThreadConfTab[MAINTHR].tid = tid;

	tThread_setKey(MAINTHR);
    tThread_getState(MAINTHR) = RUNNING;
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

//	pthread_cleanup_push( tThreadCleanUpMutex, MAINTHR );
//	}   // <<<--- This is a bug in pthread.h !!!

 	// create son's threads (they are suspended for the moment)
	if (tThreadStart(0) != 0)
        return 1;

    return 0;
}

/******************************************************************************/
int tThreadStart(int num)
/******************************************************************************/
{
pthread_t         tid;
pthread_attr_t    attr;
size_t            size;
int               status, rc;
int               threadId;

    TRACE_CORE("Start of children thread creation (%d)\n", num );
    
    pthread_attr_init( &attr );
    pthread_attr_getstacksize( &attr, &size );
    //if( size < 64*1024 )
    //    pthread_attr_setstacksize( &attr, 64*1024 );

	if (num==0 || num==STATTHR) {
		/* create the stat thread */
		if ( (status = pthread_create( (pthread_t*)&tThreadConfTab[STATTHR].tid, &attr, tThreadStatEntryPoint, (void *)STATTHR)) < 0) {
			TRACE_CRITICAL("tthread: STAT pthread_create failed! Error=%d \n", status);
			return 1;
		}
	}

	if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
		/* create the select threads */
		for (threadId=SLCTTHR ; threadId<(SLCTTHR+tcLdapBindNb) ; threadId++) {
			if (num==0 || num==threadId) {
				if ( (status = pthread_create( (pthread_t*)&tThreadConfTab[threadId].tid, &attr, tThreadSelectEntryPoint, (void *)threadId)) < 0) {
					TRACE_CRITICAL("tthread: SELECT pthread_create failed! Error=%d \n", status);
					return 1;
				}
			}
		}
	}
	
    /* create the worker threads */
    for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		if (num==0 || num==threadId) {
			if ( (status = pthread_create( (pthread_t*)&tThreadConfTab[threadId].tid, &attr, tThreadWorkerEntryPoint, (void *)threadId)) < 0) {
				TRACE_CRITICAL("tthread: WORKER pthread_create failed! Error=%d \n", status);
				return 1;
			}
		}
    }

	TRACE_CORE("End of children thread creation\n" );

//	TRACE_CORE("My priority is: %d\n", getpriority(0,0));

    pthread_attr_destroy( &attr );
    return 0;
}

/******************************************************************************/
int tThreadMaskMainSignals(char maskpipe)
//Signal Management: mask the set of signal used by thread #0 (Main thread)
/******************************************************************************/
{
sigset_t            signalSet = { 0 };
int					rc=0;

	sigemptyset( &signalSet);

	sigaddset( &signalSet, SIGINT );
	sigaddset( &signalSet, SIGTSTP);
	sigaddset( &signalSet, SIGURG);
	if (maskpipe) sigaddset( &signalSet, SIGPIPE);

	if ( (rc=pthread_sigmask(SIG_BLOCK, &signalSet, NULL)) ) {
		perror("tthread: pthread_sigmask failed");
	}

	return rc;
}


/******************************************************************************/
void *tThreadWorkerEntryPoint (void *param)
/******************************************************************************/
{
int       rc, key = (int)param;

	tThread_setKey(key);
    tThread_getState(key) = SUSPEND;

	tThreadMaskMainSignals(1);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
//    pthread_cleanup_push( tThreadCleanUpMutex, key );
//    }   // <<<--- This is a bug in pthread.h !!!

//	TRACE_CORE("My priority is: %d\n", getpriority(0,0));

    tExec(key);
}

/******************************************************************************/
void *tThreadStatEntryPoint (void *param)
/******************************************************************************/
{
int       rc;

    TRACE_CORE("Stat   thread: %d (%d) is running\n", STATTHR, pthread_self());

	tThread_setKey(STATTHR);
    tThread_getState(STATTHR) = SUSPEND;

	tThreadMaskMainSignals(0);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
//	pthread_cleanup_push( tThreadCleanUpMutex, STATTHR );
//	}   // <<<--- This is a bug in pthread.h !!!

//	TRACE_CORE("My priority is: %d\n", getpriority(0,0));

	tStat(STATTHR);
}


/******************************************************************************/
void *tThreadSelectEntryPoint (void *param)
/******************************************************************************/
{
int       rc, key = (int)param;

pthread_t           thid;
struct sched_param  sched;
pthread_attr_t      attr;
int 				ret_val;

    TRACE_CORE("Select thread: %d (%d) is running\n", key, pthread_self());


	tThread_setKey(key);
    tThread_getState(key) = SUSPEND;

	tThreadMaskMainSignals(1);
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
//	pthread_cleanup_push( tThreadCleanUpMutex, key );
//	}   // <<<--- This is a bug in pthread.h !!!

/*
	// increase thread prio (renice -10)
		// we must use Fifo or RoundRobin policy => must be done now, at thread creation
		if ( pthread_attr_setschedpolicy(&attr, SCHED_FIFO) != 0 ) {
			TRACE_CORE("pthread_attr_setschedpolicy system call failed : %s\n", strerror(errno));
		}
		
		sched.sched_priority = 50;
		if( pthread_attr_setschedparam(&attr,&sched) !=0 ) {
			TRACE_CORE("pthread_attr_setschedparam system call failed : %s\n", strerror(errno));
		}
//	setpriority(0,0,-10);
	TRACE_CORE("My priority is: %d\n", getpriority(0,0));
*/

	tSelect(key);
}

