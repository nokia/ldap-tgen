
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <stddef.h>
#include <pthread.h>
#include <sys/timeb.h> 

#include "ldap.h"
#include "taction.h"

typedef int     tThreadState;
#define SUSPEND		0
#define RUNNING		1
#define ENDING		2
#define FINISHED    3
#define ENDING2		4

#define MAINTHR		0
#define STATTHR		1
#define SLCTTHR		2	// 2 to 11
#define WORKTHR		12

typedef struct  tThreadConf {
//    LDAP *				ld;
    int	            	radSockFd;
    tThreadState    	state;
    pthread_t       	tid;
    struct timeval    	timeBeg[2];
    struct timeval    	timeEnd[2];
} tThreadConf ;


extern pthread_key_t    tThreadIdKey;
extern tThreadConf*     tThreadConfTab;

int  tThreadInit();
int  tThreadStart(int num);
void *tThreadWorkerEntryPoint (void *param);
void *tThreadStatEntryPoint (void *param);
void *tThreadSelectEntryPoint (void *param);


#define tThread_getKey()      \
                ( (int)pthread_getspecific(tThreadIdKey) )

#define tThread_setKey(KEY)     \
				( pthread_setspecific(tThreadIdKey, (const void*)(KEY) ) )




#define tThread_getRadSockFd(TID2)      \
                ( tThreadConfTab[TID2].radSockFd )

#define tThread_getState(TID2)      \
                ( tThreadConfTab[TID2].state )

#define tThread_getTimeBeg(TID2, idx)      \
                (&( tThreadConfTab[TID2].timeBeg[idx] ))

#define tThread_getTimeEnd(TID2, idx)      \
                (&( tThreadConfTab[TID2].timeEnd[idx] ))

#define tThread_getStatThread()      \
                ( tThreadConfTab[STATTHR].tid )
                
#define tThread_getMainThread()      \
                ( tThreadConfTab[MAINTHR].tid )

#define tThread_getWorkThread(TID2)      \
                ( tThreadConfTab[TID2].tid )
                
#define tThread_getId2()      \
                ( ((int *) pthread_getspecific(*tThreadIdKey)) )


