#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include "limits.h"

#include "tconf.h"
#include "tdebug.h"
#include "tsce.h"
#include "tldap.h"
#include "tthread.h"
#include "texec.h"


// from openldap/result.c
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <netdb.h>

#include "portable.h"

#include <ac/stdlib.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>

#include "ldap-int.h"


extern pthread_mutex_t searchMutex;

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

static int					tSelectFd2ThId[1024];
static fd_set 				tSelectReadFdSet;
static int 					tSelectMaxSock = -1;	// highest socket number
static pthread_mutex_t 		tSelectMutex = PTHREAD_MUTEX_INITIALIZER;
static fd_set *				currentrfds;

#define	NB_THREAD_MAX	1024
static int					tSelectThId2Ld[NB_THREAD_MAX];


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tSelectInit ()
/******************************************************************************/
{
int	reqId,rc=0,i;

    TRACE_CORE("tSelect module init starts\n");

	bzero( (char *)tSelectFd2ThId, sizeof(tSelectFd2ThId) );
	bzero( (char *)tSelectThId2Ld, sizeof(tSelectThId2Ld) );
	FD_ZERO(&tSelectReadFdSet);
    
    return rc;
}

/******************************************************************************/
int tSelectCountNbSock ()
/******************************************************************************/
{
int nb_sock_set = 0;
int i;

	for (i=0; i<=tSelectMaxSock;i++) {
		if ( FD_ISSET(i, &tSelectReadFdSet) ) {
			nb_sock_set++;
		}
	}
	TRACE_DEBUG("tSelectCountNbSock: %d\n", nb_sock_set);
	return nb_sock_set;
}

/******************************************************************************/
int tSelectRegisterSocket (int threadId, int sock)
/******************************************************************************/
{
//int sock = tThread_getRadSockFd(threadId);

//	pthread_mutex_lock( &tSelectMutex );

	TRACE_DEBUG("tSelectRegisterSocket: socket=%d\n", sock);

	if (sock > FD_SETSIZE)
		TRACE_ERROR("tSelectRegisterSocket: too high socket nb -> not registered\n");

	else {
		tSelectFd2ThId[sock] = threadId;

		if( sock > tSelectMaxSock )
			tSelectMaxSock = sock;
		FD_SET( sock, &tSelectReadFdSet );
	}

	tSelectCountNbSock();
//	pthread_mutex_unlock( &tSelectMutex );
}

/******************************************************************************/
int tSelectUnregisterSocket (int threadId, int sock)
/******************************************************************************/
{
//int sock = tThread_getRadSockFd(threadId);

//	pthread_mutex_lock( &tSelectMutex );

	TRACE_DEBUG("tSelectUnregisterSocket: socket=%d\n", sock);

	if (sock > FD_SETSIZE)
		TRACE_ERROR("tSelectUnregisterSocket: too high socket nb -> not unregistered\n");

	else {
		tSelectFd2ThId[sock] = 0;

		FD_CLR( sock, &tSelectReadFdSet );
		if ( sock == tSelectMaxSock ) {
			do {
				tSelectMaxSock--;
			} while ( !FD_ISSET( tSelectMaxSock, &tSelectReadFdSet ) );
		}
	}

	tSelectCountNbSock();
//	pthread_mutex_unlock( &tSelectMutex );
}

#ifdef DO_NOT_COMPILE
/******************************************************************************/
int tSelectRegisterLd (int threadId, void* ld)
/******************************************************************************/
{
//int sock = tThread_getRadSockFd(threadId);

//	pthread_mutex_lock( &tSelectMutex );

	TRACE_DEBUG("tSelectRegisterLd: threadId=%d, ld=%d\n", threadId, (int)ld);

	if (threadId > NB_THREAD_MAX)
		TRACE_ERROR("tSelectRegisterLd: too high threadId -> not registered\n");

	else {
		tSelectThId2Ld[threadId] = ld;

		if( sock > tSelectMaxSock )
			tSelectMaxSock = sock;
		FD_SET( sock, &tSelectReadFdSet );
	}

//	pthread_mutex_unlock( &tSelectMutex );
}


/******************************************************************************/
int tSelectUnregisterLd (int threadId, void* ld)
/******************************************************************************/
{
//int sock = tThread_getRadSockFd(threadId);

//	pthread_mutex_lock( &tSelectMutex );

	TRACE_DEBUG("tSelectRegisterLd: socket=%d\n", sock);

	if (threadId > NB_THREAD_MAX)
		TRACE_ERROR("tSelectRegisterLd: too high socket nb -> not unregistered\n");

	else {
		tSelectFd2ThId[sock] = 0;

		FD_CLR( sock, &tSelectReadFdSet );
		if ( sock == tSelectMaxSock ) {
			do {
				tSelectMaxSock--;
			} while ( !FD_ISSET( tSelectMaxSock, &tSelectReadFdSet ) );
		}
	}

	tSelectCountNbSock();
//	pthread_mutex_unlock( &tSelectMutex );
}
#endif

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// BODY PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tSelectIsFdSet (int fd)
/******************************************************************************/
{
//	if ( select( fd + 1, currentrfds, NULL, NULL, NULL ) > 0 ) {
	if ( FD_ISSET( fd, currentrfds ) ) {
		return 1;
	} else {
		TRACE_ERROR("socket not set %d\n", fd);
		return 0;
	}
}


/******************************************************************************/
void tSelect (int key)
/******************************************************************************/
{
int		  		fd, nb_sock, rc=0;
int 			size;
size_t 			fd_set_size;
struct timeval  select_tmo;
int 			ldId = (key-SLCTTHR);
LDAPMessage     *res;
int				msgtype;
tSleep   		*sleepCtx;
int				nbmsgrecvd;
long 			tm;
int				myerrno;

	// find out how many fd's there is space for in svc_fdset
	size = getdtablesize ( );
	// calculate how many bytes that is the same as.
	fd_set_size = howmany (size, NFDBITS);
	// allocate an fd_set of the same size
	currentrfds = (fd_set *) malloc (fd_set_size);

	// set higher priority
	setpriority(0,0,-15);

	while (tThread_getState(key) == SUSPEND) sleep(1);

	while (tThread_getState(key) == RUNNING) {

		while (!tLdapLdTab[ldId].ld) sleep(1);

		TRACE_ERROR("start listening loop on ldId=%d, ld=%p\n", ldId, tLdapLdTab[ldId].ld);
		// scan responded LdapSearch on the Ld
		nbmsgrecvd = 0;

		ldap_result( tLdapLdTab[ldId].ld, LDAP_RES_ANY, 1, NULL, &res );
		while ( (myerrno = tLdapLdTab[ldId].ld->ld_errno) == LDAP_SUCCESS ) {

			TRACE_TRAFIC("tSelect: recved resp msg (ldId=%d,msgid=%d,msgtype=%d)\n", ldId, res->lm_msgid, res->lm_msgtype);
			nbmsgrecvd++;

// EmA,01/10/2008: Forget to count "No such object" as errors
			rc = result2error( tLdap_getLd(ldId), res, 0 ); // cf ldap_search_st()
			TRACE_TRAFIC("tSelect: result2error=%d\n", rc);

			// look for retrieved response in request list attached to Ld
// EmA,01/10/2008: Forget to count "No such object" as errors
//			if ( (sleepCtx = getAndMove_RequestToResponse(ldId, res->lm_msgid, res, LDAP_SUCCESS, &tm)) == NULL ) {
			if ( (sleepCtx = getAndMove_RequestToResponse(ldId, res->lm_msgid, res, rc, &tm)) == NULL ) {

				TRACE_ERROR("tSelect: resp msg recv not found in Ld ctx (ldId=%d,msgid=%d)\n", ldId, res->lm_msgid);
				//Free msg
				if (res) ldap_msgfree( res );
//			} else {
//				tStatActionTime(LDAP_Search_Rq, LDAP_SUCCESS, 0, tm);
			}

			// try another msg
			ldap_result( tLdapLdTab[ldId].ld, LDAP_RES_ANY, 1, NULL, &res );
		}
		// res != LDAP_SUCCESS
		pthread_mutex_lock( tLdapLdTab[ldId].mutex );

		TRACE_ERROR("end of while loop ldId=%d, ld=%p, nbmsgrecvd=%d, errno=%d(%s)\n", ldId, tLdapLdTab[ldId].ld, nbmsgrecvd, myerrno, ldap_err2string(myerrno));
//		ldap_perror( tLdapLdTab[ldId].ld, "ldap_result" );

		treatError_Ld(ldId, myerrno);

		pthread_mutex_unlock( tLdapLdTab[ldId].mutex );

#ifdef _ASYNCHRONE_RADIUS_

		 if (verbose>=2 && nb_sock)
			 TRACE_TRAFIC("tSelectMaxSock=%d, nb_sock=%d\n", tSelectMaxSock, nb_sock);

		 if ( nb_sock < 0 ) {
			 perror("select");
			 continue;

		 } else if ( nb_sock > 0 ) {

			for( fd=0; (fd <= tSelectMaxSock) && nb_sock ; fd++ ) {
			  if ( FD_ISSET( fd, currentrfds ) ) {
				  nb_sock--;
				  TRACE_DEBUG("receive on socket %p\n", fd);
				  TRACE_DEBUG("threadid=%d, cond=%d\n", tSelectFd2ThId[fd], tThread_getCond(tSelectFd2ThId[fd]));
			
				  if ( tSelectFd2ThId[fd] && tThread_getCond(tSelectFd2ThId[fd]) ) {
					  TRACE_DEBUG("sending signal\n");
					  rc = pthread_mutex_lock( tThread_getMutex(tSelectFd2ThId[fd]) );
					  if (rc) perror("pthread_mutex_lock");
					  rc = pthread_cond_signal( tThread_getCond(tSelectFd2ThId[fd]) );
					  if (rc) perror("pthread_cond_signal");
					  rc = pthread_mutex_unlock( tThread_getMutex(tSelectFd2ThId[fd]) );
					  if (rc) perror("pthread_mutex_unlock");
			
				  } else {
					  TRACE_TRAFIC("fd=%d, tSelectFd2ThId[fd]=%d, tThread_getCond(tSelectFd2ThId[fd])=%d, tThread_getCond(tSelectFd2ThId[fd])=%d\n",
							  fd, tSelectFd2ThId[fd], tThread_getCond(tSelectFd2ThId[fd]), tThread_getCond(tSelectFd2ThId[fd]) );
				  }
			  }
			}
		 }
#endif
		 // with LINUX, the timeout value must be refreshed while looping
		 select_tmo.tv_sec = 0;
		 select_tmo.tv_usec = 100000;	// 100ms

   //	  pthread_mutex_lock( &tSelectMutex );
   //	  memcpy(currentrfds, &tSelectReadFdSet, fd_set_size);
   //	  pthread_mutex_unlock( &tSelectMutex );

		 nb_sock = select( tSelectMaxSock + 1, currentrfds, NULL, NULL, &select_tmo );
 //		 TRACE_ERROR("tSelect: wake up after sleep\n");

	}

	pthread_exit(0);
}



