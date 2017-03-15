/*
 ** FILE         : tloadserver.c
 ** AUTHOR       : E. Anthoine
 ** DATE         : 16-OCT-2002
 ** PURPOSE		  : give CPU load of HssMain when asked by a client
 ** BUILD        : cc tloadserver.c -o tloadserver
 ** RUN          : ./server
*/

#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>

// added for Linux:
#include <signal.h>
#include <unistd.h>

#define BUFLEN			64
#define NB_MAX_CMD	10
#define NB_WTHREADS	10

#define WT_STATE_WAIT		0
#define WT_STATE_ACTIVE		1

void *mainWork (void *param);
void *childWork (void *param);
void sigHandler(int sigNum);
extern void *timerWork (void *param);
//extern int main_iostat(int argc, char **argv);
extern int main_mpstat(int argc, char **argv);

struct WT {
	char					num;
	pthread_t			id;
	char					state;
	int					socket;
	pthread_mutex_t	mutex;
	pthread_cond_t		cond;
};

int						nb_proc;
pthread_t         	timerThreadId, mainTreadId;
char 						cpuLoads[BUFLEN];
char						proc_name[NB_MAX_CMD][BUFLEN];
float						proc_load[NB_MAX_CMD];
static struct WT		workerThreads[NB_WTHREADS];
pthread_attr_t    	attr;

int						showThreads = 0;
int						portId = 3333;


/************************************************************************************/
void register_signals()
/************************************************************************************/
//
// Signal Management: signal handling by thread #i except #0 !
//
    {
    struct sigaction    sigAction  = { 0 };

    sigAction.sa_handler = sigHandler;
    //sigAction.sa_flags   = SA_RESETHAND;
    sigAction.sa_flags   = 0;

    //sigaction(SIGTSTP,&sigAction,NULL);
    sigaction(SIGPIPE,&sigAction,NULL);
    sigaction(SIGSEGV,&sigAction,NULL);

    }


/************************************************************************************/
int main( int argc, char **argv )
/************************************************************************************/
{
struct sockaddr_in	servAddr;
size_t					servAddr_len;
int						i, status;
int						sockMain;
int						sockClient;
struct sched_param	sched;
pthread_mutex_t	   selfBlockingMutex;

sigset_t					signalSet = { 0 };
int						sigNum;


//
// args
//

	while ((i = getopt(argc, argv, "vp:")) != EOF) {
		switch(i) {
			case 'v':
			  showThreads = 1;
			  break;

			case 'p':
			  portId = atoi(optarg);
			  break;

	      default:
			  break;
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);
	
#ifdef _NAMED_PROCESS
  // at least one process to be observed
  if (argc < 2) {
		printf("Usage: %s [-v] p1 [p2] ... [p%d]\n", argv[0], NB_MAX_CMD);
		exit(1);
  }
  nb_proc = argc - 1;
  if (nb_proc > NB_MAX_CMD)
  		nb_proc = NB_MAX_CMD;

  for (i=0; i<nb_proc; i++)
  		strcpy(proc_name[i], argv[i+1]);
#else
  // 3 values transmitted: usr/sys/idle rates
  nb_proc = 3;

#endif

  register_signals();

//
// create master socket
//
  if ( (sockMain = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("tloadserver: Server allocate main socket");
    exit(1);
  }

  servAddr_len = sizeof(servAddr);
  bzero( (char *) &servAddr, servAddr_len);
  servAddr.sin_family = AF_INET;
  servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servAddr.sin_port = htons(portId);

  // bind socket
  if ( bind (sockMain, (struct sockaddr *)&servAddr, servAddr_len) < 0 ) {
    perror("tloadserver: Server's bind failed");
    exit(1);
  }
  
  // SET UP A QUEUE THAT CAN HOLD UP TO FIVE CLIENTS
  listen(sockMain, NB_WTHREADS);
  printf("tloadserver: listening on port %d\n", portId);

//  
// create timer thread (minor priority)
//
	pthread_attr_init( &attr );
// formerly based on Top tool:
//	if ( pthread_create( &timerThreadId, &attr, timerWork, (void *)0) < 0) {
// mono-proc:
// 	if ( pthread_create( &timerThreadId, &attr, main_iostat, (void *)0) < 0) {
// multi-proc:
	if ( pthread_create( &timerThreadId, &attr, main_mpstat, (void *)0) < 0) {
	   perror("tloadserver: pthread_create failed");
	   exit(1);
	}

//
// create worker threads (with high priority)
//
	pthread_attr_init( &attr );
	pthread_attr_getschedparam( &attr, &sched );
	sched.sched_priority ++;
	pthread_attr_setschedparam( &attr, &sched );

	bzero(workerThreads, NB_WTHREADS * sizeof(struct WT) );
	for (i=0; i<NB_WTHREADS; i++) {
		workerThreads[i].num = i;
		workerThreads[i].state = WT_STATE_WAIT;
		workerThreads[i].socket = 0;
		
		if ( pthread_mutex_init(&(workerThreads[i].mutex), NULL) > 0 ) {
			perror("tloadserver: pthread_mutex_init failed");
			exit(1);
		}
		if ( pthread_cond_init(&(workerThreads[i].cond), NULL) > 0 ) {
			perror("tloadserver: pthread_cond_init failed");
			exit(1);
		}
		
		if ( pthread_create(&(workerThreads[i].id), &attr, childWork, (void *)(workerThreads + i)) < 0 ) {
		   perror("tloadserver: pthread_create failed");
		   exit(1);
		}
		printf("tloadserver: worker thread %d created (%d)\n", i, workerThreads[i].id);
	}
   

//
// main serving loop
//
	for (;;) {
		// wait for client socket demand
		if ( (sockClient = accept(sockMain, 0, 0)) < 0) {
			perror("tloadserver: Bad client socket");
			exit(1);
		}
		
		// wake up a child thread to treat this dialog with tgen
		for (i=0; i<NB_WTHREADS; i++) {
			// find a waiting WT
			if (workerThreads[i].state == WT_STATE_WAIT) {
				printf("[INFO] tloadserver: wake up thread %d\n", i);
				workerThreads[i].socket = sockClient;
				workerThreads[i].state = WT_STATE_ACTIVE;
				
		  		pthread_cond_signal(&(workerThreads[i].cond));
				break;
			}
		}
			
		if (i == NB_WTHREADS) {
			perror("tloadserver: not enough WT to treat a new tgen client");
			exit(1);
		}
	} /* FOR LOOP */

}


/************************************************************************************/
void *childWork (void *param)
/************************************************************************************/
{
struct WT *		me = (struct WT *)param;
char				val[6];
int				res;

//	printf("WT %d self = %d\n", me->num, pthread_self());

for (;;) {

   pthread_mutex_lock(&(me->mutex));
   pthread_cond_wait(&(me->cond), &(me->mutex));
   pthread_mutex_unlock(&(me->mutex));

   // I've been activated !!!
   for (;;) {
     
     // wait for each second signal
	  bzero(val, 6);
	  if ( res = recv(me->socket, val, BUFLEN, 0) < 0) {
	    perror("Bad receive by child, closing socket");
	    break;
	  }
	  //printf("[INFO] tloadserver: have read : '%s'\n", val);

	  // message than tgen is quiting
	  if ( val[0] == '*' ) {
			printf("[INFO] tloadserver: socket closed by peer (thread %d)\n", me->num);
	  		break;
	  }

	  if ( val[0] == '.' ) {
		  // send result on socket
		  if (send(me->socket, cpuLoads, strlen(cpuLoads), 0) < 0) {
			perror("Problem with send");
			break;
		  }
		  //printf("[INFO] tloadserver: have send : '%s'\n", cpuLoads);
	  } else {
		  printf("[INFO] tloadserver: did not recvd '.' => finish \n");
		  break;
	  }

   }
  
   // close socket
   close(me->socket);
   me->socket = 0;
  
   // I've finished my job
   me->state = WT_STATE_WAIT;
}

//  pthread_exit(0);      // doesn't work
}


/******************************************************************************/
void restartOneWorkerThread()
/******************************************************************************/
{
pthread_t		localId;
int				i;

   localId = pthread_self();
   for (i=0; i<NB_WTHREADS; i++) {
		// find a waiting WT
	   if (workerThreads[i].id == localId) {
			printf("[INFO] tloadserver: restart W thread %d\n", i);
			workerThreads[i].state = WT_STATE_WAIT;
			workerThreads[i].socket = 0;
			
			if ( pthread_mutex_init(&(workerThreads[i].mutex), NULL) > 0 ) {
				perror("tloadserver: pthread_mutex_init failed");
				exit(1);
			}
			if ( pthread_cond_init(&(workerThreads[i].cond), NULL) > 0 ) {
				perror("tloadserver: pthread_cond_init failed");
				exit(1);
			}
			
			if ( pthread_create(&(workerThreads[i].id), &attr, childWork, (void *)(workerThreads + i)) < 0 ) {
			   perror("tloadserver: pthread_create failed");
			   exit(1);
			}
			
			pthread_exit(1);
		}
	}
	
	// something's wrong !!!
	pthread_exit(1);
}


/******************************************************************************/
void sigHandler(int sigNum)
/******************************************************************************/
{
pthread_t		localId;
int				i;

	if (sigNum == SIGPIPE) {
	   fprintf(stderr, "\ntloadserver: broken pipe received\n");
	   restartOneWorkerThread();
   }
    
   if (sigNum == SIGSEGV) {
      fprintf(stderr, "\ntloadserver: segmentation fault received\n");
	   restartOneWorkerThread();
   }

}
