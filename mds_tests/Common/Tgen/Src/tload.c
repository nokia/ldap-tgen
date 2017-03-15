
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
#include "tstat.h"
#include "tsce.h"
#include "tthread.h"
#include "tdebug.h"
#include "tload.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// DATA PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
pthread_t   			tloadThreadId = 0;
unsigned long			nbSecWithTraficOn = 0;

int		            	tloadSock = -1;
int		            	tloadNbProcess;
unsigned long        	tloadNbSecond;
double      	        tloadCurrentCpuLoad[NB_MAX_PROCESS];
double      	        tloadMin[NB_MAX_PROCESS];
double      	        tloadMax[NB_MAX_PROCESS];
long double    	        tloadTotal[NB_MAX_PROCESS];
char		            tloadBufCpuLoad[BUFLEN];


//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// INIT PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

/******************************************************************************/
static int InetAddrFromString( const char *ip_str )
/******************************************************************************/
{
  char   buf[6];
  char  *ptr;
  int    i;
  int    count;
  int    ipaddr;
  int    cur_byte;

  ipaddr = 0;
  for (i = 0; i < 4; i++)
  {
    ptr = buf;
    count = 0;
    *ptr = '\0';
    while (*ip_str != '.' && *ip_str != '\0' && count < 4)
    {
      if (! isdigit(*ip_str))
	return(0);
      *ptr++ = *ip_str++;
      count++;
    }
    if (count >= 4 || count == 0)
    {
      return (0);
    }
    *ptr = '\0';
    cur_byte = atoi(buf);
    if (cur_byte < 0 || cur_byte > 255)
    {
      return (0);
    }
    ip_str++;
    ipaddr = (ipaddr << 8) | cur_byte;
  }
  return (ipaddr);
}

/******************************************************************************/
void 	tLoadCnxBreak(int sig)
/******************************************************************************/
{
	close(tloadSock);
    tloadSock = -1;
}

/******************************************************************************/
int tLoadInit ()
/******************************************************************************/
{
struct sockaddr_in	servAddr;
struct sockaddr_in6	servAddr6;
struct hostent 		*hp, *gethostbyname2();
struct hostent      *remoteHost1;
int i;
int af;


	if (cpuLoad[0]) {
		char *server;
		TRACE_DEBUG("Start tload socket\n");

		signal(SIGPIPE, tLoadCnxBreak);

		//init socket towards CPU load server
		//if ( (tloadSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		//	TRACE_ERROR("Could not get a socket: %s (error #%d)\n", strerror(errno), errno);
		//	tloadSock = -1;
		//	return -1;
		//}
	
		//bzero( (char *) &servAddr, sizeof(servAddr));
		TRACE_TRAFIC("cpuLoad[0] = %s\n",cpuLoad[0]);
		remoteHost1 = gethostbyname(cpuLoad[0]);

        server = ( cpuLoad[0][0] ? cpuLoad[0] : tcServerHost[tcActiveServerId] );
        TRACE_DEBUG(">>> cpuLoad server = %s\n", server);

printf("my remoteHost1 =  \t%d\n",remoteHost1->h_addrtype);
        if (remoteHost1->h_addrtype == AF_INET) {
        	//init socket towards CPU load server
        	if ( (tloadSock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        		TRACE_ERROR("Could not get a socket: %s (error #%d)\n", strerror(errno), errno);
        		tloadSock = -1;
        		return -1;
        	}
        	bzero( (char *) &servAddr, sizeof(servAddr));

        		// EmA,11/10/2007: ATCA conf, measure on OAMvip while trafic on CXvip
        	if ( inet_aton(server, &servAddr.sin_addr) == 0 ) {
        		hp = gethostbyname(server);
        		bcopy(hp->h_addr, &servAddr.sin_addr, hp->h_length);
        	}

        	TRACE_DEBUG(">>> servAddr.sin_addr = %d\n", servAddr.sin_addr);
        	servAddr.sin_family = AF_INET;
        	servAddr.sin_port = htons(cpuLoadPortId);

        	if (connect(tloadSock, (const struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        		TRACE_ERROR("Client could not connect CPU load server: %s (error #%d)\n", strerror(errno), errno);
        		close(tloadSock);
        		tloadSock = -1;
        		return -1;
        	}
        }
        else {
        	//init socket towards CPU load server
        	if ( (tloadSock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        		TRACE_ERROR("Could not get a socket: %s (error #%d)\n", strerror(errno), errno);
        	    tloadSock = -1;
        	    return -1;
        	}
        	bzero( (char *) &servAddr6, sizeof(servAddr6));

        	// EmA,11/10/2007: ATCA conf, measure on OAMvip while trafic on CXvip
        	if ( inet_pton(server, &servAddr6.sin6_addr) == 0 ) {
        		TRACE_DEBUG("af = %d\n", af);
        	     hp = gethostbyname2(server,af);
        	     bcopy(hp->h_addr, &servAddr6.sin6_addr, hp->h_length);
        	}

        	TRACE_DEBUG(">>> servAddr6.sin6_addr = %d\n", servAddr6.sin6_addr);
        	servAddr6.sin6_family = AF_INET6;
        	servAddr6.sin6_port = htons(cpuLoadPortId);

        	if (connect(tloadSock, (const struct sockaddr *)&servAddr6, sizeof(servAddr6)) < 0) {
        	     TRACE_ERROR("Client could not connect CPU load server: %s (error #%d)\n", strerror(errno), errno);
        	     close(tloadSock);
        	     tloadSock = -1;
        	     return -1;
        	}
        }

		// end init socket
	}
	
	return 0;
}

/******************************************************************************/
int tLoadEnd ()
/******************************************************************************/
{
int rc;

/*	if (cpuLoad[0]) {
		// kill socket thread
		rc = pthread_kill(tloadThreadId, SIGKILL);
		if (rc) {
			TRACE_CRITICAL("pthread_kill failed with #%d\n", rc);
			exit(1);
		}
	}
*/
	if (tloadSock != -1) {
	    // close infinite loop of remote server child process
		// le MSG_DONTWAIT ne sert à rien: 0 marche aussi bien (si cnx ok) et
		// aussi mal si cnx cassée et sigpipe non traité...
       	if (send(tloadSock, "*", 2, MSG_DONTWAIT) < 0) {
			TRACE_ERROR("send pb thru socket: %s (error #%d)\n", strerror(errno), errno);
    	}
    	   
    	close(tloadSock);
    	tloadSock = -1;
    }
}


//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// 
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

/******************************************************************************/
void *tLoadSocketEntryPoint (void *param)
/******************************************************************************/
{
int							len, rc, i;
fd_set						rdfdesc;
static struct timeval		tv;


	tloadNbSecond = 0;
	tloadNbProcess = 3;
	for (i=0; i<tloadNbProcess; i++) tloadMin[i] = 1000;
	bzero(tloadMax, NB_MAX_PROCESS * sizeof(double) );
	bzero(tloadTotal, NB_MAX_PROCESS * sizeof(double) );

   while (1) {
        // wait every second top
		tStatWaitForStart();
		
		if (!cpuLoad[0])
			continue;
		
		// check socket
		if (tloadSock == -1) {
			// try each second indefinitely (To be limited if it consumes too much CPU)
			tLoadInit();
			continue;
		}
		
		if ((rc = send(tloadSock, ".", 2, 0)) < 0) {
		   TRACE_ERROR("send pb thru socket: %s (error #%d)\n", strerror(rc), rc);
		   close(tloadSock);
		   tloadSock = -1;
		   continue;
		}

        // Wait for reply, timing out as necessary
        FD_ZERO(&rdfdesc);
        FD_SET(tloadSock, &rdfdesc);
        
        tv.tv_sec = 0;
        tv.tv_usec = 500000;  // 500ms
    
		// Something's wrong if we don't get exactly one fd.
		if (select(tloadSock + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
		   close(tloadSock);
		   tloadSock = -1;
		   continue;
		}
        
		bzero(tloadBufCpuLoad, BUFLEN);
		if ( (len = recv(tloadSock, tloadBufCpuLoad, BUFLEN, 0)) < 0 ) {
		   TRACE_ERROR("recv pb in socket: %s (error #%d)\n", strerror(errno), errno);
		   close(tloadSock);
		   tloadSock = -1;
		   continue;
		}

		TRACE_DEBUG("tloadBufCpuLoad = %s\n", tloadBufCpuLoad);
	}
}

/******************************************************************************/
static void tLoadGetCpuInfo ()
/******************************************************************************/
{
char			*p;
char			*end;
float			load;
int				i;
int				len = 0;

	/*for (i=0; i<tloadNbProcess; i++)
		tloadCurrentCpuLoad[i] = -1;
	*/
	if (tloadBufCpuLoad) len = strlen(tloadBufCpuLoad);

	if ( (tloadSock != -1) && len ) {

//		// read number of processes to scan
//		sscanf(p, "%d", &tloadNbProcess);

		// we don't memorize the n first seconds that may not be significative
        if (nbSecWithTraficOn > tcTimeBeforeStats) {
			 tloadNbSecond ++;
			 p = tloadBufCpuLoad;
			 end = tloadBufCpuLoad + len;

			 // read and store CPU load values
			 for (i=0; i<tloadNbProcess; i++) {
   
				 // next value
				 if ( sscanf(p+1, "%f", &load) == 1 ) {

					 tloadCurrentCpuLoad[i] = load;
					 tloadTotal[i] += load;
					 if (load < tloadMin[i]) tloadMin[i] = load;
					 if (load > tloadMax[i]) tloadMax[i] = load;
					 while ( *++p!='\t' && p<end ) ;
				 } else {
					 break;
				 }
			 }
		}
	}
}

/******************************************************************************/
void tLoadUpdateConsole ()
/******************************************************************************/
{
	if (cpuLoad[0]) {
		tLoadGetCpuInfo();
		fprintf(stdout, "\t%s", tloadBufCpuLoad);
	}
}


/******************************************************************************/
int tLoadPrintCsv (FILE *output)
/******************************************************************************/
{
int i;

	if (output && tloadNbSecond) {
		for (i=0; i<tloadNbProcess; i++) {
			fprintf(output, ",%6.2f", (double)tloadTotal[i] / tloadNbSecond);
		}
	}
}

/******************************************************************************/
int tLoadPrintReport (FILE* output)
/******************************************************************************/
{
int i;

	if (output) {
		if (tloadNbSecond) {
			fprintf(output, "              \t user \t  sys \t idle");
			fprintf(output, "\nMean CPU load:");
			for (i=0; i<tloadNbProcess; i++)
				fprintf(output, "\t%6.2f", (double)tloadTotal[i] / tloadNbSecond);
			
			fprintf(output, "\nMin  CPU load:");
			for (i=0; i<tloadNbProcess; i++)
				fprintf(output, "\t%6.2f", tloadMin[i]);
	
			fprintf(output, "\nMax  CPU load:");
			for (i=0; i<tloadNbProcess; i++)
				fprintf(output, "\t%6.2f", tloadMax[i]);
	   }
	   fprintf(output, "\n");
	}
}

