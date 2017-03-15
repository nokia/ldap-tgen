
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#ifdef __TGEN_ON_LINUX_TIMESPEC
#include <time.h>
#else
#include <sys/time.h>
#endif
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

extern int killcalled;

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

pthread_mutex_t      		schedulingMutex = PTHREAD_MUTEX_INITIALIZER   ;
static pthread_cond_t       schedulingCond = PTHREAD_COND_INITIALIZER    ;
pthread_mutex_t      		schedulingMutexI = PTHREAD_MUTEX_INITIALIZER  ;
pthread_mutex_t      		tstatMutexI = PTHREAD_MUTEX_INITIALIZER       ;
static pthread_cond_t       schedulingCondI = PTHREAD_COND_INITIALIZER   ;

#ifdef __TGEN_ON_LINUX_TIMESPEC
static struct timespec      schedulingTick;
#else
static timespec_t           schedulingTick;
#endif


// statistic infos
extern int		            traficOn;
static unsigned long        tstatRequestPerSecondSent;      //Nb of Request Per Second Sent
static unsigned long        tstatRequestPerSecondMeasured;  //Nb of Request Per Second Answered
static int                  tstatRequestPerSecondWanted;
                                                 
static unsigned long        tstatTotalNbOfSeconds; 	//Nb of seconds  used by tstat for statistics purpose
												
static unsigned long        tstatNbRequest[DIM_MAX]; //Nb of Requests 
static unsigned long        tstatNbKO[DIM_MAX]; 	 //Nb of KO 
static unsigned long        tstatNbTimeout[DIM_MAX]; //Nb of timeouts 
static unsigned int         tstatNbStationShutdown;
static unsigned int         tstatNbStationRestart;
static unsigned int         tstatNbServerMPswitch;

//static struct timeb 		nowTime, lastTime;


//Traffic Function: default registered is stable
static tStatTrafficFunctionType tStatTrafficFunction;

extern 	   tTimerTopTU();


// screen presentation
static void tStatUpdateConsole();
static void tStatPrintCsv (FILE *output);



//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tStatInit ()
/******************************************************************************/
{
int	reqId,rc=0,i;

    if (verbose >= 1)
        TRACE_CORE("Stat init starts\n");

	bzero( (char *)tStatTab, SCE_End * sizeof(tStatMeasure) );
    for (reqId=SCE_Begin+1; reqId<SCE_End; reqId++) {
        tStatTab[reqId].tm_min=10000000;
    }
    //Traffic Function: default registered is stable
    tStatTrafficFunction=tStatTrafficFunction_stable;
    tstatRequestPerSecondWanted = tcNbOfRequestPerSecond;
   	
    // init final stats 
	tstatTotalNbOfSeconds = 0;
	bzero(tstatNbRequest, DIM_MAX * sizeof(unsigned long) );
	bzero(tstatNbKO, DIM_MAX * sizeof(unsigned long) );
	bzero(tstatNbTimeout, DIM_MAX * sizeof(unsigned long) );

    schedulingTick.tv_sec=1  ;
    schedulingTick.tv_nsec=0  ;

    tstatNbStationShutdown=0;
    tstatNbStationRestart=0;
    tstatNbServerMPswitch=0;

	if (cpuLoad[0])
	{
		pthread_attr_t    attr;
		size_t            size;
	  
		if (verbose >= 1)
			TRACE_CORE("create a thread for CPU load socket\n" );
		
		pthread_attr_init( &attr );
		pthread_attr_getstacksize( &attr, &size );
	
		// create the socket thread
		if ( rc = pthread_create( &tloadThreadId, &attr, tLoadSocketEntryPoint, (void *)0) < 0) {
			TRACE_CRITICAL("init exit: pthread_create failed!\n");
			return rc;
		}
	}

	clrscr();
	if (_lignes() < 40 || _colonnes() < 140) {
		TRACE_CRITICAL("Terminal is too small (set at least 40x140)\n");
		//return 1;
	}

    // Start time (start overall chrono both in MAINTHR & STATTHR)
    tStatTimeBegin(1);

    return rc;
}

/******************************************************************************/
int tStatEnd ()
/******************************************************************************/
{
	tStatUpdateConsole();
	return tLoadEnd();
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// BODY PART
// 
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい


/******************************************************************************/
void tStat (int key)
/*
pthread_get_expiration_np could be used on DEC station
pthread_get_expiration_np( &schedulingTick,&schedulingExpirationTime);
but time shift appears ...
*/
/******************************************************************************/
{
int             rc, i;
struct timeval  ExpectedTime;
#ifdef __TGEN_ON_LINUX_TIMESPEC
struct timespec schedulingTime;
#else
timespec_t      schedulingTime;
#endif

    while ( tThread_getState(key) == SUSPEND) sleep(1);

#ifdef __TGEN_HAS_MUTEX_TIMEOUTS
    //Take schedulingMutexI for ever
    rc = pthread_mutex_lock(&schedulingMutexI);
#endif
    //Start time
    tStatTimeBegin(1);

//	ftime(&lastTime);
	gettimeofday(&ExpectedTime, NULL);
    
    while (1) {

       // schedule Scenarios
	   rc = pthread_cond_broadcast(&schedulingCond) ;
	   if ( rc > 0 ) {
			TRACE_CRITICAL("scheduling failed: %d\n",rc);
			pthread_exit(1);
	   }
	   if (traficOn) {
		   if (!nbSecWithTraficOn) TRACE_CORE("Resume trafic\n");
		   nbSecWithTraficOn++;
		   tstatTotalNbOfSeconds++;
	   } else {
		   if (nbSecWithTraficOn) TRACE_CORE("Pausing trafic\n");
		   nbSecWithTraficOn = 0;
	   }

	   // Internal Scheduling: Start of a new period of 1 second
	   ExpectedTime.tv_sec  += schedulingTick.tv_sec;
	   ExpectedTime.tv_usec += (schedulingTick.tv_nsec / 1000);

       schedulingTime.tv_sec  = ExpectedTime.tv_sec;
       schedulingTime.tv_nsec = ExpectedTime.tv_usec * 1000;
		
#ifdef __TGEN_HAS_MUTEX_TIMEOUTS
       rc = pthread_mutex_timedlock(&schedulingMutexI, &schedulingTime);
#else
       pthread_mutex_lock(&schedulingMutexI);
       rc = pthread_cond_timedwait( &schedulingCondI, &schedulingMutexI, &schedulingTime);
       if (rc == ETIMEDOUT)
           pthread_mutex_unlock(&schedulingMutexI);
#endif


	   if (traficOn) {
		   tStatUpdateConsole();

		   if ( (tstatTotalNbOfSeconds % tcCsvPeriod) == 0 ) {
			   tStatPrintCsv(tcCsvFile);
			   tstatNbRequest[IN_PERIOD] = 0;
			   tstatNbKO[IN_PERIOD] = 0;
			   tstatNbTimeout[IN_PERIOD] = 0;
		   }
	
		   if ( (tstatTotalNbOfSeconds % tcReportPeriod) == 0 ) {
			   tStatPrintReport(tcRptFile);
		   }
	   }

       //The new period starts
       pthread_mutex_lock(&schedulingMutex);
       tstatRequestPerSecondSent=0;
       tstatRequestPerSecondMeasured=0;
       tstatRequestPerSecondWanted = tStatTrafficFunction(tstatTotalNbOfSeconds);
	   tstatNbRequest[IN_SECOND] = 0;
	   tstatNbKO[IN_SECOND] = 0;
	   tstatNbTimeout[IN_SECOND] = 0;
       pthread_mutex_unlock(&schedulingMutex);
        
       // send top 1 second to Timer module
       tTimerTopTU();
	   if (tcTimeToRun && (tstatTotalNbOfSeconds >= tcTimeToRun) && !killcalled) {
		   // stop cleanly the Tgen
		   pthread_kill(tThread_getMainThread(), SIGINT);
		   sched_yield();	// I don't want this thread to continue immediatly
	   }
	}

}

/******************************************************************************/
int tStatIncrStationDown ()
/******************************************************************************/
{
    return  ++tstatNbStationShutdown;
}

/******************************************************************************/
int tStatIncrStationRestart ()
/******************************************************************************/
{
    return  ++tstatNbStationRestart;
}

/******************************************************************************/
int tStatIncrServerMPswitch ()
/******************************************************************************/
{
    return  ++tstatNbServerMPswitch;
}


/******************************************************************************/
int     tStatRegisterTrafficFunction( tStatTrafficFunctionType fct)
/******************************************************************************/
{   
    tStatTrafficFunction=fct;
}


/******************************************************************************/
int tStatTrafficFunction_stable (int time)
//The traffic request is stable and equals to the requested traffic.
/******************************************************************************/
{   
    return tstatRequestPerSecondWanted;
}


/******************************************************************************/
int tStatTrafficFunction_bursty (int time)
//One burst every 10 seconds period. The burst appears randomly during the period. 
//Burst excluded, the traffic request is stable and equals to the requested traffic.
/******************************************************************************/
{
    // One burst per tcTrafficPeriod sec period
    static burst=0; 
    static int r;
    int tcTrafficPeriod = 10;
    int k = tstatTotalNbOfSeconds % tcTrafficPeriod;
   
    //start of period
    if (k==1) {
        burst=0;
        r = rand() % tcTrafficPeriod;
    }

    if (burst==0 && r == k) {
        burst = 1;
        return (1000);
    }
    return tcNbOfRequestPerSecond;
}


/******************************************************************************/
int tStatTrafficFunction_linear1 (int time)
//The traffic request grows in a linear way during the 20 seonds period from
//the requested traffic.
/******************************************************************************/
{
    //From tcRequestPerSecond to tcNbOfRequestPerSecond+200, step=10
    int tcTrafficPeriod = 20;
    int k = tstatTotalNbOfSeconds % tcTrafficPeriod;

    return (tcNbOfRequestPerSecond + 10*k);
}


/******************************************************************************/
int tStatTrafficFunction_sine (int time)
/******************************************************************************/
{   
    tstatRequestPerSecondWanted= 0.002962 + 0.028135*(sin(2*3.914*time/(0.83233-0.22993)));
}


/******************************************************************************/
int tStatRegulation (int key)
/******************************************************************************/
{
    pthread_mutex_lock(&schedulingMutex);

	// no regulation if tgen is in ending phase !!!
	if ( tThread_getState(key) == RUNNING ) {
		// "if" is not enough if one thread reaches the RequestedNb before giving hand !!!
		while (tstatRequestPerSecondSent >= tstatRequestPerSecondWanted ) {
			pthread_cond_wait( &schedulingCond, &schedulingMutex);
		}
	}
    tstatRequestPerSecondSent++;
    
    pthread_mutex_unlock(&schedulingMutex);
}

/******************************************************************************/
int tStatCount (int key)
/******************************************************************************/
{
    pthread_mutex_lock(&schedulingMutex);

    tstatRequestPerSecondMeasured++;

    pthread_mutex_unlock(&schedulingMutex);
}

/******************************************************************************/
void tStatWaitFor (long int sec)
/******************************************************************************/
{
struct timeval  now;
int				 rc;
struct timespec expirationTime;

	gettimeofday(&now, NULL);
	expirationTime.tv_sec  = now.tv_sec  + sec;
	expirationTime.tv_nsec = now.tv_usec * 1000;
		
#ifdef __TGEN_HAS_MUTEX_TIMEOUTS
	rc = pthread_mutex_timedlock(&schedulingMutexI, &expirationTime);
#else
	pthread_mutex_lock(&schedulingMutexI);
	rc = pthread_cond_timedwait( &schedulingCondI, &schedulingMutexI, &expirationTime);
	if (rc == ETIMEDOUT)
	   pthread_mutex_unlock(&schedulingMutexI);
#endif
}

/******************************************************************************/
int tStatWaitForStart ()
/******************************************************************************/
{
    pthread_mutex_lock(&schedulingMutex);
    pthread_cond_wait(&schedulingCond, &schedulingMutex);
    pthread_mutex_unlock(&schedulingMutex);
} 

/******************************************************************************/
int tStatTimeRegister (int reqId, const char* reqName, const int default_val)
/******************************************************************************/
{
char *line = reqName;

    // checkings and skipping WS
    if (!line || !line[0]) {
        return 0;
    }
    while ( isspace(*line) )
      line++;

    strcpy(tStatTab[reqId].rq_name, reqName);
    tStatTab[reqId].tm_maxDelay = ProfileGetInt( inifile, "MaxDelay", line, default_val );
    
    return 0;
}   

/******************************************************************************/
int tStatTimeBegin (int idx)
/******************************************************************************/
{
	//EmA,18/03/2011: not precise enough now...
	//ftime(tThread_getTimeBeg( tThread_getKey(), idx));
	gettimeofday(tThread_getTimeBeg( tThread_getKey(), idx), NULL);
    
    if (verbose>=3) TRACE_DEBUG("tStatTimeBegin: threadid %d timer %d\n", tThread_getKey(), idx);
    return 1;
}

/******************************************************************************/
int tStatTimeEnd (int idx)
/******************************************************************************/
{
	//EmA,18/03/2011: not precise enough now...
    //ftime(tThread_getTimeEnd( tThread_getKey(), idx));
	gettimeofday(tThread_getTimeEnd( tThread_getKey(), idx), NULL);

	if (verbose>=3) TRACE_DEBUG("tStatTimeEnd: threadid %d timer %d\n", tThread_getKey(), idx);
    return 1;
}

/******************************************************************************/
long tStatTimeDelta (int idx)
/******************************************************************************/
{
int     key;
long    tm;

    key = tThread_getKey();

    tm = 1000000 * (tThread_getTimeEnd(key, idx)->tv_sec    - tThread_getTimeBeg(key, idx)->tv_sec) +
	     (tThread_getTimeEnd(key, idx)->tv_usec - tThread_getTimeBeg(key, idx)->tv_usec);

    if (verbose>=3) TRACE_DEBUG("tStatTimeDelta: threadid %d timer %d result %ld\n", key, idx, tm);
    return tm;
}


#define ULLONG_MAX	18446744073709551615ULL

/******************************************************************************/
int tStatActionTime (int reqId, char verdict, int retry, long usec)
/******************************************************************************/
// not to count twice some request, we deliberatly not count Access Request Identity in EAP-SIM/EAP-TTLS cases
{ 
long    tm = ( usec == 0 ? tStatTimeDelta(0) : usec);

    pthread_mutex_lock(&tstatMutexI);

    tStatTab[reqId].rq_cnt++;
	if (reqId != RADIUS_AccessEapId_Rq) {
		tstatNbRequest[IN_SECOND]++;
		tstatNbRequest[IN_PERIOD]++;
		tstatNbRequest[IN_TOTAL]++;
	}

    tStatTab[reqId].rq_retry += retry;
	if (reqId != RADIUS_AccessEapId_Rq) {
		tstatNbTimeout[IN_SECOND] += retry;
		tstatNbTimeout[IN_PERIOD] += retry;
		tstatNbTimeout[IN_TOTAL] += retry;
	}

    if (verdict) {
		tStatTab[reqId].rq_ko++;
		if (reqId != RADIUS_AccessEapId_Rq) {
			tstatNbKO[IN_SECOND]++;
			tstatNbKO[IN_PERIOD]++;
			tstatNbKO[IN_TOTAL]++;
		}
	}

	tStatTab[reqId].tm_cum += tm;
	if ( tm < tStatTab[reqId].tm_min ) tStatTab[reqId].tm_min = tm;
	if ( tm > tStatTab[reqId].tm_max ) tStatTab[reqId].tm_max = tm;
	if ( tm > (1000*tStatTab[reqId].tm_maxDelay)) tStatTab[reqId].rq_maxDelay++;

    //overflow control (EmA,02/11/2005: ULONG -> ULONGLONG)
    if ( tStatTab[reqId].tm_cum > (ULLONG_MAX-1000000) ) {
        tStatTab[reqId].tm_cum = 0;
// EmA,02/11/2005: do not loose cnt (only mean time)
//        tStatTab[reqId].rq_cnt = 0;
        tStatTab[reqId].overflow++;
		TRACE_ERROR("tStatActionTime: overflow event for reqId=%d overflow=%d\n", reqId, tStatTab[reqId].overflow);
    }

    pthread_mutex_unlock(&tstatMutexI);
}




//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// PRINTING PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい


/******************************************************************************/
static int tStatPrintHeader (FILE * output)
/******************************************************************************/
{
char    buf[64];
long    tm, s, m, h;
int     i;

	if (output == stdout) gotoxy(1,1);
	if (output == stdout) clreol();
	if (output == stdout) fprintf(output, "Tgen version %s, Clearcase label %s\n", __VERSION__, __CCLABEL__);
	if (output == stdout) clreol();
	if (output == stdout) fprintf(output, "Simu PC: \t\t%s (%s)\n", RADIUS_CLIENT_NAS_IP_ADD, RADIUS_CLIENT_NAS_ID);
	if (output == stdout) clreol();
	//if (output == stdout) 
	fprintf(output, "Launching command line: %s\n", tcFullCommandLine);
	if (output == stdout) clreol();
    if (g_option != 1) {
        fprintf(output, "Destination Servers: \tMASTER=%s - SLAVE=%s\n",tcServerHost[0], (tcServerHost[1] ? tcServerHost[1] : "none"));
    } else {
        fprintf(output, "Destination Servers: \t%s",tcServerHost[0]);
        for(i=1; i<nbserver; i++){
			fprintf(output, " - %s", tcServerHost[i]);
		}
		fprintf(output, "\n");
    }
	if (output == stdout) clreol();
	fprintf(output, "Starting date:\t\t%s", ctime_r(&tThread_getTimeBeg(tThread_getKey(), 1)->tv_sec, buf) );
	// be carefull: ctime prints a \n !!!

	tStatTimeEnd(1);
	if (output == stdout) clreol();
	fprintf(output, "Current date:\t\t%s", ctime_r(&tThread_getTimeEnd(tThread_getKey(), 1)->tv_sec, buf+32) );
	// be carefull: ctime prints a \n !!!

    tm = round( tStatTimeDelta(1)/1000000 );
	h=tm/3600;
	m=(tm/60)%60;
	s=tm%60;
	if (output == stdout) clreol();
	fprintf(output, "Total running time:\t%0.2dH:%0.2dM:%0.2dS\n",h,m,s);

	if (output == stdout) clreol();
	fprintf(output, "\n");
}

/******************************************************************************/
static int tStatPrintRequests (FILE * output)
/******************************************************************************/
{
int     reqId, sceId;

/*
               ********* statistics - request **********
-------------------------------------------------------------------------------------------------------------
| 1234567890123456789012345678 | 12345 | 12345 | 12345 | 12345678 | 12345678 | 12345678 | 123.5% (12345678) |
|         Request name         |  mean |  min  |  max  |    cnt   |    ko    |  timout  |   over max delay  |
-------------------------------------------------------------------------------------------------------------
*/
    if (output == stdout) clreol();
    fprintf(output, "\t\t********* statistics - request **********\n");
    if (output == stdout) clreol();
    fprintf(output, "-------------------------------------------------------------------------------------------------------------------\n");
    if (output == stdout) clreol();
    fprintf(output, "|         Request name         |   mean  |   min   |   max   |    cnt   |    ko    |  timout  |   over max delay  |\n");
    if (output == stdout) clreol();
    fprintf(output, "-------------------------------------------------------------------------------------------------------------------\n");

    for (reqId=SCE_Begin; reqId<SCE_End; reqId++) {

        if ( tStatTab[reqId].rq_name[0] && tStatTab[reqId].rq_cnt  ) {
            float percent,maxDelay,rq_cnt;

            percent = ((float)tStatTab[reqId].rq_maxDelay/(float)tStatTab[reqId].rq_cnt) * 100 ;

            tStatTab[reqId].tm_mean = ((float)(tStatTab[reqId].tm_cum)/1000) / (tStatTab[reqId].rq_cnt);

			if (output == stdout) clreol();
            fprintf(output, "| %-28.28s | %7.2f | %7.2f | %7.2f | %8ld | %8ld | %8ld | %5.1f\% (%8ld) |\n",
                            tStatTab[reqId].rq_name,tStatTab[reqId].tm_mean, (float)tStatTab[reqId].tm_min/1000, (float)tStatTab[reqId].tm_max/1000,
                            tStatTab[reqId].rq_cnt, tStatTab[reqId].rq_ko, tStatTab[reqId].rq_retry, percent,tStatTab[reqId].rq_maxDelay);
        }

    }
	if (output == stdout) clreol();
    fprintf(output, "-------------------------------------------------------------------------------------------------------------------\n");

	if (output == stdout) clreol();
	fprintf(output, "\n");
}


/******************************************************************************/
static void tStatPrintFooter (FILE * output)
/******************************************************************************/
{
char    buf[64];
long    tm, s, m, h;

	if (tstatNbStationRestart) {
    	if (output == stdout) clreol();
        fprintf(output, "Nb of recovered Ldap cnx: \t\t\t\t%d\n", tstatNbStationRestart);
    }
    if (tstatNbStationShutdown || tstatNbServerMPswitch) {
		if (output == stdout) clreol();
        fprintf(output, "Nb of broken Ldap cnx: \t\t\t\t\t%d\n", tstatNbStationShutdown);
		if (output == stdout) clreol();
        fprintf(output, "Nb of server unavailabilities (= Matted-pair switches): %d\n", tstatNbServerMPswitch);
    }
	
    if (tstatTotalNbOfSeconds) {
		h=tstatTotalNbOfSeconds/3600;
		m=(tstatTotalNbOfSeconds/60)%60;
		s=tstatTotalNbOfSeconds%60;
		if (output == stdout) clreol();
		fprintf(output, "Duration of trafic:\t\t%2dH:%2dM:%2dS\n",h,m,s);
		if (output == stdout) clreol();
		fprintf(output, "Mean nb of request by second:\t%-6.2f\n", (double)tstatNbRequest[IN_TOTAL] / tstatTotalNbOfSeconds);
		if (output == stdout) clreol();
		fprintf(output, "QOS  (ko/total):\t\t%-7.1E\n", (float)(tstatNbKO[IN_TOTAL]+1) / (tstatNbRequest[IN_TOTAL]+1));
		if (output == stdout) clreol();
		fprintf(output, "QOSt (timeout/total):\t\t%-7.1E\n", (float)(tstatNbTimeout[IN_TOTAL]+1) / (tstatNbRequest[IN_TOTAL]+1));
	}
	if (output == stdout) clreol();
	if (output == stdout) fprintf(output, "----------------------------------------------------------------------------------------------------------------------------------------\n");
	if (output == stdout) clreol();
	if (output == stdout) fprintf(output, "        Date             seconds    sent     recv   errors  timeouts  ok%wanted   Cpu used (usr/sys/idle)\n");
//                                         22/11/2007 08:54:11.762    2133      150      150        0        0      0.00       00
}


/******************************************************************************/
static void tStatUpdateConsole ()
/******************************************************************************/
{
time_t 			now;
struct tm 		ptm;
struct timeb 	ptb;


	ftime(&ptb);
	now = ptb.time;
	localtime_r(&now, &ptm );

	// Header part
	tStatPrintHeader(stdout);

	// Requests statistics
	tStatPrintRequests(stdout);

	// Scenario statistics
	tScePrintScenarios(stdout, tstatTotalNbOfSeconds);

	// Footer part
	tStatPrintFooter(stdout);

	//
	// Scrolling part:
	//

	// delete oldest 'each-second' line and add a new one at the end
	delline();

	gotoxy(1,_lignes()-1);
	clreol();
	fprintf(stdout, "%02d/%02d/%d %02d:%02d:%02d.%03d  %6ld   %6ld   %6ld   %6ld   %6ld    %6.2f",
			ptm.tm_mday, ptm.tm_mon+1, 1900+ptm.tm_year, ptm.tm_hour, ptm.tm_min, ptm.tm_sec, ptb.millitm,
			tstatTotalNbOfSeconds,
			tstatRequestPerSecondSent, tstatNbRequest[IN_SECOND], //tstatRequestPerSecondWanted,
			tstatNbKO[IN_SECOND], tstatNbTimeout[IN_SECOND],
			100*((float)(tstatNbRequest[IN_SECOND]-tstatNbKO[IN_SECOND])/tstatRequestPerSecondWanted)
			);
	tLoadUpdateConsole();

	fprintf(stdout, "\n");
	fflush(stdout);
}

/******************************************************************************/
static void tStatPrintCsv (FILE *output)
/******************************************************************************/
{
time_t 			now;
struct tm 		ptm;
struct timeb 	ptb;

	ftime(&ptb);
	now = ptb.time;
	localtime_r(&now, &ptm );

	if (output) {
		fprintf(output, "%02d/%02d/%d %02d:%02d:%02d.%03d,%6ld,%6ld,%6ld,%6ld,%6ld,%7.1E,%7.1E",
				ptm.tm_mday, ptm.tm_mon+1, 1900+ptm.tm_year, ptm.tm_hour, ptm.tm_min, ptm.tm_sec, ptb.millitm,
				tstatTotalNbOfSeconds,
				tstatNbRequest[IN_PERIOD], tstatRequestPerSecondWanted*tcCsvPeriod,
				tstatNbKO[IN_PERIOD], tstatNbTimeout[IN_PERIOD],
				(tstatNbRequest[IN_PERIOD] ? (float)tstatNbKO[IN_PERIOD] / tstatNbRequest[IN_PERIOD] : 0),
				(tstatNbRequest[IN_PERIOD] ? (float)tstatNbTimeout[IN_PERIOD] / tstatNbRequest[IN_PERIOD] : 0)
				);
		tLoadPrintCsv(output);

		fprintf(output, "\n");
		fflush(output);
	}
}



/******************************************************************************/
int tStatPrintReport (FILE * output)
//printing are done in CSV format in order to be simply treated by Excel tool 
/******************************************************************************/
{
    
    pthread_mutex_lock(&tstatMutexI);

	if (!traficOn) {
		fprintf(output, "\n\t===========================");
		fprintf(output, "\n\t===  TGEN FINAL REPORT  ===");
		fprintf(output, "\n\t===========================\n");
    }
    
	// Header part
	tStatPrintHeader(output);

	// Requests statistics
	tStatPrintRequests(output);
    
	// Scenario statistics
    tScePrintScenarios(output, tstatTotalNbOfSeconds);

	// Footer part
	tStatPrintFooter(output);

	// CPU report
	tLoadPrintReport(output);

   pthread_mutex_unlock(&tstatMutexI);
}


