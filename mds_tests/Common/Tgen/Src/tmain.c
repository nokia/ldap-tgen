
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include "tconf.h"
#include "tinit.h"
#include "tthread.h"
#include "tstat.h"
#include "tsce.h"
#include "libradius.h"
#include "tdebug.h"

/* 
TGEN NOTES:


TGEN EVOL:
1)create a treg tread which regulate W thread via tstat

    pthread_kill(tThread_getStatThread(), ...);

    tstat suspends W threads for a defined while

2)terminate in a proper way Tgen, when SIGINT is received (tMainSigHandler)
  instead of for(i=0; i<0xFFFFFFE; i++);
    pthread_join of all W thread

*/


void            tMainSigHandler(int sigNum);
static void *   tThreadMainEntryPoint (void *param);
//verbose Allows trace switch on/off with CTRL-Z when verbose level zero is required

// indicator that all Worker Threads have close all the sessions
extern int nbSessionsClosed;

extern int killcalled;
int nb_wt_to_restart = 0;

/************************************************************************************/
static int usage(void)
/************************************************************************************/
{
	TRACE_CONSOLE("\nTgen version " __VERSION__ ", Clearcase label " __CCLABEL__ "\n");
	TRACE_CONSOLE("Tgen: built on " __DATE__ " at " __TIME__ "\n\n");
	TRACE_CONSOLE("Usage:\n");
    TRACE_CONSOLE("------\n\n");
    TRACE_CONSOLE("\ttgen [-t traffic | -s scenario] [-r rate] [-p popul{,popul}] [-z thread] [-q] [-g group | hostname[=hostname2][:ldap_port:rad_port]]\n");
    TRACE_CONSOLE("\t\n");
    TRACE_CONSOLE("\tspecific:  [-a auth] [-U policy] [-w]\n");
    TRACE_CONSOLE("\tfiles:     [-o file] [-l log] [-c file]\n");
    TRACE_CONSOLE("\tmeasures:  [-T sec] [-u [server[:port]]]\n");
    TRACE_CONSOLE("\tinfo only: [-i traffic] [-j popul] [-h]\n");
    TRACE_CONSOLE("\tdebug:     [-v level] [-e | -ee] [-d | -dd]\n");
    TRACE_CONSOLE("\tobsolete:  [-x sec] \n");
    TRACE_CONSOLE("\t\n");
	
    TRACE_CONSOLE(" -t traffic  Requested traffic profile\n");
	TRACE_CONSOLE("             type \"tgen -i\" for traffic infos\n");
	TRACE_CONSOLE(" -s scenario Run 100%% of specified scenario. Then ignore -t option\n");
	TRACE_CONSOLE(" -r rate     Requested rate (message per sec)\n");
    TRACE_CONSOLE(" -p p1,p2... List of populations (comma separated)\n");
    TRACE_CONSOLE("             type \"tgen -j\" for population infos\n");
	TRACE_CONSOLE(" -z thread   Thread number running concurrently\n");
	TRACE_CONSOLE(" -b bind     Ldap Bind number established concurrently\n");
	TRACE_CONSOLE(" -x sec      User exclusion time (seconds)    !!! OBSOLETE!!!\n");
	TRACE_CONSOLE(" -q          Do not prints traffic error\n");
    TRACE_CONSOLE(" -g          Group of server\n");
    TRACE_CONSOLE(" hostname    IP address of server interface - default($HSS_IP_CX):%s\n", SERVER_HOST_IP);
    TRACE_CONSOLE(" hostname2   IP address of matted-pair seondary server interface - default(none)\n");
	TRACE_CONSOLE(" ldap_port   Ldap port - default: %d\n", LDAP_SERVER_HOST_PORT);
	TRACE_CONSOLE(" rad_port    Radius port - default: %d\n", RADIUS_SERVER_HOST_PORT); 
	
	TRACE_CONSOLE(" -T sec      Programs the Tgen time to run\n");
	TRACE_CONSOLE(" -u [server] Give server's CPU usage each second\n");	

	TRACE_CONSOLE(" -a auth     AuthenticationType policy - default: %d (%s)\n", RADIUS_AUTHTYPE_READ, tcRadiusAuthTypePolicyString[RADIUS_AUTHTYPE_READ]);
	TRACE_CONSOLE("             auth = [0: read, 1: user, 2: distrib]\n");
    TRACE_CONSOLE(" -U policy   User pick-up policy - default: %d (%s)\n", 0, "Ramdomly");
	TRACE_CONSOLE("             policy = [0: ramdom, 1: from 1 to n than stops, 2: from 1 to N then loop, X: loop on user X]\n");
    TRACE_CONSOLE(" -w          Use always the same user password (\"jean\") or same Authentication Vectors (first one)\n");	
    TRACE_CONSOLE(" -n          No NAS-Port attribute sent\n");
    TRACE_CONSOLE(" -m          Activate Mated-pair\n");	
    
    TRACE_CONSOLE(" -o file     Result csv filename - default: %s\n", CSV_FILE_NAME);
    TRACE_CONSOLE(" -l log      All log filename - default: %s\n", LOG_FILE_NAME);
    TRACE_CONSOLE(" -c file     Configuration filename (optional) - default if exists: ~/%s\n", INIT_FILE_NAME);
	
    TRACE_CONSOLE(" -v level    Verbose level - default: 1\n");
	TRACE_CONSOLE("             level = [0: quiet, 1: request rate tracing, 2:message header tracing, 3:message content tracing]\n");
	TRACE_CONSOLE(" -i traffic  Shows traffic infos\n");
	TRACE_CONSOLE("             i = 0: shows all available traffics\n");
	TRACE_CONSOLE(" -j popul    Shows population infos\n");
	TRACE_CONSOLE("             j = 0: shows all available populations\n");
    TRACE_CONSOLE(" -h          Shows program version information, options usage and quits\n");
	
    TRACE_CONSOLE(" -e          tgen stops on traffic error\n");	
	TRACE_CONSOLE(" -ee         abort tgen on abnormal signal (debugging)\n");	
    TRACE_CONSOLE(" -d          tgen debug mode\n");
    TRACE_CONSOLE(" -dd         tgen + openldap/freeradius stacks debug mode\n");
    TRACE_CONSOLE(" -A          IPV6 address of server interface\n");
    TRACE_CONSOLE(" -P          IPV6 port\n");
    TRACE_CONSOLE(" -L val      val = [0: nolog, 1: no log on error]\n");
   	exit(1);
}

/************************************************************************************/
int main( int argc, char **argv )
/************************************************************************************/
{
void                *status =NULL;
int                 c,rc,i,j;
pthread_t           tid;
char *				pldap;
char *				prad;
char *				psec;
int					index_popul;
char                ldapdebug = -1;
char				csvfname[64];
char				rptfname[64];
char				logfname[64];
char *				p;
struct timeb		ptb;
char				buf[32];
int 				test_all;
int					threadId;
int 				test_conflit = 0; //test conflit Group of server vs Matted_pair

    //set Tgen Conf data to their unset value
    strcpy(csvfname, CSV_FILE_NAME);
    strcpy(logfname, LOG_FILE_NAME);
	strcpy(inifile, getenv("HOME"));
  	strcat(inifile, "/" INIT_FILE_NAME);


	for (i=0; i<argc; i++) 
	 	sprintf(tcFullCommandLine + strlen(tcFullCommandLine), "%s ", argv[i]);

    /* get args */
    while ((c = getopt(argc, argv, "a:b:c:deg:hi:j:l:mno:p:qr:s:t:u::v:wx:z:A:L:P:U:T:")) != EOF) {
      switch(c) {
		case 'a':
			if (!isdigit(*optarg))
				usage();
			tcRadiusAuthTypePolicy = atoi(optarg);
			break;
	    case 'b':
			  if (!isdigit(*optarg))
				  usage();
			  tcLdapBindNb = atoi(optarg);
			  break;
	    case 't':
			  if (!isdigit(*optarg))
				  usage();
			  tcTrafficProfile = atoi(optarg);
			  break;
		case 'r':
			if (!isdigit(*optarg))
				usage();
			tcNbOfRequestPerSecond = atoi(optarg);
			break;
		case 'p':
			if ( optarg != NULL && strcmp(optarg, "") != 0 ) {
				tcPopulation = strdup(optarg);
			}		
            break;
		case 'v':
			if (!isdigit(*optarg))
				usage();
			verbose = atoi(optarg);
			break;
		case 'o':
			if (optarg != NULL && strcmp(optarg, "") != 0 )
				strcpy(csvfname, optarg);
			break;
		case 'l':
			if (optarg != NULL && strcmp(optarg, "") != 0 )
				strcpy(logfname, optarg);
			break;
		case 'c':
			if (optarg != NULL && strcmp(optarg, "") != 0 )
				strcpy(inifile, optarg);
			break;			
		case 'e':
            		stopOnError += 2;
			break;
		case 'w':
            		sameUserPasswd = 1;
			break;
		case 'u':
			if ( optarg != NULL ) {
				cpuLoad[0] = strdup(optarg);
			} else {
				cpuLoad[0] = "";
			}
			break;
		case 'q':
            		quietOnError = 1;
			break;
		case 's':
			if (!isdigit(*optarg))
				usage();
			tcScenario = atoi(optarg);
			break;
        case 'g'://///////////////////////////////////////rajout pour serveur
			if ( optarg != NULL && strcmp(optarg, "") != 0 )
				tcGroupServer = strdup(optarg);
			g_option = 1;
			test_conflit ++;
			break;
        case 'd':
		    debug ++;
            if (debug == 2) {
                ber_set_option(NULL, LBER_OPT_DEBUG_LEVEL, &ldapdebug);
                ldap_set_option(NULL, LDAP_OPT_DEBUG_LEVEL, &ldapdebug);
				librad_debug = 1;
			}
			break;		
		case 'h':
			usage();
			break;
		case 'i':
			if (!isdigit(*optarg))
				usage();
			tcTrafficInfo = 2;

			tcTrafficProfile = atoi(optarg);
			break;
		case 'j':
			if (!isdigit(*optarg))		// even a list should start by a digit
				usage();
			tUserPopulInfo(optarg);
			break;
        case 'x':
            if (!isdigit(*optarg))
                usage();
            tcUserExclusion = atoi(optarg);
            break;
		case 'z':
			if (!isdigit(*optarg))
				usage();
			tcWThreadNb = atoi(optarg);
            break;
		case 'n':
			// add the NAS-Port attribute to AccessRequest messages
			tcRadiusNoNasPort = 0;
			break;
		case 'm':
			// activate the matted-pair function (specific defense & keep alive)
		    tcNoMattedPair = 0;
            test_conflit ++;
			break;
		case 'U':
		    if (!isdigit(*optarg))
			   usage();
			tcUserGetPolicy = atoi(optarg);
			break;
		case 'T':
			if (!isdigit(*optarg))
			   usage();
			tcTimeToRun = atoi(optarg);
			break;
		case 'A':
			if (!isalnum(*optarg))
				usage();
			A_option = 1;
			tcServerHost[0] = strdup(optarg);
			break;
		case 'P':
			if (!isdigit(*optarg))
				usage();
			tcServerPort[0] = atoi(optarg);
			tcServerPort[1] = atoi(optarg);
			break;
		case 'L':
			if (!isdigit(*optarg))
				usage();
			if (atoi(optarg)==0) nolog_option = 1;
			if (atoi(optarg)==1) nolog_option = 2;
			break;
		default:
			usage();
			break;
	  }
	}
	argc -= (optind - 1);
	argv += (optind - 1);

    //test conflit Matted_pair vs Group of server
	if(test_conflit == 2) {
		printf("It's not possible to activate the group of server option and the matted_pair option together\n");
		exit(1);
	}

	strcpy(rptfname, csvfname);
	if ( !(p = strrchr(rptfname, '.')) )
		p = rptfname + strlen(rptfname);
	strcpy(p, ".out");

	// protection against erasing old output files
	test_all =  (tcLogFile = fopen(logfname, "r"));
	test_all += (tcCsvFile = fopen(csvfname, "r"));
	test_all += (tcRptFile = fopen(rptfname, "r"));
	if ( test_all ) {
		char rep;
		printf("Following Output files already exists:\n");
		if (tcLogFile) {
			printf("\t- %s\n", logfname);
			fclose(tcLogFile);
		}
		if (tcCsvFile) {
			printf("\t- %s\n", csvfname);
			fclose(tcCsvFile);
		}
		if (tcRptFile) {
			printf("\t- %s\n", rptfname);
			fclose(tcRptFile);
		}
		printf("Overwrite them ? (y/n): ");
		rep = getchar();
		if (tolower(rep) != 'y') {
			printf("Did not want to overwrite output files. Quit.\n");
		    exit(1);
		}
	}

	// init LOG file
	if ( !(tcLogFile = fopen(logfname, "w")) ) {
		TRACE_CRITICAL("can't open log file %s\n", logfname);
		exit(1);
	}
	stderr = tcLogFile;

	// init CSV file
	if ( !(tcCsvFile = fopen(csvfname, "w")) ) {
		TRACE_CRITICAL("can't open csv ouput file %s\n", csvfname);
		exit(1);
	}
	fprintf(tcCsvFile, "Date,Sec of trafic,Responses received,Asked rate,Errors,Timeouts,QOS(ko),QOS(timeout),Cpu user,Cpu sys,Cpu idle\n");
	fflush(tcCsvFile);

	// init REPORT file
	if ( !(tcRptFile = fopen(rptfname, "w")) ) {
		 TRACE_CRITICAL("can't open report file %s\n", rptfname);
		 exit(1);
	 }

	TRACE_CORE("Tgen version %s, Clearcase label %s, build %s %s\n", __VERSION__, __CCLABEL__, __DATE__, __TIME__);


	// hostname is NOT mandatory
	if ((argc < 2) && (g_option == 0) && (A_option == 0)){
	   tcServerHost[0] = SERVER_HOST_IP;
	} else if ((g_option == 0) && (A_option == 0)){
		// parsing hostname
		TRACE_CORE("Parsing hostname: %s\n", argv[1]);

		// read Ldap port if present
 		if ((pldap = strchr(argv[1], ':')) != NULL) {
			*pldap++ = 0;

			// read Radius port if present
			if ((prad = strchr(pldap, ':')) != NULL) {
			*prad++ = 0;
				tcServerRADIUSPort = atoi(prad);
			}
			tcServerLDAPPort = atoi(pldap);
			tcServerPort[0] = tcServerLDAPPort;
			tcServerPort[1] = tcServerLDAPPort;
		}
        
        // read secondary server if present
        if ((psec = strchr(argv[1], '=')) != NULL) {
            *psec++ = 0;
            tcServerHost[1] = strdup(psec);
        }

        tcServerHost[0] = strdup(argv[1]);
    }

    // Get IP address of server interface
    if ( tcServerHost[0] && !isalnum(tcServerHost[0][0]) ) {
        struct hostent*     remoteHost;
        unsigned int        hostaddr;
        char                tmpadd[32];
        int					af;

        af= AF_INET;
        remoteHost = gethostbyname2(tcServerHost[0],af);
        if (!remoteHost) {
        	af= AF_INET6;
        	remoteHost = gethostbyname2(tcServerHost[i],af);
        }
        
        printf("gethostbyname2 tcServerHost[0] = %s\n", tcServerHost[0]);
        if (!remoteHost) {
            TRACE_CRITICAL("Unable to resolve hostname: %s\n", tcServerHost[0]);
            exit(1);
        }
        sprintf( tmpadd, "%d.%d.%d.%d", (unsigned char)(remoteHost->h_addr)[0],
                                        (unsigned char)(remoteHost->h_addr)[1],
                                        (unsigned char)(remoteHost->h_addr)[2], 
                                        (unsigned char)(remoteHost->h_addr)[3]);
        tcServerHost[0] = strdup( tmpadd );
    }

    // Get IP address of secondary server interface
    if ( tcServerHost[1] && !isalnum(tcServerHost[1][0]) ) {
        struct hostent*     remoteHost;
        unsigned int        hostaddr;
        char                tmpadd[32];
        int					af;

        af= AF_INET;
        remoteHost = gethostbyname2(tcServerHost[i],af);
        if (!remoteHost) {
        	af= AF_INET6;
        	remoteHost = gethostbyname2(tcServerHost[i],af);
        }
        
        if (!remoteHost) {
            TRACE_CRITICAL("Unable to resolve hostname: %s\n", tcServerHost[1]);
            exit(1);
        }
        sprintf( tmpadd, "%d.%d.%d.%d", (unsigned char)(remoteHost->h_addr)[0],
                                        (unsigned char)(remoteHost->h_addr)[1],
                                        (unsigned char)(remoteHost->h_addr)[2], 
                                        (unsigned char)(remoteHost->h_addr)[3]);
        tcServerHost[1] = strdup( tmpadd );
    }


	// increase priority of whole process
	//sched_setscheduler(pit_t pid, int policy, const struct sched_param *param);

	// launch tgen init
	tInit();
	
	ftime(&ptb);
	fprintf(tcRptFile, "\t=============================\n");
	fprintf(tcRptFile, "\t===  PERIODIC REPORT FILE ===\n");
	fprintf(tcRptFile, "\t=============================\n\n");
	fprintf(tcRptFile, "Tgen Report file every %d seconds\n", tcReportPeriod);
	
	fprintf(tcRptFile, "Tgen version %s, Clearcase label %s\n", __VERSION__, __CCLABEL__);
	fprintf(tcRptFile, "Simu PC: \t\t\t\t\t\t%s (%s)\n", RADIUS_CLIENT_NAS_IP_ADD, RADIUS_CLIENT_NAS_ID);
	fprintf(tcRptFile, "Launching command line: \t\t%s\n", tcFullCommandLine);
    if(g_option == 0)
		fprintf(tcRptFile, "Initial destination servers: \tMASTER=%s - SLAVE=%s \n", tcServerHost[0], (tcServerHost[1] ? tcServerHost[1] : "none"));
	if(g_option == 1){
		fprintf(tcRptFile, "Destination servers: \t%s",tcServerHost[0]);
		for(i=1; i<nbserver; i++){
			fprintf(tcRptFile, " - %s", tcServerHost[i]);
		}
		fprintf(tcRptFile, "\n");
	}
    fprintf(tcRptFile, "Starting date:\t\t\t\t\t%s\n", ctime_r(&ptb.time, buf) );
	fflush(tcRptFile);


	// Signal Management: signal handler for signal handling by thread #0
	{
		struct sigaction 	sigAction  = { 0 };
		
//		sigfillset( &sigAction.sa_mask);
//		sigdelset( &sigAction.sa_mask, SIGINT);
		sigAction.sa_handler = tMainSigHandler;
		sigAction.sa_flags   = 0;
		
		sigaction(SIGPIPE, &sigAction, NULL);
		sigaction(SIGSEGV, &sigAction, NULL);
		sigaction(SIGTSTP, &sigAction, NULL);
		sigaction(SIGURG,  &sigAction, NULL);

		// special for CrtlC
//		sigAction.sa_flags   = SA_NOMASK;
		sigaction(SIGINT,  &sigAction, NULL);
	}
	// set to main thread a higher priority to be able to treat interruption ASAP
	setpriority(0,0,-19);

	// resume children threads
	for (threadId=MAINTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		tThread_getState(threadId) = RUNNING ;
		if ( (threadId%10) == 0) usleep(5000);
	};
	
	//Wait for Signal, see tMainSigHandler
	while (!killcalled) {
		sleep(1);
		
		if (!tcNoMattedPair) {
			// server keep alive
			if ( !tReinitIsAlive(tcLdapBindNb) )
				tBreak(0);
		}

		if (nb_wt_to_restart) {
			tThreadStart(nb_wt_to_restart);
			nb_wt_to_restart = 0;
		}
	}

	//
	// Terminate pg (outside of signal handling)
	//
	
	// EmA,14/02/2011: avoid decreasing the traffic rate at the 2 seconds ending
	// switch off: counting stats, tracing
	traficOn = 0;
	
	 // indicates Worker Threads not to start new scenario
	 tInitServerState = SRV_DOWN; // do not try to reopen broken Ldap cnx (inside tLdap_abandon() called by tSelect)
	 for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		 tThread_getState(threadId) = ENDING ;		// threads are still active
	 }

	 // ends all current delays in scenarios
	 if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) sleep(2);			// for Ldap asynchronous requests
	 tTimerClose();		// will make ldap async requests to be in timeout!

	 // indicates Worker Threads to terminate started scenario
	  for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		  tThread_getState(threadId) = ENDING2 ;		// threads are still active
	  }

	 // wait for each thread to terminate its current sce and all user session
	 while ( nbSessionsClosed < tcWThreadNb ) {
		 TRACE_DEBUG("still waiting for a thread to FINISH... (%d on %d)\n", nbSessionsClosed, tcWThreadNb);
		 sleep(1);
	 }
	 TRACE_DEBUG("all threads FINISH.\n");

	 // unbind Ldap connexions (may lead to deadlock if a restart is in process) before tStatEnd() for unbind stats
	 tLdapClose();

// EmA,14/02/2011: avoid decreasing the traffic rate at the 2 seconds ending
	 // switch off: counting stats, tracing
	 //traficOn = 0;

	 /* print stat */
	 tStatPrintReport(tcRptFile);
	 tStatEnd();        

	 /* nothing else to put into these files */
	 fclose(tcCsvFile);
	 fclose(tcRptFile);
	 fclose(tcLogFile);

	 /* exit */
	 exit(0);
  /* EmA,17/03/2004: profiling with gprof needs a clean exit
	 pthread_kill( tThread_getStatThread(), SIGKILL );
	 for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
		 pthread_kill( tThreadConfTab[threadId].tid, SIGKILL );
	 };

	 pthread_exit(0);
  */
}


extern void *tThreadStatEntryPoint (void *param);
extern void *tThreadWorkerEntryPoint (void *param);
/******************************************************************************/
void tMainSigHandler(int sigNum)
/******************************************************************************/
{   
sigset_t		  signalSet = { 0 };
pthread_t         tid;
pthread_attr_t    attr;
size_t            size;
int               status;

	TRACE_CORE("signal %d catched by thread %d, stopOnError=%d \n", sigNum, tThread_getKey(), stopOnError);
	
	if (sigNum==SIGPIPE) 
	  TRACE_CORE("broken pipe received by thread %d \n", tThread_getKey());
	
	if (sigNum==SIGSEGV)
	  TRACE_CORE("segmentation fault received by thread %d \n", tThread_getKey());

    if (sigNum==SIGPIPE || sigNum==SIGSEGV) {

        if ( stopOnError & 0x02 ) {
			fclose(tcLogFile);
			fclose(tcRptFile);
			fclose(tcCsvFile);
			abort();
		}

		// try to avoid loops of SEGV which are fatal for tgen
		if (tThread_getKey() != MAINTHR) {
			//EmA,04/03/2011: il faudrait gérer une liste (avec mutex) pour réactivation à la seconde pour que ça marche !!!
			//nb_wt_to_restart = tThread_getKey();
			nbSessionsClosed++; // ne pas attendre ce thread à la fin !!!
		}
        /* re-start a new thread
        pthread_attr_init( &attr );
        pthread_attr_getstacksize( &attr, &size );
        if ( tThread_getKey() == STATTHR ) {
            TRACE_CORE("restarting the Stat thread\n");
            if ( pthread_create( &tid, &attr, tThreadStatEntryPoint, (void *)tThread_getKey() ) < 0) {
                TRACE_CRITICAL("pthread_create failed! Error=%d \n", status);
            }
		} else if ( tThread_getKey() >= SLCTTHR && tThread_getKey() < WORKTHR) {
			TRACE_CORE("restarting the Select thread\n");
			if ( pthread_create( &tid, &attr, tThreadSelectEntryPoint, (void *)tThread_getKey() ) < 0) {
				TRACE_CRITICAL("pthread_create failed! Error=%d \n", status);
			}
        } else if ( tThread_getKey() != MAINTHR ) {
            TRACE_CORE("restarting a Worker thread\n");
            if ( pthread_create( &tid, &attr, tThreadWorkerEntryPoint, (void *)tThread_getKey() ) < 0) {
              TRACE_CRITICAL("pthread_create failed! Error=%d \n", status);
            }
        }
        tThreadConfTab[tThread_getKey()].tid = tid;
        pthread_attr_destroy(&attr);
		*/

		// kill myself
        tThreadCleanUpMutex(tThread_getKey());
		pthread_exit(1);
	}
	
    if (sigNum==SIGURG) {
		// Ldap server down
		tBreak(0);
	}
	
	if (sigNum==SIGTSTP) {
		// temporary stop tgen
		tStop(0);
	}
	
	if (sigNum==SIGINT) {
	    // end of tgen
	    tEnd(0);
	}

}

