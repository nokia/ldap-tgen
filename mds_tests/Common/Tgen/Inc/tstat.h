
#include "texec.h";

#define IN_SECOND 0
#define IN_PERIOD 1
#define IN_TOTAL  2
#define	DIM_MAX	  3

extern unsigned long		nbSecWithTraficOn;
extern pthread_t   			tloadThreadId;

int     tStatInit ();
int     tStatEnd ();
void    tStat (int key);

int     tStatWaitForStart();
void    tStatWaitFor (long int sect);
int     tStatRegulation (int key);
int     tStatCount (int key);
//traffic Function 
typedef int     (*tStatTrafficFunctionType)(int) ;
int     tStatRegisterTrafficFunction( tStatTrafficFunctionType fct);

//default registered: stable traffic
//The traffic request is stable and equals to the requested traffic.
int      tStatTrafficFunction_stable( time);

//The traffic request grows in a linear way during the 20 seonds period from
//the requested traffic.
int      tStatTrafficFunction_linear1 (int time);

//One burst every 10 seconds period. The burst appears randomly during the period. 
//Burst excluded, the traffic request is stable and equals to the requested traffic.
int      tStatTrafficFunction_bursty (int time);

//
int     tStatTimeBegin (int idx);
int     tStatTimeEnd (int idx);
long    tStatTimeDelta (int idx);
int     tStatActionTime (int reqId, char verdict, int retry, long usec);
int     tStatSceTime (int sceId);
int     tStatPrintReport (FILE * output);

typedef struct tStatActionMeasure {
    
    char                 rq_name[32];
    char                 overflow;
    unsigned long long   tm_cum;
	//EmA,02/03/2011: increase precision of mean response time (ms is not enough now)
    float		         tm_mean;
    unsigned long        tm_min;
    unsigned long        tm_max;
    unsigned long        tm_maxDelay; /* Max answer delay */
    unsigned long        rq_cnt;
    unsigned long        rq_maxDelay;
    unsigned long        rq_ko;
    unsigned long        rq_retry;

} tStatMeasure ;

tStatMeasure   tStatTab[SCE_End];

int tStatIncrStationDown ();
int tStatIncrStationRestart ();
int tStatIncrServerMPswitch ();

