
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include "limits.h"


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい


//CPU Load stat
#define BUFLEN              256
#define NB_MAX_PROCESS	    10



//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// METHODS PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

void 	tLoadCnxBreak(int sig);
int 	tLoadInit();
int 	tLoadEnd();
void *	tLoadSocketEntryPoint(void *param);
void 	tLoadUpdateConsole ();
int 	tLoadPrintCsv (FILE* output);
int 	tLoadPrintReport (FILE* output);

