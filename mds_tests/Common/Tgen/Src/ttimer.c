#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "ttimer.h"
#include "tdebug.h"
#include "tthread.h"


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

elem *				*tTimerCircularTable;
pthread_mutex_t *   tTimerMutex;
static	int			tTimerCircularTableSize = 0;
static	int			currentIndex = 0;
static	int			tableClosed = 1;

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tTimerInit(int tableSize)
/******************************************************************************/ 
{
int rc=0;
    
   tTimerMutex = (pthread_mutex_t *) malloc ( sizeof (pthread_mutex_t) );
   if ( rc = pthread_mutex_init(tTimerMutex, NULL) > 0 ) {
	 TRACE_CRITICAL("tTimerInit exit: pthread_mutex_init failed! \n");    
	 return 1;
   }

   if (verbose >= 1) TRACE_CORE("init: circular timetable on %d TimeUnits\n", tableSize );

   if ( (tTimerCircularTable = (elem *)malloc( tableSize * sizeof(elem *) ) ) == NULL ) {
	 TRACE_CRITICAL("init: tTimer init failed\n");
	 return 1;

   } else {
	  int i;

	  for (i=0; i<tableSize; i++)
		 tTimerCircularTable[i] = NULL;
	  tTimerCircularTableSize = tableSize;

	  tableClosed = 0;
   }

   TRACE_DEBUG("init: tTimer tab size=%d\n", tableSize);

   return rc;
}    

/******************************************************************************/
void tTimerPrint()
/******************************************************************************/ 
{
elem*	myElem;
elem*	firstElem = NULL;
int		i, nb;
   
//   pthread_mutex_lock(tTimerMutex);
   
   for (i=0; i<tTimerCircularTableSize; i++) {
	  // mv ctx from 0 to max
	  nb = 0;

	  myElem = tTimerCircularTable[i];
	  while ( myElem ) {
   		 nb++;
		 myElem = myElem->next;
	  }
	  if (nb) TRACE_DEBUG("\tttimer: index=%d, nb_elem=%d\n", i, nb);
   }
   TRACE_DEBUG("\tttimer: currentIndex=%d\n", currentIndex);

//   pthread_mutex_unlock(tTimerMutex);
}

/******************************************************************************/
void tTimerClose()
// order is respected (may be important according to scenarios ???)
/******************************************************************************/ 
{
elem*	myElem;
elem*	firstElem = NULL;
int		i;
   
   pthread_mutex_lock(tTimerMutex);

   tTimerPrint();

   for (i=tTimerCircularTableSize-1; i>=0; i--) {
	  // mv ctx from i to 0

	  while ( myElem = tTimerCircularTable[i] ) {

   		 // suppress elem from list i
		 tTimerCircularTable[i] = tTimerCircularTable[i]->next;

		 // add elem in order in firstElem
		 myElem->next = firstElem;
		 firstElem = myElem;
	  }
   }

   // add firstElem at end of list 0
   tTimerCircularTable[0] = firstElem;

   // block add and top operations
   currentIndex = 0;
   tableClosed = 1;
   
   tTimerPrint();

   pthread_mutex_unlock(tTimerMutex);
}

/******************************************************************************/ 
void	tTimerTopTU()
/******************************************************************************/ 
{
int debuginfo = 0, i;

   pthread_mutex_lock(tTimerMutex);
   if ( tableClosed == 1 ) {
	  TRACE_DEBUG("ttimer: Timer table closed: can not top TU (threadId=%d)\n", tThread_getKey());
	  for (i=0; i<tTimerCircularTableSize; i++) {
		  int nb=0;
		  elem*	myElem = tTimerCircularTable[i];

		  while ( myElem ) {
			  nb++;
			  myElem = myElem->next;
		  }
		  if (nb) TRACE_DEBUG("\tttimer: index=%d, nb_elem=%d\n", i, nb);
	  }

	  pthread_mutex_unlock(tTimerMutex);
	  return;
   }
   pthread_mutex_unlock(tTimerMutex);
   
   // what to do with untreated remaining users ? => put them in next TU
   while ( !tTimerSetUserToSleep(tTimerGetUserToResume(),1) )
	  debuginfo++;
   
   if (debuginfo) TRACE_DEBUG("ttimer: tTimerTopTU: %d ctx pushed\n", debuginfo);

   pthread_mutex_lock(tTimerMutex);
   
   currentIndex = (currentIndex + 1) % tTimerCircularTableSize;
   
   pthread_mutex_unlock(tTimerMutex);
}

/******************************************************************************/ 
int		tTimerGetMaxSleepTime()
/******************************************************************************/ 
{
   return (tTimerCircularTableSize - 1);
}

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい   
// TIMER HANDLING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/ 
void*  tTimerGetUserToResume()
/******************************************************************************/ 
{
void*	res;
elem*	delElem;

   pthread_mutex_lock(tTimerMutex);
   
   if ( (delElem = tTimerCircularTable[currentIndex]) != NULL ) {
	  // remove first elem at that index
	  res = delElem->ctx;
	  tTimerCircularTable[currentIndex] = delElem->next;

	  free(delElem);

	  // TRACE_DEBUG("ttimer: tTimerGetUserToResume: found one\n");

   } else {
	  // no element
	  res = NULL;
   }

   pthread_mutex_unlock(tTimerMutex);

   return res;
}


/******************************************************************************/ 
int		tTimerSetUserToSleep(void* aCtx, int nbTimeUnit)
/******************************************************************************/ 
{
int 	rc=0;
elem*	newElem;
int		resumeIndex;
int		delay;

   if ( !aCtx ) {
   	  return 1;
   }

   if ( nbTimeUnit >= tTimerCircularTableSize) {
	  TRACE_CRITICAL("tTimerSetUserToSleep: sleep time is too long\n");
	  return 1;
   }

   if ( tableClosed == 1 )
	  // add ctx in current 
	  delay = 0;
   else
	  delay = nbTimeUnit;
   
   pthread_mutex_lock(tTimerMutex);
   
   // TRACE_DEBUG("valid tTimerSetUserToSleep - wait=%d\n", nbTimeUnit);
   
   if ( (newElem = malloc( sizeof(elem) ) ) == NULL ) {
	  TRACE_CRITICAL("tTimerSetUserToSleep: can not allocate timelist element\n");

	  pthread_mutex_unlock(tTimerMutex);
	  return 1;
   }
   newElem->ctx = aCtx;
   
   resumeIndex = (currentIndex + delay) % tTimerCircularTableSize;
   
   // add element at first position in list
   newElem->next = tTimerCircularTable[resumeIndex];
   tTimerCircularTable[resumeIndex] = newElem;

   pthread_mutex_unlock(tTimerMutex);
   return rc;
}




