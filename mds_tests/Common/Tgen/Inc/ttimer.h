#ifndef ttimer_h
#define ttimer_h

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

//timelist
typedef struct elem {
   struct elem		*next;
   void				*ctx;
} elem;


extern	elem*				*tTimerCircularTable;
extern	pthread_mutex_t *   tTimerMutex;


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
int		tTimerInit(int tableSize);
void	tTimerClose();
void	tTimerTopTU();
int		tTimerGetMaxSleepTime();


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい   
// TIMER HANDLING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
void*	tTimerGetUserToResume();
int		tTimerSetUserToSleep(void* aCtx, int nbTimeUnit);


#endif
