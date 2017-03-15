#ifndef tserver_h
#define tserver_h

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>


int     tServerInit (char *gouplist);
int     tServerPopulInit(int serverIndex);
int     getNextServer(int ActiveServer);

#endif

