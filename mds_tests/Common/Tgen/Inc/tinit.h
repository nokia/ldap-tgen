
int	    tInit();
int	    tReinit();
int     tReinitIsAlive(int key);
void	tBreak(int sigNum);
void	tStop(int sigNum);
void*	tEnd(void *param);
int                     tInitGetServerState ();
int                     tInitSetServerState (int state);

#define SRV_DOWN                0
#define SRV_RUNNING             1

extern int     tInitServerState;


