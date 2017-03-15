#ifndef tSce_h
#define tSce_h

#include "taction.h"


#define MAX_TRAFFIC_PROFILE 15
#define SCE_NAME_LENGHT 128
typedef struct tSce {
    
    char            name[SCE_NAME_LENGHT];
    tAction        *action;
    long            cnt;
    long            ko;
    long            timeout;
	int				exclusion;
	int				populMin;
	int				populNb;
} tSce ;

typedef struct tUser;
extern int		   tUserCurrentIndex;

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
int     tSceInit ();

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// SCENARIO HANDLING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
int     tScePrintScenarios (FILE * output, unsigned long nbsec);
tSce *  tSceGet ();
int     tSceRegister (const char * aSceName, tAction * aSce, int aOccurence, int exclusion, char * population);
void    tScePrecondition (const tSce* aSce, const struct tUser* aUser);


#endif
