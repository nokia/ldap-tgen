#ifndef tUser_h
#define tUser_h

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "taction.h"
#include "tsce.h"

typedef struct eapsim_keys;
#define MY_ENCR_DATA_LEN_MAX   64              // should be 200, but it's to big !!!
#define EAPSIM_AUTH_SIZE    16

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA
//
// What is a common user in MDS scope ?
// First Response (assertion?): A user is a LDAP entry and a Authenticable entity
// How to do with entry without Common Name ... more generalize...
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

typedef struct tLdapEntry {
        char            dn[256];   //DN Distinguish Name
//        char           rdn[32];  //Main RDN attribute/value     
        char            base[256]; //search base DN                
        char            filter[128];//search filter        
        int             scope;     //search scope
} tLdapEntry;   

typedef struct tAuth {
        char            nai[64];  
        char            passwd[32];
        int             authType;  
        char            stateAttrib[2][160];      // between Challenge/Response + Re-Authentication
        int             stateAttribLength[2];
        unsigned char   K_aut[EAPSIM_AUTH_SIZE];
        unsigned char   K_encr[16];
        char *          frId;
        char            aaa_session_id[32];
		int             aaa_session_idLength;
        char            ppaq[128]; 
        int             ppaqLength;
} tAuth;

typedef struct tSess {
		char            sessionId[2][32];  
		int             sessionIdLength[2];  
        int             startTime[2];
        char            classAttrib[2][160];
        int             classAttribLength[2];     // between Auth & Acct
        int             portNb;  
} tSess;

//private to tgen
typedef struct tPrivate {
        int                   id;
        long                  cnt;
        time_t                lastTime;
        unsigned short        exeState;
		tSce *				  lastSce;
} tPrivate;
   
typedef struct tUser {
            tPrivate        priv;
            tLdapEntry      *ldapE;
            tCmdRes         *cmdRes; // temporary allocation to store cmde result
            tAuth           *auth;
            tSess           *sess;
//            void*           additionalInfo;
} tUser;

struct stats_memory {
       unsigned long frmkb	__attribute__ ((aligned (8)));
       unsigned long bufkb	__attribute__ ((aligned (8)));
       unsigned long camkb	__attribute__ ((aligned (8)));
       unsigned long tlmkb	__attribute__ ((aligned (8)));
       unsigned long frskb	__attribute__ ((aligned (8)));
       unsigned long tlskb	__attribute__ ((aligned (8)));
       unsigned long caskb	__attribute__ ((aligned (8)));
       unsigned long comkb	__attribute__ ((aligned (8)));
       unsigned long activekb	__attribute__ ((aligned (8)));
       unsigned long inactkb	__attribute__ ((aligned (8)));
      };

#define STATS_MEMORY_SIZE	(sizeof(struct stats_memory))

#define     exeState_IDLE           0
#define     exeState_RUNNING        1
#define     exeState_ABORT          2

#define     MAX_POPUL        	    13

#ifndef MAX
#define MAX( x, y )   ( (x) > (y) ? (x) : (y) )
#endif
#ifndef MIN
#define MIN( x, y )   ( (x) < (y) ? (x) : (y) )
#endif


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT POPUL
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
int     tUserInit (char *populationList);
int     tUserPopulInfo(char *populationList);
int     tUserPopulInit(int populIndex);
//int     tUserPopulMalloc(int size_of_user);
int     tUserPopulFillIn(int  scope,
                        char *pdn,
                        char *rdn,
						char *filter,
                        char *nai,
                        char *passwd,
						int	 authType,
						int  idx);
                        
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい   
// USER CHOICING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
tUser*  tUserGet(int userIndex);
tUser*  tUserGetRandomly(tSce * sce);
void    tUserFree(int);
void    tUserAbort(int tUseri);
int     tUserIsAborted(int tUseri);


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// USER DATA ACCESSORS
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

// read only
char *      tUserGetDN(tUser *aUser);
int         tUserGetExclusion(tUser *aUser);
//char *      tUserGetRDN(tUser *aUser);
long        tUserGetId(tUser *aUser);
char *      tUserGetBase(tUser *aUser);
char *      tUserGetFilter(tUser *aUser);
int         tUserGetScope(tUser *aUser);
int         tUserGetBaseIsThereACmd(tUser *aUser);
char *      tUserGetBaseFromCmdRes(tUser *aUser);
char *      tUserGetFilterFromCmdRes(tUser *aUser);
char *      tUserGetNAI(tUser *aUser);

// read write
int         tUserGetAuthType(tUser *aUser);
void        tUserSetAuthType(tUser *aUser, int authType);
char *      tUserGetPasswd(tUser *aUser);
void      	tUserSetPasswd(tUser *aUser, char * passwd);
char *      tUserGetIMSI(tUser *aUser);
void      	tUserSetIMSI(tUser *aUser, char * imsi);
char *      tUserGetSessionId(tUser *aUser, int reloc);
int         tUserGetSessionIdLength(tUser *aUser, int reloc);
void	    tUserSetSessionId(tUser *aUser, char * sessionId, int length, int reloc);
int         tUserGetSessionStartTime(tUser *aUser, int reloc);
void        tUserSetSessionStartTime(tUser *aUser, int date, int reloc);
char *      tUserGetClassAttrib(tUser *aUser, int reloc);
int         tUserGetClassAttribLength(tUser *aUser, int reloc);
void        tUserSetClassAttrib(tUser *aUser, char * classAttrib, int length, int reloc);
char *      tUserGetStateAttrib(tUser *aUser, int reloc);
int         tUserGetStateAttribLength(tUser *aUser, int reloc);
void        tUserSetStateAttrib(tUser *aUser, char * stateAttrib, int length, int reloc);
int         tUserGetPortNb(tUser *aUser);
void        tUserSetPortNb(tUser *aUser, int portNb);
int         tUserGetFastAuthData(tUser *aUser, struct eapsim_keys *eapsim_mk, char* fr_id);
void        tUserSetFastAuthData(tUser *aUser, struct eapsim_keys *eapsim_mk, char* fr_id);

// Added by RHL | Aug 21, 2008 | used for Prepaid Charging testing
char *	    tUserGetAAASessionId(tUser *aUser);
int         tUserGetAAASessionIdLength(tUser *aUser);
void	    tUserSetAAASessionId(tUser *aUser, char * aaa_session_id, int length);
char *	    tUserGetPPAQ(tUser *aUser);
int         tUserGetPPAQLength(tUser *aUser);
void	    tUserSetPPAQ(tUser *aUser, char * ppaq, int length);


#endif 
