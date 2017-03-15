#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <sys/resource.h>

#include "tconf.h"
#include "tthread.h"
#include "tuser.h"
#include "tradius.h"
#include "tdebug.h"

#include "eap_sim.h"

extern int 		killcalled;

tUser*                 tUserPopul = NULL;
tUser*                 tUserPopul1 = NULL;
pthread_mutex_t        tUserMutex = PTHREAD_MUTEX_INITIALIZER;
static int			   tUserSize;
int     		       radAuthTypeTab[100];
int			   		   tUserCurrentIndex = 0;
unsigned long 		tlmkb;
unsigned long 		frmkb;

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT POPUL
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tUserInit (char *populationList)
/******************************************************************************/    
{
int    popul;
char * pch;

	// EmA,26/11/2007: we do not use the tgen.ini default popul anymore
    if (populationList == NULL)
		// populations has been loaded by scenarios
		return 0;

	if ( (pch = strtok (populationList, ",")) == NULL ) {
		TRACE_CRITICAL("init: bad population's list \n");
		return 1;
	}
	while ( pch != NULL ) {
		popul = atoi(pch);
		if  ( tUserPopulInit(popul) != 0 ) return 1;
	
		pch = strtok (NULL, ",");
	}

	// init Authentication Type table (for -a2 option)
	int authtype_code;
	char authtype_param[32];
	int authtype_rate;
	int i=0;
	int j;
	for (authtype_code=0;authtype_code<20;authtype_code++) {	// max 20 different authtypes
		sprintf(authtype_param, "authtype_distrib_%d", authtype_code );
		authtype_rate = ProfileGetInt( inifile, "Radius", authtype_param, 0 );
		if (authtype_rate)
			TRACE_CORE("    	AuthType Distrib #%d: %d%%\n", authtype_code, authtype_rate);

		if ( (i+authtype_rate) > 100 ) {
			TRACE_CRITICAL("tuser: tUserPopulInit: bad Authtypes distribution\n");
			return 1;
		}
		for (j=0; j<authtype_rate; j++) radAuthTypeTab[i+j] = authtype_code;
		i += authtype_rate;
	}
	for (j=0; j<100; j++)
		TRACE_DEBUG("    	AuthType Distrib radAuthTypeTab[%d]=%d\n", j, radAuthTypeTab[j]);

	return 0;
}

    
/******************************************************************************/
int tUserPopulInfo (char *populationList)
/******************************************************************************/    
{
int 	popul;
char * 	pch;

	tcTrafficInfo = 1;

	if ( atoi(populationList) == 0 ) {
		// list all popul
		for (popul=1; popul<10000; popul++ )
			tUserPopulInit(popul);

	} else {
		if ( (pch = strtok (populationList, ",")) == NULL ) {
			TRACE_CRITICAL("init: bad population's list \n");
			exit(1);
		}
		while ( pch != NULL ) {
			popul = atoi(pch);
			tUserPopulInit(popul);

			pch = strtok (NULL, ",");
		}
	}

    exit(0);
}


/******************************************************************************/
int     tUserPopulInit(int populIndex)   
/******************************************************************************/ 
{
int 	rc=0;
int 	i,j;
int 	userMin, userMax, userNb, userNbMax;
char 	section[128] = "";
char    description[256] = "";
int     scope;
char    pdn[128] = "";
char    rdn_i[128] = "";
char    rdn[128] = "";
char    filter_i[128] = "";
char    filter[128] = "";
char    nai_i[128] = "";
char    nai[128] = "";
char    passwd_i[128] = "";
char    passwd[128] = "";
int     authtype;

    sprintf(section, "Popul_%d", populIndex );
    
    // if not description, considere the population is not present in ini file
    ProfileGetString( inifile, section, "description", "", description, sizeof(description) );
    if (description[0] == 0) {
        if (!tcTrafficInfo) TRACE_CRITICAL("tuser: tUserPopulInit: unknown population\n");
        return 1;
    }

    sprintf(tcRadiusNasIdBase[0], "NAS_%s_", section);             // must not exeed 32 bytes !!!
    sprintf(tcRadiusNasIdBase[1], "WAC_%s_", section);             // must not exeed 32 bytes !!!
//EmA,11/01/2007: compatibility with Supplicant tool (EAP/TTLS need)
//    sprintf(tcRadiusNasIpAddBase, "135.10.%d.", populIndex);
    strcpy(tcRadiusNasIpAddBase[0], "127.0.0.");
    strcpy(tcRadiusNasIpAddBase[1], "127.1.1.");

    userMin = ProfileGetInt( inifile, section, "min", 0 );
    userMax = ProfileGetInt( inifile, section, "max", 0 );
    
    TRACE_TRAFIC("inifile = %s section = %s\n", inifile,section);
    TRACE_TRAFIC("userMin = %d userMax = %d\n", userMin,userMax);
    if (userMin >= userMax) {
    	TRACE_CRITICAL("In %s min(%d) is > max(%d)\n",section, userMin, userMax);
    	exit(1);
    }

    userNbMax = userMax - userMin + 1;
    userNb      = ProfileGetInt( inifile, section, "nb", userNbMax );
    if (userNb > userNbMax) {
		TRACE_CORE("WARNING: [min(%d),max(%d)] range will not contain up to nb=%d users in population #%d\n", userMin, userMax, userNb, populIndex);
		userNb = userNbMax;
	}
	if (userNb < userNbMax) {
		TRACE_CORE("WARNING: only the first nb=%d users in [min(%d),max(%d)] range will be used in population #%d\n", userNb, userMin, userMax, populIndex);
		userMax = userMin + userNb - 1;
	}

    tcUserNb += userNb;
// Control not compatible with multiple-popul
//    if (tcUserGetPolicy > tcUserNb)
//        return 1;

    if (tcTrafficInfo == 1 ) {
		TRACE_CONSOLE("    Population #%d: %s, %d users in range = [%d, %d]\n", populIndex, description, userNb, userMin, userMax);
		return 0;
	} else
		TRACE_CORE("    Population #%d: %s, %d users in range = [%d, %d]\n", populIndex, description, userNb, userMin, userMax);
	

    // read popul in tgen.ini file
    scope = ProfileGetInt( inifile, section, "scope", LDAP_SCOPE_BASE );
    ProfileGetString( inifile, section, "pdn", "", pdn, sizeof(pdn) );
    ProfileGetString( inifile, section, "rdn_i", "", rdn_i, sizeof(rdn_i) );
    ProfileGetString( inifile, section, "filter_i", "(objectclass=*)", filter_i, sizeof(filter_i) );
    ProfileGetString( inifile, section, "nai_i", "", nai_i, sizeof(nai_i) );
    ProfileGetString( inifile, section, "passwd_i", "", passwd_i, sizeof(passwd_i) );
    authtype = ProfileGetInt( inifile, section, "authtype", AUTHTYPE_EAPSIM );

    read_proc_meminfo();
    TRACE_CORE("MemTotal = %u \n",tlmkb);
    TRACE_CORE("MemFree = %u \n",frmkb);

    tUserSize = sizeof(tUser);
    long MemUtil = tUserSize * (tcUserNb/100);
    TRACE_CORE("MemUtile = %u \n",MemUtil);
    //TRACE_CORE("tUserS = %u \n",(tUserSize * tcUserNb));

    if(frmkb < MemUtil){
    	TRACE_CRITICAL("not enough memory\n");
    	return 1;
    }
    if(tcUserNb <= MaxUsrMemory){
    	// allocate memory
    	if ( (tUserPopul = realloc( tUserPopul, tUserSize * tcUserNb)) == NULL ) {
    		 TRACE_CRITICAL("tUserPopulMalloc: not enough memory\n");
    		 return 1;
    	}
    }else {
    	tcUserNb1 = tcUserNb - MaxUsrMemory;
    	tcUserNb2 = MaxUsrMemory;
    	if ( (tUserPopul = realloc( tUserPopul, tUserSize * tcUserNb2)) == NULL ) {
    	    TRACE_CRITICAL("tUserPopulMalloc: not enough memory\n");
    	    return 1;
    	}
    	if ( (tUserPopul1 = realloc( tUserPopul1, tUserSize * tcUserNb1)) == NULL ) {
    	    TRACE_CRITICAL("tUserPopulMalloc: not enough memory\n");
    	    return 1;
    	}
    }

	// fill user table
    TRACE_CORE("\t\t(First user of popul %d at index = %d)\n", populIndex, tUserCurrentIndex);

    for (i=userMin; i<=userMax && !rc; i++) {
        sprintf(rdn, rdn_i, i);
        sprintf(filter, filter_i, i);
        sprintf(nai, nai_i, i);
        sprintf(passwd, passwd_i, i);
        
        rc = tUserPopulFillIn(scope, pdn, rdn, filter, nai, passwd, authtype, tUserCurrentIndex++);
    }

	return rc;
}


/******************************************************************************/
int  tUserPopulFillIn(  int  scope,
                        char *pdn,
                        char *rdn,
                        char *filter,
                        char *nai,
                        char *passwd,
						int	 authType,
						int  idx)
/******************************************************************************/
{
tUser       *tuser;
       
/*    if ( tUserCurrentIndex >= tcUserNb) {
        TRACE_CRITICAL("tUserPopulFillIn: user index overwhelm user nb\n");
        return 1;     
    }
*/
    tuser = tUserGet(idx) ;

    // Private part
    tuser->priv.id = idx;
    tuser->priv.cnt = 0;
    tuser->priv.lastSce = NULL;
/* user with empty RDN are frozen
    if (strlen(rdn) == 0)
        tuser->priv.exeState=exeState_RUNNING;
    else
        tuser->priv.exeState=exeState_IDLE;
*/
    // LDAP Entry part
	if (rdn[0]) {
		if ( (tuser->ldapE = malloc(sizeof(tLdapEntry))) == NULL ) {
		  TRACE_CRITICAL("tUserPopulFillIn: not enough memory for tLdap struct\n");
		  return 1;
		}

		if (scope != LDAP_SCOPE_BASE && scope != LDAP_SCOPE_ONELEVEL && scope != LDAP_SCOPE_SUBTREE ) {
			TRACE_CRITICAL("tUserPopulInit: unknown scope value\n");
			return 1;
		}
	/*    switch (scope) {
			case LDAP_SCOPE_BASE:
			case LDAP_SCOPE_SUBTREE:
				sprintf(tuser->ldapE->base, "%s,%s", rdn, pdn);
				break;
			case LDAP_SCOPE_ONELEVEL:
				strcpy(tuser->ldapE->base, pdn);
				break;
			default:
				TRACE_CRITICAL("tUserPopulInit: unknown scope value\n");
				return 1;
		}*/
		sprintf(tuser->ldapE->base, "%s,%s", rdn, pdn);
		strcpy(tuser->ldapE->dn, tuser->ldapE->base);    
	//    strcpy(tuser->ldapE->rdn, rdn);
		tuser->ldapE->scope = scope;
		strcpy(tuser->ldapE->filter, filter);    
	}

    tuser->cmdRes = NULL;
    
    // Auth part
	if (nai[0]) {
		if ( (tuser->auth = malloc(sizeof(tAuth))) == NULL ) {
		  TRACE_CRITICAL("tUserPopulFillIn: not enough memory\n");
		  return 1;
		}
		if ( (tuser->sess = malloc(sizeof(tSess))) == NULL ) {
		  TRACE_CRITICAL("tUserPopulFillIn: not enough memory\n");
		  return 1;
		}

		tuser->auth->frId = NULL;
		strcpy(tuser->auth->nai, nai);    
		tuser->auth->authType = authType;
		if (sameUserPasswd && authType != AUTHTYPE_EAPSIM)
			strcpy(tuser->auth->passwd, "jean");
		else
			// remember it's the IMSI !!!
			strcpy(tuser->auth->passwd, passwd);   
	}

    if (verbose >= 3) {
        fprintf(stderr, "tUserCurrentIndex= %d / pdn= %s / rdn=%s / nai=%s / autht=%d\n", idx, pdn, rdn, nai, authType);
    }

    return 0;  
}    



//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA ACCESSOR PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
long        tUserGetId(tUser *aUser)
/******************************************************************************/
{
   return aUser->priv.id;
}

/******************************************************************************/
int        tUserGetExclusion(tUser *aUser)
/******************************************************************************/
{
	if (aUser->priv.lastSce) {
		return aUser->priv.lastSce->exclusion;
	} else
		return 0;
}


/******************************************************************************
char *      tUserGetRDN(tUser *aUser)
/******************************************************************************
{
   return aUser->ldapE->rdn;
}
*/

/******************************************************************************/
char *      tUserGetDN(tUser *aUser)
/******************************************************************************/
{
   if (tUserGetBaseIsThereACmd(aUser)) 
        return tUserGetBaseFromCmdRes(aUser);
   else
        return aUser->ldapE->dn;      
}

/******************************************************************************/
char *      tUserGetBase(tUser *aUser)
/******************************************************************************/
{
   if (tUserGetBaseIsThereACmd(aUser)) 
        return tUserGetBaseFromCmdRes(aUser);
   else
        return aUser->ldapE->base;      
}

/******************************************************************************/
char *      tUserGetFilter(tUser *aUser)
/******************************************************************************/
{   
   if (tUserGetBaseIsThereACmd(aUser))
       return tUserGetFilterFromCmdRes(aUser); 
   else
       return aUser->ldapE->filter;      
}

/******************************************************************************/
int         tUserGetScope(tUser *aUser)
/******************************************************************************/
{
   return aUser->ldapE->scope;
}

/******************************************************************************/
int      tUserGetBaseIsThereACmd(tUser *aUser)
/******************************************************************************/
{
   return (aUser->cmdRes);
}
/******************************************************************************/
char *      tUserGetBaseFromCmdRes(tUser *aUser)
/******************************************************************************/
{
    if (aUser->cmdRes) 
        return aUser->cmdRes->base;
    else
        return NULL;
}    

/******************************************************************************/
char *      tUserGetFilterFromCmdRes(tUser *aUser)
/******************************************************************************/
{
    if (aUser->cmdRes) 
        return aUser->cmdRes->filter;
    else
        return NULL;
}

/******************************************************************************/
char *      tUserGetNAI(tUser *aUser)
/******************************************************************************/
{
   return aUser->auth->nai;
}


/******************************************************************************/
int         tUserGetAuthType(tUser *aUser) 
/******************************************************************************/
{
   return aUser->auth->authType;
}
/******************************************************************************/
void        tUserSetAuthType(tUser *aUser, int authType) 
/******************************************************************************/
{
   aUser->auth->authType=authType;
}           


/******************************************************************************/
char *      tUserGetPasswd(tUser *aUser)
/******************************************************************************/
{
   return aUser->auth->passwd;
}
/******************************************************************************/
void      tUserSetPasswd(tUser *aUser, char * passwd)
/******************************************************************************/
{
   strcpy(aUser->auth->passwd, passwd);
}
        

/******************************************************************************/
char *      tUserGetSessionId(tUser *aUser, int reloc)
/******************************************************************************/
{
   return aUser->sess->sessionId[(reloc?1:0)];
}           
/******************************************************************************/
int         tUserGetSessionIdLength(tUser *aUser, int reloc)
/******************************************************************************/
{
    return aUser->sess->sessionIdLength[(reloc?1:0)];
}
/******************************************************************************/
void	    tUserSetSessionId(tUser *aUser, char * sessionId, int length, int reloc)
/******************************************************************************/
{
   aUser->sess->sessionIdLength[(reloc?1:0)] = ( length > 32 ? 32 : length);
   memcpy(aUser->sess->sessionId[(reloc?1:0)], sessionId, aUser->sess->sessionIdLength[(reloc?1:0)]);
}           


/******************************************************************************/
int         tUserGetSessionStartTime(tUser *aUser, int reloc)
/******************************************************************************/
{
   return aUser->sess->startTime[(reloc?1:0)];
}           
/******************************************************************************/
void        tUserSetSessionStartTime(tUser *aUser, int date, int reloc)
/******************************************************************************/
{
   aUser->sess->startTime[(reloc?1:0)]=date;
}           


/******************************************************************************/
char *      tUserGetClassAttrib(tUser *aUser, int reloc)
/******************************************************************************/
{
   return aUser->sess->classAttrib[(reloc?1:0)];
}           
/******************************************************************************/
int         tUserGetClassAttribLength(tUser *aUser, int reloc)
/******************************************************************************/
{
    return aUser->sess->classAttribLength[(reloc?1:0)];
}
/******************************************************************************/
void        tUserSetClassAttrib(tUser *aUser, char * classAttrib, int length, int reloc)
/******************************************************************************/
{
   aUser->sess->classAttribLength[(reloc?1:0)] = ( length > 160 ? 160 : length);
   memcpy(aUser->sess->classAttrib[(reloc?1:0)], classAttrib, aUser->sess->classAttribLength[(reloc?1:0)]);
}           


/******************************************************************************/
char *      tUserGetStateAttrib(tUser *aUser, int reloc)
/******************************************************************************/
{
   return aUser->auth->stateAttrib[(reloc?1:0)];
}           
/******************************************************************************/
int         tUserGetStateAttribLength(tUser *aUser, int reloc)
/******************************************************************************/
{
    return aUser->auth->stateAttribLength[(reloc?1:0)];
}
/******************************************************************************/
void        tUserSetStateAttrib(tUser *aUser, char * stateAttrib, int length, int reloc)
/******************************************************************************/
{
   aUser->auth->stateAttribLength[(reloc?1:0)] = ( length > 160 ? 160 : length);
   memcpy(aUser->auth->stateAttrib[(reloc?1:0)], stateAttrib, aUser->auth->stateAttribLength[(reloc?1:0)]);
}           


/******************************************************************************/
int         tUserGetPortNb(tUser *aUser)
/******************************************************************************/
{
   return aUser->sess->portNb;
}           
/******************************************************************************/
void        tUserSetPortNb(tUser *aUser, int portNb)
/******************************************************************************/
{
   aUser->sess->portNb=portNb;
}           


/******************************************************************************/
char *      tUserGetAAASessionId(tUser *aUser) 
/******************************************************************************/
{
   return aUser->auth->aaa_session_id;
}

/******************************************************************************/
int         tUserGetAAASessionIdLength(tUser *aUser)
/******************************************************************************/
{
    return aUser->auth->aaa_session_idLength;
}

/******************************************************************************/
void	    tUserSetAAASessionId(tUser *aUser, char * aaa_session_id, int length)
/******************************************************************************/
{
   aUser->auth->aaa_session_idLength = ( length > 32 ? 32: length);
   memcpy(aUser->auth->aaa_session_id, aaa_session_id, aUser->auth->aaa_session_idLength);
}    

/******************************************************************************/
char *  tUserGetPPAQ(tUser *aUser)
/******************************************************************************/  
{
   return aUser->auth->ppaq;
}

/******************************************************************************/
int         tUserGetPPAQLength(tUser *aUser)
/******************************************************************************/
{
    return aUser->auth->ppaqLength;
}

/******************************************************************************/
void      tUserSetPPAQ(tUser *aUser, char * ppaq, int length)
/******************************************************************************/
{
   aUser->auth->ppaqLength = ( length > 128 ? 128 : length);
   memcpy(aUser->auth->ppaq, ppaq, aUser->auth->ppaqLength);
}




//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// SPECIFIC ADDITIONAL INFO
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
char *  tUserGetIMSI(tUser *aUser)
/******************************************************************************/  
{
   return aUser->auth->passwd;
}

/******************************************************************************/
void      tUserSetIMSI(tUser *aUser, char * imsi)
/******************************************************************************/
{
   strcpy(aUser->auth->passwd, imsi);
}


/******************************************************************************/
int  tUserGetFastAuthData(tUser *aUser, struct eapsim_keys *eapsim_mk, char* fr_id)
/******************************************************************************/  
{
    if (!aUser->auth->frId)
        return 0;
    
    // copy K_encr & K_auth data from User ctx to eapsim_mk ctx
    if (eapsim_mk) {
        memcpy(eapsim_mk->K_aut, aUser->auth->K_aut, EAPSIM_AUTH_SIZE);
        memcpy(eapsim_mk->K_encr, aUser->auth->K_encr, 16);
    }
    if (fr_id) {
        strcpy(fr_id, aUser->auth->frId);
    }

    return 1;
}
/******************************************************************************/
void  tUserSetFastAuthData(tUser *aUser, struct eapsim_keys *eapsim_mk, char* fr_id)
/******************************************************************************/  
{
    if (aUser->auth->frId)
        free(aUser->auth->frId);
    
    if (fr_id && fr_id[0]) {
        // copy K_encr & K_auth data from eapsim_mk ctx to User ctx
        memcpy(aUser->auth->K_aut, eapsim_mk->K_aut, EAPSIM_AUTH_SIZE);
        memcpy(aUser->auth->K_encr, eapsim_mk->K_encr, 16);
        aUser->auth->frId = strdup(fr_id);
    } else {
        aUser->auth->frId = NULL;
    }
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA HANDLING PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
tUser*  tUserGet(int userIndex)
/******************************************************************************/
{
	if(userIndex <= MaxUsrMemory){
		//    TRACE_DEBUG("tUserGet: trying user %d\n", userIndex, 0, 0 );
		//TRACE_CORE("tUserPopul = %d \t userIndex = %d \t tUserSize = %d)\n",tUserPopul, userIndex, tUserSize);
		return (tUser *)((char *)tUserPopul + tUserSize*userIndex);
	}else{
		//    TRACE_DEBUG("tUserGet: trying user %d\n", userIndex, 0, 0 );

		int userIndex1 =0;
		userIndex1 = userIndex - MaxUsrMemory;
		//TRACE_CORE("userIndex = %d userIndex1 = %d\n", userIndex,userIndex1);
		return (tUser *)((char *)tUserPopul1 + tUserSize*userIndex1);
	}
}    


/******************************************************************************/
static int  tUserCheckExclusion(int userIndex,int nbPopul,int MinPopul)
// return -1 if can not get a correct user index
/******************************************************************************/
{
int         	initial_tUseri, tUseri;
tUser *			tuser;
time_t      	now = time(NULL);
static time_t 	already_printed = 0;
    
    initial_tUseri = tUseri = userIndex;
    tuser = tUserGet(userIndex);

    if ( tUserGetExclusion(tuser) ) {
        while ( tuser->priv.exeState != exeState_IDLE || (now - tuser->priv.lastTime) < tUserGetExclusion(tuser) ) {

//              TRACE_DEBUG("tUserGetRandomly: user=%s not free\n", tUserGetNAI(tuser));

        	tUseri = ((++tUseri) % nbPopul)+MinPopul;

           if (tUseri == initial_tUseri) {
              if ( (already_printed+5) < now) {
				  TRACE_TRAFIC("WARNING: no more free user in popul\n");
				  already_printed = now;
			  }
              return -1;    
           }
           tuser = tUserGet(tUseri) ;
        }
    }

    return tUseri;
}    



/******************************************************************************/
tUser* tUserGetRandomly(tSce * sce)
/******************************************************************************/    
{
static int  tUseri=-1;
tUser	   *tuser;

   // only but all the user reservation phase is protected
   // after that, we are sure 2 threads can not work on the same user   
   pthread_mutex_lock(&tUserMutex);
   
   switch (tcUserGetPolicy) {
   
	  //Case 0: Random Get
	  case 0:
		 if (sce && sce->populNb)
			// restriction on the popul associated to the scenario
			tUseri = tUserCheckExclusion((rand() % sce->populNb) + sce->populMin , sce->populNb,sce->populMin);
		 else
			tUseri = tUserCheckExclusion( rand() % tcUserNb, tcUserNb,0);
		 break;
	  
	  //Case 1: Sequential Get
	  case 1:
		 if ( (tUseri != -2) && (++tUseri >= tcUserNb) ) {
            tUseri = -2;        // popul normal end !
			TRACE_CORE("End of Loop on User\n");
			// tUseri modification to -2 is protected by tUserMutex
			if (!killcalled) pthread_kill(tThread_getMainThread(), SIGINT);
		 }
		 break;
	  
      //Case 2: Loop on Sequential Get
      case 2:
    	  //TRACE_DEBUG("sce->populNb = %d \n",sce->populNb);
       	 if (sce && sce->populNb){
			// restriction on the popul associated to the scenario
       		//TRACE_DEBUG("tUseri av= %d name = %s\n",tUseri,sce->name);
       		//TRACE_DEBUG("tUseri avant = %d  \n",((tUseri + 1) % sce->populNb) + sce->populMin);
			tUseri = tUserCheckExclusion(((tUseri + 1) % sce->populNb) + sce->populMin,sce->populNb ,sce->populMin);
       	 	//TRACE_DEBUG("tUseri = %d sce->populNb = %d sce->populMin = %d name = %s\n",tUseri,sce->populNb,sce->populMin,sce->name);
       	 }else{
          	tUseri = tUserCheckExclusion( (tUseri + 1) % tcUserNb,tcUserNb,0);
       	 	//TRACE_DEBUG("tcUserNb = %d \n",tcUserNb);
       	 }
       	 break;

	  //Case N>2: 
	  default:
		 tUseri = tcUserGetPolicy;
		 break;
   }
   
   if (tUseri < 0) {
       pthread_mutex_unlock(&tUserMutex);
       return NULL;
   }

   tuser = tUserGet(tUseri) ;
   tuser->priv.exeState = exeState_RUNNING;
   tuser->priv.lastSce = sce;
   //TRACE_DEBUG("sce name = %s \n",sce->name);
   //TRACE_DEBUG("tuser-id = %d \t name = %s \t dn = %s \n",tuser->priv.id,tuser->priv.lastSce->name,tuser->ldapE->dn);

   pthread_mutex_unlock(&tUserMutex);
   return  tuser ; 
}  

/******************************************************************************/
void tUserFree(int tUseri)
/******************************************************************************/
{    
tUser	   *tuser;

   tuser = tUserGet(tUseri) ;
   tuser->priv.exeState = exeState_IDLE;
   tuser->priv.lastTime = time(NULL);
}  

/******************************************************************************/
void tUserAbort(int tUseri)
/******************************************************************************/
{    
tUser	   *tuser;

   tuser = tUserGet(tUseri) ;
   tuser->priv.exeState = exeState_ABORT;
   tuser->priv.lastTime = time(NULL);
}


/******************************************************************************/
int tUserIsAborted(int tUseri)
/******************************************************************************/
{    
tUser	   *tuser;

   tuser = tUserGet(tUseri) ;
   return (tuser->priv.exeState == exeState_ABORT);
}  

/*
 ***************************************************************************
 * Read /proc/meminfo.
 ***************************************************************************
 */
void read_proc_meminfo(void)
{
	struct stats_memory st_mem;

	memset(&st_mem, 0, STATS_MEMORY_SIZE);
	read_meminfo(&st_mem);
	tlmkb = st_mem.tlmkb;
	frmkb = st_mem.frmkb;
}

void read_meminfo(struct stats_memory *st_memory)
{
	FILE *fp;
	char line[128];

	if ((fp = fopen("/proc/meminfo", "r")) == NULL)
		return;

	while (fgets(line, 128, fp) != NULL) {

		if (!strncmp(line, "MemTotal:", 9)) {
			/* Read the total amount of memory in kB */
			sscanf(line + 9, "%lu", &st_memory->tlmkb);
		}
		else if (!strncmp(line, "MemFree:", 8)) {
			/* Read the amount of free memory in kB */
			sscanf(line + 8, "%lu", &st_memory->frmkb);
		}
		else if (!strncmp(line, "Buffers:", 8)) {
			/* Read the amount of buffered memory in kB */
			sscanf(line + 8, "%lu", &st_memory->bufkb);
		}
		else if (!strncmp(line, "Cached:", 7)) {
			/* Read the amount of cached memory in kB */
			sscanf(line + 7, "%lu", &st_memory->camkb);
		}
		else if (!strncmp(line, "SwapCached:", 11)) {
			/* Read the amount of cached swap in kB */
			sscanf(line + 11, "%lu", &st_memory->caskb);
		}
		else if (!strncmp(line, "Active:", 7)) {
			/* Read the amount of active memory in kB */
			sscanf(line + 7, "%lu", &st_memory->activekb);
		}
		else if (!strncmp(line, "Inactive:", 9)) {
			/* Read the amount of inactive memory in kB */
			sscanf(line + 9, "%lu", &st_memory->inactkb);
		}
		else if (!strncmp(line, "SwapTotal:", 10)) {
			/* Read the total amount of swap memory in kB */
			sscanf(line + 10, "%lu", &st_memory->tlskb);
		}
		else if (!strncmp(line, "SwapFree:", 9)) {
			/* Read the amount of free swap memory in kB */
			sscanf(line + 9, "%lu", &st_memory->frskb);
		}
		else if (!strncmp(line, "Committed_AS:", 13)) {
			/* Read the amount of commited memory in kB */
			sscanf(line + 13, "%lu", &st_memory->comkb);
		}
	}

	fclose(fp);
}
