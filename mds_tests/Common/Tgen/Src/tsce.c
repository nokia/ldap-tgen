#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "tsce.h"
#include "texec.h"
#include "tstat.h"
#include "tdebug.h"
#include "taction.h"


#define MAXSCE 32
static int      tsceRegisterCheck();
static tSce*    tsceTab[MAXSCE];
static tSce*    sceOccurenceTab[100];

static int      tSceLoadTraffic (int idx);


/******************************************************************************/
int tSceInit()
/******************************************************************************/
{
int rc=0, i;

    if (verbose >= 1)
        TRACE_CORE("Scenario init starts\n" );

    //Reset registration table
    memset( tsceTab, 0, sizeof(tsceTab) );

    //Stat registration
    tStatTimeRegister(LDAP_Bind_Rq,				"LDAP_Bind_Rq",				0);
    tStatTimeRegister(LDAP_UnBind_Rq,			"LDAP_UnBind_Rq",			0);
    tStatTimeRegister(LDAP_Search_Rq,       	"LDAP_Search_Rq",			0);
    tStatTimeRegister(LDAP_Modify_Rq,       	"LDAP_Modify_Rq",			0);
    tStatTimeRegister(LDAP_Add_Rq,          	"LDAP_Add_Rq",				0);
    tStatTimeRegister(LDAP_Delete_Rq,       	"LDAP_Delete_Rq",			0);
    
    tStatTimeRegister(RADIUS_Auth_Rq,           "RADIUS_Auth_Rq",	            0);
    tStatTimeRegister(RADIUS_AccessEapId_Rq,   	"   RADIUS_AccessEapId_Rq", 	0);
    tStatTimeRegister(RADIUS_AccessEapStart_Rq, "   RADIUS_AccessSimStart_Rq",	0);
    tStatTimeRegister(RADIUS_AccessEapChal_Rq,  "   RADIUS_AccessSimChal_Rq", 	0);
    tStatTimeRegister(RADIUS_AccessEapCliErr_Rq,"   RADIUS_AccessSimCliErr_Rq", 0);
    tStatTimeRegister(RADIUS_AccessEapNotif_Rq, "   RADIUS_AccessSimNotif_Rq",  0);
    tStatTimeRegister(RADIUS_AccessEapFast_Rq,  "   RADIUS_AccessSimFast_Rq",   0);
    tStatTimeRegister(RADIUS_AccessEapTtls_Rq,  "   RADIUS_AccessEapTtls_Rq",   0);
    tStatTimeRegister(RADIUS_AccessEapTls_Rq,   "   RADIUS_AccessEapTls_Rq",   0);
// AKA stat
	tStatTimeRegister(RADIUS_AccessEapAKAIdentity_Rq,   "   RADIUS_AccessAkaIdentity_Rq", 	0);    
	tStatTimeRegister(RADIUS_AccessEapAKAChal_Rq,   	"   RADIUS_AccessAkaChal_Rq", 	0);
	tStatTimeRegister(RADIUS_AccessEapAKARej_Rq,   		"   RADIUS_AccessAkaRej_Rq", 	0);
	tStatTimeRegister(RADIUS_AccessEapAKASynfail_Rq,   	"   RADIUS_AccessAkaSynfail_Rq", 	0);

	tStatTimeRegister(RADIUS_AuthWP_Rq,         "RADIUS_AuthWP_Rq",	        0);
    
    tStatTimeRegister(RADIUS_AccountStart_Rq,   "RADIUS_AccountStart_Rq", 	0);
    tStatTimeRegister(RADIUS_AccountInterim_Rq, "RADIUS_AccountInterim_Rq", 0);
    tStatTimeRegister(RADIUS_AccountStop_Rq,    "RADIUS_AccountStop_Rq", 	0);
    tStatTimeRegister(RADIUS_AccountOn_Rq,   	"RADIUS_AccountOn_Rq", 		0);
    tStatTimeRegister(RADIUS_AccountOff_Rq,   	"RADIUS_AccountOff_Rq", 	0);
    tStatTimeRegister(SCE_Wait,   	            "SCE_Wait", 	            0);

    if ( tcTrafficInfo == 2 ) {
        // only print info and exits
        if (tcTrafficProfile == 0) {
            for (i=1; i<10000; i++ ) tSceLoadTraffic(i);
        } else {
            tSceLoadTraffic(tcTrafficProfile);
        }
        exit(0);
    }

	if (tcScenario) {
		// run one unique scenario instead of a trafic
		char    section_sce[128] = "";

		sprintf(section_sce, "Scenario_%d", tcScenario );
		rc = tSceLoadScenario(section_sce, 100);

	} else if ( rc = tSceLoadTraffic(tcTrafficProfile) ) {
	   TRACE_CRITICAL("invalid trafic\n" );
	}
	TRACE_TRAFIC("tcTrafficProfile = %d\n", tcTrafficProfile);
    rc += tsceRegisterCheck();

    //Traffic function registration
    tStatRegisterTrafficFunction( tStatTrafficFunction_stable );

    return rc;
}


/******************************************************************************/
static int tSceStringActionToEnumAction (char *actionName)
/******************************************************************************/
{
         if ( !strcmp(actionName, "LDAP_Bind_Rq") )             return LDAP_Bind_Rq;
    else if ( !strcmp(actionName, "LDAP_UnBind_Rq") )           return LDAP_UnBind_Rq;
    else if ( !strcmp(actionName, "LDAP_Search_Rq") )           return LDAP_Search_Rq;
    else if ( !strcmp(actionName, "LDAP_Modify_Rq") )           return LDAP_Modify_Rq;
    else if ( !strcmp(actionName, "LDAP_Add_Rq") )              return LDAP_Add_Rq;
    else if ( !strcmp(actionName, "LDAP_Delete_Rq") )           return LDAP_Delete_Rq;
    else if ( !strcmp(actionName, "RADIUS_Auth_Rq") )           return RADIUS_Auth_Rq;
    else if ( !strcmp(actionName, "RADIUS_AuthWP_Rq") )         return RADIUS_AuthWP_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapId_Rq") )     return RADIUS_AccessEapId_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapStart_Rq") )  return RADIUS_AccessEapStart_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapChal_Rq") )   return RADIUS_AccessEapChal_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapCliErr_Rq") ) return RADIUS_AccessEapCliErr_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapNotif_Rq") )  return RADIUS_AccessEapNotif_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapFast_Rq") )   return RADIUS_AccessEapFast_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapTtls_Rq") )   return RADIUS_AccessEapTtls_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapTls_Rq") )   return RADIUS_AccessEapTls_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccountStart_Rq") )   return RADIUS_AccountStart_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccountInterim_Rq") ) return RADIUS_AccountInterim_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccountStop_Rq") )    return RADIUS_AccountStop_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccountOn_Rq") )      return RADIUS_AccountOn_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccountOff_Rq") )     return RADIUS_AccountOff_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapAKAChal_Rq") )     return RADIUS_AccessEapAKAChal_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapAKARej_Rq") )     return RADIUS_AccessEapAKARej_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapAKASynfail_Rq") )     return RADIUS_AccessEapAKASynfail_Rq;
    else if ( !strcmp(actionName, "RADIUS_AccessEapAKAIdentity_Rq") )     return RADIUS_AccessEapAKAIdentity_Rq;
    else if ( !strcmp(actionName, "SCE_Wait") )                 return SCE_Wait;
    else if ( !strcmp(actionName, "SCE_Begin") )                return SCE_Begin;
    else if ( !strcmp(actionName, "SCE_End") )                  return SCE_End;
    else return -1;
}

#ifdef SCE_GENERIC

/******************************************************************************/
int tSceLoadScenario (char * sce_name, int rate)
/******************************************************************************/
{
char    description[256] = "";
int		exclusion;
char	population[32];
char    param_name[128] = "";
char    param_val[8192] = "";
int     iact;
tAction *actTab;
char*   pch;


        // read scenario section
        ProfileGetString( inifile, sce_name, "description", "", description, sizeof(description) );
        if (description[0] == 0) {
            TRACE_CRITICAL("tSceLoadTraffic: unknown scenario %s \n", sce_name);
            return 1;
        }
        TRACE_CORE("         %s: %s\n", sce_name, description);
		exclusion = ProfileGetInt( inifile, sce_name, "exclusion", 0 );
        ProfileGetString( inifile, sce_name, "population", "", population, sizeof(population) );

        
        // get scenario actions
        iact = 0;
        actTab = NULL;
        while ( 1 ) {
            // next action
            iact++;

            sprintf(param_name, "action%d", iact );
            ProfileGetString( inifile, sce_name, param_name, "", param_val, sizeof(param_val) );
            
            if ( !strcmp(param_val, "") ) {
//                TRACE_CORE("no more action\n");
                break;
            }
            
            actTab = (tAction *) realloc( actTab, sizeof(tAction)*iact );
            (actTab + iact-1)->cmds = NULL;
            (actTab + iact-1)->attrs = NULL;
            
            if ( (pch = strtok(param_val, ",")) == NULL ) {
                TRACE_CRITICAL("tSceLoadTraffic: bad %s in %s \n", param_name, sce_name);
                return 1;
            }
            if ( ((actTab + iact-1)->requestId = tSceStringActionToEnumAction(pch)) == -1 ) {
                TRACE_CRITICAL("tSceLoadTraffic: unknown action %s \n", pch);
                return 1;
            }

            if ( (pch = strtok(NULL, "\"")) == NULL ) continue;
            if ( !strcmp("\\0", pch) ) {
                TRACE_DEBUG("tSceLoadTraffic: \\0 cmd found\n" );
                (actTab + iact-1)->cmds = strdup("\0");
            } else
                (actTab + iact-1)->cmds = strdup(pch);

            if ( (pch = strtok(NULL, "\"")) == NULL ) continue;
            if ( (pch = strtok(NULL, "\"")) == NULL ) continue;
            if ( !strcmp("\\*", pch) ) {
                TRACE_DEBUG("tSceLoadTraffic: \\* attrs found\n" );
                (actTab + iact-1)->attrs = strdup("\*");
            } else {
				(actTab + iact-1)->attrs = strdup(pch);
                TRACE_DEBUG("tSceLoadTraffic: action value = %s\n", pch );
			}

//            TRACE_CRITICAL("tSceLoadTraffic: bad %s in %s \n", param_name, sce_name);
        }

        return tSceRegister(description, actTab, rate, exclusion, population);
}


/******************************************************************************/
static int tSceLoadTraffic (int idx)
/******************************************************************************/
{
int     rc=0;
char    description[256] = "";
char    section_traf[128] = "";
char    section_sce[128] = "";
char    param_name[128] = "";
int     isce=0;
int     rate;
    
    
    // if no description, considere the trafic is not present in ini file
    sprintf(section_traf, "Trafic_%d", idx );
    ProfileGetString( inifile, section_traf, "description", "", description, sizeof(description) );
    if (description[0] == 0) {
        if (!tcTrafficInfo)
			TRACE_CRITICAL("tSceLoadTraffic: unknown trafic\n");
        return 1;
    }
    TRACE_CORE("    Trafic #%d: %s\n", idx, description);
	
    while ( 1 ) {
        // next scenario
        isce++;

        // read scenario name & occurence rate
        sprintf(param_name, "rate%d", isce );
        rate = ProfileGetInt( inifile, section_traf, param_name, -1 );

        if ( rate == -1 ) break;  // no more scenario to read

        sprintf(param_name, "scenario%d", isce );
        ProfileGetString( inifile, section_traf, param_name, "", section_sce, sizeof(section_sce) );
        
        rc += tSceLoadScenario(section_sce, rate);
        TRACE_TRAFIC("section_sce = %s  rate = %d\n", section_sce,rate);
    }

    return rc;
}
#endif


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
//TSCE HANDLING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい


/******************************************************************************/
int tScePrintScenarios (FILE * output, unsigned long nbsec)
/******************************************************************************/
{
int sceId;

/*
		********* statistics - scenario **********
-----------------------------------------------------------------------------------------------------------------------
| 12345678901234567890123456789012345678901234567890123456789012345678 | 12345678 | 12345678 | 123.56/sec |  x.yE-ii  |
|                             Scenario name                            |    cnt   |    ko    |    rate    |    QOS    |
-----------------------------------------------------------------------------------------------------------------------
*/
    
    if (output == stdout) clreol();
    fprintf(output, "\t\t********* statistics - scenario *********\n");
    
	if (output == stdout) clreol();
    fprintf(output, "----------------------------------------------------------------------------------------------------------------------------------------\n");
	if (output == stdout) clreol();
    fprintf(output, "|                             Scenario name                            |    cnt   |    ko    |    rate     |  ko ratio | timeout ratio |\n");
	if (output == stdout) clreol();
    fprintf(output, "----------------------------------------------------------------------------------------------------------------------------------------\n");

    for (sceId=0; sceId<MAXSCE && tsceTab[sceId] != 0 ; sceId++) {
		if (output == stdout) clreol();
        fprintf(output, "| %-68.68s | %8ld | %8ld |", tsceTab[sceId]->name, tsceTab[sceId]->cnt, tsceTab[sceId]->ko);
        if (nbsec) {
            fprintf(output, " %9.2f/s |", (float)tsceTab[sceId]->cnt/nbsec );
        } else {
            fprintf(output, "     none   |"  );
        }
        if (tsceTab[sceId]->cnt) {
            fprintf(output, "  %7.1E  |", (float)(tsceTab[sceId]->ko+1)/tsceTab[sceId]->cnt );
        } else {
            fprintf(output, "    none   |"  );
        }
        if (tsceTab[sceId]->cnt) {
            fprintf(output, "    %7.1E    |\n", (float)(tsceTab[sceId]->timeout+1)/tsceTab[sceId]->cnt );
        } else {
            fprintf(output, "      none     |\n"  );
        }
    }

	if (output == stdout) clreol();
    fprintf(output,   "---------------------------------------------------------------------------------------------------------------------------------------\n");
}

/******************************************************************************/
tSce* tSceGet ()
/******************************************************************************/
{
    int     index;
    index = rand()      ;
    index = index % 100  ;

    return (sceOccurenceTab[index]);

}

/******************************************************************************/
int tSceRegister (const char * aSceName, tAction * aSce, int aOccurence, int exclusion, char * population)
/******************************************************************************/
{
    static int  index=0,sceId=0;
    int         i, status;
    tSce*       sce;
	
    //Traffic informations are printed, U can use tStatTab...
    if ( tcTrafficInfo ) {
        tAction *foo=aSce;
        foo++; //Skip Begin
        while ( foo->requestId != SCE_End ) {
            TRACE_CORE("\t\t%s [ %s ] [ %s ] \n", tStatTab[foo->requestId].rq_name , foo->cmds, foo->attrs);
            foo++;
        }
    }

    if (index+aOccurence > 100) {
        TRACE_CRITICAL("tSceRegister failed: wrong occurence \n");
        return 1;
    }

    if (verbose >= 1)
        TRACE_CORE("\t\t => register: %-28s, occurence:%4d \n", aSceName, aOccurence);

    TRACE_DEBUG("tcTrafficInfo = %d \n", tcTrafficInfo);
    if (tcTrafficInfo)
        return;

    if ( ( sce = (tSce *)malloc( sizeof(tSce) ) ) == NULL) {
        TRACE_CRITICAL("tSceRegister failed! Error=%d", status,"\n");
        return 1;
    }

    bzero( sce, sizeof(tSce) );
    strncpy(sce->name, aSceName, SCE_NAME_LENGHT-1);
    sce->action= aSce;
	sce->exclusion = exclusion;
	if (population && !tcPopulation) {
		// a default population is associated to this scenario and no other popul specified
		sce->populMin = tUserCurrentIndex;
		if  ( tUserInit(population) != 0 ) return 1;
		sce->populNb = tUserCurrentIndex - sce->populMin;
	}

    tsceTab[sceId++]=sce;

    for (i = index; i < index+aOccurence; i++)
        sceOccurenceTab[i]=sce;

    index=i;

    return 0;

}

/******************************************************************************/
static int tsceRegisterCheck ()
/******************************************************************************/
{
    int  index;

    for (index=0; index < 100 && (sceOccurenceTab[index] != 0); index++)
        ;

    if (index != 100 ) {
        TRACE_CRITICAL("tSceRegister failed: occurence table is not full filled in\n");
        return 1;
    }

    return 0;

}

#ifdef SCE_GENERIC
/******************************************************************************/
void tScePrecondition (const tSce* aSce, const struct tUser* aUser)
/******************************************************************************/
{
/*    if (verbose >= 2)
        TRACE_CORE("Scenario: %s, user(RDN): %s \n", aSce->name, tUserGetDN(aUser) );
*/
}
#endif
