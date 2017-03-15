#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "tuser.h"
#include "tradius.h"

int				radAuthTypeTab[100];

//tuser LDAS is a common tUser
typedef struct tUserLdas {

    tUser           user;

} tUserLdas;

/*
Popul 
*/
int     tUserPopulST10000HSS();
int     tUserPopulEasi();

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tUserInit()
/******************************************************************************/    
{
int i;

    if ( tUserPopulMalloc(sizeof(tUserLdas)) ) {
        fprintf(stderr, "tgen_ldas: init exit: tUserPopul init failed\n");
        return 1;
	}
	
	// init Authentication Type table
	for (i=0; i<80; i++) radAuthTypeTab[i] = AUTHTYPE_DIGEST;
	for (   ; i<96; i++) radAuthTypeTab[i] = AUTHTYPE_SIP_CHAP;
	for (   ; i<99; i++) radAuthTypeTab[i] = AUTHTYPE_PROPRIETARY;
	for (   ; i<100;i++) radAuthTypeTab[i] = AUTHTYPE_NONE;

	return 0;
}    

/******************************************************************************/
int tUserPopulInit(int populIndex)
/******************************************************************************/    
{
    int rc=0;
    
    switch (populIndex) {
        case 1:
            rc=tUserPopulEasi();
        		break;
        case 2:
            rc=tUserPopulST10000HSS();
        		break;
        default:
            fprintf(stderr, "tgen_ldas: ERROR: unknown population in tUserPopulInit\n");
            rc=1;    
    }
	
	return rc;
}  

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA ACCESSOR PART
// MOUAIS ...tUserWriteSCSCF, tUserGetSCSCF!!!!
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
void tUserWriteSCSCF(tUser *aUser)
//Modify Selected CSCF of the given user, it aims to force write in HPD database
/******************************************************************************/  
{

}

/******************************************************************************/
char *  tUserGetSCSCF(tUser *aUser)
/******************************************************************************/  
{
   return "/0";
}

/******************************************************************************/
char *  tUserGetIMSI(tUser *aUser)
/******************************************************************************/  
{
   return "/0";
}

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// POPUL PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int  tUserPopulInfo(int  index)
/******************************************************************************/
{
    switch (index ) {
        case 1 : tUserPopulEasi()       ; return 0; break;   
        case 2 : tUserPopulST10000HSS() ; return 0; break;     
        case 0 : tUserPopulEasi()       ;
                 tUserPopulST10000HSS() ; return 0; break;
        default:                          return 1; break;
    }    
}          
      

	
/******************************************************************************/
int  tUserLdasPopulFillIn(  int  useri,
                            char *rdn,
                            char *pdn)
                
//No NAI, No passwd, it is not a Authenticable user
/******************************************************************************/
{ 
    char    nai[256]="\0";
    char    passwd[256]="\0";
    
    char    base[256]="\0";
    char    filter[256]="\0";
    int     scope, rc;
    
    //Set filter: politic to set filter...
    //strcpy(filter, "(");
    //strcat(filter, rdn);
    //strcat(filter, ")");
    strcpy(filter, "(objectclass=*)");
        
    //politic to change scope...
    scope=LDAP_SCOPE_BASE;
    
    //set search base
    switch (scope) {
        case LDAP_SCOPE_BASE:
            strcat(base, rdn);
            strcat(base," ,");
            strcat(base,pdn);              
        break;
        case LDAP_SCOPE_ONELEVEL:
            strcpy(base, pdn);
        break;    
        //case LDAP_SCOPE_SUBTREE:
        //    strcpy(base, suffix);
        break;    
        default:
            return 1;
    }        
    
    rc = tUserPopulFillIn(useri, base, pdn, filter, scope, nai, rdn, passwd, AUTHTYPE_SIP_CHAP);
    
    return rc;  

}    


/******************************************************************************/
int tUserPopulST10000HSS()
/* Popul 10000 Users of HSS::HPD */
/******************************************************************************/
{
    int     i, rc=0;
    int     useri=0;
    char    * pdn = "ou=HSS_DATA, o=customer, c=fr";
    
    if (tcTrafficInfo) 
        fprintf(stderr, "\tPopulation #2: ST 10.000 HSS users\n");
    else
        fprintf(stderr, "\tPopulation #2: ST 10.000 HSS users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
        
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    rdn[256]="\0";
        sprintf(rdn, "cn=cn_user%0.5d@yellow.fr", i);
        
        //No NAI, No passwd, it is not a Authenticable user

        rc = tUserLdasPopulFillIn(useri, rdn, pdn);
        
        if (rc) {
            break;
        }
            
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulEasi()
/* Popul MMS user for EASI Project */
/******************************************************************************/
{
    int i, rc=0;
    int useri=0;
    
    if (tcTrafficInfo) 
        fprintf(stderr, "\tPopulation #1: ST 10.000 Easi MMS users\n");
    else
        fprintf(stderr, "\tPopulation #1: ST 10.000 Easi MMS users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
        
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    rdn[256]="\0";
        char    pdn[256]="\0";
        int     range;
        
        range = i % 100;
        
        //Set baseRDN, pdn, filter for first search
        
		//Target is EASI scenario
		sprintf(rdn, "pnnumber=\\+%0.10d", i);
        sprintf(pdn, "ou=range%0.2d, ou=msisdn, ou=INDEXES, o=alcatel,c=fr", range);
        
		//Target is pnnumber entry under each userid entry
		//sprintf(rdn, "pnnumber=\\+%0.10d", i);
		//sprintf(pdn, "userid=%0.5d, ou=REPOSITORY, ou=CONTENT, o=alcatel,c=fr", i);

		//Target is userid entry 
		//sprintf(rdn, "userid=%0.5d", i);
		//sprintf(pdn, "ou=REPOSITORY, ou=CONTENT, o=alcatel,c=fr", i);

        rc = tUserLdasPopulFillIn( useri, rdn , pdn) ;      
        if (rc) {
            break;
        }
            
        useri++;
    }

    return rc;
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA HANDLING PART
// This in tUserGetRange function that you have to set the Population Dimensionning
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tUserGetRange(int *min, int *max)
/******************************************************************************/    
{
    int rc=0;
     
    switch (tcPopulation) {
        case 1:
            *min = ProfileGetInt( inifile, "MmsPopulRanges", "min_p1", 0 );
            *max = ProfileGetInt( inifile, "MmsPopulRanges", "min_p1", 9999 );
        	break;
        	
        case 2:
            *min = ProfileGetInt( inifile, "MmsPopulRanges", "min_p2", 0 );
            *max = ProfileGetInt( inifile, "MmsPopulRanges", "min_p2", 9999 );
        	break;
        	
        default:
            fprintf(stderr, "tgen: ERROR: unknown population in tUserGetRange\n");
            rc=1;
    }
	
	return rc;
}
