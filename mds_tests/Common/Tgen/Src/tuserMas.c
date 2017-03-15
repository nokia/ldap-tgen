#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "tuserMas.h"
#include "tradius.h"

#ifndef MAX
#define MAX( x, y )   ( (x) > (y) ? (x) : (y) )
#endif
#ifndef MIN
#define MIN( x, y )   ( (x) < (y) ? (x) : (y) )
#endif

int				radAuthTypeTab[100];

//tUser HSS is a common tUser
typedef struct tUserMas {

    tUser           user;
    char*           imsi;

} tUserMas;

/*
Popul 
*/
int     tUserPopulTU15();

int		tUserPopulSSC();
int     tUserPopulPostpaid();
int     tUserPopulEapSim();
int     tUserPopulBSC();
int     tUserPopulEF500();
int     tUserPopulDHFWK50K();
int     tUserCreationPopulDHFWK();
int     tUserPopulEFProxy();
int     tUserPopulEFLocal();
int     tUserPopulEFLocalAndProxy();

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい


/******************************************************************************/
int tUserPopulInfo (int index)
/******************************************************************************/    
{
    int nbEntries;
    
    if(!(tcPopulation=index)) 
        tcPopulation = 7;

    if ( tUserGetRange( &tcUserNbMin, &tcUserNbMax) != 0)
       return 1; 
               
    nbEntries =  (tcUserNbMax-tcUserNbMin)+1 ; 
    
    switch (index ) {
        case 1  : fprintf(stderr, "\tPopul =  1: FT %d  SSC users\n", nbEntries);
                  return 0;  break;
        case 2  : fprintf(stderr, "\tPopul =  2: FT %d  Web users\n", nbEntries);
                  return 0;  break;
        case 3  : fprintf(stderr, "\tPopul =  3: FT %d  EapSim users\n", nbEntries);
                  return 0;  break;
        case 4  : fprintf(stderr, "\tPopul =  4: FT %d  BSC users\n", nbEntries);
                  return 0;  break;
        case 5  : fprintf(stderr, "\tPopul =  5: FT %d  Mix users\n", nbEntries);
                  return 0;  break;
        case 6  : fprintf(stderr, "\tPopul =  6: Test DH FWK 50K postpaid users : 100K FWK Entries\n");
                  return 0;  break;
		case 7  : fprintf(stderr, "\tPopul =  7: Test DH FWK %d Subscription postpaid users : %d FWK Entries\n",nbEntries,nbEntries);
		          return 0;  break;
		case 8  : fprintf(stderr, "\tPopul =  8: ST %d proxy users\n", nbEntries);
				  return 0;  break;
	    case 9  : fprintf(stderr, "\tPopul =  9: ST %d users\n", nbEntries);
				  return 0;  break;
		case 10 : fprintf(stderr, "\tPopul =  10: ST %d users (mix proxy and not)\n", nbEntries);
				  return 0;  break;
        case 0  : fprintf(stderr, "\tPopul =  1: FT %d  SSC users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  2: FT %d  Web users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  3: FT %d  EapSim users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  4: FT %d  BSC users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  5: FT %d  Mix users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  6: Test DH FWK 50K postpaid users : 100K FWK Entries\n");
                  fprintf(stderr, "\tPopul =  7: Test DH FWK %dK Subscription postpaid users : %dK FWK Entries\n",nbEntries,nbEntries);
                  fprintf(stderr, "\tPopul =  8: ST %d proxy users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  9: ST %d local users\n", nbEntries);
                  fprintf(stderr, "\tPopul =  10: ST %d users (mix proxy and not)\n", nbEntries);
                  return 0; break;
        default:  return 1; break;
   }
}

/******************************************************************************/
int tUserInit()
/******************************************************************************/    
{
int i;

    if ( tUserPopulMalloc(sizeof(tUserMas)) ) {
        fprintf(stderr, "tgen_mas: init exit: tUserPopul init failed\n");
        return 1;
	}

	// init Authentication Type table
	for (i=0; i<50; i++) radAuthTypeTab[i] = AUTHTYPE_PAP;
	for (   ; i<100;i++) radAuthTypeTab[i] = AUTHTYPE_SIP_CHAP;

	return 0;
}    



/******************************************************************************/
int tUserPopulInit(int populIndex)
/******************************************************************************/    
{
    int rc=0;
    
    switch (populIndex) {
	   case 0:
		  rc=tUserPopulTestTgen();
		  break;
	   case 1:
		  rc=tUserPopulSSC();
		  break;
/*        case 1:
		   rc=tUserPopulTU15();
		   break;
*/
        case 2:
           rc=tUserPopulPostpaid();
		   break;
		case 3:
		   rc=tUserPopulEapSim();
		   break;
	    case 4:
		  rc=tUserPopulBSC();
		  break;
	    case 5:
		  rc=tUserPopulEF500();
		  break;
	    case 6:
		  rc=tUserPopulDHFWK50K();
		  break;
	   case 7:
		 rc=tUserCreationPopulDHFWK();
		 break;
	   case 8:
		 rc=tUserPopulEFProxy();
		 break;
	   case 9:
		 rc=tUserPopulEFLocal();
		 break;
	   case 10:
		 rc=tUserPopulEFLocalAndProxy();
		 break;
        default:
           fprintf(stderr, "tgen_mas: ERROR: unknown population in tUserPopulInit\n");
           rc=1;    
    }
	
	return rc;
}  

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA ACCESSOR PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

#ifdef DO_NOT_COMPILE
/******************************************************************************/
char *  tUserGetIMSI(tUser *aUser)
/******************************************************************************/  
{
   return (( tUserMas *)(aUser))->imsi;
}
#endif

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// POPUL PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
      
/******************************************************************************/
int  tUserMasPopulFillIn(   int  useri,
                            char *nai,
                            char *cn,
                            char *passwd,
                            char *imsi,
							int	 authType)
/******************************************************************************/
{
    char   base[256]="\0";
    char * pdn = "OU=SUBSCRIPTION,NE=MOBILE_DATA_SERVER";
	char * filter = "(objectclass=*)";
    
    strcpy(base, cn);
    strcat(base, ",");
    strcat(base, pdn);
 
    tUserPopulFillIn(useri, base, pdn, filter, LDAP_SCOPE_BASE, nai, cn, passwd, authType);
  
	((tUserMas *)(tUserGet(useri)))->imsi = strdup(imsi);
    
    return 0;  
}    

/******************************************************************************/
int tUserPopulTestTgen()
/* Popul 0 */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #0: TEST of Tgen, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    
	for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(nai, "SSC_USER%0.5d@yellow.fr", i);
        sprintf(cn, "SUBSID=SSC_SUBS%0.5d", i);
		sprintf(passwd, "nextpasswd%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", AUTHTYPE_PAP );
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulSSC()
/* Popul 1 */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #1: SSC users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    
	for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(nai, "SSC_USER%0.5d@wifi1.fr", i);
        sprintf(cn, "SUBSID=SSC_SUBS%0.5d", i);
		sprintf(passwd, "nextpasswd%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", AUTHTYPE_OTP );
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulTU15()
/******************************************************************************/
{
   
    fprintf(stderr, "    Population #1: TU 15 users\n");
    if (sameUserPasswd)
        fprintf(stderr, "WARNING: same user password option not compatible with population. Be sure...\n");
	
	tUserMasPopulFillIn(0, "pseudonym_000001@yellow.fr","SUBSID=BSC000001", "reporter","noimsi", AUTHTYPE_PAP);
	tUserMasPopulFillIn(1, "pseudonym_000002@yellow.fr","SUBSID=BSC000002", "cantatrice","noimsi", AUTHTYPE_PAP);
	tUserMasPopulFillIn(2, "pseudonym_000003@yellow.fr","SUBSID=BSC000003", "milou","noimsi", AUTHTYPE_PAP);
	tUserMasPopulFillIn(3, "SSC_000001@yellow.fr","SUBSID=SSC000001", "potion","noimsi", AUTHTYPE_OTP);
	tUserMasPopulFillIn(4, "pos_000001@yellow.fr","SUBSID=POS000001", "scoubidou","noimsi", AUTHTYPE_PAP);
	tUserMasPopulFillIn(5, "seraphin@yellow.fr","SUBSID=PRU_WEB001", "lampion","noimsi", AUTHTYPE_PAP);
	tUserMasPopulFillIn(6, "VSC_000001@yellow.fr","SUBSID=VSC000001", "lips-egew","noimsi", AUTHTYPE_OTP);
	tUserMasPopulFillIn(7, "VSC_000002@yellow.fr","SUBSID=VSC000002", "NextPwdVSC2","noimsi", AUTHTYPE_OTP);
	tUserMasPopulFillIn(8, "VSC_000003@yellow.fr","SUBSID=VSC000003", "ouso-nqug","noimsi", AUTHTYPE_OTP);
	tUserMasPopulFillIn(9, "1258516040010000@sim-operator.com","SUBSID=EAPSIM00000", "", "258516040010000", AUTHTYPE_EAPSIM);
	tUserMasPopulFillIn(10, "1258516040010001@sim-operator.com","SUBSID=EAPSIM00001", "", "258516040010001", AUTHTYPE_EAPSIM);
	tUserMasPopulFillIn(11, "1258516040010002@sim-operator.com","SUBSID=EAPSIM00002", "", "258516040010002", AUTHTYPE_EAPSIM);
	tUserMasPopulFillIn(12, "1258516040010003@sim-operator.com","SUBSID=EAPSIM00003", "", "258516040010003", AUTHTYPE_EAPSIM);
	tUserMasPopulFillIn(13, "1258516040000000@sim-operator.com","SUBSID=EAPSIMDEM1", "", "258516040000000", AUTHTYPE_EAPSIM);
	tUserMasPopulFillIn(14, "1258516040009010@sim-operator.com","SUBSID=EAPSIMDEM2", "", "258516040009010", AUTHTYPE_EAPSIM);
	
	return 0;
}

/******************************************************************************/
int tUserPopulPostpaid()
/* Popul 2 */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #2: Postpaid users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    
	for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "WEB_TRAF%0.5d@wifi2.fr", i);
		 sprintf(cn, "SUBSID=WEB_TRAF%0.5d", i);
		 sprintf(passwd, "WEB_PWD%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

    return rc;
}

/******************************************************************************/
int tUserPopulEapSim()
/* Popul 3 */
/******************************************************************************/
{
    int i,j, rc=0, useri=0;
    fprintf(stderr, "    Population #3: EapSim users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

#ifdef OLD_VERSION
    for (i=tcUserNbMin, j=0; i<=MIN(tcUserNbMax,199) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi2.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

    for (i=MAX(tcUserNbMin,200), j=0; i<=tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi1.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
#else
/*
    for (i=tcUserNbMin, j=(tcUserNbMin/100 + 1); i<=tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";
        
        if ( i%100 == 0 )
            j++;

		sprintf(imsi, "2585160400%0.5d", i);
        sprintf(nai, "1%s@wifi%0.2d.fr", imsi, j);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
*/
    for (i=tcUserNbMin; i<=tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";
        
		sprintf(imsi, "25851602120%0.4d", i);
        sprintf(nai, "1%s@wifi1.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF00%0.4d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
#endif
	return rc;
}
    
/******************************************************************************/
int tUserPopulBSC()
/* Popul 4 */
/******************************************************************************/
{
    int i,j, rc=0, useri=0;

    fprintf(stderr, "    Population #4: BSC users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

	   char    cn[256]="\0";
	   char    nai[256]="\0";
	   char    passwd[256]="\0";
	   sprintf(nai, "BSC_TRAF%0.5d@WIFI%1d.FR", i, 4-(i%2) );
	   sprintf(cn, "SUBSID=BSC_TRAF%0.5d", i);
	   sprintf(passwd, "BSC_PWD%0.5d", i);

	   rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
	   useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulEF500()
/* Popul 5 */
/******************************************************************************/
{
    int i,j, rc=0, useri=0;

    fprintf(stderr, "    Population #5: Mix users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

    for (i=MAX(tcUserNbMin,0); i<=MIN(tcUserNbMax,199) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(nai, "POST_USER%0.5d@yellow.fr", i);
        sprintf(cn, "SUBSID=POST_SUBS%0.5d", i);
		sprintf(passwd, "passwd%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
        useri++;
    }

	for (i=MAX(tcUserNbMin,200); i<=MIN(tcUserNbMax,399) && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "BSC_USER%0.5d@wifi1.fr", i);
		 sprintf(cn, "SUBSID=BSC_SUBS%0.5d", i);
		 sprintf(passwd, "passwd%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

    for (i=MAX(tcUserNbMin,400), j=0; i<=MIN(tcUserNbMax,599) && !rc; i++, j++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

        sprintf(imsi, "258516040000%0.3d", j);
        sprintf(nai, "1%s@sim-operator.com", imsi);
        sprintf(cn, "SUBSID=EAPSIM_SUBS%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

/* UMTS Users in HLR !!! Have quintuplets instead of triplets => MAP SCIM Errors
    for (i=240; i<= 249 && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

        sprintf(imsi, "25851604000901%0.1d", i-240);
        sprintf(nai, "1%s@sim-operator.com", imsi);
        sprintf(cn, "SUBSID=EAPSIM_SUBS%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
*/
	return rc;
}

/******************************************************************************/
int tUserPopulEFProxy()
/* Popul 8 */
/******************************************************************************/
{ 
    int i,j, rc=0, useri=0;

    fprintf(stderr, "    Population #8: EF local users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

    for (i=MAX(tcUserNbMin,1001); i<=MIN(tcUserNbMax,1100) && !rc; i++) {

	   char    cn[256]="\0";
	   char    nai[256]="\0";
	   char    passwd[256]="\0";
	   sprintf(nai, "BSC_TRAF%0.5d@WIFI%1d.FR", i, 4-(i%2) );
	   sprintf(cn, "SUBSID=BSC_TRAF%0.5d", i);
	   sprintf(passwd, "BSC_PWD%0.5d", i);

	   rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
	   useri++;
    }

	for (i=MAX(tcUserNbMin,1101); i<=MIN(tcUserNbMax,1200) && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "WEB_TRAF%0.5d@WIFI%1d.FR", i, 4-(i%2) );
		 sprintf(cn, "SUBSID=WEB_TRAF%0.5d", i);
		 sprintf(passwd, "WEB_PWD%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

    for (i=MAX(tcUserNbMin,1201), j=300; i<=MIN(tcUserNbMax,1300) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@WIFI%1d.FR", imsi, 4-(i%2) );
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
    
    
    for (i=tcUserNbMin, j=0; i<=MIN(tcUserNbMax,199) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi2.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

    for (i=MAX(tcUserNbMin,200), j=0; i<=tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi1.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

	return rc;
}

/******************************************************************************/
int tUserPopulEFLocal()
/* Popul 9 */
/******************************************************************************/
{
    int i,j, rc=0, useri=0;

    fprintf(stderr, "    Population #9: EF local users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

    for (i=MAX(tcUserNbMin,101); i<=MIN(tcUserNbMax,400) && !rc; i++) {

	   char    cn[256]="\0";
	   char    nai[256]="\0";
	   char    passwd[256]="\0";
	   sprintf(nai, "BSC_TRAF%0.5d@wifi2.fr", i);
	   sprintf(cn, "SUBSID=BSC_TRAF%0.5d", i);
	   sprintf(passwd, "BSC_PWD%0.5d", i);

	   rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
	   useri++;
    }

	for (i=MAX(tcUserNbMin,401); i<=MIN(tcUserNbMax,700) && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "WEB_TRAF%0.5d@wifi2.fr", i);
		 sprintf(cn, "SUBSID=WEB_TRAF%0.5d", i);
		 sprintf(passwd, "WEB_PWD%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

	j = 0;
    for (i=MAX(tcUserNbMin,701); i<=MIN(tcUserNbMax,1000) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi2.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

	return rc;
}

/******************************************************************************/
int tUserPopulEFLocalAndProxy()
/* Popul 10 */
/******************************************************************************/
{
    int i,j, rc=0, useri=0;

    fprintf(stderr, "    Population #9: EF local users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);

	// local part
    for (i=MAX(tcUserNbMin,101); i<=MIN(tcUserNbMax,400) && !rc; i++) {

	   char    cn[256]="\0";
	   char    nai[256]="\0";
	   char    passwd[256]="\0";
	   sprintf(nai, "BSC_TRAF%0.5d@wifi2.fr", i);
	   sprintf(cn, "SUBSID=BSC_TRAF%0.5d", i);
	   sprintf(passwd, "BSC_PWD%0.5d", i);

	   rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
	   useri++;
    }

	for (i=MAX(tcUserNbMin,401); i<=MIN(tcUserNbMax,700) && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "WEB_TRAF%0.5d@wifi2.fr", i);
		 sprintf(cn, "SUBSID=WEB_TRAF%0.5d", i);
		 sprintf(passwd, "WEB_PWD%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

	j = 0;
    for (i=MAX(tcUserNbMin,701); i<=MIN(tcUserNbMax,1000) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@wifi2.fr", imsi);
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }

	// proxy part
    for (i=MAX(tcUserNbMin,1001); i<=MIN(tcUserNbMax,1100) && !rc; i++) {

	   char    cn[256]="\0";
	   char    nai[256]="\0";
	   char    passwd[256]="\0";
	   sprintf(nai, "BSC_TRAF%0.5d@WIFI%1d.FR", i, 4-(i%2) );
	   sprintf(cn, "SUBSID=BSC_TRAF%0.5d", i);
	   sprintf(passwd, "BSC_PWD%0.5d", i);

	   rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
	   useri++;
    }

	for (i=MAX(tcUserNbMin,1101); i<=MIN(tcUserNbMax,1200) && !rc; i++) {

		 char    cn[256]="\0";
		 char    nai[256]="\0";
		 char    passwd[256]="\0";
		 sprintf(nai, "WEB_TRAF%0.5d@WIFI%1d.FR", i, 4-(i%2) );
		 sprintf(cn, "SUBSID=WEB_TRAF%0.5d", i);
		 sprintf(passwd, "WEB_PWD%0.5d", i);

		 rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
		 useri++;
	 }

	j = 300;
    for (i=MAX(tcUserNbMin,1201); i<=MIN(tcUserNbMax,1300) && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    imsi[256]="\0";

		sprintf(imsi, "258516040000%0.3d", j++);
        sprintf(nai, "1%s@WIFI%1d.FR", imsi, 4-(i%2) );
        sprintf(cn, "SUBSID=EAP_TRAF%0.5d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, "", imsi, AUTHTYPE_EAPSIM );
        useri++;
    }
	
	return rc;
}

/******************************************************************************/
int tUserPopulDHFWK50K()
/* Popul 50.000 MAS Users */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "\tPopulation #6: DH FWK 50.000 users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    fprintf(stderr, "\tPopulation #6 initialization is on going...Be Patient...Wait FEW SECONDS...!!\n");

	for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {
	    
        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        char    imsi[256]="\0";

        sprintf(nai, "POST_USER%0.7d@yellow.fr", i);
        sprintf(cn, "SUBSID=POST_SUBS%0.7d", i);
		sprintf(passwd, "passwd%0.7d", i);

        rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
        useri++;
    }
    fprintf(stderr, "\tPopulation #6 End initialization\n");
    
	return rc;
}

/******************************************************************************/
int tUserCreationPopulDHFWK()
/* Mass Provisionning MAS Subscription Users */
/******************************************************************************/
{
    int i, rc=0, useri=0, nbEntries = ((tcUserNbMax-tcUserNbMin)+1)/1000 ;
    
    fprintf(stderr, "\tPopulation #7: Test Creation DH FWK %dK Subscription postpaid users, i.e %d FWK Entries, range = [%d, %d]\n", nbEntries, nbEntries, tcUserNbMin, tcUserNbMax);
    fprintf(stderr, "\tPopulation #7 initialization is on going...Be Patient...Wait FEW MINUTES...!!\n");
            
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        char    imsi[256]="\0";
   
        sprintf(nai, "POST_USER%0.7d@yellow.fr", i);
        sprintf(cn, "SUBSID=POST_SUBS%0.7d", i);
		sprintf(passwd, "passwd%0.7d", i);
	        
        rc = tUserMasPopulFillIn(useri, nai, cn, passwd, "", (i%2 ? AUTHTYPE_SIP_CHAP : AUTHTYPE_PAP) );
        
        if (rc) {
            break;
        }
            
        useri++;
    }
    fprintf(stderr, "\tPopulation #7 End initialization\n");
    
    return rc;
} 



//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// DATA HANDLING PART
//
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tUserGetRange(int *min, int *max)
/******************************************************************************/    
{
    int rc=0;
     
    switch (tcPopulation) {
	  case 0:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p0", 1 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p0", 10000 );
		  break;
      case 1:
        *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p1", 1 );
        *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p1", 100 );
        break;
	  case 2:
		 *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p2", 401 );
		 *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p2", 700 );
		 break;
	   case 3:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p3", 701 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p3", 1000 );
		  break;
	   case 4:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p4", 101 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p4", 400 );
		  break;
	   case 5:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p5", 0 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p5", 599 );
		  break;
	   case 6:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p6", 0 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p6", 49999 );
		  break;
	   case 7:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p7", 500000 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p7", 700000 );
		  break;
	   case 8:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p8", 1001 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p8", 1300 );
		  break;
	   case 9:
          *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p9", 101 );
          *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p9", 1000 );
		  break;
	   case 10:
		  *min = ProfileGetInt( inifile, "MasPopulRanges", "min_p10", 101 );
		  *max = ProfileGetInt( inifile, "MasPopulRanges", "max_p10", 1300 );
		  break;
        default:
            fprintf(stderr, "tgen_mas: ERROR: unknown population in tUserPopulInit\n");
            rc=1;
    }
	
	return rc;
}
