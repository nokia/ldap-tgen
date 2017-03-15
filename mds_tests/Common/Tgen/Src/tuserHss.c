#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "tuserHss.h"
#include "tradius.h"

int				radAuthTypeTab[100];

//tUser HSS is a common tUser
typedef struct tUserHss {

    tUser           user;
    char            S_CSCF[256]; 

} tUserHss;

/*
Popul 
*/
int     tUserPopulST10000();
int     tUserPopulFT17();
int     tUserPopulST10000Old();
int     tUserPopulST10000Wrong();
int     tUserPopulStep1Distrib();
int     tUserPopulStep1Chap();
int     tUserPopulStep1Digest();

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// INIT PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

/******************************************************************************/
int  tUserPopulInfo(int  index)
/******************************************************************************/
{
    	fprintf(stderr, "             popul = [  1: ST 1000 users in range={1001,2000}\n");
	fprintf(stderr, "                        2: FT 17 users\n");
	fprintf(stderr, "                        3: for DHA\n");
	fprintf(stderr, "                        4: wrong accesses\n");
	fprintf(stderr, "                        5: ST step1 10000 users in range={10001,20000}\n");
	fprintf(stderr, "                        6: ST step1 1000 users in range={30001,31000}\n");
	fprintf(stderr, "                        7: ST step1 1000 users in range={32001,33000}  ]\n");        
}    

/******************************************************************************/
int tUserInit()
/******************************************************************************/    
{
int i;

    if ( tUserPopulMalloc(sizeof(tUserHss)) ) {
        fprintf(stderr, "tgen_hss: init exit: tUserPopul init failed\n");
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
            rc=tUserPopulST10000();
        		break;
        case 2:
            rc=tUserPopulFT17();
        		break;
        case 3:
            rc=tUserPopulST10000Old();
        		break;    
        case 4:
            rc=tUserPopulST10000Wrong();
        		break;
        case 5:
            rc=tUserPopulStep1Distrib();
        		break;    
        case 6:
            rc=tUserPopulStep1Chap();
        		break;
        case 7:
            rc=tUserPopulStep1Digest();
        		break;
        default:
            fprintf(stderr, "tgen_hss: ERROR: unknown population in tUserPopulInit\n");
            rc=1;    
    }
	
	return rc;
}  

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// DATA ACCESSOR PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

/******************************************************************************/
void tUserWriteSCSCF(tUser *aUser)
//Modify Selected CSCF of the given user, it aims to force write in HPD database
/******************************************************************************/  
{
    int len,digit;
        
    len = strlen((( tUserHss *)(aUser))->S_CSCF);
    if ( isdigit((( tUserHss *)(aUser))->S_CSCF[len-1]) ) {
        digit = atoi( &((( tUserHss *)(aUser))->S_CSCF[len-1]) ) ;
        digit = ++digit % 10;
        (( tUserHss *)(aUser))->S_CSCF[len-1] = '\0';   
    } else {
        digit = 1;
    }
    sprintf( (( tUserHss *)(aUser))->S_CSCF,"%s%d", (( tUserHss *)(aUser))->S_CSCF, digit); 
}

/******************************************************************************/
char *  tUserGetSCSCF(tUser *aUser)
/******************************************************************************/  
{
   return (( tUserHss *)(aUser))->S_CSCF;
}

/******************************************************************************/
char *  tUserGetIMSI(tUser *aUser)
/******************************************************************************/  
{
   return "/0";
}


//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// POPUL PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
      
/******************************************************************************/
int  tUserHssPopulFillIn(   int  useri,
                            char *nai,
                            char *cn,
                            char *passwd,
                            char *mmcs1)
/******************************************************************************/
{
    char * base = "o=alcatel, c=fr";
    char * pdn = "ou=HSS_DATA, o=alcatel, c=fr";
    char   filter[256]="\0";
    
    strcpy(filter, "(cn=");
    strcat(filter, cn);
    strcat(filter, ")");
    
    tUserPopulFillIn(useri, base, pdn, filter, LDAP_SCOPE_SUBTREE, nai, cn, passwd, AUTHTYPE_SIP_CHAP);

    //S_CSCF_list Not used
    //strcpy(tuser->S_CSCF_list[0], mmcs1);
    //strcpy(tuser->S_CSCF_list[1], mmcs2);
    //strcpy(tuser->S_CSCF_list[2], mmcs3);
    //strcpy(tuser->S_CSCF_list[3], mmcs4);
    //strcpy(tuser->S_CSCF_list[4], mmcs5);
    strcpy(((tUserHss *)(tUserGet(useri)))->S_CSCF, mmcs1);
    
    return 0;  

}    

/******************************************************************************/
int tUserPopulST10000()
/* Popul 10000 Users Lannion */
/******************************************************************************/
{
    int i, rc=0;
    int useri=0;
    
    fprintf(stderr, "    Population #1: ST 10.000 users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(cn, "cn_user%0.5d@yellow.fr", i);
        sprintf(nai, "user%0.5d@here.com", i);
        sprintf(passwd, "user%0.5d", i);

        rc = tUserHssPopulFillIn(useri, nai, cn, passwd, "mmcs1.here.com");
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulST10000Old()
/* Popul 10000 Users Lannion - old one*/
/******************************************************************************/
{
	int i,j, rc=0;
    int useri=0;
    
    fprintf(stderr, "    Population #3: ST 10.000 users, range = [%d, %d] (old one)\n", tcUserNbMin, tcUserNbMax);
	for (i=tcUserNbMin, j=0; i<= tcUserNbMax && !rc; i++, j++) {

	    char    cn[256]="\0";
	    char    nai[256]="\0";
	    char    passwd[256]="\0";
	    sprintf(cn, "xuser%d@here.com",i);
	    sprintf(nai, "user%d@here.com",i);
		sprintf(passwd, "user%0.5d", i);

	    if (j>9) j=0;

        switch (j) {
            case 0:
            case 1:
                rc = tUserHssPopulFillIn(useri, nai, cn, passwd,"mmcs1.here.com");
                useri++;
            break;
            default:
                rc = tUserHssPopulFillIn(useri, nai, cn, passwd,"mmcs1.here.com");
                useri++;
            break;
        }
	}

    return rc;
}

/******************************************************************************/
int tUserPopulFT17()
/******************************************************************************/
{
   
    fprintf(stderr, "    Population #2: FT 17 users\n");
    if (sameUserPasswd)
        fprintf(stderr, "WARNING: same user password option not compatible with population. Be sure...\n");
        
	tUserHssPopulFillIn(0, "liNAI1_11111@yellow.fr","cn1_jean@yellow.fr", "jean","mmcs1.here.com");
	tUserHssPopulFillIn(1, "liNAI2_22222@yellow.fr","cn2_yves@yellow.fr", "yves","mmcs1.here.com");
	tUserHssPopulFillIn(2, "liNAI3_33333@nawadoo.fr","cn3_bentoto@yellow.fr", "bentoto","mmcs1.here.com");
	tUserHssPopulFillIn(3, "liNAI4_44444@yellow.fr","cn4_bull@yellow.fr", "bull","mmcs1.here.com");
	tUserHssPopulFillIn(4, "liNAI5_55555@yellow.fr","cn5_chirac@yellow.fr", "chirac","mmcs1.here.com");
	tUserHssPopulFillIn(5, "liNAI6_66666@alcatel.fr","cn6_jospin@yellow.fr", "jospin","mmcs1.here.com");
	tUserHssPopulFillIn(6, "liNAI7_77777@yellow.fr","cn7_valvin@yellow.fr", "valvin","mmcs1.here.com");
	tUserHssPopulFillIn(7, "liNAI8_88888@pamela.com","cn8_fabius@yellow.fr", "fabius","mmcs1.here.com");
	tUserHssPopulFillIn(8, "liNAI9_99999@yellow.fr","cn9_thomson@yellow.fr", "thomson","mmcs1.here.com");
	tUserHssPopulFillIn(9, "liNAI10_AAAAA@yellow.fr","cn10_pierre@yellow.fr", "pierre","mmcs1.here.com");
	tUserHssPopulFillIn(10, "liNAI11_BBBBB@yellow.fr","cn11_glasgow@yellow.fr", "glasgow","mmcs1.here.com");
//	tUserHssPopulFillIn(useri, "tarte@an.pion","francois.jacques@chez.com", "jean","mmcs1.here.com");
	tUserHssPopulFillIn(11, "jeannegros@surlapatate.fr","cn13_jeannegros@surlapatate.fr", "jeannegros","mmcs1.here.com");
	tUserHssPopulFillIn(12, "titi@etgrosminet.fr","cn14_titi@etgrosminet.fr", "titi","mmcs1.here.com");
	tUserHssPopulFillIn(13, "bipbip@lecoyotte.fr","cn15_bipbip@lecoyotte.fr", "bipbip","mmcs1.here.com");
	tUserHssPopulFillIn(14, "claudia@chipher.com","cn16_claudia@chipher.com", "claudia","mmcs1.here.com");
	tUserHssPopulFillIn(15, "ursula@andress.org","ursula@andress.org", "ursula","mmcs1.here.com");
  
}    

/******************************************************************************/
int tUserPopulST10000Wrong()
/* Popul 10000 Users Lannion - wrong one*/
/******************************************************************************/
{
	int i,j, rc=0;
    int useri = 0;
    
    fprintf(stderr, "    Population #4: ST 10.000 users, range = [%d, %d] (old one)\n", tcUserNbMin, tcUserNbMax);
    if (sameUserPasswd)
        fprintf(stderr, "WARNING: same user password option not compatible with population. Be sure...\n");
        
	for (i=tcUserNbMin, j=0; i<= tcUserNbMax && !rc; i++, j++) {

	    char    cn[256]="\0";
	    char    cnWrong1[256]="\0", cnWrong2[256]="\0";
	    char    nai[256]="\0";
	    char    naiWrong1[256]="\0", naiWrong2[256]="\0";
	    char    passwd[256]="jean";
	    char    passwdWrong1[256]="\0", passwdWrong2[256]="\0";

	    //cnWrong1: Wrong CN,
	    //cnWrong2: Invalid CN,
	    //naiWrong1: Wrong NAI,
	    //naiWrong2: Invalid NAI
        sprintf(cn, "xuser%d@here.com",i);
	    sprintf(cnWrong1, "xuserWhichIsNotWithinDatabase%d@here.com",i);
	    sprintf(cnWrong2, "userWhichIsInvalidCauseItsCNContainsAnInvalidCharacter§%d@here.com",i);
	    sprintf(nai, "user%d@here.com",i);
	    sprintf(naiWrong1, "userWhichIsNotWithinDatabase%d@here.com",i);
	    sprintf(naiWrong2, "userWhichIsInvalidCauseItsNAIContainsAnInvalidCharacter§%d@here.com",i);
	    strcpy(passwdWrong1, "jeannot");
	    strcpy(passwdWrong2, "lapin");
	    if (j>9) j=0;

        switch (j) {
            case 0:
            case 1:
                rc = tUserHssPopulFillIn(useri, nai, cn, passwdWrong1,"mmcs1.here.com");
                useri++;
            break;
            case 2:
            case 3:
            case 4:
            case 5:
                rc = tUserHssPopulFillIn(useri, nai, cn, passwdWrong2,"mmcs1.here.com");
                useri++;
            break;    
            case 6:
                rc = tUserHssPopulFillIn(useri, naiWrong1, cn, passwd,"mmcs1.here.com");
                useri++;
            break;
            case 7:
                rc = tUserHssPopulFillIn(useri, nai, cnWrong1, passwd,"mmcs1.here.com");
                useri++;
            break;
            case 8:
                rc = tUserHssPopulFillIn(useri, naiWrong2, cn, passwd,"mmcs1.here.com");
                useri++;
            break;
            case 9:
                rc = tUserHssPopulFillIn(useri, nai, cnWrong2, passwd,"mmcs1.here.com");
                useri++;
            break;
            default:
                rc = tUserHssPopulFillIn(useri, nai, cn, passwd,"mmcs1.here.com");
                useri++;
            break;
        }
	}

    return rc;
}


/******************************************************************************/
int tUserPopulStep1Distrib()
/* Popul 10000 Users: step 1, tranche 10001 à 20000, Distribution */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #5: ST 100.000 users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(cn, "cn_user%0.5d@yellow.fr", i);
        sprintf(nai, "user%0.5d@here.com", i);
		sprintf(passwd, "user%0.5d", i);

        rc = tUserHssPopulFillIn(useri, nai, cn, passwd, "mmcs1.here.com");
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulStep1Chap()
/* Popul 10000 Users: step 1, tranche 30001 à 31000, CHAP */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #6: ST 100.000 users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(cn, "cn_user%0.5d@yellow.fr", i);
        sprintf(nai, "user%0.5d@here.com", i);
		sprintf(passwd, "user%0.5d", i);

        rc = tUserHssPopulFillIn(useri, nai, cn, passwd, "mmcs1.here.com");
        useri++;
    }

    return rc;
}

/******************************************************************************/
int tUserPopulStep1Digest()
/* Popul 10000 Users: step 1, tranche 32001 à 33000, DIGEST */
/******************************************************************************/
{
    int i, rc=0, useri=0;

    fprintf(stderr, "    Population #7: ST 100.000 users, range = [%d, %d]\n", tcUserNbMin, tcUserNbMax);
    for (i=tcUserNbMin; i<= tcUserNbMax && !rc; i++) {

        char    cn[256]="\0";
        char    nai[256]="\0";
        char    passwd[256]="\0";
        sprintf(cn, "cn_user%0.5d@yellow.fr", i);
        sprintf(nai, "user%0.5d@here.com", i);
		sprintf(passwd, "user%0.5d", i);

        rc = tUserHssPopulFillIn(useri, nai, cn, passwd, "mmcs1.here.com");
        useri++;
    }

    return rc;
}

//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤
// DATA HANDLING PART
//
//¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤¤

/******************************************************************************/
int tUserGetRange(int *min, int *max)
/******************************************************************************/    
{
    int rc=0;
     
    switch (tcPopulation) {
        case 1:	// step 0
        case 3:	// step 0, DHA
        case 4:	// step 0, Wrong
            *min = ProfileGetInt( inifile, "HssPopulRanges", "min_p1", 1001 );
            *max = ProfileGetInt( inifile, "HssPopulRanges", "min_p1", 2000 );
        	break;
        case 2:	// step 0, EF
            *min = ProfileGetInt( inifile, "HssPopulRanges", "min_p2", 1  );
            *max = ProfileGetInt( inifile, "HssPopulRanges", "min_p2", 16 );
        	break;
        case 5:	// step 1, tranche 10001 à 20000, Distribution
            *min = ProfileGetInt( inifile, "HssPopulRanges", "min_p5", 10001 );
            *max = ProfileGetInt( inifile, "HssPopulRanges", "min_p5", 20000 );
        	break;
        case 6:	// step 1, tranche 30001 à 31000, CHAP
            *min = ProfileGetInt( inifile, "HssPopulRanges", "min_p6", 30001 );
            *max = ProfileGetInt( inifile, "HssPopulRanges", "min_p6", 31000 );
        	break;
        case 7:	// step 1, tranche 32001 à 33000, DIGEST
            *min = ProfileGetInt( inifile, "HssPopulRanges", "min_p7", 32001 );
            *max = ProfileGetInt( inifile, "HssPopulRanges", "min_p7", 33000 );
            break;
        default:
            fprintf(stderr, "tgen: ERROR: unknown population in tUserPopulInit\n");
            rc=1;
    }
	
	return rc;
}
