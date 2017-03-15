#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "texec.h"
#include "tsce.h" 
#include "taction.h"


/******************************************************************************/
//
// CAVEAT: BIND/UNBIND IS MANDATORY
//
/******************************************************************************/

//#####################################
// Network Level Scenarios 
//#####################################

/*
Name
    Scenario Basic Session
Details
    Sessions of 5 to 15 seconds.
*/
static const char*  Basic_Session_Name="Basic_Session";
static tAction Basic_Session[] = {

    { SCE_Begin					, "\0", "\0" },
    { RADIUS_Access_Rq			, "\0", "\0" },
    { RADIUS_AccountStart_Rq    , "\0", "\0"},
    { SCE_Wait				    , "_RAND_", "5 15"},
    { RADIUS_AccountStop_Rq		, "\0", "\0" },
    { SCE_End             		, "\0", "\0" },

};

/*
Name
    Scenario Basic Session for SSC user
Details
    Sessions of 5 to 15 seconds.
*/
static const char*  Ssc_Session_Name="Ssc_Session";
static tAction Ssc_Session[] = {

    { SCE_Begin					, "\0", "\0" },
    { LDAP_Bind_Rq        		, "\0", "\0" },    
    { LDAP_Search_Rq      		, "_getAsBase_: NextPassword", "NextPassword" },
    { RADIUS_Access_Rq			, "\0", "\0" },
    { RADIUS_AccountStart_Rq    , "\0", "\0"},
    { SCE_Wait				    , "_RAND_", "5 15"},
    { RADIUS_AccountStop_Rq		, "\0", "\0" },
    { LDAP_UnBind_Rq      		, "\0", "\0" },   
    { SCE_End             		, "\0", "\0" },

};

/*
Name
    Scenario Basic Session with Interim
Details
    - Sessions of 20 to 60 seconds.
	- one Interim at approx. half-session
*/
static const char*  Interim_Session_Name="Session_with_Imterim";
static tAction Interim_Session[] = {

    { SCE_Begin					, "\0", "\0" },
    { RADIUS_Access_Rq			, "\0", "\0" },
    { RADIUS_AccountStart_Rq    , "\0", "\0"},
    { SCE_Wait				    , "_RAND_", "10 30"},
    { RADIUS_AccountInterim_Rq	, "\0", "\0" },
    { SCE_Wait				    , "_RAND_", "10 30"},
    { RADIUS_AccountStop_Rq		, "\0", "\0" },
    { SCE_End             		, "\0", "\0" },

};


/******************************************************************************/
/* Elementary Level RADIUS Scenarios */
/******************************************************************************/

/*
Name
    Scenario ELS A: Registration with wrong password - user gets locked
Details
*/
static const char*  AuthenticationWP_UserLocked_Loop_Name="AuthenticationWP_UserLocked";
static tAction AuthenticationWP_UserLocked_Loop[] = {

    { SCE_Begin				, "\0", "\0" },
    { RADIUS_AccessWP_Rq	, "\0", "\0" },
    { RADIUS_AccessWP_Rq    , "\0", "\0" },    
    { RADIUS_Access_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};


/*
Name
    Scenario ELS B: Loop of Radius Authentication
Details
*/
static const char*  Authentication_Loop_Name="Authentication_Loop";
static tAction Authentication_Loop[] = {

    { SCE_Begin				, "\0", "\0" },
    { RADIUS_Access_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};


/******************************************************************************/
/* Elementary Level LDAP Scenarios */
/******************************************************************************/

/*
Name
    DH FWK Test: Loop of LDAP Search on a MAS user
Details
*/
static const char* LDAP_SearchMasUser_Name="LDAP_SearchMasUser";
static tAction LDAP_SearchMasUser[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Search_Rq      , "\0", "\*" },    
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};
    
/*
Name
    Ldap/Diameter Test: Loop of LDAP Search on a HSS R2.2 IMPUs
Details
*/
static const char* LDAP_LIR_Name="LDAP_LIR";
static tAction LDAP_LIR[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Search_Rq      , "\0", "SCServerName # SCMandatoryCapability # SCOptionalCapability" },
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    Ldap/Diameter Test: Loop of LDAP Search on a HSS R2.2 Registered IMPUs
Details
*/
static const char* LDAP_SAR_Complete_Profile_Download_Name="LDAP_SAR_Complete_Profile_Download";
static tAction LDAP_SAR_Complete_Profile_Download[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },
    { LDAP_Search_Rq      , "\0", "SPRID" },     
    { LDAP_Search_Rq      , "\0", "SubscribedMediaProfileId" },
    { LDAP_Search_Rq      , "\0", "IFCElementList" },    
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    Ldap/Diameter Test: Loop of LDAP Modify-Replace on a HSS R2.2 Not Registered IMPUs (First Registration Simulation)
Details
*/
static const char* LDAP_SAR_First_Registration_Name="LDAP_SAR_First_Registration";
static tAction LDAP_SAR_First_Registration[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },
    { LDAP_Modify_Rq      , "\0", "replace:AuthenticationPendingFlag > 0"},   
    { LDAP_Modify_Rq      , "\0", "replace:IMSState > 1"},   
    { LDAP_Modify_Rq      , "\0", "replace:SCSCFAssigned > scscf5@yellow.com"},     
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    PoC TMobile Test: Loop of LDAP Search on a MAS user
Details
*/
static const char* LDAP_SearchMasUser_Attrib_Name="LDAP_SearchMasUser_Attrib";
static tAction LDAP_SearchMasUser_Attrib[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Search_Rq      , "\0", "UserLoginName" },    
    { LDAP_Search_Rq      , "\0", "UserRealm" },    
    { LDAP_Search_Rq      , "\0", "AuthenticationProfileId" },    
    { LDAP_Search_Rq      , "\0", "SubscriptionAdministrativeState" },    
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    DH FWK Test: Loop of LDAP Modify Attribute IMSI on a MAS user
Details
*/
static const char* LDAP_Modify_IMSI_AccountingProfileId_Name="LDAP_Modify_IMSI_AccountingProfileId";
static tAction LDAP_Modify_IMSI_AccountingProfileId[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Modify_Rq      , "\0", "replace:IMSI > 123451234512345"},  
    { LDAP_Modify_Rq      , "\0", "replace:AccountingProfileId > TPLID=POSTPAID,OU=Accounting,OU=WLAN,OU=TEMPLATE,NE=MOBILE_DATA_SERVER"},  
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    PoC TMobile Test: Loop of LDAP Modify Attributes MaximumActivityDuration/AuthTemplate on a MAS user
Details
*/
static const char* LDAP_Modify_MAD_AuthTemplate_Name="LDAP_Modify_MAD_AuthTemplate";
static tAction LDAP_Modify_MAD_AuthTemplate[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 360000"},  
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 840000"},  
    { LDAP_Modify_Rq      , "\0", "replace:AuthenticationProfileId > TPLID=AuthenticationProfile_001,OU=Authentication,OU=WLAN,OU=TEMPLATE,NE=MOBILE_DATA_SERVER"},  
    { LDAP_Modify_Rq      , "\0", "replace:AuthenticationProfileId > TPLID=AUTH_PROFILE_WEB,OU=Authentication,OU=WLAN,OU=TEMPLATE,NE=MOBILE_DATA_SERVER"},  
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    PoC TMobile Test: Loop of LDAP Modify Attribute MaximumActivityDuration on a MAS user
Details
*/
static const char* LDAP_Modify_MAD_Name="LDAP_Modify_MAD";
static tAction LDAP_Modify_MAD[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 360000"},  
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 840000"},  
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 360000"},  
    { LDAP_Modify_Rq      , "\0", "replace:MaximumActivityDuration > 840000"},  
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    DH FWK Test: Loop of Add MAS user
Details
*/
static const char* LDAP_Add_MasUser_Name="LDAP_AddMasUser";
static tAction LDAP_AddMasUser[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Add_Rq         , "\0", "objectclass > WLANUserSubscription   &    POU  &   AccountingTemplateReference  &   AuthenticationTemplateReference &   PasswordLoginAuthenticationData&SubscriptionValidity  &   AccountSessionsStatus&   SIMUserAuthenticationKey # SUBSID > _RDN_ # AccountingProfileId > TPLID=ACCOUNT_PROFILE_POSTPAID,OU=ACCOUNTING,OU=WLAN,OU=TEMPLATE,NE=MOBILE_DATA_SERVER # AuthenticationProfileId > TPLID=AUTH_PROFILE_WEB,OU=AUTHENTICATION,OU=WLAN,OU=TEMPLATE,NE=MOBILE_DATA_SERVER # UserLoginName > _RDN_ # Password > passwd01 # UserRealm > YELLOW.FR  # IMSI > 20801123001 # SubscriptionAdministrativeState > 1" },
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};



/******************************************************************************/
int tSceTrafficProfile (int idx)
/******************************************************************************/
{
int rc=0;
    switch (idx) {
	case 1 :  
	   fprintf(stderr, "tgen: Traffic Profile #%d: Basic Session Traffic A (Reference)\n", idx);
	   rc += tSceRegister(Basic_Session_Name, Basic_Session, 100);
	   break;
	case 2 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Session Traffic for SSC users (only with popul 1)\n", idx);
	   rc += tSceRegister(Ssc_Session_Name, Ssc_Session, 100);
	   break;        
	case 3 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: WLAN Sessions REFERENCE Traffic\n", idx);
	   rc += tSceRegister(Basic_Session_Name, Basic_Session, 45);
	   rc += tSceRegister(Interim_Session_Name, Interim_Session, 45);
	   rc += tSceRegister(AuthenticationWP_UserLocked_Loop_Name, AuthenticationWP_UserLocked_Loop, 10);
	   break;        
	case 4 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Authentication with wrong password on a user (will block user!)\n", idx);
	   tcUserGetPolicy = 3;
	   rc += tSceRegister(AuthenticationWP_UserLocked_Loop_Name, AuthenticationWP_UserLocked_Loop,100);
	   break;        
	case 5 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Authentication with wrong password on a bank of user (will block users!)\n", idx);
	   rc += tSceRegister(AuthenticationWP_UserLocked_Loop_Name, AuthenticationWP_UserLocked_Loop,100);
	   break;        
	case 6 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: not defined and available\n", idx);
	   break;      
	case 7 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: not defined and available\n", idx);
	   break;      
	case 8 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Radius Authentication on a user (should be lauched with -z1 option)\n", idx);
	   tcUserGetPolicy = 18;
	   rc += tSceRegister(Authentication_Loop_Name,Authentication_Loop,100);
	   break;        
	case 9 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Radius Authentication on a bank of user\n", idx);
	   rc += tSceRegister(Authentication_Loop_Name,Authentication_Loop,100);
	   break;        
	case 10 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Ldap Search all attributes and Modify IMSI and AccountingProfileId values \non a bank of 50K users for DH FWK test campaign purpose\n", idx);
	   rc += tSceRegister(LDAP_SearchMasUser_Name,    LDAP_SearchMasUser,    95);
	   rc += tSceRegister(LDAP_Modify_IMSI_AccountingProfileId_Name,LDAP_Modify_IMSI_AccountingProfileId, 5);
	   break;        
	case 11 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Ldap Add MAS Users for DH FWK test campaign purpose\n", idx);
	   //Force Sequential Mode for User Get Policy
	   tcUserGetPolicy=1;
	   fprintf(stderr, "tgen_mas: Traffic Profile #11 forces Sequential User Get Policy\n", idx);    
	   rc += tSceRegister(LDAP_Add_MasUser_Name,      LDAP_AddMasUser,       100);
	   break;        
	case 12 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Ldap Search all attributes values on a bank of 50K users for DH FWK test campaign purpose\n", idx);
	   rc += tSceRegister(LDAP_SearchMasUser_Name,    LDAP_SearchMasUser,    100); 
	   break;        
	case 13 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Ldap Search / Diameter LIR request ", idx);
	   fprintf(stderr, "on a bank of 500 HSS R2.2 IMPUs for Ldap/Diameter Benchmarks purpose\n");
	   rc += tSceRegister(LDAP_LIR_Name,    LDAP_LIR,    100);
	   break;        
	case 14 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Ldap Search / Diameter SAR on registered IMPU request\n", idx);
	   fprintf(stderr, "on a bank of 500 HSS R2.2 IMPUs for Ldap/Diameter Benchmarks purpose (Complete Profile Download)\n");
	   rc += tSceRegister(LDAP_SAR_Complete_Profile_Download_Name,    LDAP_SAR_Complete_Profile_Download,    100);
	   break;
	case 15 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Ldap Modify-Replace / Diameter SAR on IMPU First Registration request\n", idx);
	   fprintf(stderr, "on a bank of 1000 HSS R2.2 IMPUs for Ldap/Diameter Benchmarks purpose (First Registration)\n");
	   rc += tSceRegister(LDAP_SAR_First_Registration_Name,    LDAP_SAR_First_Registration,    100);	   
	   break;
	case 150 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of 1 Ldap Search all attributes and Modify MaximumActivityDuration/AuthTemplate values on a bank of users\n", idx);
	   rc += tSceRegister(LDAP_SearchMasUser_Name,      	LDAP_SearchMasUser,	         80);
	   rc += tSceRegister(LDAP_Modify_MAD_Name,				LDAP_Modify_MAD,	 		 20);
	   break;        
	case 190 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of 4 Ldap Search on single attributes and Modify an int value on a bank of users\n", idx);
	   rc += tSceRegister(LDAP_SearchMasUser_Attrib_Name,	LDAP_SearchMasUser_Attrib,	 90);
	   rc += tSceRegister(LDAP_Modify_MAD_Name,             LDAP_Modify_MAD,             10);
	   break;        
	default :
       if (idx < 0 || idx > 100)
            return 1;
            
/*	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of 4 Ldap Search on single attributes and Modify an int and a string values on a bank of users\n", idx);
	   rc += tSceRegister(LDAP_SearchMasUser_Attrib_Name,	LDAP_SearchMasUser_Attrib,	 idx);
	   rc += tSceRegister(LDAP_Modify_MAD_AuthTemplate_Name,LDAP_Modify_MAD_AuthTemplate,100-idx); */
	   break;        
	}

    return rc;
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
//TSCE HANDLING
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
void tScePrecondition (const tSce* aSce, const tUser* aUser)
/******************************************************************************/
{

    if (verbose2)
        fprintf(stderr, "tExec: Scenario: %s, user(RDN): %s \n", aSce->name, tUserGetRDN(aUser) );

}

