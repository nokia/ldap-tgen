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
    Scenario NLS Ses_MO: Session Setup, Originated Session
Details
    The S-MMCS does not download authentication type since it
    is already known by S-MMCS thanks to stored user's SDP.
*/
static const char* Session_Setup_Name="Session_Setup";
static tAction Session_Setup[] = {

    { SCE_Begin           , "\0", "\0" },   
    { RADIUS_Access_Rq    , "\0", "\0" },    
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    Scenario NLS Reg: First Registration
Details
    The S-MMCS performs authentication. .
*/
static const char*  First_Registration_Name="First_Registration";
static tAction First_Registration[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { LDAP_Search_Rq      	, "\0", "AuthenticationType"},
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},
    { LDAP_Search_Rq      	, "\0", "\*" }, 
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS Reg_IMMCS: First Registration with I-MMCS
Details
    The I-MMCS performs a HSS interrogation as a combined Cx-Query and Cx-Select-Pull.
*/
static const char*  First_Registration_WithIMMCS_Name="First_Registration_WithIMMCS";
static tAction First_Registration_WithIMMCS[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { LDAP_Search_Rq      	, "\0", "sCSCFselected # sCSCFpreference"},
    { LDAP_Search_Rq      	, "\0", "AuthenticationType"},    
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},
    { LDAP_Search_Rq      	, "\0", "\*" }, 
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End           	, "\0", "\0" },

};

/*
Name
    Scenario NLS Reg_MMAS: Explicit Registration to MMAS via HTTP
Details
    The S-MMCS performs a SIP_CHAP authentication.
*/
static const char* Explicit_Registration_ToMMAS_Name="Explicit_Registration_ToMMAS";
static tAction Explicit_Registration_ToMMAS[] = {

    { SCE_Begin           , "\0", "\0" },   
    { RADIUS_Access_Rq    , "\0", "\0" },    
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    NLS ReReg_TO: Re-Registration - user currently registered
Details
    No DAP_Search_AuthType_Rq is done since the User Profile including
    the Authentication type is already stored inside the SDP of the S-MMCS
*/
static const char*  Re_Registration_Name="Re_Registration";
static tAction Re_Registration[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},
    { LDAP_Search_Rq      	, "\0", "\*" }, 
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS DeReg: De-Registration
Details
    The S-MMCS does not download authentication type since it is
    already known by S-MMCS thanks to stored user's SDP
*/
static const char*  De_Registration_Name="De_Registration";
static tAction De_Registration[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "delete:sCSCFselected"},
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS DeReg_Net Network initiated De-Registration - Registration timeout
Details
    The S-MMCS initiates the de-registration
*/
static const char*  De_Registration_Network_Name="De_Registration_Network";
static tAction De_Registration_Network[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "delete:sCSCFselected"},
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS Reg_WP: Registration with wrong password
Details
    After the Access Request with wrong password, a right Access Request
    is done in order to reset the CFAC of the current user.
*/
static const char*  Registration_WrongPasswd_Name="Registration_WrongPasswd";
static tAction Registration_WrongPasswd[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { RADIUS_AccessWP_Rq      	, "\0", "\0"},
    { RADIUS_Access_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS Reg_ST: Registration of a second or more terminal
Details

*/
static const char*  Registration_SecondTerminal_Name="Registration_SecondTerminal";
static tAction Registration_SecondTerminal[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario NLS Reg_RM: Registration rejected by MMAS
Details

*/
static const char*  Registration_RejectedByMMAS_Name="Registration_RejectedByMMAS";
static tAction Registration_RejectedByMMAS[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { LDAP_Search_Rq      	, "\0", "AuthenticationType"},    
    { RADIUS_Access_Rq		, "\0", "\0" },
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},
    { LDAP_Search_Rq      	, "\0", "\*"},    
    { LDAP_Modify_Rq      	, "\0", "delete:sCSCFselected"},
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};


/******************************************************************************/
/* Elementary Level Scenarios */
/*CAVEAT: BIND/UNBIND IS MANDATORY */
/******************************************************************************/

/*
Name
    Scenario ELS A: Registration with wrong password - user gets locked
Details
*/
static const char*  AuthenticationWP_UserLocked_Loop_Name="AuthenticationWP_UserLocked";
static tAction AuthenticationWP_UserLocked_Loop[] = {

    { SCE_Begin			, "\0", "\0" },
    { RADIUS_AccessWP_Rq	, "\0", "\0" },
    { RADIUS_AccessWP_Rq      	, "\0", "\0" },    
    { RADIUS_Access_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario ELS B: Loop of LDAP Modify
Details
*/
static const char*  Registration_Loop_Name="Registration_Loop";
static tAction Registration_Loop[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { RADIUS_Access_Rq      	, "\0", "\0"},    
    { LDAP_Modify_Rq      	, "\0", "replace:sCSCFselected > mmcs@tgen.test"},  
    { LDAP_Modify_Rq      	, "\0", "delete:sCSCFselected"},
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario ELS B: Loop of Radius Authentication
Details
*/
static const char*  Authentication_Loop_Name="Authentication_Loop";
static tAction Authentication_Loop[] = {

    { SCE_Begin			, "\0", "\0" },
    { RADIUS_Access_Rq		, "\0", "\0" },
    { SCE_End             	, "\0", "\0" },

};

/*
Name
    Scenario out of System Test: Loop of LDAP Search
Details
*/
static const char*  LDAP_Search_Loop_Name="LDAP_Search_Loop";
static tAction LDAP_Search_Loop[] = {

    { SCE_Begin			, "\0", "\0" },
    { LDAP_Bind_Rq		, "\0", "\0" },
    { LDAP_Search_Rq      	, "\0", "AuthenticationType"},    
    { LDAP_Search_Rq      	, "\0", "\*" }, 
    { LDAP_UnBind_Rq		, "\0", "\0" },
    { SCE_End           	, "\0", "\0" },

};


/******************************************************************************/
int tSceTrafficProfile (int idx)
/******************************************************************************/
{
    int rc=0;

    switch (idx) {
	case 1 :  
	   fprintf(stderr, "tgen: Traffic Profile #%d: Batch Service Traffic A (Reference)\n", idx);
	   rc += tSceRegister(Session_Setup_Name,Session_Setup,55);
	   rc += tSceRegister(First_Registration_Name,First_Registration,11);
	   rc += tSceRegister(De_Registration_Name,De_Registration,11);
	   rc += tSceRegister(Re_Registration_Name,Re_Registration,23);
	   break;
	case 2 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Batch Service Traffic B\n", idx);
	   rc += tSceRegister(Session_Setup_Name,Session_Setup,50);
	   rc += tSceRegister(First_Registration_Name,First_Registration,4);
	   rc += tSceRegister(First_Registration_WithIMMCS_Name,First_Registration_WithIMMCS,4);
	   rc += tSceRegister(Explicit_Registration_ToMMAS_Name,Explicit_Registration_ToMMAS,4);
	   rc += tSceRegister(Re_Registration_Name,Re_Registration,14);
	   rc += tSceRegister(De_Registration_Name,De_Registration,6);
	   rc += tSceRegister(De_Registration_Network_Name,De_Registration_Network,6);
	   rc += tSceRegister(Registration_WrongPasswd_Name,Registration_WrongPasswd,4);
   //  if (tcNoWriteInScenario)
   //     rc += tSceRegister(First_Registration_Name,First_Registration,4);
   //  else
		  rc += tSceRegister(Registration_SecondTerminal_Name,Registration_SecondTerminal,4);
	   rc += tSceRegister(Registration_RejectedByMMAS_Name,Registration_RejectedByMMAS,4);
	   break;        
	case 3 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Traffic Profile #2 without Re_Registration\n", idx);
	   rc += tSceRegister(Session_Setup_Name,Session_Setup,56);
	   rc += tSceRegister(First_Registration_Name,First_Registration,22);
	   rc += tSceRegister(De_Registration_Name,De_Registration,22);
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
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of LDAP Modify on a user (should be lauched with -r1 option)\n", idx);
	   tcUserGetPolicy = 18;
	   rc += tSceRegister(Registration_Loop_Name,Registration_Loop,100);
	   break;        
	case 7 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of LDAP Modify on a bank of user\n", idx);
	   rc += tSceRegister(Registration_Loop_Name,Registration_Loop,100);
	   break;        
	case 8 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Radius Authentication on a user (should be lauched with -r1 option)\n", idx);
	   tcUserGetPolicy = 18;
	   rc += tSceRegister(Authentication_Loop_Name,Authentication_Loop,100);
	   break;        
	case 9 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of Radius Authentication on a bank of user\n", idx);
	   rc += tSceRegister(Authentication_Loop_Name,Authentication_Loop,100);
	   break;        
	case 10 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: Loop of LDAP_Search on a bank of user\n", idx);
	   rc += tSceRegister(LDAP_Search_Loop_Name,LDAP_Search_Loop,100);
	   break;        
	default :
	   rc = 1;
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

    //When First_Registration is carried out, a write must be forced within database
    //To do that, user's S_CSCF is changed
    if ( !strcmp("First_Registratio",aSce->name) ||
         !strcmp("Registration_Seco",aSce->name) ||
         !strcmp("Registration_Reje",aSce->name) ||
         !strcmp("Registration_Loop",aSce->name)   ) {

        tUserWriteSCSCF( aUser );
    }
}
