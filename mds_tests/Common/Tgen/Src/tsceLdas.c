#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tconf.h"
#include "texec.h"
#include "tsce.h" 
#include "tstat.h"
#include "taction.h"

//Known bugs

// 1
// LDAP_Modify_Rq      , "\0", "add:objectclass > externalaccount #  homeDirectory > /home/_RDN_ ...
// is OK, since within attribute expression add is default modify operation
// but write
// LDAP_Modify_Rq      , "\0", "delate:objectclass > externalaccount #  homeDirectory  ...
// fails  (tgen_ldas: encode.c:328: ber_put_string: Assertion `str != ((void *)0)' failed.)
// you must set attribute expression with delete as modify operation: 
// LDAP_Modify_Rq      , "\0", "delete:objectclass > externalaccount #  delete:homeDirectory  ...

//#####################################
// EASI
//#####################################

/*
Name
    System Test: Loop of LDAP Search on a MMS user
Details
*/
static const char* LDAP_SearchMMSuser_Loop_Name="LDAP_SearchMMSuser_Loop";
static tAction LDAP_SearchMMSuser_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },    
    { LDAP_Search_Rq      , "\0", "\*" },          
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    

/*
Name
    System Test: Loop of LDAP Search && LDAP Modify Add on a MMS user
Details
	Modify replace of one integer value 
	Out of EASI Test Scope
*/
static const char* LDAP_SearchModifyMMSuser_Loop_Name="LDAP_SearchModifyMMSuser_Loop";
static tAction LDAP_SearchModifyMMSuser_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },   
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },    
    { LDAP_Modify_Rq      , "\0", "replace:profileid > 2" },          
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};    


/*
Name
    System Test: Loop of LDAP Search && LDAP Modify Add on a MMS user
Details
Details
	Modify replace of one integer value 
	Sequential Mode MUST BE set for User Get Policy
	Out Of EASI Test Scope
	entry grows from 277 to 604 octets lenght
*/
static const char* LDAP_SearchModifyAddOcMMSuser_Loop_Name="LDAP_SearchModifyAddOcMMSuser_Loop";
static tAction LDAP_SearchModifyAddOcMMSuser_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },      
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },    
    { LDAP_Modify_Rq      , "\0", "add:objectclass > courierinfo # homeDirectory > /home/_RDN_ # mailMessageStore > /home/_RDN_/mailbox  # mailQuota > 500000" },	
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },
	{ LDAP_Modify_Rq      , "\0", "add:objectclass > externalaccount # loginname > _RDN_@account.alcatel.fr # loginpasswd > 010203 # externalservername > account@account.alcatel.fr # externalserverprotocol > externalserverprotocol # isexternalactive > TRUE" },
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};  


/*
Name
    System Test: Loop of LDAP Search && LDAP Modify Del on a MMS user
Details
Details
	Modify replace of one integer value 
	Sequential Mode MUST BE set for User Get Policy
	Out Of EASI Test Scope
	first search gets 238 octets lenght
	second search gets 277 octets lenght
*/
static const char* LDAP_SearchModifyDelOcMMSuser_Loop_Name="LDAP_SearchModifyDelOcMMSuser_Loop";
static tAction LDAP_SearchModifyDelOcMMSuser_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },      
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },    
    { LDAP_Modify_Rq      , "\0", "delete:objectclass > courierinfo # delete:homeDirectory # delete:mailMessageStore # delete:mailQuota" },
    { LDAP_Search_Rq      , "_getAsBase_: refdn", "\*" },
	{ LDAP_Modify_Rq      , "\0", "delete:objectclass > externalaccount # delete:loginname # delete:loginpasswd # delete:externalservername # delete:externalserverprotocol # delete:isexternalactive" },
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },

};  

//#####################################
// HSS / HPD
//#####################################

/*
Name
    Scenario out of System Test: Loop of LDAP Search on a HPD user
    Search AuthenticationType
Details
*/
static const char* LDAP_Search_Loop_Name="LDAP_Search_Loop";
static tAction LDAP_Search_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },      
    { LDAP_Search_Rq      , "\0", "AuthenticationType" },          
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    Scenario out of System Test: Loop of LDAP Search / LDAP Modify on a HPD user
Details
*/
static const char* LDAP_SearchModify_Loop_Name="LDAP_SearchModify_Loop";
static tAction LDAP_SearchModify_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Search_Rq      , "\0", "AuthenticationType "},
    { LDAP_Modify_Rq      , "\0", "replace:sCSCFselected > mmcs@tgen.test"},  
    { LDAP_Search_Rq      , "\0", "\*" },         
    { LDAP_Modify_Rq      , "\0", "delete:sCSCFselected"},     
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    Scenario out of System Test: Loop of LDAP Search / LDAP Modify on a HPD user
Details
*/
static const char* LDAP_Modify_Loop_Name="LDAP_Modify_Loop";
static tAction LDAP_Modify_Loop[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Modify_Rq      , "\0", "replace:sCSCFselected > mmcs@tgen.test"},         
    { LDAP_Modify_Rq      , "\0", "delete:sCSCFselected"},     
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    Scenario out of System Test: Loop of Population of HPD user
Details
*/
static const char* LDAP_Add_PopulHPD_Name="LDAP_PopulAddHSS_Loop";
static tAction LDAP_Add_PopulHPD[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Add_Rq         , "\0", "objectclass > im-user # cn > _RDN_ # NAI > _RDN_ # E164 > 0123456789 # sCSCFpreference > mmas1@alcatel.fr & mmas2@alcatel.fr & mmas3@alcatel.fr & mmas4@alcatel.fr # AuthenticationType > 1 # subscribedQoS > streaming # sCSCFselected > mmas1@alcatel.fr # initialFilterCriteria > SIPMethod=MESSAGE, SessionCase=0, ServerName=mmas4@alcatel.fr, ServiceInfo=fourth initial Criteria & SIPMethod=INVITE, SessionCase=1, ServerName=mmas2@alcatel.fr, ServiceInfo=second initial Criteria & SIPMethod=SUBSCRIBE, SessionCase=2, ServerName=mmas3@alcatel.fr, ServiceInfo=third initial Criteria & SIPMethod=MESSAGE, SessionCase=0, ServerName=mmas4@alcatel.fr, ServiceInfo=fourth initial Criteria " },    
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};

/*
Name
    Scenario out of System Test: Loop of Population of HPD user
Details
*/
static const char* LDAP_Delete_Popul_Name="LDAP_PopulDelete_Loop";
static tAction LDAP_Delete_Popul[] = {

    { SCE_Begin           , "\0", "\0" },   
    { LDAP_Bind_Rq        , "\0", "\0" },    
    { LDAP_Delete_Rq      , "\0", "\0" },   
    { LDAP_UnBind_Rq      , "\0", "\0" },   
    { SCE_End             , "\0", "\0" },
};


/******************************************************************************/
/* Elementary Level Scenarios */ 
/*CAVEAT: BIND/UNBIND IS MANDATORY */
/******************************************************************************/ 



/******************************************************************************/
int tSceTrafficProfile (int idx)
/******************************************************************************/
{
int rc=0;

    switch (idx) {
	case 1 :  
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Search on MMS user\n", idx);
	   rc += tSceRegister(LDAP_SearchMMSuser_Loop_Name,LDAP_SearchMMSuser_Loop,100);
	   break;
	case 2 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Search && Modify Add on MMS user\n", idx);
	   //Force Sequential Mode for User Get Policy
	   tcUserGetPolicy=1;
	   rc += tSceRegister(LDAP_SearchModifyAddOcMMSuser_Loop_Name,LDAP_SearchModifyAddOcMMSuser_Loop,100);
	   //rc += tSceRegister(LDAP_SearchModifyMMSuser_Loop_Name,LDAP_SearchModifyMMSuser_Loop,100);
	   break;        
	case 3 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Search && Modify Del on MMS user\n", idx);
	   //Force Sequential Mode for User Get Policy
	   tcUserGetPolicy=1;
	   rc += tSceRegister(LDAP_SearchModifyDelOcMMSuser_Loop_Name,LDAP_SearchModifyDelOcMMSuser_Loop,100);
	   break;        
	case 4 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Search on HPD user: get HSS user\n", idx);
	   rc += tSceRegister(LDAP_Search_Loop_Name,LDAP_Search_Loop,100);
	   break;        
	case 5 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Search: get HSS user, LDAP Modify: write sCSCFselected\n", idx);
	   rc += tSceRegister(LDAP_SearchModify_Loop_Name,LDAP_SearchModify_Loop,100);
	   break;        
	case 6 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP HDP Population Create\n", idx);
	   //Force Sequential Mode for User Get Policy
	   tcUserGetPolicy=1;
	   fprintf(stderr, "tgen: Traffic Profile #%d forces Sequential User Get Policy\n", idx);
	   rc += tSceRegister(LDAP_Add_PopulHPD_Name,LDAP_Add_PopulHPD,100);
	   break;        
	case 7 :
	   fprintf(stderr, "tgen: Traffic Profile #%d: LDAP Population Delete\n", idx);
	   //Force Sequential Mode for User Get Policy
	   tcUserGetPolicy=1;
	   fprintf(stderr, "tgen: Traffic Profile #%d forces Sequential User Get Policy\n", idx);
	   rc += tSceRegister(LDAP_Delete_Popul_Name,LDAP_Delete_Popul,100);
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
        
    //No defined Precondition
  
}    