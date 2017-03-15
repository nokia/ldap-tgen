#ifndef texec_h
#define texec_h

/******************************************************************************/
// 
// CAVEAT: BIND/UNBIND IS MANDATORY
//
// CAVEAT: Following ATTR_* characters can not be used !!!!! as value field in sce
// ATTR_DELIMITER          '#'
// ATTR_ACTION_SCOPE       ':'
// ATTR_EQUALITY           '>'
// ATTR_VALUE_SEPARATOR    '&' 
//
// getAsBase operation as cmd field of LDAP_Search_Rq set the parameter of the
// next LDAP_Search_Rq on the current user as follows:
//      - base= value ( get  in the search response) of the attribute type 
//              specified in the cmde field
//      - filter= (objectClass=*)
//      - scope= one level 

// Current Problem: to resolve...
//  - Multivalued attribute: The 2nd and next values are preceded by a blank space...
/******************************************************************************/ 

//Request Name
enum Request_Name {
	SCE_Begin=0,		// must be the first one

	// Ldap
	LDAP_Bind_Rq,
	LDAP_UnBind_Rq,
	
	LDAP_Search_Rq,
	LDAP_Modify_Rq,
	LDAP_Add_Rq,
	LDAP_Delete_Rq,
	LDAP_Search_Resp,
	LDAP_Bind_Resp,
	
	//All
	RADIUS_AuthWP_Rq,
	RADIUS_Auth_Rq,
	
	//SIM
	RADIUS_AccessEapId_Rq,
	RADIUS_AccessEapStart_Rq,
	RADIUS_AccessEapChal_Rq,
	RADIUS_AccessEapCliErr_Rq,
	RADIUS_AccessEapNotif_Rq,
	RADIUS_AccessEapFast_Rq,
	
	//TLS/TTLS
	RADIUS_AccessEapTtls_Rq,
	// RHL, 01/08/2008; add for eap-tls, need adjust the int because the stat arrange sequence by it
	RADIUS_AccessEapTls_Rq,
	
	// AKA
	RADIUS_AccessEapAKAIdentity_Rq,
	RADIUS_AccessEapAKAChal_Rq,
	RADIUS_AccessEapAKARej_Rq,
	RADIUS_AccessEapAKASynfail_Rq,
	
	// Acct
	RADIUS_AccountStart_Rq,
	RADIUS_AccountInterim_Rq,
	RADIUS_AccountStop_Rq,
	RADIUS_AccountOn_Rq,
	RADIUS_AccountOff_Rq,
	
	SCE_Wait,
	SCE_End	// must be the latest one
};


//Request Attribute Metacharaters
//EmA,30/09/2010: # is used in config file as a comment !!!
// #define ATTR_DELIMITER          '#'
#define ATTR_DELIMITER          '|'
#define ATTR_ACTION_SCOPE       ':'
#define ATTR_EQUALITY           '>'
#define ATTR_VALUE_SEPARATOR    '&' 
#define WHITE_CHARACTER         ' ' 

// SCE_Wait parameters
#define KEYWD_RAND             	"_RAND_"
#define KEYWD_VALUE            	"_VALUE_"

// LDAP_Search_Rq parameters to manipulate DN
#define KEYWD_GETASBASE         "_getAsBase_"
#define KEYWD_RDN               "_RDN_"
#define KEYWD_DN               	"_DN_" 

// LDAP_*_Rq to activate a control
#define KEYWD_LDAPCONTROL		"_LDAPCTRL_"

// LDAP_Search_Rq for UMA
#define KEYWD_SCRUBBING         "_SCRUB_"
#define KEYWD_IHLR              "_IHLR_"
#define KEYWD_COTF              "_COTF_"
#define KEYWD_CMOD              "_CMOD_"
#define KEYWD_DYNAMICSCRUBBING  "_DYNAMICSCRUB_"

// RADIUS_Account_Rq
#define KEYWD_BEINGOFSESSION	"_BOS_"
#define KEYWD_SESSIONCONTINUE	"_SC_"

// RADIUS_Auth_Rq
#define KEYWD_PREPAID			"_CreditSession_"

/* UMA controls, already defined in ldap.h */
#define LDAP_CONTROL_SCRUBBING "1.1.2.3.1.1001"
#define LDAP_ADD_IMSI_IF_NOT_EXIST "1.1.2.3.1.1002"
#define LDAP_CONTROL_CMOD "1.1.2.3.1.1003"
#define LDAP_CONTROL_IHLR "1.1.2.3.1.1004"
#define LDAP_CONTROL_SCRUBBING_2 "1.1.2.3.1.1005"
#define LDAP_CONTROL_COUNT_ENTRIES " 1.3.6.1.4.1.637.81.2.10.9"

// others controls, not defined in ldap.h (so not visible by RootDSE querry on server...)
//#define LDAP_CONTROL_DATAPROFILE "1.3.6.1.4.1.637.81.2.10.2"


/* size of registration data (binary field  for iHLR */
#define IHLR_REGISTRATION_DATA_SIZE   25

//forwards
typedef struct tLdapReqCtx;
typedef struct tUser;
typedef struct tSce;
typedef struct tAction;

// ctx to be memorised when a scenario is sleeping
typedef struct tSleep {
   struct tLdapReqCtx	*req;
   struct tUser			*user;
   struct tSce			*sce;
   struct tAction		*action;
} tSleep;


int     tExecInit ()        ;
void    tExec (int key)    ;


#endif
