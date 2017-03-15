#include "tuser.h"


int tRadiusInit() ;
#define  WAIT_FOR_ACK   (int)0
#define  WAIT_FOR_RJ    (int)1

#define     AUTHTYPE_NONE           0	// HSS
#define     AUTHTYPE_PROPRIETARY    1	// HSS
#define     AUTHTYPE_SIP_CHAP       2	// HSS, MAS
#define     AUTHTYPE_GPP_AKA        3	// HSS
#define     AUTHTYPE_DIGEST         4	// HSS, MAS
#define		AUTHTYPE_PAP			5	// MAS
#define		AUTHTYPE_EAPSIM         6	// MAS
#define		AUTHTYPE_OTP	        7	// MAS
#define		AUTHTYPE_EAPTTLS        8	// MAS
#define		AUTHTYPE_EAPAKA         9 // MAS
#define		AUTHTYPE_EAPTLS         10 // MAS

// Hard-coded Authentication Vectors for EAP/SIM authentication type
#define		EAPSIM_SRES1			"0xE5B03356" // old: "0x37127B31"
#define		EAPSIM_SRES1_BAD		"0xBADBADBA"
#define		EAPSIM_SRES2			"0x2E5A8EEA" // old: "0x0DA986C8"
#define		EAPSIM_SRES3 			"0x50AF59AF" // old: "0x60E5E4BC"
#define		EAPSIM_KC1 				"0xFC596DE3F72DFD40" // old: "0x40B8E9A5B338AA5D"
#define		EAPSIM_KC2 				"0x40EDBB98C2F56B7C" // old: "0x12C94B850683FA61"
#define		EAPSIM_KC3 				"0x8F8AB5014900B74C" // old: "0x71E75D4DCA679A70"

#define		EAPAKA_AUTN				"0x45454545454545454545454545454545"  //"0xa0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"
#define		EAPAKA_IK				"0x44444444444444444444444444444444"  //"0xb0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
#define		EAPAKA_CK				"0x43434343434343434343434343434343"  //"0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
#define 	EAPAKA_RES				"0x42424242424242424242424242424242"  //"0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0"
#define		EAPAKA_RAND				"0xe0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0"
#define		EAPAKA_RES_BAD			"0xd0d0d0d0d0d0d0d0d0d0d0d0d0d0d010"


/* EapSim AccessRequest types & sub-types
#define     EAPSIM_TYPE_ID          0
#define     EAPSIM_TYPE_START       1
#define     EAPSIM_TYPE_CHALL       2
#define     EAPSIM_TYPE_CLIERR      3
#define     EAPSIM_TYPE_NOTIF       4
#define     EAPSIM_TYPE_FAST        5
#define     EAPSIM_TYPE_MAX         6
#define	   EAPAKA_TYPE_CHALL		  21
#define	   EAPAKA_TYPE_AUTHREJ		  22
#define	   EAPAKA_TYPE_SYNFAIL		  23
#define	   EAPAKA_TYPE_IDENTITY		  24
*/

// Hard-coded Wimax values to support Prepaid Charging
// FR SDMAAAFAG222657: most common value is 12 bytes length (and not 13)
//#define		CreditSessionInitial_WIMAXCAPABILITY			"0x0001060501000202030003030a"
#define		CreditSessionInitial_WIMAXCAPABILITY				"0x000105312e30020300030302"
#define		CreditSessionInitial_SessionTerminationCapability 	"0x00000001"
#define		CreditSessionInitial_PPAC							"0x00010600000003"
#define		ServiceType_Framed									"2"	//Framed user
#define		ServiceType_AuthenticateOnly						"8"	//AuthenticateOnly
#define		ServiceType_AuthorizeOnly							"17"	//AuthorizeOnly
#define		PPAQ_UpdateReason_QuotaReached						"080304"
#define		PPAQ_UpdateReason_AccessServiceTerminated			"080308"
#define		BeginningOfSession_false							"0x00000000"
#define		BeginningOfSession_true								"0x00000001"
#define		SessionContinue_false								"0x00000000"
#define		SessionContinue_true								"0x00000001"

// WiMAX has vendor code 24757
#define WIMAX_VENDORCODE_FREERADIUS	24757

// Vendor specific attributes
#define PW_WIMAX_CAPABILITY	        	((WIMAX_VENDORCODE_FREERADIUS<<16)|1)
#define PW_AAA_SESSION_ID	        	((WIMAX_VENDORCODE_FREERADIUS<<16)|4)
#define PW_SESSION_CONTINUE	        	((WIMAX_VENDORCODE_FREERADIUS<<16)|21)
#define PW_BEGINNING_OF_SESSION	        ((WIMAX_VENDORCODE_FREERADIUS<<16)|22)
#define PW_HOTLINE_INDICATION	        ((WIMAX_VENDORCODE_FREERADIUS<<16)|24)
#define PW_PREPAID_INDICATOR	        ((WIMAX_VENDORCODE_FREERADIUS<<16)|25) 
#define PW_PDFID	        			((WIMAX_VENDORCODE_FREERADIUS<<16)|26)
#define PW_SDFID	        			((WIMAX_VENDORCODE_FREERADIUS<<16)|27)
#define PW_PPAC	        				((WIMAX_VENDORCODE_FREERADIUS<<16)|35)
#define PW_SESSION_TERMINATION_CAPABILITY	((WIMAX_VENDORCODE_FREERADIUS<<16)|36)
#define PW_PPAQ	        				((WIMAX_VENDORCODE_FREERADIUS<<16)|37)


// RHL, Sep 1, 2008: add tActionFlags for AccessRq sub-action process,
// creditSessionAction for '_CreditSession_', which is used for Prepaid charging (AccessRequests)
// Acct Segmentation which is used for both Prepaid/Postpaid (AcctRequests)
// relocation to tell if NAS relocation is activated (both AccessRequests & AcctRequests)
// Pls add other flags according to your requirements. It will easy to enhance.
typedef struct tActionFlags {
    int creditSessionAction;     // Credit Session Action: 1=Initial, 2=Update, 3=Termination      
	int beginofsession;   		 // Begin-Of-Session : -1=notrequired, 0=false, 1=true
	int sessioncontinue;   		 // Session-Continue : -1=notrequired, 0=false, 1=true
    int relocation;				 // tell if the second pre-configured NASid should be used or not: 0=false, 1=true
} tActionFlags;


int tRadiusAuthTypeGet ();

int tRadius_accessRq( int             waitFor,
                      int       	  sockFd,
                      int *			  retry,
                      tUser *    	  aUser,
                      int			  authType,
                      int             fasteap,
                      tActionFlags *  actionFlags);

int tRadius_accountRq(int       	  sockFd,
                      int *			  retries,
                      tUser *    	  aUser,
                      int			  statusType,
                      tActionFlags *  actionFlags);

