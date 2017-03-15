#include "tuser.h"

// Hard-coded Authentication Vectors for EAPTTLS authentication type to support Prepaid Charging
// EmA,15/10/2008, FR SDMAAAFAG222657: most common value is 12 bytes length (and not 13)
//#define		CreditSessionInitial_WIMAXCAPABILITY_TTLS		"0001060501000202030003030a"
#define		CreditSessionInitial_WIMAXCAPABILITY_TTLS			"000105312e30020300030302"
#define		CreditSessionInitial_SessionTerminationCapability_TTLS 	"00000001"
#define		CreditSessionInitial_PPAC_TTLS				"00010600000003"
#define		ServiceType_Framed_TTLS					"02"	//Framed user
#define		ServiceType_AuthenticateOnly_TTLS			"08"	//AuthenticateOnly
#define		ServiceType_AuthorizeOnly_TTLS				"11"	//AuthorizeOnly 0x11==17

int tSupplicantInit() ;


/*RHL | Sep 16, 2008 | add creditSesAction into tActionFlags*/
/*                     for prepaid charging traffic with eapttls              */
int tSupplicant_accessRq( 
                      int             waitFor,
                      int       	  sockFd,
                      int *			  retry,
                      tUser *    	  aUser,
                      int			  authType,
                      int             fasteap,
		      tActionFlags *  actionFlags);

