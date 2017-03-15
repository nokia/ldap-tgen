
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#include "libradius.h"
#include "digcalc.h"

#include "tdebug.h"
#include "tconf.h"
#include "tthread.h"
#include "tuser.h"
#include "tradius.h"
#include "texec.h"
#include "tselect.h"

#include "eap_types.h"
#include "eap_sim.h"

// misc functions (from radclient.c)
static int     	send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep, int *retries); 
static void		random_vector(uint8_t *vector);
static int		rad_http_encode(RADIUS_PACKET *req, char *user, char *passwd);
// misc functions (from radeapclient.c)
int radlog(int lvl, const char *msg, ...);
static void cleanresp(RADIUS_PACKET *resp);
static int process_eap_start(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk);
static int process_eap_challenge(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id);
static int process_eap_reauth(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id);
static int respond_eap_sim(RADIUS_PACKET *req, RADIUS_PACKET *resp, struct eapsim_keys *eapsim_mk, char* fr_id);
static int sendrecv_eap(RADIUS_PACKET *rep, RADIUS_PACKET **final_rep, int *total_retriest, tUser *user);
static int process_eap_clienterror (RADIUS_PACKET *req, RADIUS_PACKET *rep);

// RHL, It will copy the char(s) type value from source to the dest
void copyVSAAttrValue(char* destVSA, char* srcVSA, int length );

/* RHL, Sep 16, 2008; It will put the Wimax VSA value to VP*/
VALUE_PAIR * putWimaxVSA( VALUE_PAIR	*vps_out,
                  tUser *    	aUser,
                  int		authType,
		  int 	        creditSessionAction);
		  
// static vars
static uint8_t				random_vector_pool[AUTH_VECTOR_LEN*2];
static const char *			secret;
extern int				   	radAuthTypeTab[100];
static char *				envvar[PW_SUBATTRIBUTE_USERNAME + 1] = {
	"",
	"RAD_HTTPDIGEST_REALM",
	"RAD_HTTPDIGEST_NONCE",
	"RAD_HTTPDIGEST_METHOD",
	"RAD_HTTPDIGEST_URI",
	"RAD_HTTPDIGEST_QOP",
	"RAD_HTTPDIGEST_ALGORITHM",
	"RAD_HTTPDIGEST_BODYDIGEST",
	"RAD_HTTPDIGEST_CNONCE",
	"RAD_HTTPDIGEST_NONCECOUNT",
	"RAD_HTTPDIGEST_USERNAME",
};

char *					authTypeName[] = {
   "NONE",
   "PROPRIETARY",
   "CHAP",
   "GPP_AKA",
   "HTTP-DIGEST",
   "PAP",
   "EAP-SIM",
   "OTP",
   "EAP-TTLS",
   "EAP-AKA",
   "EAP-TLS"
};

char *					acctStatusTypeName[] = {
	"Start",
	"Interim-Update",
	"Stop",
	"Accounting-On",
	"Accounting-Off",
};

// global vars to be transformed into each request vars...
int estart = 0; /* a client error is sent at start reception */
int estartNotif = 0; /* value of ClientError code */
int echallenge = 0; /* a client error is sent at challenge reception */
int eclienterror = 0; /* a client error is sent as first message */
int ecounterTooSmall = 0; /* a counter too small is sent in reauth */
int atEncrData = 0; /* add AT_ENCR_DATA, AT_IV, AT_RESULT_IND in SIM-Challenge */
char eapid[80];

pthread_mutex_t            radomMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t            eapMutex = PTHREAD_MUTEX_INITIALIZER;
int haveSendRejectOrSyncFailure = 0; 


/******************************************************************************/
int tRadiusCreateSocket(int threadId)
/******************************************************************************/
{
int    		optval = 128 * 1024;
int    		optlen;

    if ( tThread_getRadSockFd(threadId) ) close( tThread_getRadSockFd(threadId) );

	tThread_getRadSockFd(threadId) =  socket(AF_INET, SOCK_DGRAM, 0);
	if ( tThread_getRadSockFd(threadId) < 0) {
		perror("Radius socket creation failure");
		return 1;
	}                      
	if( setsockopt( tThread_getRadSockFd(threadId), SOL_SOCKET, SO_SNDBUF, ( void * ) &optval, sizeof(optval) ) < 0 ) {
		TRACE_ERROR("Error opening socket %d", threadId);
		return 1;
	}
	if( setsockopt( tThread_getRadSockFd(threadId), SOL_SOCKET, SO_RCVBUF, ( void * ) &optval, sizeof(optval) ) < 0 ) {
		TRACE_ERROR("Error opening socket %d", threadId);
		return 1;
	}

	optval = 1;
	if( setsockopt( tThread_getRadSockFd(threadId), SOL_SOCKET, SO_OOBINLINE, ( void * ) &optval, sizeof(optval) ) < 0 ) {
		TRACE_ERROR("Error opening socket %d", threadId);
		return 1;
	}

	// checks size is well took into account
	getsockopt(tThread_getRadSockFd(threadId), SOL_SOCKET, SO_RCVBUF, ( void * ) &optval, &optlen );
	if (verbose >= 2) TRACE_DEBUG("getsockopt(SO_RCVBUF) = %d\n", optval);
	getsockopt(tThread_getRadSockFd(threadId), SOL_SOCKET, SO_SNDBUF, ( void * ) &optval, &optlen );
	if (verbose >= 2) TRACE_DEBUG("getsockopt(SO_SNDBUF) = %d\n", optval);

#ifdef _ASYNCHRONE_RADIUS_
	tSelectRegisterSocket(threadId, tThread_getRadSockFd(threadId));
#endif

	return 0;
}

/******************************************************************************/
int tRadiusInit()
/******************************************************************************/
{
char		radius_dir[128];
int			threadId;
       
//   TRACE_CORE("RAD_CLIENTS=%s\n", getenv("RAD_CLIENTS"));
	strcpy(radius_dir, getenv("RAD_RACINE"));
	strcat(radius_dir, "/etc/raddb");
	//strcpy(radius_dir, RADDBDIR);

   if (verbose >= 1)
       TRACE_CORE("Radius init starts, auth. vector len=%d\n", AUTH_VECTOR_LEN );
    
   // dictionary init
   if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
		librad_perror("dict_init error: ");
		return 1;
   }
		             
   if (verbose >= 2)
       TRACE_CORE("Radius dict_init ok\n" );
   
   // Create socket for sending request
   for (threadId=WORKTHR ; threadId<(WORKTHR+tcWThreadNb) ; threadId++) {
	   if ( tRadiusCreateSocket(threadId) )
		   return 1;
   }
   if (verbose >= 2)
       TRACE_CORE("Radius socket init ok\n" );
   
   // get Radius secret from environment variable RAD_SECRET
   secret = RADIUS_CLIENT_HOST_PASSWD;
   
   return 0;
}

/******************************************************************************/
static void tRadius_abandon()
/******************************************************************************/
{
int threadId=tThread_getKey();
       
    if (verbose >= 2)
        TRACE_CORE("Abandon on thread: %d\n", threadId);
    
	tRadiusCreateSocket(threadId);
}

/******************************************************************************/
int tRadiusAuthTypeGet ()
/******************************************************************************/    
{
int     index = rand();

    return (radAuthTypeTab[index % 100]);
}    


/******************************************************************************/
/*RHL | Sep 1, 2008 | change creditSesAction into tActionFlags by adding accSegmentationAction*/
/*RHL | Aug 20, 2008 | Add the parameter creditSesAction for prepaid charging */
/*                   1:	Initial	Session                                       */
/*                   2: Update Session                                        */
/*                   3: Termination Session                                   */
/*                   0: No credit session, for common radius request          */
int tRadius_accessRq( int             waitFor,
                      int       	  sockFd,
                      int *			  retries,
                      tUser *    	  aUser,
                      int			  authType,
                      int             fasteap,
					  tActionFlags *  actionFlags)
/******************************************************************************/
{
RADIUS_PACKET   *req;
RADIUS_PACKET   *rep = NULL;
VALUE_PAIR	    *vp;
VALUE_PAIR	    *vps = NULL;
int             temp, rc, i;
char            vpBuffer[1024] = "\0";
char *          p;
char *    		aNai = tUserGetNAI(aUser);
const char *	wrongPasswd = "wrong password";
char *			aPasswd;
static unsigned char	id = 0;
static unsigned int		portNb = 0;
char			portNbString[32];
char			nasIdString[32];
int             userId;
char            username[64];
char            buf[64];
char            fastid[64];
char			aaa_session_id[32];
int 			creditSessionAction = actionFlags->creditSessionAction;
int 			relocation = actionFlags->relocation;   


   TRACE_DEBUG("Enter into tRadius_accessRq , authType = %d, fasteap = %d, creditSessionAction = %d, relocation = %d\n",authType,fasteap,creditSessionAction,relocation);
   // use fast re-authentif ?
   if ( !fasteap || !tUserGetFastAuthData(aUser, NULL, fastid) )
       fastid[0] = 0;
   
//EmA,25/04/2006: viewing User0 Radius activity
//   if (verbose >= 2 || (aUser->priv.id == 0) ) {
   if (verbose >= 2)
	  TRACE_TRAFIC("tRadius_accessRq on %s (%s,%s)\n", aNai, (fastid[0] ? fastid : "NULL"), (tUserGetAAASessionIdLength(aUser) ? "with AAASessId" : "NULL") );
   
   if ((req = rad_alloc(1)) == NULL) {
	 librad_perror("tgen: tradius: rad_alloc: ");
	 return -1;
   }
   
   // unchanged fields
   req->code = PW_AUTHENTICATION_REQUEST; 
   req->dst_port = (tcServerRADIUSPort);
   req->dst_ipaddr = ip_addr(tcServerHost[tcActiveServerId]);
   req->sockfd = sockFd;
   
   // fields modified at each request
   // EmA,18/08/2004: try not to use the same id twice
   // EmA,03/11/2005: mutex is mandatory to guaranty not twice the same couple (id,RA) !!!
   pthread_mutex_lock(&radomMutex);
   req->id = id;
   if (authType == AUTHTYPE_EAPSIM)
       id += 4;
   else if (authType == AUTHTYPE_EAPAKA)
       id += 3;
   else if (authType == AUTHTYPE_EAPTTLS || authType == AUTHTYPE_EAPTLS)
       id += 6;
   else
       id++;
   random_vector(req->vector);
   pthread_mutex_unlock(&radomMutex);

   // EmA,14/10/2008: not yet implemented
/*   if (creditSessionAction >= 2) {
	   // Authorize-only: no Username needed, use anonymous instead
	   sprintf(username, "anonymous%s", strchr(aNai,'@'));
	   vps = pairmake("User-Name", username, 0);
   } else {*/
	   if ( fastid[0] )
		   vps = pairmake("User-Name", fastid, 0);
	   else
		   vps = pairmake("User-Name", aNai, 0);
//   }

   userId = aUser->priv.id;
   if (!tcRadiusNoNasPort) {
	// EmA,05/08/2004: always the same portNb for a user insteed of simply incrementing between users
	//  tUserSetPortNb(aUser, portNb);
	//  sprintf(portNbString, "%d", (portNb++));
	   sprintf(portNbString, "%d", userId);
	   vp = pairmake("NAS-Port", portNbString, 0);
	   vp->next = vps; vps = vp;
   }

// EmA,21/09/2004: do not use always the same Nas Id
//   vp = pairmake("NAS-IP-Address", RADIUS_CLIENT_NAS_IP_ADD, 0);
   temp = MIN( 255, (userId % tcRadiusNbNas) + 1);
   TRACE_DEBUG("Auth debug, UserId=%d temp=%d\n", userId, temp );
   if (userId % 2) {
       sprintf(nasIdString, "%s%d", tcRadiusNasIdBase[ (actionFlags->relocation ? 1 : 0) ], temp);
       vp = pairmake("NAS-Identifier", nasIdString, 0);
   } else {
       sprintf(nasIdString, "%s%d", tcRadiusNasIpAddBase[ (actionFlags->relocation ? 1 : 0) ], temp);
       vp = pairmake("NAS-IP-Address", nasIdString, 0);
   }
   vp->next = vps; vps = vp;
   
   if (tcRadiusCalledStId[0]) {
	   vp = pairmake("Called-Station-Id", tcRadiusCalledStId, 0);
	   vp->next = vps; vps = vp;
   }

   if (tcRadiusCallingStId[0]) {
		sprintf(nasIdString, tcRadiusCallingStId, temp, 255 - temp );
		vp = pairmake("Calling-Station-Id", nasIdString, 0);
		vp->next = vps; vps = vp;
   }
   
   // do re-authentication if available in user ctx
   if ( tUserGetStateAttribLength(aUser, actionFlags->relocation) ) {
      // EmA,07/04/2005: do not trust "pairmake" function for binary sequence types: 2 bugs inside when
      //    - sequence contains null chars
      //    - sequence starts by '0x' sequence
      vp = pairmake("State", "", 0);
      vp->length = tUserGetStateAttribLength(aUser, actionFlags->relocation);
	  memcpy(vp->strvalue, tUserGetStateAttrib(aUser, actionFlags->relocation), vp->length );  // strvalue already allocated
      vp->next = vps; vps = vp;
   }
   
   // EmA,18/09/2008: add WIMAX session Id if available
   if ( tUserGetAAASessionIdLength(aUser) ) {
	   copyVSAAttrValue((char*)aaa_session_id, tUserGetAAASessionId(aUser), tUserGetAAASessionIdLength(aUser));
	   TRACE_DEBUG("tRadius_accessRq on %s: adding AAA-Session-ID= %s \n", aNai, aaa_session_id);	 
	   vp = pairmake("AAA-Session-ID", aaa_session_id, 0); vp->next = vps; vps = vp;
	   vp = pairmake("WIMAX-CAPABILITY", CreditSessionInitial_WIMAXCAPABILITY, 0); vp->next = vps; vps = vp;
   } else {
	   aaa_session_id[0] = 0;
	   if (relocation || creditSessionAction >= 2) {
		   // can not get valid AAA-Session-ID, throw error
		   TRACE_ERROR("tRadius_accessRq on %s: can not get valid AAA-Session-ID\n",aNai);
		   return -1;
	   }
   }

   // 18/09/2008,EmA: handle Service-Type attribute for Wimax
   // It should be decorrelated from any particular AuthType
   if (creditSessionAction >= 2) {
	   TRACE_TRAFIC("tRadius_accessRq on %s (%s)\n", aNai, (tUserGetAAASessionIdLength(aUser) ? "with AAASessId" : "NULL") );
       TRACE_TRAFIC("\tauthType = %d, AuthorizeOnly, creditSessionAction = %d, relocation = %d\n",authType,creditSessionAction,relocation);
	   vp = pairmake("Service-Type", ServiceType_AuthorizeOnly, 0); vp->next = vps; vps = vp;
   } else if (creditSessionAction != 1 && aaa_session_id[0]) {
//   } else if (aaa_session_id[0]) {
	   TRACE_TRAFIC("tRadius_accessRq on %s (%s)\n", aNai, (tUserGetAAASessionIdLength(aUser) ? "with AAASessId" : "NULL") );
       TRACE_TRAFIC("\tauthType = %d, AuthenticateOnly, creditSessionAction = %d, relocation = %d\n",authType,creditSessionAction,relocation);
       // RHL, Oct 22, 2008; Add the condition creditSessionAction != 1  to avoid the error 
	   // when Termination failed and then no Initial case calling this user next time
       vp = pairmake("Service-Type", ServiceType_AuthenticateOnly, 0); vp->next = vps; vps = vp;
   } else {
	   vp = pairmake("Service-Type", ServiceType_Framed, 0); vp->next = vps; vps = vp;
   }

   // password
   if ( waitFor == WAIT_FOR_ACK ) {
	  aPasswd = ( authType == AUTHTYPE_OTP ? aUser->cmdRes->base : tUserGetPasswd(aUser) );
   } else
	  aPasswd = wrongPasswd;
   
   switch (authType) {
	  case AUTHTYPE_SIP_CHAP:
		 // Add a CHAP-Challenge once on two
		 if (id % 2) {
			// TODO; temporary PATH because MAS1.01.01.04 does not support CHAP whitout CHAP-Challenge attribute
			vp = pairmake("CHAP-Challenge", aNai, 0);	// took aNai as challenge
			vp->next = vps; vps = vp;
		 }
		 
		 // Encrypt the CHAP-Password attribute
		 vp = pairmake("CHAP-Password", aPasswd, 0);
		 vp->next = vps; vps = vp;
		 req->vps = vps;
		 
		 rad_chap_encode(req, (char *)vp->strvalue, req->id, vp);
		 vp->length = 17;
		 break;
	  
	  case AUTHTYPE_DIGEST:
		 // Encrypt the Digest-Response and Digest-Atributes(Body-Digest) attributes if necessary.
		 req->vps = vps;
		 
		 if ( !rad_http_encode(req, aNai, aPasswd) ) {
			TRACE_ERROR("tRadius_accessRq on %s: bad HTTP Digest parameters\n", aNai);
			return -1;
		 }
		 break;
	  
	  case AUTHTYPE_OTP:
	  case AUTHTYPE_PAP:
		 // Encrypt the Password attribute
		 vp = pairmake("Password", aPasswd, 0);
		 vp->next = vps; vps = vp;
		 break;
	  
	  case AUTHTYPE_EAPSIM:
   		 // same params for all users
		 vp = pairmake("EAP-Code", "Response", 0); vp->next = vps; vps = vp;
         sprintf(buf, "%d", req->id);
         vp = pairmake("EAP-Id", buf, 0); vp->next = vps; vps = vp;
		 vp = pairmake("Message-Authenticator", 0, 0); vp->next = vps; vps = vp;
		 if ( waitFor == WAIT_FOR_ACK ) {
   			// good authentication
			vp = pairmake("EAP-Sim-Sres1", EAPSIM_SRES1, 0); vp->next = vps; vps = vp;
		 } else {
			// bad authentication
			vp = pairmake("EAP-Sim-Sres1", EAPSIM_SRES1_BAD, 0); vp->next = vps; vps = vp;
		 }
         vp = pairmake("EAP-Sim-KC1", EAPSIM_KC1, 0); vp->next = vps; vps = vp;
         if (sameUserPasswd) {
             vp = pairmake("EAP-Sim-Sres2", EAPSIM_SRES1, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-Sres3", EAPSIM_SRES1, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-KC2", EAPSIM_KC1, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-KC3", EAPSIM_KC1, 0); vp->next = vps; vps = vp;
         } else {
             vp = pairmake("EAP-Sim-Sres2", EAPSIM_SRES2, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-Sres3", EAPSIM_SRES3, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-KC2", EAPSIM_KC2, 0); vp->next = vps; vps = vp;
             vp = pairmake("EAP-Sim-KC3", EAPSIM_KC3, 0); vp->next = vps; vps = vp;
         }
		 
		 // add IMSI of user
		 vp = pairmake("EAP-Type-Identity", (fastid[0] ? fastid : aNai), 0);
//		 vp = pairmake("EAP-Type-Identity", tUserGetIMSI(aUser), 0);
		 vp->next = vps; vps = vp;


		 //add wimax vsa according to action types
		/* RHL,9/16/2008, It will put the Wimax VSA value for SIM*/
		TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for SIM start\n", aNai);
		VALUE_PAIR *vps_return = putWimaxVSA(vps,aUser,authType,creditSessionAction);
		if( vps_return == NULL){
			TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for SIM failed!\n", aNai);
			rad_free(&req);
			return -1;
		}
		vps = vps_return;
		TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for SIM end\n", aNai);
		
		 break;

	  case AUTHTYPE_EAPAKA:
   		 // same params for all users
 
		 vp = pairmake("EAP-Code", "Response", 0); vp->next = vps; vps = vp;
         sprintf(buf, "%d", req->id);
         vp = pairmake("EAP-Id", buf, 0); vp->next = vps; vps = vp;
		 vp = pairmake("Message-Authenticator", 0, 0); vp->next = vps; vps = vp;

        //add eap-type: AKA=23
		 vp = pairmake("EAP-Type", "23", 0); vp->next = vps; vps = vp;

		 if ( waitFor == WAIT_FOR_ACK ) {
   			// good authentication
  	 
			vp = pairmake("EAP-AKA-RES", EAPAKA_RES, 0); vp->next = vps; vps = vp;

		 } else {
			// bad authentication
			vp = pairmake("EAP-AKA-RES", EAPAKA_RES_BAD, 0); vp->next = vps; vps = vp;
		 }

         vp = pairmake("EAP-AKA-AUTN", EAPAKA_AUTN, 0); vp->next = vps; vps = vp;
         vp = pairmake("EAP-AKA-IK", EAPAKA_IK, 0); vp->next = vps; vps = vp;
          
         vp = pairmake("EAP-AKA-CK", EAPAKA_CK, 0); vp->next = vps; vps = vp;
         //vp = pairmake("EAP-AKA-RAND", EAPAKA_RAND, 0); vp->next = vps; vps = vp;
        	
		 // add IMSI of user
		 vp = pairmake("EAP-Type-Identity", (fastid[0] ? fastid : aNai), 0);
//		 vp = pairmake("EAP-Type-Identity", tUserGetIMSI(aUser), 0);
		 vp->next = vps; vps = vp;
		 
		 /* RHL,9/16/2008, It will put the Wimax VSA value for AKA*/
		TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for AKA start\n", aNai);
		VALUE_PAIR *vps_return_aka = putWimaxVSA(vps,aUser,authType,creditSessionAction);
		if( vps_return_aka == NULL){
			TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for AKA failed!\n", aNai);
			rad_free(&req);
			return -1;
		}
		vps = vps_return_aka;
		TRACE_DEBUG("tRadius_accessRq on %s: put the WiMAX VSA for AKA end\n", aNai);
		
		 break;

	  case AUTHTYPE_NONE:
	  case AUTHTYPE_PROPRIETARY:
	  case AUTHTYPE_GPP_AKA:
	  default:
		 TRACE_ERROR("tRadius_accessRq on %s: wrong authentication type %s\n", aNai, authTypeName[authType] );
		 return -1;
		 break;
   }

   req->vps = vps;
   TRACE_TRAFIC("tRadius_accessRq: user=%s (%s), portnb=%d, authType=%s \n", aNai, (fastid[0] ? fastid : "NULL"), userId, authTypeName[authType] );
   // libradius debug already prints out the value pairs for us
   
   // Send paket and wait for response
//   if ( (authType == AUTHTYPE_EAPSIM || authType == AUTHTYPE_EAPAKA) ) {
// EmA,15/10/2008: apply this when FR SDMAAAFAG223113 will be solved
   if ( (authType == AUTHTYPE_EAPSIM || authType == AUTHTYPE_EAPAKA) && (creditSessionAction < 2) ) {
      tStatTimeBegin(1);
	  rc = sendrecv_eap(req, &rep, retries, aUser);
// EmA,18/08/2004: this is not multi-thread safe ! Must be done as soon as possible...
//	  id = req->id + 1;
      tStatTimeEnd(1);
   } else {
	  tStatRegulation( tThread_getKey() );
      tStatTimeBegin(0);
	  rc = send_packet(req, &rep, retries);
      tStatTimeEnd(0);
   }

   if (rc || !rep || (rep && rep->code == PW_AUTHENTICATION_REJECT) ) {
       // EmA,24/02/2006: if any auth trouble, delete FR id => full auth next time
       if (verbose >= 2) TRACE_TRAFIC("delete FRID in user=%s\n", tUserGetNAI(aUser));
       tUserSetFastAuthData(aUser, NULL, NULL);

	   // clear the related attrs in the session in order not impact running the same user next time
	   tUserSetAAASessionId(aUser, "", 0);	
	   tUserSetPPAQ(aUser, "", 0);
   }

   TRACE_DEBUG("tRadius_accessAccept: before analysis of attrs in response, rc = %d\n", rc);
//	 jzhao for tgen testing
   if (!rc && rep) {
	  // Add here analyse of response
	  if ( waitFor == WAIT_FOR_ACK && rep->code != PW_AUTHENTICATION_ACK )
		 rc = 1;
	  if ( waitFor == WAIT_FOR_RJ  && rep->code != PW_AUTHENTICATION_REJECT )
		 rc = 1;
   	  TRACE_DEBUG("tRadius_accessAccept: After analysis of response, rc = %d. \n", rc);
		
   	  // Memorisation of received attributes in case of awaited success
	  if ( waitFor == WAIT_FOR_ACK && rep->code == PW_AUTHENTICATION_ACK ) {

		 //
		 // Class attribute
		 //
		 if ((vp = pairfind(rep->vps, PW_CLASS)) != NULL) {
			// TRACE_TRAFIC("tRadius_accessAccept: nai=%s class=%s\n", aNai, (char *)vp->strvalue);
			tUserSetClassAttrib(aUser, (char *)vp->strvalue, vp->length, actionFlags->relocation);
		 } else {
			if (verbose >= 2)
				TRACE_ERROR("tRadius_accessAccept on %s: no Class attribute found\n", aNai);
		    tUserSetClassAttrib(aUser, "", 0, actionFlags->relocation);
			if (creditSessionAction == 0)		// to be remove after FR SDMAAAFAG221895 is corrected
				rc = 1;
		 }
   	     TRACE_DEBUG("tRadius_accessAccept: After analysis of Class attribute, rc = %d\n", rc);
		 
		 //
		 // Session-Timeout attribute
		 //
		 if ((vp = pairfind(rep->vps, PW_SESSION_TIMEOUT)) != NULL) {
			// TRACE_TRAFIC("tRadius_accessAccept: nai=%s sessionTimeout=%d\n", aNai, vp->lvalue);
            ;
			//tUserSetSessionTimeout(aUser, vp->lvalue);
		 } else {
			if (verbose >= 2)
			   TRACE_ERROR("tRadius_accessAccept on %s: no Session-Timeout attribute found\n", aNai);
			//EmA,14/09/2010, PAP ne passe plus !
			// rc = 1;
		 }
		 TRACE_DEBUG("tRadius_accessAccept: After analysis of Session-Timeout attribute, rc = %d\n", rc);
		 
/* EmA,25/05/2007: Session-Id is not given by server but generated on Client at AcctStart time
	In case of Radius Re-Authentication, take the same one as previous session.
		 //
		 // Session-Id attribute
		 //
		 if ((vp = pairfind(rep->vps, PW_ACCT_SESSION_ID)) != NULL) {
			// TRACE_TRAFIC("tRadius_accessAccept: nai=%s sessionId=%d\n", aNai, vp->lvalue);
			tUserSetSessionId(aUser, (char *)vp->lvalue, vp->length, actionFlags->relocation);
		 } else {
			if (verbose >= 3)
			   TRACE_TRAFIC("tRadius_accessAccept on %s: no Session-Id attribute found\n", aNai);
			tUserSetSessionId(aUser, "", 0, actionFlags->relocation);	// Important: to avoid using the same Session-Id all the time
         											// (a new one will then be allocated at Acct-Start)
		 }
*/

		 //
		 // State attribute if Terminate-Action==RADIUS-Request
		 //
		 if ( ( (vp = pairfind(rep->vps, PW_TERMINATE_ACTION)) != NULL && vp->lvalue==1 )
              && (vp = pairfind(rep->vps, PW_STATE)) != NULL                                ) {
            // TRACE_TRAFIC("tRadius_accessAccept: nai=%s class=%s\n", aNai, (char *)vp->strvalue);
            tUserSetStateAttrib(aUser, (char *)vp->strvalue, vp->length, actionFlags->relocation);
         } else {
            if (verbose >= 2)
               TRACE_ERROR("tRadius_accessAccept on %s: no State attribute found\n", aNai);
            tUserSetStateAttrib(aUser, "", 0, actionFlags->relocation);
			// 18/09/2008,EmA: Support of usual Radius re-authentication. This is not mandatory and not used in Wimax => do not stop with error
			//rc = 1;
         }
		 TRACE_DEBUG("tRadius_accessAccept: After analysis of State attribute, rc = %d\n", rc);
		 
		 
		 //
		 // AAA-Session-ID attribute
		 //
		 if ((vp = pairfind(rep->vps, PW_AAA_SESSION_ID)) != NULL) {
			 //TRACE_TRAFIC("tRadius_accessAccept: nai=%s, AAA-Session-ID(%02x)=%02x \n", aNai,PW_AAA_SESSION_ID, (unsigned char *)vp->strvalue);
			 if ( tUserGetAAASessionIdLength(aUser) && strcmp(tUserGetAAASessionId(aUser), (char *)vp->strvalue)!=0 ) {
				 // there was already a different AAA-Sess-Id stored
				 // can not get valid AAA-Session-ID, throw error
				 char buf1[32];
				 char buf2[32];
				 strncpy(buf1, (char *)vp->strvalue, vp->length);
				 strncpy(buf2, tUserGetAAASessionId(aUser), tUserGetAAASessionIdLength(aUser));
				 TRACE_ERROR("tRadius_accessRq on %s: received AAA-Session-ID=%s differs from precedently stored one=%s\n", aNai, buf1, buf2 );
				 // go on with new value...
				 //return -1;
			 }
			 tUserSetAAASessionId(aUser, (char *)vp->strvalue, vp->length);

		 } else {
			 tUserSetAAASessionId(aUser, "", 0);
			 if (creditSessionAction == 1 || creditSessionAction == 2) {
//			if (verbose >= 2)
				TRACE_ERROR("tRadius_accessAccept on %s: no awaited AAA-Session-ID attribute found\n", aNai);
//  			 if (creditSessionAction == 1)
				rc = 1;
			 }
		 }
		 TRACE_DEBUG("tRadius_accessAccept: After analysis of AAA-Session-ID attribute, rc = %d \n", rc);

		 if (creditSessionAction == 1 || creditSessionAction == 2) {
			//
			// PPAQ attribute
			//
			if ((vp = pairfind(rep->vps, PW_PPAQ)) != NULL) {
				//TRACE_TRAFIC("tRadius_accessAccept: nai=%s, PPAQ(%02x)=%s\n", aNai, PW_PPAQ, (unsigned char *)vp->strvalue);
				tUserSetPPAQ(aUser, (char *)vp->strvalue, vp->length);
			} else {
				tUserSetPPAQ(aUser, "", 0);	
//				if (verbose >= 2)
					TRACE_ERROR("tRadius_accessAccept on %s: no awaited PPAQ attribute found when creditSessionAction is %d\n", aNai,creditSessionAction);
				rc = 1;
		    }
			TRACE_DEBUG("tRadius_accessAccept: After analysis of PPAQ attribute, rc = %d\n", rc);
		 }

	 
	  }
   }

   // end of Wimax session (prepaid case only)
   if (creditSessionAction == 3) {
	   // clear the related attrs in the session in order not impact running the same user next time
	   tUserSetAAASessionId(aUser, "", 0);	
	   tUserSetPPAQ(aUser, "", 0);
   }

   TRACE_DEBUG("tRadius_accessAccept: at last, rc = %d \n", rc);
	  
   if (rc && (!quietOnError)) {
       if (fastid[0])
           sprintf(vpBuffer,"User-Name=%s, FastId=%s [%s]", aNai, fastid, authTypeName[authType]);
       else
           sprintf(vpBuffer,"User-Name=%s, Password=%s [%s]", aNai, aPasswd, authTypeName[authType]);

       TRACE_ERROR("tRadius_accessRq: unexpected result to %s\n", vpBuffer);
        
       if (rep) {
          TRACE_ERROR("\tReceived response ID=%d, code=%d, length=%d\n", rep->id, rep->code, rep->data_len);
		  //EmA,27/10/2008: due to PPAQ missing tgen.log is too big after dozen of hours of traffic
          if (verbose >= 2) vp_printlist(stderr, rep->vps);
       } else {
          TRACE_ERROR("\tNo response received after %d attemps\n", tcRadiusRetries);
       }
   }
   
   // Change socket to avoid to get the message the next time the socket is readed
   // Otherwise, message "Received authentication reply packet from 172.25.205.185 with invalid signature!" appears
   if (*retries)
	  tRadius_abandon();
   
   // free msgs memory
   if (rep) rad_free(&rep);
   rad_free(&req);
   
   return rc;
}

/******************************************************************************/
int tRadius_accountRq(int       	  sockFd,
                      int *			  retries,
                      tUser *    	  aUser,
                      int			  statusType,
/* statusType =	  RADIUS_AccountStart_Rq,
				  RADIUS_AccountInterim_Rq,
				  RADIUS_AccountStop_Rq,
				  RADIUS_AccountOn_Rq,
				  RADIUS_AccountOff_Rq,*/
					  tActionFlags *  actionFlags)
/******************************************************************************/
{
RADIUS_PACKET   *req;
RADIUS_PACKET   *rep = NULL;
VALUE_PAIR	    *vp;
VALUE_PAIR	    *vps = NULL;
int             temp, rc, i;
char            vpBuffer[1024] = "\0";
char *          p;
char *    		aNai = tUserGetNAI(aUser);
char *			aPasswd;
static unsigned char	id = 127;
static unsigned int		sessionId = 0;
char			nasIdString[32];
int             userId;
   
//EmA,25/04/2006: viewing User0 Radius activity
//   if (verbose >= 2 || (aUser->priv.id == 0) ) {
   if (verbose >= 2)
	  TRACE_TRAFIC("tRadius_accountRq on %s\n", aNai);
   
   if ((req = rad_alloc(1)) == NULL) {
	 librad_perror("tgen: tradius: rad_alloc: ");
	 return -1;
   }
   
   // unchanged fields
   req->code = PW_ACCOUNTING_REQUEST; 
   req->dst_port = (tcServerRADIUSPort+1);
   req->dst_ipaddr = ip_addr(tcServerHost[tcActiveServerId]);
   req->sockfd = sockFd;
   
   // fields modified at each request
   // EmA,03/11/2005: mutex is mandatory to guaranty not twice the same couple (id,RA) !!!
   pthread_mutex_lock(&radomMutex);
   req->id = (id++);
   random_vector(req->vector);
   pthread_mutex_unlock(&radomMutex);
   
   // attributes
   vps = pairmake("User-Name", aNai, 0);

// EmA,21/09/2004: do not use always the same Nas Id
//   vp = pairmake("NAS-IP-Address", RADIUS_CLIENT_NAS_IP_ADD, 0);
   userId = aUser->priv.id;
   temp = MIN( 255, (userId % tcRadiusNbNas) + 1); // NasId: from 1 to tcRadiusNbNas (<=255)
   TRACE_DEBUG("Acct debug, UserId=%d temp=%d\n", userId, temp );
   if (userId % 2) {
       sprintf(nasIdString, "%s%d", tcRadiusNasIdBase[ (actionFlags->relocation ? 1 : 0) ], temp);
       vp = pairmake("NAS-Identifier", nasIdString, 0);
   } else {
       sprintf(nasIdString, "%s%d", tcRadiusNasIpAddBase[ (actionFlags->relocation ? 1 : 0) ], temp);
       vp = pairmake("NAS-IP-Address", nasIdString, 0);
   }
   vp->next = vps; vps = vp;

   vp = pairmake("Called-Station-Id", "serv1.operator.com", 0);
   vp->next = vps; vps = vp;

   if (tcRadiusCallingStId[0]) {
		sprintf(nasIdString, tcRadiusCallingStId, temp, 255 - temp );
		vp = pairmake("Calling-Station-Id", nasIdString, 0);
		vp->next = vps; vps = vp;
   }

   vp = pairmake("Acct-Status-Type", acctStatusTypeName[statusType-RADIUS_AccountStart_Rq], 0);
   vp->next = vps; vps = vp;

   if ( tUserGetClassAttribLength(aUser, actionFlags->relocation) ) {
      // EmA,07/04/2005: do not trust "pairmake" function for binary sequence types: 2 bugs inside when
      //    - sequence contains null chars
      //    - sequence starts by '0x' sequence
      vp = pairmake("Class", "", 0);
      vp->length = tUserGetClassAttribLength(aUser, actionFlags->relocation);
	  memcpy(vp->strvalue, tUserGetClassAttrib(aUser, actionFlags->relocation), vp->length );  // strvalue already allocated
      vp->next = vps; vps = vp;
   }
   
   // EmA,25/05/2007: AcctStart must always regenerates Session-Id
   // EmA,24/10/2208: no true anymore with Wimax prepaid: additional criteria is Beginning-Of-Session==true
   if ( tUserGetSessionIdLength(aUser, actionFlags->relocation) && statusType!=RADIUS_AccountStart_Rq ) {
      // EmA,07/04/2005: do not trust "pairmake" function for binary sequence types: 2 bugs inside when
      //    - sequence contains null chars
      //    - sequence starts by '0x' sequence
      vp = pairmake("Acct-Session-Id", "", 0);
      vp->length = tUserGetSessionIdLength(aUser, actionFlags->relocation);
      memcpy(vp->strvalue, tUserGetSessionId(aUser, actionFlags->relocation), vp->length );  // strvalue already allocated
      vp->next = vps; vps = vp;
		
   } else {
	   if (tcRadiusSessIdBinary) {
		   vp = pairmake("Acct-Session-Id", "", 0);
		   vp->length = AUTH_VECTOR_LEN;
		   memcpy(vp->strvalue, req->vector, AUTH_VECTOR_LEN );  // strvalue already allocated
		   vp->next = vps; vps = vp;

	 /* EmA: check the sent SessionId => to be compared with CDR one
		   char buftest[2*AUTH_VECTOR_LEN+1];
		   int m;
		   for (m=0; m<AUTH_VECTOR_LEN; m++) {
			   sprintf(&buftest[2*m], "%02X", (unsigned char)req->vector[m]);
		   }
		   buftest[2*AUTH_VECTOR_LEN] = 0;
		   TRACE_TRAFIC("Binary SessionId = 0x%s\n", buftest);
	 */
		   tUserSetSessionId(aUser, req->vector, AUTH_VECTOR_LEN, actionFlags->relocation);
		   
	   } else {
		  char buf[128];
		  char c;
		  char uniqueId[11];
		  int m;
	
		  // 10 octets are enough ?
		  for (m=0; m<5; m++) {
			  c = ( req->vector[m] ? req->vector[m] : 0xEA );
			  sprintf(uniqueId + 2*m, "%02X", (unsigned char)c);
		  }
		  uniqueId[10] = 0;
	
		  sprintf(buf, "Tgen%s_Session_%d", uniqueId, (sessionId++) );
		  vp = pairmake("Acct-Session-Id", buf, 0);
		  vp->next = vps; vps = vp;
	
		  tUserSetSessionId(aUser, buf, strlen(buf), actionFlags->relocation);
	   }
   }

   // EmA,18/09/2008: add WIMAX VSA
   if ( tUserGetAAASessionIdLength(aUser) ) {
	   char aaa_session_id[32];
	   copyVSAAttrValue((char*)aaa_session_id, tUserGetAAASessionId(aUser), tUserGetAAASessionIdLength(aUser));
	   TRACE_DEBUG("tRadius_accountRq on %s: adding AAA-Session-ID= %s \n", aNai, aaa_session_id);	 
	   vp = pairmake("AAA-Session-ID", aaa_session_id, 0); vp->next = vps; vps = vp;
   }

   if ( actionFlags->beginofsession == 0 ) {
	   vp = pairmake("Beginning-Of-Session", BeginningOfSession_false, 0); vp->next = vps; vps = vp;
   } else if ( actionFlags->beginofsession == 1 ) {
	   vp = pairmake("Beginning-Of-Session", BeginningOfSession_true, 0); vp->next = vps; vps = vp;
   }

   if ( actionFlags->sessioncontinue == 0 ) {
	   vp = pairmake("Session-Continue", SessionContinue_false, 0); vp->next = vps; vps = vp;
   } else if ( actionFlags->sessioncontinue == 1 ) {
	   vp = pairmake("Session-Continue", SessionContinue_true, 0); vp->next = vps; vps = vp;
   }


   if ( statusType==RADIUS_AccountOn_Rq || statusType==RADIUS_AccountOff_Rq )
   {
     int uid;

       // abort all user scenario that are attached to the same NasId
       for(uid = (userId%tcRadiusNbNas); uid<tcUserNb; uid+=tcRadiusNbNas)
           tUserAbort(uid);
   }
   else if ( statusType==RADIUS_AccountStop_Rq || statusType==RADIUS_AccountInterim_Rq )
   {
     int    sessionDuration;
     char   buf[64];

       sessionDuration = time(NULL) - tUserGetSessionStartTime(aUser, actionFlags->relocation);

       sprintf(buf, "%d", sessionDuration);
       vp = pairmake("Acct-Session-Time", buf, 0);
       vp->next = vps; vps = vp;

       if (userId % 2) {
           sprintf(buf, "%d", sessionDuration*2048);
           vp = pairmake("Acct-Input-Octets", buf, 0);
           vp->next = vps; vps = vp;
    
           sprintf(buf, "%d", sessionDuration*1024);
           vp = pairmake("Acct-Output-Octets", buf, 0);
           vp->next = vps; vps = vp;

           vp = pairmake("Acct-Terminate-Cause", "User-Request", 0);
           vp->next = vps; vps = vp;

       } else {
           sprintf(buf, "%d", sessionDuration*50);
           vp = pairmake("Acct-Input-Packets", buf, 0);
           vp->next = vps; vps = vp;
    
           sprintf(buf, "%d", sessionDuration*30);
           vp = pairmake("Acct-Output-Packets", buf, 0);
           vp->next = vps; vps = vp;

           vp = pairmake("Acct-Terminate-Cause", "Lost-Service", 0);
           vp->next = vps; vps = vp;

       }
   }

   if ( statusType==RADIUS_AccountStop_Rq ) {
       // remove the State attribute from the user ctx if present: Re-authentication is not possible anymore after Acct-Stop !
       tUserSetStateAttrib(aUser, "", 0, actionFlags->relocation);

	   if (actionFlags->sessioncontinue != 1) {
		   // If nothing defined in scenario or SessionContinue=false => end of Wimax session
		   tUserSetAAASessionId(aUser, "", 0);	
		   tUserSetPPAQ(aUser, "", 0);
	   }
   }

   req->vps = vps;
   // Send paket and wait for response
   if (tcRadiusSessIdBinary) {
	   TRACE_TRAFIC("tRadius_accountRq: user=%s, statusType=%s \n", aNai, acctStatusTypeName[statusType-RADIUS_AccountStart_Rq]);
   } else {
	   TRACE_TRAFIC("tRadius_accountRq: user=%s, sessionId=%s, statusType=%s \n", aNai, tUserGetSessionId(aUser, actionFlags->relocation), acctStatusTypeName[statusType-RADIUS_AccountStart_Rq]);
   }
   // libradius debug already prints out the value pairs for us
   tStatTimeBegin(0);
   rc = send_packet(req, &rep, retries);
   tStatTimeEnd(0);




   if (rc || !rep || (rep && rep->code == PW_AUTHENTICATION_REJECT) ) {
       // EmA,24/02/2006: if any auth trouble, delete FR id => full auth next time
       if (verbose >= 2) TRACE_TRAFIC("delete FRID in user=%s\n", tUserGetNAI(aUser));
       tUserSetFastAuthData(aUser, NULL, NULL);

	   // clear the related attrs in the session in order not impact running the same user next time
	   tUserSetAAASessionId(aUser, "", 0);	
	   tUserSetPPAQ(aUser, "", 0);
   }





   if (!rc && rep) {
	  // Add here analyse of response
	  if ( rep->code != PW_ACCOUNTING_RESPONSE ) {
		  TRACE_ERROR("tRadius_accountRq on %s: unexpected code received (%d)\n", aNai, rep->code);
		  rc = 1;
	  }
   }
	  
   if (rc && (!quietOnError)) {
	  TRACE_ERROR("tRadius_accountRq on %s: unexpected result\n", aNai);
	  
	  if (rep) {
		  TRACE_ERROR("\tReceived response ID=%d, code=%d, length=%d\n", rep->id, rep->code, rep->data_len);
		  vp_printlist(stderr, rep->vps);
	  } else {
		  if (tcRadiusSessIdBinary) {
			  sprintf(vpBuffer,"User-Name=%s", aNai);
		  } else {
			  sprintf(vpBuffer,"User-Name=%s, SessionId=%s", aNai, tUserGetSessionId(aUser, actionFlags->relocation));
		  }
		  TRACE_ERROR("\tReceived no response after %d attemps to: %s\n", tcRadiusRetries, vpBuffer );
	  }
   }
   
   // Change socket to avoid to get the message the next time the socket is readed
   // Otherwise, message "Received authentication reply packet from 172.25.205.185 with invalid signature!" appears
// EmA,16/11/2007: performance side effect ?
//   if (*retries) tRadius_abandon();
   
   // free msgs memory
   if (rep) rad_free(&rep);
   rad_free(&req);
   
   return rc;
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// ADAPTED FROM RADCLIENT.C
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/************************************************************************************/
static int send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep, int *retries)
/************************************************************************************/
{
int                 i, rc=0;
VALUE_PAIR	        *vp;
int					rcsock;
fd_set				rdfdesc;
struct timeval		tv;

struct timeval  now;
struct timezone tz;
struct timespec expirationTime;


	for (i = 0; i < tcRadiusRetries; i++) {

		FD_ZERO(&rdfdesc);
		FD_SET(req->sockfd, &rdfdesc);

        while ( rad_send(req, NULL, secret) < 0 ) {
			 librad_perror("sendto: ");
			 TRACE_ERROR("bad sendto with UserName=%s\n", (char *)vp->strvalue);
		}

        /* And wait for reply, timing out as necessary */
        tv.tv_sec = tcRadiusTimeout;
        tv.tv_usec = 0;

wait_again:
        /* Something's wrong if we don't get exactly one fd. */
		rcsock = select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv);

        if ( rcsock < 0 ) {
			// error on socket
			librad_perror("select: ");
			continue;		// try to send again

		} else if ( rcsock == 0 ) {
			// timeout
//			if (verbose >= 2) {
				TRACE_TRAFIC("timeout on request packet Id=%d, retry=%d, sockfd=%d\n", (unsigned char)req->id, i, req->sockfd);
				if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
				   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
				}
//			}
            continue;		// try to send again

		} else if ( rcsock > 1 ) {
            // more than one descriptor set : print msg and go on
			TRACE_TRAFIC("select(rc=%d): more than one descriptor set on request packet Id=%d, Code=%d\n", rcsock, (unsigned char)req->id, (unsigned char)req->code);
			if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
			   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
			}

			if (verbose >= 2) {
				int j;
				for (j=0; j<=(req->sockfd+1); j++) {
					if ( FD_ISSET(j, &rdfdesc) )
						TRACE_TRAFIC("descriptor %d is set\n", j);
				}
			}
        }
		// one or several packets has been received on the right descriptor

		// check id
		while ( (*rep = rad_recv(req->sockfd)) && ((unsigned char)(*rep)->id != (unsigned char)req->id) ) {
			// response packet Id doesn't match with request one: drop response
			TRACE_TRAFIC("Response packet Id (%d) doesn't match with request one (%d), drop and read again \n", (unsigned char)(*rep)->id, (unsigned char)req->id);
			if (verbose >= 2) {
				TRACE_DEBUG("==> Sent request ID=%d, code=%d, length=%d\n", req->id, req->code, req->data_len);
				vp_printlist(stderr, req->vps);
				TRACE_DEBUG("==> Received response ID=%d, code=%d, length=%d\n", (*rep)->id, (*rep)->code, (*rep)->data_len);
				if ( rad_decode(*rep, req, secret) && !quietOnError) {
					librad_perror("tgen: tradius: rad_decode: ");
				}	
				vp_printlist(stderr, (*rep)->vps);
			}
			if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
			   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
			}
			rad_free(rep);
			*rep = NULL;
		}

        if (*rep)
   			// response packet is accepted
           	break;
        else {
			// all packets are bad: wait again until end of timeout
            if (!quietOnError) {
            	librad_perror("tgen: tradius: rad_recv: ");
            	rc = 1;
            }
			goto wait_again;
        }
    }

#ifdef _ASYNCHRONE_RADIUS_

/************************************************************************************/
static int send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep, int *retries)
/************************************************************************************/
{
int             i, rc=0;
VALUE_PAIR	    *vp;
struct timeval  now;
struct timezone tz;
struct timespec expirationTime;
pthread_mutex_t *mutex = tThread_getMutex(tThread_getKey());
pthread_cond_t  *cond = tThread_getCond(tThread_getKey());


	gettimeofday(&now, &tz);
	expirationTime.tv_sec  = now.tv_sec  + tcRadiusTimeout;
	expirationTime.tv_nsec = now.tv_usec * 1000;

// EmA,14/06/04: time mesures are done outside of this function because of EapSim 3-requests
//    tStatTimeBegin();

	pthread_mutex_lock(mutex);

	for (i = 0; i < tcRadiusRetries; i++)
	{
        rad_send(req, NULL, secret);

read_again:

//		if ( !tSelectIsFdSet(req->sockfd) ) {
			// not yet received; need to wait
			if (verbose2) fprintf(stderr, "tradius: wait response...\n");

			rc = pthread_cond_timedwait( cond, mutex, &expirationTime);
			if (rc == ETIMEDOUT) {
				if (verbose2) fprintf(stderr, "tradius: timeout!\n");
	
				expirationTime.tv_sec  += tcRadiusTimeout;
				continue;
			} else if (rc) {
				perror("tradius: pthread_cond_timedwait");
				continue;
			}
//		}

		if (verbose2) fprintf(stderr, "tradius: signal received\n");
		// several packets received ???

		// normal case: one response in time
		*rep = NULL;
//		if ( tSelectIsFdSet(req->sockfd) ) 
			*rep = rad_recv(req->sockfd);

		if ( *rep && ((unsigned char)(*rep)->id != (unsigned char)req->id) ) {
			// response packet Id doesn't match with request one: drop response
			fprintf(stderr, "Response packet Id (%d) doesn't match with request one (%d), listen again\n", (unsigned char)(*rep)->id, (unsigned char)req->id);
			rad_free(rep);
			*rep = NULL;

			// do not restart the select delay !
			goto read_again;
		}

		if (*rep)
    			// response packet is accepted
           	break;
        else {
            /* NULL: couldn't receive the packet */
            if (!quietOnError) {
            	librad_perror("tradius: send_packet: ");
            	rc = 1;
            }
        }
	}

	pthread_mutex_unlock(mutex);
#endif


    *retries=i;

    if (!*rep) {
       // No response or no data read (?)
       rc = 1;
       
	 } else if ( (rad_decode(*rep, req, secret) != 0) && !quietOnError) {
       librad_perror("tgen: tradius: rad_decode: ");
       if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL)
          TRACE_ERROR("rad_decode: error on %s\n", (char *)vp->strvalue);
       rc = 1;
    }

    return rc;
}

/************************************************************************************/
static int send_packet_sync(RADIUS_PACKET *req, RADIUS_PACKET **rep, int *retries)
/************************************************************************************/
{
int                 i, rc=0;
VALUE_PAIR	        *vp;
int					rcsock;
fd_set				rdfdesc;
struct timeval		tv;


	for (i = 0; i < tcRadiusRetries; i++) {

		FD_ZERO(&rdfdesc);
		FD_SET(req->sockfd, &rdfdesc);

        while ( rad_send(req, NULL, secret) < 0 ) {
			 librad_perror("sendto: ");
			 TRACE_ERROR("bad sendto with UserName=%s\n", (char *)vp->strvalue);
		}

        /* And wait for reply, timing out as necessary */
        tv.tv_sec = tcRadiusTimeout;
        tv.tv_usec = 0;

wait_again:
        /* Something's wrong if we don't get exactly one fd. */
		rcsock = select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv);

        if ( rcsock < 0 ) {
			// error on socket
			librad_perror("select: ");
			continue;		// try to send again

		} else if ( rcsock == 0 ) {
			// timeout
//			if (verbose >= 2) {
				TRACE_TRAFIC("timeout on request packet Id=%d, retry=%d, sockfd=%d\n", (unsigned char)req->id, i, req->sockfd);
				if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
				   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
				}
//			}
            continue;		// try to send again

		} else if ( rcsock > 1 ) {
            // more than one descriptor set : print msg and go on
			TRACE_TRAFIC("select(rc=%d): more than one descriptor set on request packet Id=%d, Code=%d\n", rcsock, (unsigned char)req->id, (unsigned char)req->code);
			if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
			   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
			}

			if (verbose >= 2) {
				int j;
				for (j=0; j<=(req->sockfd+1); j++) {
					if ( FD_ISSET(j, &rdfdesc) )
						TRACE_TRAFIC("descriptor %d is set\n", j);
				}
			}
        }
		// one or several packets has been received on the right descriptor

		// check id
		while ( (*rep = rad_recv(req->sockfd)) && ((unsigned char)(*rep)->id != (unsigned char)req->id) ) {
			// response packet Id doesn't match with request one: drop response
			TRACE_TRAFIC("Response packet Id (%d) doesn't match with request one (%d), drop and read again \n", (unsigned char)(*rep)->id, (unsigned char)req->id);
			if (verbose >= 2) {
				TRACE_DEBUG("==> Sent request ID=%d, code=%d, length=%d\n", req->id, req->code, req->data_len);
				vp_printlist(stderr, req->vps);
				TRACE_DEBUG("==> Received response ID=%d, code=%d, length=%d\n", (*rep)->id, (*rep)->code, (*rep)->data_len);
				if ( rad_decode(*rep, req, secret) && !quietOnError) {
					librad_perror("tgen: tradius: rad_decode: ");
				}	
				vp_printlist(stderr, (*rep)->vps);
			}
			if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL) {
			   TRACE_TRAFIC("\t(UserName=%s)\n", (char *)vp->strvalue);
			}
			rad_free(rep);
			*rep = NULL;
		}

        if (*rep)
   			// response packet is accepted
           	break;
        else {
			// all packets are bad: wait again until end of timeout
            if (!quietOnError) {
            	librad_perror("tgen: tradius: rad_recv: ");
            	rc = 1;
            }
			goto wait_again;
        }
    }

    *retries=i;

    if (!*rep) {
       // No response or no data read (?)
       rc = 1;
       
	 } else if ( (rad_decode(*rep, req, secret) != 0) && !quietOnError) {
       librad_perror("tgen: tradius: rad_decode: ");
       if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL)
          TRACE_ERROR("rad_decode: error on %s\n", (char *)vp->strvalue);
       rc = 1;
    }

    return rc;
}


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// STRICTLY COPIED FROM RADCLIENT.C
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/************************************************************************************/
/*
 *	Create a random vector of AUTH_VECTOR_LEN bytes.
 */
static void random_vector(uint8_t *vector)
/************************************************************************************/
{
	int		i;
	static int	did_srand = 0;
	static int	counter = 0;

#ifdef FORCE_USING_SRAND_FUNCTION
//#ifdef __linux__
	static int	urandom_fd = -1;

	/*
	 *	Use /dev/urandom if available.
	 */
	if (urandom_fd > -2) {
		/*
		 *	Open urandom fd if not yet opened.
		 */
		if (urandom_fd < 0)
			urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd < 0) {
			/*
			 *	It's not there, don't try
			 *	it again.
			 */
			TRACE_ERROR("Cannot open /dev/urandom, using rand()\n");
			urandom_fd = -2;
		} else {

			fcntl(urandom_fd, F_SETFD, 1);

			/*
			 *	Read 16 bytes.
			 */
			if (read(urandom_fd, (char *) vector, AUTH_VECTOR_LEN)
			    == AUTH_VECTOR_LEN)
				return;
			/*
			 *	We didn't get 16 bytes - fall
			 *	back on rand) and don't try again.
			 */
			TRACE_ERROR("Read short packet from /dev/urandom, using rand()\n");
			urandom_fd = -2;
		}
	}
#endif

	if (!did_srand) {
		srand(time(NULL) + getpid());

		/*
		 *	Now that we have a bad random seed, let's
		 *	make it a little better by MD5'ing it.
		 */
		for (i = 0; i < (int)sizeof(random_vector_pool); i++) {
			random_vector_pool[i] += rand() & 0xff;
		}

		librad_md5_calc((u_char *) random_vector_pool,
				(u_char *) random_vector_pool,
				sizeof(random_vector_pool));

		did_srand = 1;
	}

	/*
	 *	Modify our random pool, based on the counter,
	 *	and put the resulting information through MD5,
	 *	so it's all mashed together.
	 */
	counter++;
	random_vector_pool[AUTH_VECTOR_LEN] += (counter & 0xff);
	librad_md5_calc((u_char *) random_vector_pool,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));

	/*
	 *	And do another MD5 hash of the result, to give
	 *	the user a random vector.  This ensures that the
	 *	user has a random vector, without giving them
	 *	an exact image of what's in the random pool.
	 */
	librad_md5_calc((u_char *) vector,
			(u_char *) random_vector_pool,
			sizeof(random_vector_pool));
}

/************************************************************************************/
static int	rad_http_encode(RADIUS_PACKET *req, char *user, char *passwd)
/*
Generate HTTP digest Access Request according to the following rules:

Chekings:
 - At least one Digest-Attributes-<subattr> must be present. Else nothing is done.
 - Mandatory subattributes must be present. Else nothing is done.

Actions:
 - Translate Digest-Attributes-<subattr> pairvalues containing string value in
   Digest-Attributes containing TLV triplet (cf Draft Sterman).
 - Consecutive Digest-Attributes-<subattr> are encapsulated as several subattributes
   of the same Digest-Attributes triplet.
 - Unconsecutive ones are encapsulated in different Digest-Attributes triplet.
 - if Digest-Response attribute is not present, generate it with MD5 algo.

Default values:
 - Realm, Uri ,Nonce and Method can be set by default in env variables:
 			RAD_HTTPDIGEST_<REALM | URI | METHOD | NONCE>
   These values are overwrited if the corresponding Attribute is present
   in the radclient cmdline.
   If NONCE env var is "auto", then its value is set to MD5(RequestAuthenticator)

Return values:
 - 0: CHAP to be used besause some HTTP Digest params are missing
 - 1: HTTP Digest is OK and used preferencially
 
 */
/************************************************************************************/
{
VALUE_PAIR 		*curvp = req->vps, *predvp, *newvp;
int				conseq = 0;
unsigned char	subattr[MAX_STRING_LEN];
int				strlength;
int				i, j;
char*				env;
unsigned char	bufmd5[HASHLEN + 1];

// For computation of Digest-Response
char				*params[PW_SUBATTRIBUTE_USERNAME + 1];		// we don't use params[0]
HASHHEX			HA1;
HASHHEX			request_digest;

/* In radius.h
#define PW_SUBATTRIBUTE_REALM				1      		// Mandatory
#define PW_SUBATTRIBUTE_NONCE				2      		// Mandatory
#define PW_SUBATTRIBUTE_METHOD			3      		// Mandatory
#define PW_SUBATTRIBUTE_URI				4      		// Mandatory
#define PW_SUBATTRIBUTE_QOP				5
#define PW_SUBATTRIBUTE_ALGORITHM		6
#define PW_SUBATTRIBUTE_BODYDIGEST		7
#define PW_SUBATTRIBUTE_CNONCE			8
#define PW_SUBATTRIBUTE_NONCECOUNT		9
#define PW_SUBATTRIBUTE_USERNAME			10   			// Mandatory
*/
   
   // Reset params[][]
   memset(params, 0, sizeof(params));
   
	while(curvp) {
		
		if ( (curvp->attribute >= (PW_DIGEST_ATTRIBUTES+PW_SUBATTRIBUTE_REALM) )			&&
			  (curvp->attribute <= (PW_DIGEST_ATTRIBUTES+PW_SUBATTRIBUTE_USERNAME) )    ) {
			  	
			// build subattribute string
			subattr[0] = curvp->attribute - PW_DIGEST_ATTRIBUTES;
			strlength = strlen(curvp->strvalue) + 2;       // 2 octets = (subattr type octet) + (subattr length octet)    ### NB: final '\0' octet not included
			if ( strlength >= MAX_STRING_LEN )
				subattr[1] = MAX_STRING_LEN-1;
			else
			   subattr[1] = strlength;
			strNcpy((char *)subattr + 2, (char *)curvp->strvalue, subattr[1] - 1);   // final '\0' octet is included here (but not counted in length)
			
//			TRACE_TRAFIC("subattribute read: T=%d L=%d V=%s\n", subattr[0], subattr[1], subattr + 2);

			// memorize each first subattribute string encountered for futur compute of Digest-Response
			if (!params[subattr[0]]) {
				params[subattr[0]] = (char *)malloc(subattr[1] - 1);
				strNcpy(params[subattr[0]], (char *)subattr + 2, subattr[1] - 1);
			}

			if (conseq && (predvp->length + subattr[1]) < MAX_STRING_LEN) {
				// concat current vp to precedant one
				predvp->length += subattr[1];
				strcat(predvp->strvalue, (char *)subattr);
								
				// destroy current vp
				predvp->next = curvp->next;
				free(curvp);
				
				// predvp unchanged
				curvp = predvp->next;

			} else {
				// build a new pairvalue
				newvp = pairmake("Digest-Attributes", (char *)subattr, curvp->operator);
				
				// insert it in chain instead of the old one
				predvp->next = newvp;
				newvp->next = curvp->next;
				free(curvp);
				
				predvp = newvp;
				curvp = predvp->next;
			}
			conseq = 1;
			
		} else {
			conseq = 0;
			predvp = curvp;
			curvp = predvp->next;
		}
	}
	
	// Condition to use HTTP-Digest authentication: Realm, Method and Uri
	// must be either in Digest-Attributes subattribute, either in setenv declaration
	// If one is missing, CHAP authentication will be used insteed.
	if (  ( !params[PW_SUBATTRIBUTE_REALM] 	&& !getenv(envvar[PW_SUBATTRIBUTE_REALM]) )	||
			( !params[PW_SUBATTRIBUTE_METHOD]	&& !getenv(envvar[PW_SUBATTRIBUTE_METHOD]) )	||
			( !params[PW_SUBATTRIBUTE_URI]		&& !getenv(envvar[PW_SUBATTRIBUTE_URI]) )		 )	{
		// free params and quit
		for (i=PW_SUBATTRIBUTE_REALM; i<=PW_SUBATTRIBUTE_USERNAME; i++)
			if (params[i])
				free(params[i]);
		return 0;
	}
			
	// set the default value if it is not set yet
	for (i=PW_SUBATTRIBUTE_REALM; i<=PW_SUBATTRIBUTE_USERNAME; i++) {
		if  (!params[i]) {
			// attribute is not in radclient cmdline list
			
			// user-name subattribute must be added if it doesn't exist yet
			if (i == PW_SUBATTRIBUTE_USERNAME)
				env = user;
			else
				env = getenv(envvar[i]);
			
		   // set the NONCE if it is not in Attribute nor in default env var
			if (i == PW_SUBATTRIBUTE_NONCE && !env) {
		   	librad_md5_calc(bufmd5, req->vector, sizeof(req->vector));
				// MD5 result may contain '\0' value: AVOID IT, because NONCE must be a string !!!
		   	for (j=0; j<HASHLEN; j++)
		   		if (!bufmd5[j]) bufmd5[j] = '*';
		   	env = (char *)bufmd5;
			}
			
			if ( env ) {
				// it has a default value to apply
//				TRACE_DEBUG("%s=%s default value applied\n", envvar[i], env);
				
				// build subattribute string
				subattr[0] = i;
				strlength = strlen(env) + 2;       // 2 octets = (subattr type octet) + (subattr length octet)    ### NB: final '\0' octet not included
				if ( strlength >= MAX_STRING_LEN )
					subattr[1] = MAX_STRING_LEN-1;
				else
				   subattr[1] = strlength;
				strNcpy((char *)subattr + 2, (char *)env, subattr[1] - 1);   // final '\0' octet is included here (but not counted in length)
				
				// memorize subattribute string for futur compute of Digest-Response
				params[i] = (char *)malloc(subattr[1] - 1);
				strNcpy(params[i], (char *)subattr + 2, subattr[1] - 1);

				// build a new pairvalue and add it to chain
				newvp = pairmake("Digest-Attributes", (char *)subattr, NULL);
				newvp->next = req->vps;
				req->vps = newvp;
			}
		}
	}
   
   newvp = NULL;
   
	if (params[PW_SUBATTRIBUTE_USERNAME] && params[PW_SUBATTRIBUTE_REALM] &&
		 params[PW_SUBATTRIBUTE_NONCE] && params[PW_SUBATTRIBUTE_URI] && params[PW_SUBATTRIBUTE_METHOD]) {
		// Digest-Attributes have been found => must generate Digest-Response
		
		// Calculate H(A1)
		DigestCalcHA1(params[PW_SUBATTRIBUTE_ALGORITHM],
						  params[PW_SUBATTRIBUTE_USERNAME],
						  params[PW_SUBATTRIBUTE_REALM],
						  passwd,
						  params[PW_SUBATTRIBUTE_NONCE],
						  params[PW_SUBATTRIBUTE_CNONCE],
						  HA1);
		
		// Calculate request-digest
		DigestCalcResponse(HA1,
								 params[PW_SUBATTRIBUTE_NONCE],
								 params[PW_SUBATTRIBUTE_NONCECOUNT],
								 params[PW_SUBATTRIBUTE_CNONCE],
								 params[PW_SUBATTRIBUTE_QOP],
								 params[PW_SUBATTRIBUTE_METHOD],
								 params[PW_SUBATTRIBUTE_URI],
								 params[PW_SUBATTRIBUTE_BODYDIGEST],
								 request_digest);		

		// build a new pairvalue and add it to chain
		newvp = pairmake("Digest-Response", request_digest, NULL);
//    pairadd(&req->vps, vp);
		newvp->next = req->vps;
		req->vps = newvp;
	}

	// free params
	for (i=PW_SUBATTRIBUTE_REALM; i<=PW_SUBATTRIBUTE_USERNAME; i++)
		if (params[i])
			free(params[i]);
	
	return (newvp != NULL);
}

//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// ADAPTED FROM RADEAPCLIENT.C
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/************************************************************************************/
int radlog(int lvl, const char *msg, ...)
/************************************************************************************/
{
	va_list ap;
	int r;

	r = lvl; /* shut up compiler */

	va_start(ap, msg);
	r = vfprintf(stderr, msg, ap);
	va_end(ap);
	fputc('\n', stderr);

	return r;
}

/************************************************************************************/
static void cleanresp(RADIUS_PACKET *resp)
/************************************************************************************/
{
	VALUE_PAIR *vpnext, *vp, **last;


	/*
	 * maybe should just copy things we care about, or keep
	 * a copy of the original input and start from there again?
	 */
	pairdelete(&resp->vps, PW_EAP_MESSAGE);
	pairdelete(&resp->vps, ATTRIBUTE_EAP_BASE+PW_EAP_IDENTITY);
    // EmA,05/12/2005: next line avoid many pbs !!!
	pairdelete(&resp->vps, ATTRIBUTE_EAP_SIM_SUBTYPE);

	last = &resp->vps;
	for(vp = *last; vp != NULL; vp = vpnext)
	{
		vpnext = vp->next;

		if((vp->attribute > ATTRIBUTE_EAP_BASE &&
		    vp->attribute <= ATTRIBUTE_EAP_BASE+256) ||
		   (vp->attribute > ATTRIBUTE_EAP_SIM_BASE &&
		    vp->attribute <= ATTRIBUTE_EAP_SIM_BASE+256))
		{
			*last = vpnext;
			pairbasicfree(vp);
		} else {
			last = &vp->next;
		}
	}
}

/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Start message in a legal state.
 *
 * pick a supported version, put it into the reply, and insert a nonce.
 */
static int process_eap_start(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk)
/************************************************************************************/
{
	VALUE_PAIR *vp, *newvp;
	VALUE_PAIR *anyidreq_vp, *fullauthidreq_vp, *permanentidreq_vp;
	uint16_t *versions, selectedversion;
	unsigned int i,versioncount;

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	if((vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_VERSION_LIST)) == NULL) {
		TRACE_ERROR("illegal start message has no VERSION_LIST\n");
		return 0;
	}
	
	versions = (uint16_t *)vp->strvalue;

	/* verify that the attribute length is big enough for a length field */
	if(vp->length < 4)
	{
		TRACE_ERROR("start message has illegal VERSION_LIST. Too short: %d\n", vp->length);
		return 0;
	}

	versioncount = ntohs(versions[0]);
	/* verify that the attribute length is big enough for the given number
	 * of versions present.
	 */
// EmA,09/01/04: versioncount is already in Octets nb and not in Shorts nb
//	if((unsigned)vp->length <= (versioncount * sizeof(uint16_t) + 2))
	if((unsigned)vp->length <= (versioncount + 2))
	{
		TRACE_ERROR("start message is too short. Claimed %d versions does not fit in %d bytes\n", versioncount, vp->length);
		return 0;
	}

	/*
	 * record the versionlist for the MK calculation.
	 */
// EmA,09/01/04: versioncount is already in Octets nb and not in Shorts nb
//	eapsim_mk->versionlistlen = versioncount*2;
	eapsim_mk->versionlistlen = versioncount;
	memcpy(eapsim_mk->versionlist, (unsigned char *)(versions+1),
	       eapsim_mk->versionlistlen);

	/* walk the version list, and pick the one we support, which
	 * at present, is 1, EAP_SIM_VERSION.
	 */
	selectedversion=0;
	for(i=0; i < versioncount; i++)
	{
		if(ntohs(versions[i+1]) == EAP_SIM_VERSION)
		{
			selectedversion=EAP_SIM_VERSION;
			break;
		}
	}
	if(selectedversion == 0)
	{
		TRACE_ERROR("eap-sim start message. No compatible version found. We need %d\n", EAP_SIM_VERSION);
		for(i=0; i < versioncount; i++)
		{
			TRACE_ERROR("\tfound version %d\n",
				ntohs(versions[i+1]));
		}
	}
	
	/*
	 * now make sure that we have only FULLAUTH_ID_REQ.
	 * I think that it actually might not matter - we can answer in
	 * anyway we like, but it is illegal to have more than one
	 * present.
	 */
	anyidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ANY_ID_REQ);
	fullauthidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_FULLAUTH_ID_REQ);
	permanentidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_PERMANENT_ID_REQ);

// EmA,09/01/04: exclusive-OR between all kind of ID-REQ
	if ( (fullauthidreq_vp && anyidreq_vp) ||
		  (fullauthidreq_vp && permanentidreq_vp) ||
		  (anyidreq_vp && permanentidreq_vp) ) {
		TRACE_ERROR("start message has %sanyidreq, %sfullauthid and %spermanentid. Illegal combination.\n",
			(anyidreq_vp != NULL ? "a " : "no "),
			(fullauthidreq_vp != NULL ? "a " : "no "),
			(permanentidreq_vp != NULL ? "a " : "no "));
		return 0;
	}

	/* okay, we have just any_id_req there, so fill in response */

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_start;
	pairreplace(&(rep->vps), newvp);

	/* insert selected version into response. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_SELECTED_VERSION, PW_TYPE_OCTETS);
	versions = (uint16_t *)newvp->strvalue;
	versions[0] = htons(selectedversion);
	newvp->length = 2;
	pairreplace(&(rep->vps), newvp);

	/* record the selected version */
	memcpy(eapsim_mk->versionselect, (unsigned char *)versions, 2);

	vp = newvp = NULL;

	{
		uint32_t nonce[4];
		/*
		 * insert a nonce_mt that we make up.
		 */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT, PW_TYPE_OCTETS);
		newvp->strvalue[0]=0;
		newvp->strvalue[1]=0;
		newvp->length = 18;  /* 16 bytes of nonce + padding */
		
		nonce[0]=lrad_rand();
		nonce[1]=lrad_rand();
		nonce[2]=lrad_rand();
		nonce[3]=lrad_rand();
		memcpy(&newvp->strvalue[2], nonce, 16);
		pairreplace(&(rep->vps), newvp);

		/* also keep a copy of the nonce! */
		memcpy(eapsim_mk->nonce_mt, nonce, 16);
	}

	{
		uint16_t *pidlen, idlen;

		/*
		 * insert the identity here.
		 */
		vp = pairfind(rep->vps, PW_USER_NAME);
		if(vp == NULL)
		{
			TRACE_ERROR("eap-sim: We need to have a User-Name attribute!\n");
			return 0;
		}
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY, PW_TYPE_OCTETS);

//        if (strlen(eapid) == 0) {
            // insert User-Name if EAP-Sim-Identity not given
            idlen = strlen(vp->strvalue);
		    pidlen = (uint16_t *)newvp->strvalue;
		    *pidlen = htons(idlen);
		    newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], vp->strvalue, idlen);
/*        } else {
            // insert EAP-Sim-Identity if given
            idlen = strlen(eapid);
    		pidlen = (uint16_t *)newvp->strvalue;
    		*pidlen = htons(idlen);
    		newvp->length = idlen + 2;
    		memcpy(&newvp->strvalue[2], eapid, idlen);
        }*/
		pairreplace(&(rep->vps), newvp);

		/* record it */
        idlen = strlen(vp->strvalue);		
		memcpy(eapsim_mk->identity, vp->strvalue, idlen);
		eapsim_mk->identitylen = idlen;
	}

	return 1;
}
int process_eap_aka_authentication_reject(RADIUS_PACKET *req,
                                 RADIUS_PACKET *rep)
{
    VALUE_PAIR *newvp;

    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapaka_authentication_reject;
    pairreplace(&(rep->vps), newvp);
    return 1;
    
}


int process_eap_aka_synchronization_failure(RADIUS_PACKET *req,
                                 RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk)
{
    VALUE_PAIR *newvp;

    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapaka_synchronization_failure;
    pairreplace(&(rep->vps), newvp);
	
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_AUTS, PW_TYPE_OCTETS);
    memset(newvp->strvalue,0,2);
    memcpy(&newvp->strvalue[2],eapsim_mk->auts, EAP_AKA_AUTS_LEN);
    newvp->length = 2+EAP_AKA_AUTS_LEN;
    pairreplace(&(rep->vps), newvp);
    return 1;
    
}


/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Challenge message in a legal state.
 *
 * use the RAND challenge to produce the SRES result, and then
 * use that to generate a new MAC.
 *
 * for the moment, we ignore the RANDs, then just plug in the SRES
 * values.
 *
 */
 
/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Start message in a legal state.
 *
 * pick a supported version, put it into the reply, and insert a nonce.
 */
static int process_eap_aka_identity(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk)
/************************************************************************************/
{
	VALUE_PAIR *vp, *newvp;
	VALUE_PAIR *anyidreq_vp, *fullauthidreq_vp, *permanentidreq_vp;
	
	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	
	
	/*
	 * now make sure that we have only FULLAUTH_ID_REQ.
	 * I think that it actually might not matter - we can answer in
	 * anyway we like, but it is illegal to have more than one
	 * present.
	 */
	anyidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ANY_ID_REQ);
	fullauthidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_FULLAUTH_ID_REQ);
	permanentidreq_vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_PERMANENT_ID_REQ);

// EmA,09/01/04: exclusive-OR between all kind of ID-REQ
	if ( (fullauthidreq_vp && anyidreq_vp) ||
		  (fullauthidreq_vp && permanentidreq_vp) ||
		  (anyidreq_vp && permanentidreq_vp) ) {
		TRACE_ERROR("start message has %sanyidreq, %sfullauthid and %spermanentid. Illegal combination.\n",
			(anyidreq_vp != NULL ? "a " : "no "),
			(fullauthidreq_vp != NULL ? "a " : "no "),
			(permanentidreq_vp != NULL ? "a " : "no "));
		 estartNotif=0;
        return process_eap_clienterror( req, rep);
	}

	/* okay, we have just any_id_req there, so fill in response */

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapaka_identity;
	pairreplace(&(rep->vps), newvp);

	

	{
		uint16_t *pidlen, idlen;

		/*
		 * insert the identity here.
		 */
		vp = pairfind(rep->vps, PW_USER_NAME);
		if(vp == NULL)
		{
			TRACE_ERROR("eap-sim: We need to have a User-Name attribute!\n");
			return 0;
		}
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY, PW_TYPE_OCTETS);

//        if (strlen(eapid) == 0) {
            // insert User-Name if EAP-Sim-Identity not given
            idlen = strlen(vp->strvalue);
		    pidlen = (uint16_t *)newvp->strvalue;
		    *pidlen = htons(idlen);
		    newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], vp->strvalue, idlen);
/*        } else {
            // insert EAP-Sim-Identity if given
            idlen = strlen(eapid);
    		pidlen = (uint16_t *)newvp->strvalue;
    		*pidlen = htons(idlen);
    		newvp->length = idlen + 2;
    		memcpy(&newvp->strvalue[2], eapid, idlen);
        }*/
		pairreplace(&(rep->vps), newvp);

		/* record it */
      		
		memcpy(eapsim_mk->identity, &newvp->strvalue[2], idlen);
		eapsim_mk->identitylen = idlen;
	}

	return 1;
}

static int process_eap_challenge(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
VALUE_PAIR *newvp;
VALUE_PAIR *mac, *randvp;
VALUE_PAIR *sres1,*sres2,*sres3;
VALUE_PAIR *Kc1, *Kc2, *Kc3;
uint8_t calcmac[20];
uint16_t *encrData;
VALUE_PAIR *encr, *iv;
unsigned char decrypt[200];

	/* look for the AT_MAC and the challenge data */
	mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
	randvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND);
	if(mac == NULL || rand == NULL) {
		TRACE_ERROR("radeapclient: challenge message needs to contain RAND and MAC\n");
		return 0;
	}

    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        TRACE_ERROR("radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
		return 0;
    }

	/*
	 * XXX compare RAND with randX, to verify this is the right response
	 * to this challenge.
	 */

	/*
	 * now dig up the sres values from the response packet,
	 * which were put there when we read things in.
	 *
	 * Really, they should be calculated from the RAND!
	 *
	 */
	sres1 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_SRES1);
	sres2 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_SRES2);
	sres3 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_SRES3);

	if(sres1 == NULL ||
	   sres2 == NULL ||
	   sres3 == NULL) {
		TRACE_ERROR("radeapclient: needs to have sres1, 2 and 3 set.\n");
		return 0;
	}
	memcpy(eapsim_mk->sres[0], sres1->strvalue, EAPSIM_SRES_SIZE);
	memcpy(eapsim_mk->sres[1], sres2->strvalue, EAPSIM_SRES_SIZE);
	memcpy(eapsim_mk->sres[2], sres3->strvalue, EAPSIM_SRES_SIZE);

	Kc1 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC1);
	Kc2 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC2);
	Kc3 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC3);
	
	if(Kc1 == NULL ||
	   Kc2 == NULL ||
	   Kc3 == NULL) {
		TRACE_ERROR("radeapclient: needs to have Kc1, 2 and 3 set.\n");
		return 0;
	}
	memcpy(eapsim_mk->Kc[0], Kc1->strvalue, EAPSIM_Kc_SIZE);
	memcpy(eapsim_mk->Kc[1], Kc2->strvalue, EAPSIM_Kc_SIZE);
	memcpy(eapsim_mk->Kc[2], Kc3->strvalue, EAPSIM_Kc_SIZE);

	/* all set, calculate keys */
	eapsim_calculate_keys(eapsim_mk);


    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys 
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    FILE *fp;
    if ((fp = fopen( nom, "w")) == NULL)
        TRACE_ERROR("Pb for opening ${PATH_RESULT}/.tmpKeys");
    if ((fwrite(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fwrite(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        TRACE_ERROR("Pb for writing in ${PATH_RESULT}/.tmpKeys");
     fclose(fp);                                                */

	if (librad_debug) eapsim_dump_mk(eapsim_mk);

	/* verify the MAC, now that we have all the keys. */
	if(eapsim_checkmac(req->vps, eapsim_mk->K_aut,
			   eapsim_mk->nonce_mt, sizeof(eapsim_mk->nonce_mt),
			   calcmac)) {
		if (librad_debug) TRACE_TRAFIC("MAC check succeed\n");
	} else {
		if (librad_debug) {
			int i, j;
			j=0;
			char tmp[128];
			tmp[0] = '\0';
			for (i = 0; i < 20; i++) {
				if(j==4) {
					sprintf(tmp+strlen(tmp), "_");
					j=0;
				}
				j++;
				
				sprintf(tmp+strlen(tmp), "%02x", calcmac[i]);
			}
			TRACE_TRAFIC("calculated MAC (%s) did not match\n", tmp);
		}
// EmA,15/12/2003: do not stop on MAC check mismatch
// EmA,20/09/2007: return 0 to send ClientError
		return 0;
	}
    
    /* decrypt AT_ENCR_DATA */
    fr_id[0] = 0;
    if (encr && iv) {
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk->K_encr);
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[0] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            int fr_id_len = decrypt[3] | (decrypt[2]<<8);
            memcpy(fr_id, &decrypt[4], fr_id_len);
            fr_id[fr_id_len] = 0;
            /* no verification of AT_PADDING */
            if (librad_debug) {
//                TRACE_TRAFIC("User-Name=%s\n", fr_id);
                TRACE_TRAFIC("EAP-Type-Identity=%s\n", fr_id);
            }
        }
    }

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_challenge;
	pairreplace(&(rep->vps), newvp);

	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*0, sres1->strvalue, EAPSIM_SRES_SIZE);
	memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*1, sres2->strvalue, EAPSIM_SRES_SIZE);
	memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*2, sres3->strvalue, EAPSIM_SRES_SIZE);
	newvp->length = EAPSIM_SRES_SIZE*3;
	pairreplace(&(rep->vps), newvp);

	newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue,    eapsim_mk->K_aut, EAPSIM_AUTH_SIZE);
	newvp->length = EAPSIM_AUTH_SIZE;
	pairreplace(&(rep->vps), newvp);

   if (atEncrData == 1) {
	/* insert AT_ENCR_DATA into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
        	encrData[1] = htons(2);
                newvp->length = 4;
		pairreplace(&(rep->vps), newvp);
	/* insert AT_IV into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
        	encrData[1] = htons(1);
        	encrData[2] = htons(2);
        	encrData[3] = htons(3);
        	encrData[4] = htons(4);
        	encrData[5] = htons(5);
        	encrData[6] = htons(6);
        	encrData[7] = htons(7);
        	encrData[8] = htons(8);
                newvp->length = 20;
		pairreplace(&(rep->vps), newvp);
	/* insert AT_IV into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RESULT_IND, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
		pairreplace(&(rep->vps), newvp);
   }

	return 1;
}


static int process_eap_aka_challenge(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
VALUE_PAIR *newvp;
VALUE_PAIR *mac, *randvp, *autnvp;
VALUE_PAIR *res,*ik,*ck,*autn,*auts;
uint8_t calcmac[20];
uint16_t *encrData;
VALUE_PAIR *encr, *iv;
VALUE_PAIR *username;
unsigned char decrypt[200];

	/* look for the AT_MAC and the challenge data */
	mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
	randvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND);
	autnvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_AUTN);
	if(mac == NULL || rand == NULL || autnvp == NULL ) {
		TRACE_ERROR("radeapclient: challenge message needs to contain RAND and MAC\n");
		return 0;
	}

    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        TRACE_ERROR("radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
		return 0;
    }

	/*
	 * XXX compare RAND with randX, to verify this is the right response
	 * to this challenge.
	 */

	/*
	 * now dig up the sres values from the response packet,
	 * which were put there when we read things in.
	 *
	 * Really, they should be calculated from the RAND!
	 *
	 */

	autn = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTN);
    res = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_RES);
    ik = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_IK);
    ck = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_CK);


    if(res == NULL ||
        autn == NULL ||
        ik == NULL ||
        ck == NULL) {
		TRACE_ERROR("radeapclient: needs to have res, ik and ck set.\n");
		return process_eap_aka_authentication_reject(req, rep);
	}

//username = pairfind(rep->vps, ATTRIBUTE_EAP_BASE+PW_EAP_IDENTITY);
	
    username = pairfind(rep->vps, PW_USER_NAME);
    if(username == NULL)
    {
        TRACE_ERROR("radeapclient: We need to have a User-Name attribute!\n");
        return process_eap_aka_authentication_reject(req, rep);
    }
    memcpy(eapsim_mk->identity, username->strvalue, strlen(username->strvalue));
    eapsim_mk->identitylen = strlen(username->strvalue);
   /* 
     if (strlen(eapid)!=0)	
    {
        eapsim_mk.identitylen = strlen(eapid);
    	 memcpy(eapsim_mk.identity, eapid, eapsim_mk.identitylen);
    }
    */
    memcpy(eapsim_mk->autn, autn->strvalue, sizeof(eapsim_mk->autn));
    memcpy(eapsim_mk->res, res->strvalue, sizeof(eapsim_mk->res));
    eapsim_mk->res_len=res->length;
    memcpy(eapsim_mk->ik, ik->strvalue, sizeof(eapsim_mk->ik));
    memcpy(eapsim_mk->ck, ck->strvalue, sizeof(eapsim_mk->ck));
//    printf(" \n");

    if (memcmp(eapsim_mk->autn,&autnvp->strvalue[2],sizeof(eapsim_mk->autn) )!=0)
    {
     /*  int i=0;
       printf(" eapsim_mk.autn=\n");
       for (i = 0; i < EAP_AKA_AUTN_LEN; i++) {
           printf("%02x", eapsim_mk.autn[i]);
       }
       printf(" \nautnvp->strvalue=\n");
       for (i = 0; i < EAP_AKA_AUTN_LEN; i++) {
           printf("%02x", autnvp->strvalue[2+i]);
       }
       */
       TRACE_ERROR("radeapclient: AUTN not match\n");
       return process_eap_aka_authentication_reject(req, rep);		
    }

    auts = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTS);
    if(auts != NULL && !haveSendRejectOrSyncFailure)
    {
        haveSendRejectOrSyncFailure = 1;
        TRACE_ERROR("radeapclient: UMTS authentication failed (AUTN seq# -> AUTS).\n");
        memcpy(eapsim_mk->auts, auts->strvalue, sizeof(eapsim_mk->auts));		
        return process_eap_aka_synchronization_failure(req,rep,eapsim_mk);
    }


	/* all set, calculate keys */
	eapaka_calculate_keys(eapsim_mk);


    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys 
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    FILE *fp;
    if ((fp = fopen( nom, "w")) == NULL)
        TRACE_ERROR("Pb for opening ${PATH_RESULT}/.tmpKeys");
    if ((fwrite(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fwrite(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        TRACE_ERROR("Pb for writing in ${PATH_RESULT}/.tmpKeys");
     fclose(fp);                                                */

	if (librad_debug) eapaka_dump_mk(eapsim_mk);

	/* verify the MAC, now that we have all the keys. */
    if(eapsim_checkmac(req->vps, eapsim_mk->K_aut,
        "", 0,
        calcmac)){
		if (librad_debug) TRACE_TRAFIC("MAC check succeed\n");
	} else {
		if (librad_debug) {
			int i, j;
			j=0;
			char tmp[128];
			tmp[0] = '\0';
			for (i = 0; i < 20; i++) {
				if(j==4) {
					sprintf(tmp+strlen(tmp), "_");
					j=0;
				}
				j++;
				
				sprintf(tmp+strlen(tmp), "%02x", calcmac[i]);
			}
			TRACE_TRAFIC("calculated MAC (%s) did not match\n", tmp);
		}
// EmA,15/12/2003: do not stop on MAC check mismatch
// EmA,20/09/2007: return 0 to send ClientError
		return 0;
	}
    
    /* decrypt AT_ENCR_DATA */
    fr_id[0] = 0;
    if (encr && iv) {
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk->K_encr);
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[0] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            int fr_id_len = decrypt[3] | (decrypt[2]<<8);
            memcpy(fr_id, &decrypt[4], fr_id_len);
            fr_id[fr_id_len] = 0;
            /* no verification of AT_PADDING */
            if (librad_debug) {
//                TRACE_TRAFIC("User-Name=%s\n", fr_id);
                TRACE_TRAFIC("EAP-Type-Identity=%s\n", fr_id);
            }
        }
    }

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapaka_challenge;
	pairreplace(&(rep->vps), newvp);

    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_RES, PW_TYPE_OCTETS);
    newvp->strvalue[0] = ((uint16_t) (eapsim_mk->res_len)) >> 8;
    newvp->strvalue[1] = ((uint16_t) (eapsim_mk->res_len)) & 0xff;
    memcpy(&newvp->strvalue[2],eapsim_mk->res, EAP_AKA_RES_MAX_LEN);
    newvp->length = 2+EAP_AKA_RES_MAX_LEN;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
        PW_TYPE_OCTETS);
    memset(newvp->strvalue,0x0,EAPSIM_CALCMAC_SIZE);
    newvp->length = 0;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
    memcpy(newvp->strvalue,    eapsim_mk->K_aut, EAPSIM_AUTH_SIZE);
    newvp->length = EAPSIM_AUTH_SIZE;
    pairreplace(&(rep->vps), newvp);
    pairdelete(&(rep->vps),ATTRIBUTE_EAP_AKA_AUTN);
    
   if (atEncrData == 1) {
	/* insert AT_ENCR_DATA into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
        	encrData[1] = htons(2);
                newvp->length = 4;
		pairreplace(&(rep->vps), newvp);
	/* insert AT_IV into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
        	encrData[1] = htons(1);
        	encrData[2] = htons(2);
        	encrData[3] = htons(3);
        	encrData[4] = htons(4);
        	encrData[5] = htons(5);
        	encrData[6] = htons(6);
        	encrData[7] = htons(7);
        	encrData[8] = htons(8);
                newvp->length = 20;
		pairreplace(&(rep->vps), newvp);
	/* insert AT_IV into response. */
		newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RESULT_IND, PW_TYPE_OCTETS);
		encrData = (uint16_t *)newvp->strvalue;
		encrData[0] = htons(0);
		pairreplace(&(rep->vps), newvp);
   }

	return 1;
}

/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Re-auth message in a legal state.
 *
 * use the RAND challenge to produce the SRES result, and then
 * use that to generate a new MAC.
 *
 * for the moment, we ignore the RANDs, then just plug in the SRES
 * values.
 *
 */
static int process_eap_reauth(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
VALUE_PAIR *newvp;
VALUE_PAIR *mac;
uint8_t calcmac[20];
VALUE_PAIR *encr, *iv;
int counter=0;
unsigned char nonce_s[EAPSIM_NONCEMT_SIZE];
unsigned char decrypt[200];


	/* look for the AT_MAC and the challenge data */
	mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
	if(mac == NULL) {
		TRACE_ERROR("radeapclient: reauth message needs to contain RAND and MAC\n");
		return 0;
	}

    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        TRACE_ERROR("radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
		return 0;

    }

	/* all set, calculate keys */
	/* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys 
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 

    FILE *fp;
    if ((fp = fopen( nom, "r")) == NULL)
        TRACE_ERROR("Pb for opening ${PATH_RESULT}/.tmpKeys");
    if ((fread(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fread(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        TRACE_ERROR("Pb for reading ${PATH_RESULT}/.tmpKeys");
    fclose(fp);  */

	/* verify the MAC, now that we have all the keys. */
	if(eapsim_checkmac(req->vps, eapsim_mk->K_aut, 0, 0, calcmac)) {
		if (librad_debug) TRACE_TRAFIC("MAC check succeed\n");
	} else {
		if (librad_debug) {
			int i, j;
			j=0;
			char tmp[128];
			tmp[0] = '\0';
			for (i = 0; i < 20; i++) {
				if(j==4) {
					sprintf(tmp+strlen(tmp), "_");
					j=0;
				}
				j++;
				
				sprintf(tmp+strlen(tmp), "%02x", calcmac[i]);
			}
			TRACE_TRAFIC("calculated MAC (%s) did not match\n", tmp);
		}
// EmA,15/12/2003: do not stop on MAC check mismatch
// EmA,20/09/2007: return 0 to send ClientError
		return 0;
	}

    /* decrypt AT_ENCR_DATA */
    fr_id[0] = 0;
    if (encr && iv) {
        int i;
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk->K_encr);
        if (decrypt[0] == PW_EAP_SIM_COUNTER) {
            counter =  decrypt[3] | (decrypt[2]<<8);
            if (librad_debug) TRACE_TRAFIC("AT_COUNTER= %d\n", counter);
        }
        if (decrypt[4] == PW_EAP_SIM_NONCE_S) {
            memcpy(nonce_s, &decrypt[8], EAPSIM_NONCEMT_SIZE);
            if (librad_debug) {
				char tmp[128];
				tmp[0] = '\0';
                for (i=0; i< EAPSIM_NONCEMT_SIZE; i++)
                    sprintf(tmp+strlen(tmp), "%x", nonce_s[i]);
                TRACE_TRAFIC("AT_NONCE_S=%s\n", tmp);
            }
        }

        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[24] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            int fr_id_len = decrypt[27] | (decrypt[26]<<8);
            memcpy(fr_id, &decrypt[28], fr_id_len);
            fr_id[fr_id_len] = 0;
            /* no verification of AT_PADDING */
            if (librad_debug) {
//                TRACE_TRAFIC("User-Name=%s\n", fr_id);
                TRACE_TRAFIC("EAP-Type-Identity=%s\n", fr_id);
            }
        }
    }

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_reauth;
	pairreplace(&(rep->vps), newvp);

    /* mac calculated with NONCE_S received */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue, nonce_s, EAPSIM_NONCEMT_SIZE);
	newvp->length = EAPSIM_NONCEMT_SIZE;
	pairreplace(&(rep->vps), newvp);

    /* mac key is K_aut */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue,    eapsim_mk->K_aut, EAPSIM_AUTH_SIZE);
	newvp->length = EAPSIM_AUTH_SIZE;
	pairreplace(&(rep->vps), newvp);

    /* add AT_COUNTER */
    if (echallenge) {
        counter = estartNotif;
    }

    /* get IV */
    unsigned char initVector[EAPSIM_NONCEMT_SIZE];
    unsigned long inVec[4];
    // chose a rand for the nonce
    inVec[0]=lrad_rand();
    inVec[1]=lrad_rand();
    inVec[2]=lrad_rand();
    inVec[3]=lrad_rand();

    memcpy(initVector, inVec, 16);


    /* add ENCR_DATA */
    unsigned char encrData[16];
    memset(encrData, 0, 16);
    encrData[0] = PW_EAP_SIM_COUNTER;
    encrData[1] = 1;
    encrData[2] = (counter & 0xFF00) >> 8;
    encrData[3] = counter &0xFF;

    if (ecounterTooSmall) {
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    } else {
        encrData[4] = PW_EAP_SIM_PADDING;
        encrData[5] = 3;
    }

    
    /* cryptage ENCR_DATA */
    unsigned char encrypt[16];
    eapsim_aesencrypt(encrData, 16, encrypt, initVector, eapsim_mk->K_encr);

    /* build ENCR_DATA attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], encrypt, 16);
    newvp->length = 18;

    pairreplace(&(rep->vps), newvp);

    /* build IV attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], initVector, EAPSIM_NONCEMT_SIZE);
    newvp->length = EAPSIM_NONCEMT_SIZE+2;
    pairreplace(&(rep->vps), newvp);

	return 1;
}


/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Re-auth message in a legal state.
 *
 * use the RAND challenge to produce the SRES result, and then
 * use that to generate a new MAC.
 *
 * for the moment, we ignore the RANDs, then just plug in the SRES
 * values.
 *
 */
static int process_eap_aka_reauth(RADIUS_PACKET *req, RADIUS_PACKET *rep, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
VALUE_PAIR *newvp;
VALUE_PAIR *mac;
uint8_t calcmac[20];
VALUE_PAIR *encr, *iv;
int counter=0;
unsigned char nonce_s[EAPSIM_NONCEMT_SIZE];
unsigned char decrypt[200];


	/* look for the AT_MAC and the challenge data */
	mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
	if(mac == NULL) {
		TRACE_ERROR("radeapclient: reauth message needs to contain RAND and MAC\n");
		return 0;
	}

    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        TRACE_ERROR("radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
		return 0;

    }

	/* all set, calculate keys */
	/* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys 
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 

    FILE *fp;
    if ((fp = fopen( nom, "r")) == NULL)
        TRACE_ERROR("Pb for opening ${PATH_RESULT}/.tmpKeys");
    if ((fread(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fread(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        TRACE_ERROR("Pb for reading ${PATH_RESULT}/.tmpKeys");
    fclose(fp);  */

	/* verify the MAC, now that we have all the keys. */
	if(eapsim_checkmac(req->vps, eapsim_mk->K_aut, 0, 0, calcmac)) {
		if (librad_debug) TRACE_TRAFIC("MAC check succeed\n");
	} else {
		if (librad_debug) {
			int i, j;
			j=0;
			char tmp[128];
			tmp[0] = '\0';
			for (i = 0; i < 20; i++) {
				if(j==4) {
					sprintf(tmp+strlen(tmp), "_");
					j=0;
				}
				j++;
				
				sprintf(tmp+strlen(tmp), "%02x", calcmac[i]);
			}
			TRACE_TRAFIC("calculated MAC (%s) did not match\n", tmp);
		}
// EmA,15/12/2003: do not stop on MAC check mismatch
// EmA,20/09/2007: return 0 to send ClientError
		return 0;
	}

    /* decrypt AT_ENCR_DATA */
    fr_id[0] = 0;
    if (encr && iv) {
        int i;
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk->K_encr);
        if (decrypt[0] == PW_EAP_SIM_COUNTER) {
            counter =  decrypt[3] | (decrypt[2]<<8);
            if (librad_debug) TRACE_TRAFIC("AT_COUNTER= %d\n", counter);
        }
        if (decrypt[4] == PW_EAP_SIM_NONCE_S) {
            memcpy(nonce_s, &decrypt[8], EAPSIM_NONCEMT_SIZE);
            if (librad_debug) {
				char tmp[128];
				tmp[0] = '\0';
                for (i=0; i< EAPSIM_NONCEMT_SIZE; i++)
                    sprintf(tmp+strlen(tmp), "%x", nonce_s[i]);
                TRACE_TRAFIC("AT_NONCE_S=%s\n", tmp);
            }
        }

        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[24] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            int fr_id_len = decrypt[27] | (decrypt[26]<<8);
            memcpy(fr_id, &decrypt[28], fr_id_len);
            fr_id[fr_id_len] = 0;
            /* no verification of AT_PADDING */
            if (librad_debug) {
//                TRACE_TRAFIC("User-Name=%s\n", fr_id);
                TRACE_TRAFIC("EAP-Type-Identity=%s\n", fr_id);
            }
        }
    }

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Start */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_reauth;
	pairreplace(&(rep->vps), newvp);

    /* mac calculated with NONCE_S received */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue, nonce_s, EAPSIM_NONCEMT_SIZE);
	newvp->length = EAPSIM_NONCEMT_SIZE;
	pairreplace(&(rep->vps), newvp);

    /* mac key is K_aut */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
	memcpy(newvp->strvalue,    eapsim_mk->K_aut, EAPSIM_AUTH_SIZE);
	newvp->length = EAPSIM_AUTH_SIZE;
	pairreplace(&(rep->vps), newvp);

    /* add AT_COUNTER */
    if (echallenge) {
        counter = estartNotif;
    }

    /* get IV */
    unsigned char initVector[EAPSIM_NONCEMT_SIZE];
    unsigned long inVec[4];
    // chose a rand for the nonce
    inVec[0]=lrad_rand();
    inVec[1]=lrad_rand();
    inVec[2]=lrad_rand();
    inVec[3]=lrad_rand();

    memcpy(initVector, inVec, 16);


    /* add ENCR_DATA */
    unsigned char encrData[16];
    memset(encrData, 0, 16);
    encrData[0] = PW_EAP_SIM_COUNTER;
    encrData[1] = 1;
    encrData[2] = (counter & 0xFF00) >> 8;
    encrData[3] = counter &0xFF;

    if (ecounterTooSmall) {
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    } else {
        encrData[4] = PW_EAP_SIM_PADDING;
        encrData[5] = 3;
    }

    
    /* cryptage ENCR_DATA */
    unsigned char encrypt[16];
    eapsim_aesencrypt(encrData, 16, encrypt, initVector, eapsim_mk->K_encr);

    /* build ENCR_DATA attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], encrypt, 16);
    newvp->length = 18;

    pairreplace(&(rep->vps), newvp);

    /* build IV attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], initVector, EAPSIM_NONCEMT_SIZE);
    newvp->length = EAPSIM_NONCEMT_SIZE+2;
    pairreplace(&(rep->vps), newvp);

	return 1;
}

/************************************************************************************/
/*
 * we got an EAP-Request/Sim/Notification message in a legal state.
 *
 * no attributes in the response (for UMA without re-auth)
 *
 */
static int process_eap_notification(RADIUS_PACKET *req, RADIUS_PACKET *rep)
/************************************************************************************/
{
	VALUE_PAIR *newvp;

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/Notification */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_notification;
        newvp->length = 8;
	pairreplace(&(rep->vps), newvp);

	return 1;
}

/************************************************************************************/
/*
 * send a client-error message
 *
 * attribute AT_CLIENT_ERROR
 *
 */
static int process_eap_clienterror (RADIUS_PACKET *req, RADIUS_PACKET *rep)
/************************************************************************************/
{
	VALUE_PAIR *newvp;
	uint16_t *clientErrorCode;

	/* form new response clear of any EAP stuff */
	cleanresp(rep);

	/* mark the subtype as being EAP-SIM/Response/ClientError */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
	newvp->lvalue = eapsim_clienterror;
	pairreplace(&(rep->vps), newvp);

	/* insert AT_CLIENT_ERROR into response. */
	newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_CLIENT_ERROR_CODE,
			   PW_TYPE_OCTETS);
	clientErrorCode = (uint16_t *)newvp->strvalue;
	clientErrorCode[0] = htons(estartNotif);
	newvp->length = 2;
	pairreplace(&(rep->vps), newvp);

	if (librad_debug) {
		TRACE_TRAFIC("<+++ EAP-sim decoded packet:\n");
		vp_printlist(stderr, req->vps);
	}	
	return 1;
}


/************************************************************************************/
/*
 * this code runs the EAP-SIM client state machine.
 * the *request* is from the server.
 * the *reponse* is to the server.
 *
 */
static int respond_eap_sim(RADIUS_PACKET *req, RADIUS_PACKET *resp, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
	enum eapsim_clientstates state, newstate;
	enum eapsim_subtype subtype;
	VALUE_PAIR *vp, *statevp, *radstate, *eapid;
	char statenamebuf[32], subtypenamebuf[32];
    if (librad_debug) TRACE_TRAFIC(" get sim response:\n");
	if ((radstate = paircopy2(req->vps, PW_STATE)) == NULL)
	{
// EmA,11/12/03: Do not reject packets without State attribute
//		return 0;
	}

	if ((eapid = paircopy2(req->vps, ATTRIBUTE_EAP_ID)) == NULL)
	{
		return 0;
	}

	/* first, dig up the state from the request packet, setting
	 * outselves to be in EAP-SIM-Start state if there is none.
	 */

	if((statevp = pairfind(resp->vps, ATTRIBUTE_EAP_SIM_STATE)) == NULL)
	{
		/* must be initial request */
		statevp = paircreate(ATTRIBUTE_EAP_SIM_STATE, PW_TYPE_INTEGER);
		statevp->lvalue = eapsim_client_init;
		pairreplace(&(resp->vps), statevp);
	}
	state = statevp->lvalue;

	/*
	 * map the attributes, and authenticate them.
	 */
	unmap_eapsim_types(req);

	if (librad_debug) {
		TRACE_TRAFIC("<+++ EAP-sim decoded packet:\n");
		vp_printlist(stderr, req->vps);
	}	

	if((vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_SUBTYPE)) == NULL)
	{
		return 0;
	}
	subtype = vp->lvalue;

	/*
	 * look for the appropriate state, and process incoming message
	 */
	switch(state) {
	case eapsim_client_init:
		switch(subtype) {
		case eapsim_start:
            if (estart == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_start(req, resp, eapsim_mk);
			break;
			
		case eapsim_notification:
            if ((echallenge == 1) || (estart == 1))
				newstate = process_eap_clienterror(req, resp);
            else
				newstate = process_eap_notification(req, resp);
			break;
                        
		case eapsim_reauth:
            newstate = process_eap_reauth(req, resp, eapsim_mk, fr_id);
			if (!newstate) process_eap_clienterror(req, resp);
            break;
        
        case eapsim_challenge:
        default:
			newstate = process_eap_clienterror(req, resp);
/*
			TRACE_ERROR("radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			** invalid state, drop message **
			return 0;
*/
			break;
		}
		break;

	case eapsim_client_start:
		switch(subtype) {
		case eapsim_start:
			/* NOT SURE ABOUT THIS ONE, retransmit, I guess */
			if (estart == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_start(req, resp, eapsim_mk);
			break;
			
		case eapsim_challenge:
            if (echallenge == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_challenge(req, resp, eapsim_mk, fr_id);
				if (!newstate) process_eap_clienterror(req, resp);
			break;

		case eapsim_notification:
			newstate = process_eap_notification(req, resp);
			break;
                        
		default:
			newstate = process_eap_clienterror(req, resp);
			break;
/*
			TRACE_ERROR("radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			** invalid state, drop message **
			return 0;
*/
		}
		break;

	default:
		TRACE_TRAFIC("radeapclient: sim in illegal state %s\n",
			sim_state2name(state, statenamebuf, sizeof(statenamebuf)));
		return 0;
	}

	/* copy the eap state object in */
	pairreplace(&(resp->vps), eapid);

	/* update state info, and send new packet */
	map_eapsim_types(resp);

	/* copy the radius state object in */
// EmA,11/12/03: Do not reject packets without State attribute
	if ( radstate )
		pairreplace(&(resp->vps), radstate);

	statevp->lvalue = newstate;
	return 1;
}



/************************************************************************************/
/*
 * this code runs the EAP-SIM client state machine.
 * the *request* is from the server.
 * the *reponse* is to the server.
 *
 */
static int respond_eap_aka(RADIUS_PACKET *req, RADIUS_PACKET *resp, struct eapsim_keys *eapsim_mk, char* fr_id)
/************************************************************************************/
{
	enum eapsim_clientstates state, newstate;
	enum eapsim_subtype subtype;
	VALUE_PAIR *vp, *statevp, *radstate, *eapid;
	char statenamebuf[32], subtypenamebuf[32];
 
	
	if ((radstate = paircopy2(req->vps, PW_STATE)) == NULL)
	{
// EmA,11/12/03: Do not reject packets without State attribute
//		return 0;
	}

	if ((eapid = paircopy2(req->vps, ATTRIBUTE_EAP_ID)) == NULL)
	{
		return 0;
	}

	/* first, dig up the state from the request packet, setting
	 * outselves to be in EAP-SIM-Start state if there is none.
	 */

	if((statevp = pairfind(resp->vps, ATTRIBUTE_EAP_SIM_STATE)) == NULL)
	{
		/* must be initial request */
		statevp = paircreate(ATTRIBUTE_EAP_SIM_STATE, PW_TYPE_INTEGER);
		statevp->lvalue = eapsim_client_start;
		pairreplace(&(resp->vps), statevp);
	}
	state = statevp->lvalue;
	/*
	 * map the attributes, and authenticate them.
	 */
   
	unmap_eapsim_types(req);

	if (librad_debug) {
		TRACE_TRAFIC("<+++ EAP-sim decoded packet:\n");
		vp_printlist(stderr, req->vps);
	}	

	if((vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_SUBTYPE)) == NULL)
	{
		return 0;
	}
	subtype = vp->lvalue;

	/*
	 * look for the appropriate state, and process incoming message
	 */
	switch(state) {
	case eapsim_client_init:
		switch(subtype) 
		{
		case eapsim_notification:
            if ((echallenge == 1) || (estart == 1))
				newstate = process_eap_clienterror(req, resp);
            else
				newstate = process_eap_notification(req, resp);
			break;
                        
		case eapsim_reauth:
            newstate = process_eap_aka_reauth(req, resp, eapsim_mk, fr_id);
			if (!newstate) process_eap_clienterror(req, resp);
            break;
        
        case eapaka_challenge:
        default:
			newstate = process_eap_clienterror(req, resp);
/*
			TRACE_ERROR("radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			** invalid state, drop message **
			return 0;
*/
			break;
		}
		break;

	case eapsim_client_start:
		switch(subtype) {
		case eapaka_identity:
			/* NOT SURE ABOUT THIS ONE, retransmit, I guess */
			if (estart == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_aka_identity(req, resp, eapsim_mk);
			break;
			
		case eapaka_challenge:
            if (echallenge == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_aka_challenge(req, resp, eapsim_mk, fr_id);
				if (!newstate) process_eap_clienterror(req, resp);
			break;
			
		case eapsim_reauth:
            newstate = process_eap_aka_reauth(req, resp, eapsim_mk, fr_id);
			if (!newstate) process_eap_clienterror(req, resp);
            break;
            
		case eapsim_notification:
			newstate = process_eap_notification(req, resp);
			break;
                        
		default:
			newstate = process_eap_clienterror(req, resp);
			break;
/*
			TRACE_ERROR("radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			** invalid state, drop message **
			return 0;
*/
		}
		break;

	default:
		TRACE_TRAFIC("radeapclient: sim in illegal state %s\n",
			sim_state2name(state, statenamebuf, sizeof(statenamebuf)));
		return 0;
	}

	/* copy the eap state object in */
	pairreplace(&(resp->vps), eapid);

	/* update state info, and send new packet */
	map_eapsim_types(resp);

	/* copy the radius state object in */
// EmA,11/12/03: Do not reject packets without State attribute
	if ( radstate )
		pairreplace(&(resp->vps), radstate);

	statevp->lvalue = newstate;
	return 1;
}

/************************************************************************************/
static int sendrecv_eap(RADIUS_PACKET *rep, RADIUS_PACKET **final_rep, int *total_retries, tUser *user)
/************************************************************************************/
{
RADIUS_PACKET *req = NULL;
VALUE_PAIR *vp, *vpnext, *newvp;
int tried_eap_md5 = 0;
int i, rc=0;
int	retries;
struct eapsim_keys eapsim_mk;
unsigned char frId[MY_ENCR_DATA_LEN_MAX];
int idx;

   *total_retries = 0;
   bzero(frId, MY_ENCR_DATA_LEN_MAX);
   
   pthread_mutex_lock(&eapMutex);
   
   tUserGetFastAuthData(user, &eapsim_mk, NULL);

/*   if (fastid) {
       strcpy(eapid, fastid);
   }*/
/*
   if (vp = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY)) {
        memcpy(eapid, &vp->strvalue, strlen(vp->strvalue));
        pairdelete(&rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY);
   }
*/
again:	
	if (librad_debug) {
		TRACE_TRAFIC("\n+++> About to send encoded packet:\n");
		vp_printlist(stderr, rep->vps);
	}
	
    // EAP-Type == Identity ?
    if ( (vp = pairfind(rep->vps, PW_EAP_TYPE)) && vp->lvalue == PW_EAP_IDENTITY) {
        idx = RADIUS_AccessEapId_Rq;

    } else if ( vp = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_SUBTYPE) ) {    // this is an affectation
        // EAP-Sim-Subtype ?
        switch ( vp->lvalue ) {

			case eapaka_challenge:
				idx = RADIUS_AccessEapAKAChal_Rq;
                break;
            case eapaka_authentication_reject:
				idx = RADIUS_AccessEapAKARej_Rq;
                break;
 			case eapaka_synchronization_failure:
				idx = RADIUS_AccessEapAKASynfail_Rq;
                break;
            case eapaka_identity:
				idx = RADIUS_AccessEapAKAIdentity_Rq;
                break;
       // AKA statistic, duplicate reauth, and notification, can not differ them with SIM, need enhance
            case eapsim_start:
                idx = RADIUS_AccessEapStart_Rq;
                break;
            case eapsim_challenge:
                idx = RADIUS_AccessEapChal_Rq;
                break;
            case eapsim_notification:
                idx = RADIUS_AccessEapNotif_Rq;
                break;
            case eapsim_reauth:
                idx = RADIUS_AccessEapFast_Rq;
                break;
            case eapsim_clienterror:
                idx = RADIUS_AccessEapCliErr_Rq;
                break;
            default:
                TRACE_ERROR("sendrecv_eap: unrecoggnized EAP-SUBTYPE \n");
                idx = RADIUS_AccessEapId_Rq;
        }
    } else {
        //TRACE_ERROR("sendrecv_eap: unrecoggnized EAP-TYPE \n");
        idx = RADIUS_AccessEapId_Rq;
    }

/*
	 * if there are EAP types, encode them into an EAP-Message
	 *
	 */
	map_eap_types(rep);
	
    /*
	 *	If we've already sent a packet, free up the old
	 *	one, and ensure that the next packet has a unique
	 *	ID and authentication vector.
	 */
	if (rep->data) {
		free(rep->data);
		rep->data = NULL;
	}
	
	librad_md5_calc(rep->vector, rep->vector,
			sizeof(rep->vector));
	
	/* send the response, wait for the next request */
    pthread_mutex_unlock(&eapMutex);

    tStatRegulation( tThread_getKey() );
    tStatTimeBegin(0);
	rc = send_packet(rep, &req, &retries);
    tStatTimeEnd(0);
    tStatCount( tThread_getKey() );
    tStatActionTime( idx, rc, retries, 0 );

    pthread_mutex_lock(&eapMutex);
    
	*total_retries += retries;
	*final_rep = req;
	
	if (rc || !req) {
       pthread_mutex_unlock(&eapMutex);
	   return 1;
	}
	/* okay got back the packet, go and decode the EAP-Message. */

	unmap_eap_types(req);
	
	if (librad_debug) {
		TRACE_TRAFIC("<+++ EAP decoded packet:\n");
		vp_printlist(stderr, req->vps);
	}
	
	/* now look for the code type (EmA: always ATTRIBUTE_EAP_BASE+PW_EAP_SIM !) */
	if ( pairfind(req->vps, ATTRIBUTE_EAP_BASE+PW_EAP_SIM) != NULL ) {

	   respond_eap_sim(req, rep, &eapsim_mk, frId);
	   	   rep->id++;
	   // free msgs memory
	   if (req) rad_free(&req);
	   goto again;

	   }

	   else {

	   	if ( pairfind(req->vps, ATTRIBUTE_EAP_BASE+PW_EAP_AKA) != NULL ) {

	   		respond_eap_aka(req, rep, &eapsim_mk, frId); 
	   		rep->id++;
	   		// free msgs memory
	   		if (req) rad_free(&req);
	   		goto again;
	   		}

	   		else {
	   // normal ending
//       TRACE_TRAFIC("set FRID = %s (user=%s)\n", frId, user->auth.nai);
       tUserSetFastAuthData(user, &eapsim_mk, frId);
       pthread_mutex_unlock(&eapMutex);
	   return 0;
			}
	   	}

    pthread_mutex_unlock(&eapMutex);
    return 1;
}

/************************************************************************************/
/* RHL, It will copy the char(s) type value from source to the dest*/
/* parameter: char* destVSA: the dest of attr value. it need set it as array of char[n]*/
/* parameter: char* srcVSA: the source of attr value */
/* parameter: length: it's the length of the vsa */
void copyVSAAttrValue(char* destVSA, char* srcVSA, int length ){
/************************************************************************************/
    int t = 0;
    char * pVSA;
    TRACE_DEBUG("copyVSAAttrValue:destVSA=%02x, srcVSA=%02x,length=%d\n",(unsigned char* )destVSA,(unsigned char* ) srcVSA, length );

    if (length == 0){
    	destVSA = NULL;
    	return;
    }
    
    strcpy(destVSA, "0x");
    pVSA = destVSA + 2; 
    for (t = 0; t < length; t++) {
    	sprintf(pVSA, "%02x", (unsigned char)srcVSA[t]);
    	pVSA += 2;
    }

}

/*******************************************************************************/
/* RHL, Sep 16, 2008; It will put the Wimax VSA value to VP*/
VALUE_PAIR * putWimaxVSA( VALUE_PAIR	*vps_out,
                  tUser *    	aUser,
                  int		authType,
		  int 	        creditSessionAction)
/******************************************************************************/
{
	
	char *  aNai = tUserGetNAI(aUser);
	VALUE_PAIR	    *vp;
	VALUE_PAIR	*vps = vps_out;
	
	// add credit session action for prepaid charging feature,
	// it will send different additional attributes according to session type
	// 1: Initial; 2: Update; 3: Termination;
	if (creditSessionAction == 1) {
			 //Initial
			 TRACE_DEBUG("tRadius_accessRq on %s: adding prepaid related attrs for Initial Session\n",aNai);

			 vp = pairmake("WIMAX-CAPABILITY", CreditSessionInitial_WIMAXCAPABILITY, 0); vp->next = vps; vps = vp;
			 vp = pairmake("Session-Termination-Capability", CreditSessionInitial_SessionTerminationCapability, 0); vp->next = vps; vps = vp;
			 vp = pairmake("PPAC", CreditSessionInitial_PPAC, 0); vp->next = vps; vps = vp;

	} else if (creditSessionAction == 2) {
			 //Update
			 TRACE_DEBUG("tRadius_accessRq on %s: adding prepaid related attrs for Update Session\n",aNai);

			 if (tUserGetPPAQLength(aUser)) {
				 char ppaq[128];
				 copyVSAAttrValue((char*)ppaq,tUserGetPPAQ(aUser),tUserGetPPAQLength(aUser));
				 //get PPAQ, add "080304"
				 strcat(ppaq ,PPAQ_UpdateReason_QuotaReached);

				 TRACE_DEBUG("tRadius_accessRq on %s: adding PPAQ = %s\n",aNai,ppaq);	 
				 vp = pairmake("PPAQ", ppaq, 0); vp->next = vps; vps = vp;
			 } else {
				// can not get valid PPAQ, throw error
				TRACE_ERROR("tRadius_accessRq on %s: can not get valid PPAQ\n",aNai);
				return NULL;;
			 }
		 
	} else if (creditSessionAction == 3) {
			 //Termination
			TRACE_DEBUG("tRadius_accessRq on %s: adding prepaid related attrs for Termination Session\n",aNai);
			
			if (tUserGetPPAQLength(aUser)) {
				char ppaq[128];
				copyVSAAttrValue((char*)ppaq,tUserGetPPAQ(aUser),tUserGetPPAQLength(aUser));
				//get PPAQ, add "080308"
				strcat(ppaq ,PPAQ_UpdateReason_AccessServiceTerminated);

				TRACE_DEBUG("tRadius_accessRq on %s: adding PPAQ = %s\n",aNai,ppaq);	 
				vp = pairmake("PPAQ", ppaq, 0); vp->next = vps; vps = vp;
			} else {
			   // can not get valid PPAQ, throw error
			   TRACE_ERROR("tRadius_accessRq on %s: can not get valid PPAQ\n",aNai);
			   return NULL;
			}
	}
	
	if (librad_debug) {
		vp_printlist(stderr, vps);
	}
	return vps;
}
