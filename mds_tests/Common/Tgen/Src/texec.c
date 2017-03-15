
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "libradius.h"

#include "tconf.h"
#include "tthread.h"
#include "texec.h"
#include "tldap.h"
#include "tradius.h"
#include "tsce.h"
#include "tuser.h" 
#include "tstat.h"
#include "tdebug.h"
#include "ttimer.h"

/* used for iHLR control value formatting */
static int revertBytes(char * tab_, int tabsize_);

extern char *	acctStatusTypeName[];
extern int 		killcalled;

#define NOT_REACHED		0
#define REACHED			1
#define	SUSPENDED		2
#define NOT_STARTED		3

pthread_mutex_t   	closingMutex = PTHREAD_MUTEX_INITIALIZER   ;
int					nbSessionsClosed = 0;

/******************************************************************************/
int tExecInit ()
/******************************************************************************/
{
    int rc=0;

    // init random sequence
    srand(time(NULL) + getpid());

    return rc;
}

/******************************************************************************/
static void tExecScenarioEnd (tSce *sce, tUser *user, int timeoutnb)
/******************************************************************************/
{    
    sce->cnt ++;
    sce->timeout += timeoutnb;
    if (user) user->priv.cnt++;
}

/******************************************************************************/
static void tExecScenarioEndKo (tSce *sce, tUser *user, int timeoutnb)
/******************************************************************************/
{    
    sce->ko ++;
//    sce->timeout += timeoutnb;
	tExecScenarioEnd(sce, user, timeoutnb);
}

/******************************************************************************/
int revertBytes(char * tab_, int tabsize_)
/******************************************************************************/
{
 int ret = 0;
/* #ifdef _LITTLE_ENDIAN  */
 char * tabloc = malloc (tabsize_);
 memcpy (tabloc, tab_ , tabsize_);      
 char * ptablocEnd = tabloc + tabsize_ -1  ;    
 char *pc;
 for (pc = tab_ ; pc < tab_ + tabsize_ ; )
        {
        (*pc++) =  (*ptablocEnd--);
        }

free (tabloc);
/* #endif */
return ret;
} // 

/******************************************************************************/
static int tExecBuildCtrl_UMA (tAction *action, tUser *user, LDAPControl ***sctrl, int *waitForRc, int *shift)
// return the nb of controls added
/******************************************************************************/
{
int  pos = 0;
int  i;
char *imsi;
char ctrlOID[32];
char ctrlValue[128];
int  ctrlvaluelength = 0;
int  ret = 0;

	*shift = 0;

	if ( action->cmds && strncmp(action->cmds, KEYWD_IHLR, strlen(KEYWD_IHLR)) == 0 ) {
		int  nbSubscribersInTest;
		char subImsiPattern[200];
		char buf[1000];
		char IMSImodified[200];

		*shift = strlen(KEYWD_IHLR);

		if ( sscanf( action->cmds + *shift, "%d %s %n", &nbSubscribersInTest, subImsiPattern, &pos ) != 2 ) {
			TRACE_ERROR("can not set iHLR control value for user %s \n", tUserGetNAI(user));

		} else {
			strcpy(ctrlOID, LDAP_CONTROL_IHLR);
			ctrlvaluelength = IHLR_REGISTRATION_DATA_SIZE + sizeof ("IMSI=") + sizeof(",registrationData=") - 2 ;

			strcpy(buf, "IMSI=");

			/* generate a dynamic imsi value */
			i = ( rand() % nbSubscribersInTest ); 
			sprintf(IMSImodified, subImsiPattern, i);
			ctrlvaluelength += strlen (IMSImodified);
			strcat(buf, IMSImodified);

			strcat(buf, ",registrationData=");		     
			/* registration data value is binary, only timestamp and registration status are set */
			time_t *presult = (time_t *) (buf + strlen(buf));
			(*presult) = time(NULL);	
			revertBytes(( char *) presult , sizeof(time_t) );
			char * pRegistrationStatus = ((char *) presult) + sizeof(time_t);
			(*pRegistrationStatus)  = rand() % 2;                    /* successful / unsuccessful list are randomly chosen */
			/* 3 hard coded ip address */
			*((int*) (pRegistrationStatus +1)) = 0x12344423;
			*((int*) (pRegistrationStatus +5)) = 0x22334523;
			*((int*) (pRegistrationStatus +9)) = 0xFFFFFFFF;
			/* 2 indicators hard coded */
			*( (pRegistrationStatus +13)) = 1;
			*( (pRegistrationStatus +14)) = 2;
			/* ap mac @ */
			*((long long*) (pRegistrationStatus +15)) = 0x4523FFFFFFFF;

			//ctrlValue = malloc (ctrlvaluelength);
			//if (ctrlValue)
				memcpy (ctrlValue, buf, ctrlvaluelength);      
			TRACE_TRAFIC("tLdap_SearchRequest - Call with iHLR control - oid: %s, value: %s \n", ctrlOID, ctrlValue);
		}
	 } /* iHLR */

	 else if ( action->cmds && strncmp(action->cmds, KEYWD_SCRUBBING, strlen(KEYWD_SCRUBBING)) == 0 ) {
		int  nbAPInTest, nbCGIInTest;
		char APPattern[200], CGIPattern[200];
		char buf[1000];  
		char APmodified[200], CGImodified[200];

		*shift = strlen(KEYWD_SCRUBBING);

		if ( sscanf( action->cmds + *shift, "%d %s %d %s %n", &nbAPInTest, APPattern, &nbCGIInTest, CGIPattern, &pos ) != 4 ) {
			TRACE_ERROR("can not set Scrubbing control value for user %s \n", tUserGetNAI(user));

		} else {		     
			strcpy(ctrlOID, LDAP_CONTROL_SCRUBBING);

			strcpy(buf, "MAC=");

			/* generate a dynamic AP MAC value */
			i = ( rand() % nbAPInTest ); 
			sprintf(APmodified, APPattern, i);
			strcat(buf, APmodified);

			strcat(buf, ",CGIRule=");

			/* generate a dynamic CGI value */
			i = ( rand() % nbCGIInTest ); 
			sprintf(CGImodified, CGIPattern, i);
			strcat(buf, CGImodified);

			//ctrlValue = strdup(buf);
			strcpy (ctrlValue, buf);      
			TRACE_TRAFIC("tLdap_SearchRequest - Call with ScrubbingControl - oid: %s, value: %s \n", ctrlOID, ctrlValue);
		} 
	 } /* scrubbing */

	 else if ( action->cmds && strncmp(action->cmds, KEYWD_DYNAMICSCRUBBING, strlen(KEYWD_DYNAMICSCRUBBING)) == 0 ) {
		int  nbAPInTest, nbCGIInTest;
		char APPattern[200], CGIPattern[200];
		char buf[1000];  
		char APmodified[200], CGImodified[200];

		*shift = strlen(KEYWD_DYNAMICSCRUBBING);

		if ( sscanf( action->cmds + *shift, "%d %s %d %s %n", &nbAPInTest, APPattern, &nbCGIInTest, CGIPattern, &pos ) != 4 ) {
			TRACE_ERROR("can not set DynamicAP control value for user %s \n", tUserGetNAI(user));

		} else {		     
			strcpy(ctrlOID, LDAP_CONTROL_SCRUBBING_2);

			strcpy(buf, "MAC=");

			/* generate a dynamic AP MAC value */
			i = ( rand() % nbAPInTest ); 
			sprintf(APmodified, APPattern, i);
			strcat(buf, APmodified);

			strcat(buf, ",CGIRule=");

			/* generate a dynamic CGI value */
			i = ( rand() % nbCGIInTest ); 
			sprintf(CGImodified, CGIPattern, i);
			strcat(buf, CGImodified);

			//new SSID attribute
			strcat(buf, ",SSID=");
			strcat(buf, "nom_reseau_radio");

			//ctrlValue = strdup(buf);
			strcpy (ctrlValue, buf);      
			TRACE_TRAFIC("tLdap_SearchRequest - Call with ScrubbingControl - oid: %s, value: %s \n", ctrlOID, ctrlValue);
		} 
	 } /* dynamic scrubbing */

	 else if ( action->cmds && strncmp(action->cmds, KEYWD_COTF, strlen(KEYWD_COTF)) == 0 ) {
		*shift = strlen(KEYWD_COTF);
		strcpy(ctrlOID, LDAP_ADD_IMSI_IF_NOT_EXIST);

		// no value
		imsi = tUserGetIMSI(user);
		if (imsi && imsi[strlen(imsi)-4] != '1') {
			// IMSI will not be allowed for CreationOnTheFly
			*waitForRc = LDAP_NO_SUCH_OBJECT;
		}
		TRACE_TRAFIC("tLdap_SearchRequest - Call with CotfControl - oid: %s, waitForRc: %d \n", ctrlOID, waitForRc);

	} else // no UMA control to create
		return 0;

	if (!ctrlvaluelength) ctrlvaluelength = strlen (ctrlValue);

	LDAPControl **ctrls = { NULL, NULL};
	// build the Ldap control (only one)
	if ( ctrlOID && *ctrlOID ) {
		 // add a Control
		 LDAPControl *c;
		
		 TRACE_TRAFIC("tLdap_SearchRequest - add control: %s, value: %s \n", ctrlOID, ctrlValue);
		
		 c = (LDAPControl *)ber_memalloc(sizeof(LDAPControl));
		 ctrls[0] = c;
		 c->ldctl_oid = strdup(ctrlOID);
		 if (ctrlValue) {
			 c->ldctl_value.bv_val = strdup(ctrlValue);
			 c->ldctl_value.bv_len = ctrlvaluelength;
		 } else {
			 c->ldctl_value.bv_val = NULL;
			 c->ldctl_value.bv_len = 0;
		 }
		 c->ldctl_iscritical = 0;

		 ret = 1;
	}

	*sctrl = ctrls;
	*shift += (pos ? pos+1 : 0);
	return ret;
}

/******************************************************************************/
static int tExecBuildCtrl_Generic (tAction *action, tUser *user, LDAPControl ***sctrl, int *shift)
// return the nb of controls added
// -1 if malloc error
// Syntaxe: Ldap_<action>_Req "_LDAPCTRL_ 0 <oid1> <val1> | 1 <oid2> <val2> | ... | 0 <oidn> <valn> " "..."
// with: action = Search | Bind | Modify | Add | Delete
// 4 controls max can be conbined
/******************************************************************************/
{
int   pos,pos2;
int   i = 0;
int   critic;
char  ctrlOID[32];
char  ctrlValue[128];
LDAPControl **ctrls = NULL;
char  sep = 0;
int	  res=0;


	*shift = 0;
	action->unLimitSize = 0;
	TRACE_DEBUG("tExecBuildCtrl_Generic - Testing Ldap Control on lentgh %d\n", strlen(KEYWD_LDAPCONTROL));

	if ( action->cmds && strncmp(action->cmds, KEYWD_LDAPCONTROL, strlen(KEYWD_LDAPCONTROL)) == 0 ) {
		*shift = strlen(KEYWD_LDAPCONTROL);

		for (i=1; i<5 && (*shift)<strlen(action->cmds); i++) {

			ctrlValue[0] = 0;
			
			if ( sscanf( action->cmds + *shift, "%s %d%n", ctrlOID, &critic, &pos) != 2) {
				TRACE_ERROR("Can not set Ldap Control #%d for user %s, res=%d \n", i, tUserGetNAI(user));
				break;

			} else {
				TRACE_TRAFIC("ctrlOID = %s critic = %d\n", ctrlOID,critic);
               TRACE_TRAFIC("action->cmds = %s \n", action->cmds + *shift);
               if (strncmp(action->cmds+ *shift, LDAP_CONTROL_COUNT_ENTRIES, strlen(LDAP_CONTROL_COUNT_ENTRIES)) == 0 ) {
            	   action->unLimitSize = 1;
               }
               TRACE_TRAFIC("UnlimitSize = %d \n", action->unLimitSize);

               (*shift) += pos;
               TRACE_TRAFIC("ctrlValue = %s \n", ctrlValue);
			   res = sscanf( action->cmds + *shift, "%s%n", ctrlValue, &pos);
			   TRACE_TRAFIC("ctrlValue = %s \n", ctrlValue);
			   TRACE_TRAFIC("res = %d \n", res);
			   if ( res==0 ) {
				   // no value, no more control
				   TRACE_DEBUG("tExecBuildCtrl_Generic - last control without value (%d)\n", *shift + pos);
			   } else if ( ctrlValue[0]=='|') {
				   // no value, some more controls
				   TRACE_DEBUG("tExecBuildCtrl_Generic - not last control without value (%d)\n", *shift + pos);
				   ctrlValue[0] = 0;
			   } else {
				   TRACE_DEBUG("tExecBuildCtrl_Generic - there is a value (%d)\n", *shift + pos);
				   // there is a value
				   (*shift) += pos;
			   }

			   if ( ctrlOID && *ctrlOID ) {
					// add a Control
					LDAPControl *c;

					TRACE_TRAFIC("tExecBuildCtrl_Generic - Adding Ldap Control #%d - oid: %s, critic:%d, value: %s \n", i, ctrlOID, critic, ctrlValue);

					if ( (c = (LDAPControl *)ber_memalloc(sizeof(LDAPControl))) == NULL ) {
						TRACE_ERROR("No more memory to create Ldap request ctrls for user %s \n", tUserGetNAI(user));
						return -1;
					}
					bzero(c, sizeof(LDAPControl));
					if ( (ctrls = (LDAPControl **)ber_memrealloc( ctrls, (i+1) * sizeof(LDAPControl *))) == NULL ) {
						TRACE_ERROR("No more memory to create Ldap request ctrls for user %s \n", tUserGetNAI(user));
						return -1;
					}

					//ldap_create_control(ctrlOID, ber_bvstrdup(ctrlValue), critic, &c );
					ctrls[i-1] = c;
					ctrls[i] = NULL;
					c->ldctl_oid = strdup(ctrlOID);
					if (ctrlValue) {
						c->ldctl_value.bv_val = strdup(ctrlValue);
						c->ldctl_value.bv_len = strlen (ctrlValue);
					} else {
						c->ldctl_value.bv_val = NULL;
						c->ldctl_value.bv_len = 0;
					}
					TRACE_TRAFIC("critic = %d\n",critic);
					//ldap_create_page_control_value( ld,ctrlValue, &ldctl_value, c->ldctl_value );
					c->ldctl_iscritical = critic;
					TRACE_TRAFIC("c->ldctl_oid = %s c->ldctl_value.bv_val = %s\n", c->ldctl_oid,c->ldctl_value.bv_val);
			   }

/*			   if ( (*shift)>=strlen(action->cmds) ) {
				   TRACE_DEBUG("tExecBuildCtrl_Generic: shift=%d, len(cmd)=%d \n", *shift, strlen(action->cmds) );
				   *shift = strlen(action->cmds);
				   break;
			   } else*/
			   if ( (sscanf( action->cmds + *shift, "%1s%n", &sep, &pos) != 1) || sep != '|') {
				   TRACE_DEBUG("tExecBuildCtrl_Generic: no more control - shift=%d, len(cmd)=%d \n", *shift, strlen(action->cmds) );
				   break;
			   } else
				   // continue next control
				   (*shift) += pos;

			}
		}
	}
	*sctrl = ctrls;

	return i;
}

/******************************************************************************/
void tExec (int key)
/******************************************************************************/
{
//LDAP    		*ld;
int     		end,rc=0,retry=0;
tUser   		*user;
int     		actionAsARequest=0;
tSce    		*sce;
tAction 		*action;
tSleep			*sleepCtx;
tLdapReqCtx		*reqCtx;
int				requestId;


    // starting-block...
    tStatWaitForStart();

    // end routine only if thread is finished
    while ( tThread_getState(key) != FINISHED) {

	  TRACE_DEBUG("status of WT is %d \n", tThread_getState(key));  	

      while ( tThread_getState(key) == SUSPEND) sleep(1);


	  // check if an asynchronous Ldap response is ready to be handled
	  if (sleepCtx = getAndRemove_firstResponse(tLdap_getLdId(key))){

		  user	 = sleepCtx->user;
		  sce    = sleepCtx->sce;
		  action = sleepCtx->action;
		  reqCtx = sleepCtx->req;

		  TRACE_DEBUG("Received an asynchronous Search result for User ctx - user=%s sleepCtx=%d\n", tUserGetNAI(user), sleepCtx);
		  TRACE_DEBUG("   dn_user=%s \n", tUserGetBase(user));  	
		  TRACE_DEBUG("   action->id=%d \n", action->requestId);  	
		  TRACE_DEBUG("   reqCtx=%d \n", reqCtx);  	

		  if (reqCtx) {
			  // response received in time
			  requestId = LDAP_Search_Resp;
			  sleepCtx->req = NULL;
		  }
		  end = NOT_REACHED;

	  // check if users must be resume at current time
	  // For the first user found:
	  // 	- retrieve it from the list
	  // 	- get sce and next action of that resumed user
	  //	- goes on the scenario
	  } else if ( sleepCtx = (tSleep *)tTimerGetUserToResume() ) {

		 user	= sleepCtx->user;
		 sce    = sleepCtx->sce;
		 action = sleepCtx->action;
		 reqCtx = sleepCtx->req;

		 TRACE_DEBUG("Resume a User ctx - user=%s \n", tUserGetNAI(user));

		 if (action->requestId == SCE_Wait) {
			 action++;
			 requestId = action->requestId;
			 TRACE_DEBUG("After Wait action user=%s,coming_action=%d \n", tUserGetNAI(user), action->requestId);
			 free(sleepCtx);

		 } else if (reqCtx) {
			 // timeout on request
			 TRACE_DEBUG("Timeout on a User ctx - user=%s \n", tUserGetNAI(user));
			 requestId = LDAP_Search_Resp;
			 reqCtx->rc = LDAP_TIMEOUT;
			 sleepCtx->req = NULL;

		 } else {
			 // already treated as a response received in time (reqCtx already freed)
			 free(sleepCtx);
			 continue;
		 }
		 end = NOT_REACHED;

#ifdef _ASYNCHRONE_RADIUS_
	  // check if end of tgen required (1st phase: ttimer not closed)
	  // check if responses are available on Radius socket
	  // If yes:
	  // 	- unblocking select on socket
	  // 	- retrieve the sleepCtx
	  //	- goes on the scenario
	  } else if ( tSelectIsFdSet(tThread_getRadSockFd(key)) ) {

		  TRACE_TRAFIC("There's something on my socket !\n");

#endif

	  // there is no more waiting user, neither waiting response:
	  //    - if end of tgen required (1st phase: ttimer not closed), wait a while and try again later
	  //    - if end of tgen required (2nd phase: ttimer closed), job is finished
	  } else if ( tThread_getState(key) == ENDING ) {

		 usleep(50000); // 50 ms
		 continue;

	  } else if ( tThread_getState(key) == ENDING2 ) {

		 // no more user to resume in ending phase: the thread is FINISHED
		 pthread_mutex_lock(&closingMutex);
		 nbSessionsClosed ++;
		 pthread_mutex_unlock(&closingMutex);
		 TRACE_DEBUG("No more user to resume ENDING => FINISHED (%d threads has finished)\n", nbSessionsClosed);
		 
		 // the thread suspends itself
		 tThread_getState(key) = FINISHED;	

		 // don't execute a null scenario !!!
		 continue;	// equivalent to return

	  } else {
		 // get a new scenario
		 sce    = tSceGet();
		 action = sce->action; 
		 requestId = action->requestId;
         end = NOT_REACHED;
	  }

	  char first_sce_stat = 1;
      while (end == NOT_REACHED) { 

        // default: no request
        actionAsARequest=0;
        retry = 0;
        rc=0;
        int i,indiceTab;
        // SUSPEND interrupts a scenario between actions
        while ( tThread_getState(key) == SUSPEND) sleep(1);

        switch (requestId) {
						 
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //BEGIN, preamble
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case SCE_Begin:
		   {
//			   ld=NULL;

			   //Get User And Set Precondition
			   if ( (user=tUserGetRandomly(sce)) == NULL ) {
/* EmA,14/02/2011: done in tUserGetRandomly to be protected by tUserMutex...
                   if ( tcUserGetPolicy==1 ) {
                       TRACE_CORE("End of Loop on User ---> error : %d\n",rc);
                       if (!killcalled) pthread_kill(tThread_getMainThread(), SIGINT);
					   sched_yield();	// I don't want this thread to continue immediatly
                   }
*/
				   // Error + NOT_STARTED = "could not get a free user" => suspend exec of scenario
                   rc = 0xff ;
                   end = NOT_STARTED;
			   } else {
				   tAction_freeCmdRes(&(user->cmdRes));
				   //tScePrecondition(sce, user);
				   TRACE_DEBUG("Picked-up user %s \n", tUserGetNAI(user));
			   }
		   }
		   break;
	   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //WAIT
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case SCE_Wait:
		   {
		   int		wmin = 0;						// min acceptable for min
		   int		wmax = tTimerGetMaxSleepTime();	// max acceptable for max
           int		imin, imax, wait;

			   if ( (sleepCtx = malloc(sizeof(tSleep))) == NULL ) {
				  TRACE_ERROR("can not suspend user %s \n", tUserGetNAI(user));
				  rc = 1;
			   
			   } else {
				  sleepCtx->user	= user;
				  sleepCtx->sce		= sce;
				  sleepCtx->action	= action; 
	  
				  if ( action->cmds && action->attrs && strcmp(action->cmds, KEYWD_RAND) == 0 ) {
					 // read 2 values: min and max (use wait as temp var)

					 if ( sscanf( action->attrs, "%d %d", &imin, &imax ) == 2 &&
						  wmin < imin && imin <= wmax &&
						  wmin < imax && imax <= wmax &&
						  imin <= imax  ) {

						wmin = imin;
						wmax = imax;
						wait = ( rand() % (wmax - wmin) ) + wmin;

					 } else {
						TRACE_ERROR("can not set sleep time for user %s \n", tUserGetNAI(user));
						rc = 1;
					 }

				  } else if ( action->cmds && action->attrs && ( strcmp(action->cmds, KEYWD_VALUE) == 0 )) {
					 // 1 fixed value
					 
					 if ( sscanf( action->attrs, "%d", &wait ) == 1 &&
						  wait > wmin && wait <= wmax ) {

						wmin = wait;

					 }  else {
						TRACE_ERROR("can not set sleep time for user %s \n", tUserGetNAI(user));
						rc = 1;
					 }
				  }
   
				  if ( rc = tTimerSetUserToSleep( (void *)sleepCtx, wait) )
					  TRACE_ERROR("can not insert a sleep ctx for user %s \n", tUserGetNAI(user));
			   }
			   
			   // false end: goes out the first 'while loop' (execution of the scenario)
			   end = SUSPENDED;
		   }
		   break;
	   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //END, postamble
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case SCE_End:
		   {
			   if (user) tUserFree(tUserGetId(user));

			   end = REACHED;
		   }
		   break;
   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP BIND
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Bind_Rq:
		   {
		   LDAPControl **sctrl = NULL;
		   int 			pos = 0;
		   int 			res;
		   int			i,indiceTab;

			   res = tExecBuildCtrl_Generic(action, user, &sctrl, &pos);
			   TRACE_TRAFIC("LDAP_Bind_Rq - fin build control %d \n", res);

			   rc = tLdap_BindRequest(&actionAsARequest, sctrl);
			   TRACE_TRAFIC("LDAP_Bind_Rq action end - (action=%d) \n", actionAsARequest);

			   for (i = 0; i<tcWThreadNb;i++){
				   if(tLdapLdTab[i].KeyThead == tThread_getKey()){
					   	   indiceTab=i;
				   }
			   }

			   if(rc == LDAP_SERVER_DOWN ){
				   TRACE_ERROR("LDAP_SERVER_DOWN = %s:%d\n", tLdapLdTab[indiceTab].serverHost, tLdapLdTab[indiceTab].serverPort);
			   }

               // exception: count action after (because only if really done)
               // possible because it's a short operation
               if (actionAsARequest) tStatRegulation(key);             

			   if (sctrl) ldap_controls_free(sctrl); // on nettoye aussi ceci car la stack a fait une copie
		   }
		   break;
	   
            //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
            //LDAP UNBIND
            //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
            case LDAP_UnBind_Rq:
            {
                rc = tLdap_UnbindRequest(&actionAsARequest);
				TRACE_TRAFIC("LDAP_UnBind_Rq action end - (action=%d) \n", actionAsARequest);  	

                // exception: count action after (because only if really done)
                // possible because it's a short operation
                if (actionAsARequest) tStatRegulation(key);             
            }
            break;

   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP SEARCH
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Search_Rq:
		   {
		   tCmdRes     *cmdRes = NULL;
           int          waitForRc=LDAP_SUCCESS;
		   LDAPControl **sctrl = NULL;
		   int 			pos = 0;
		   int 			res;

			   if (user->cmdRes)
				   TRACE_TRAFIC("tLdap_SearchRequest - Call with CmdRes - filter: %s, base: %s \n", user->cmdRes->filter, user->cmdRes->base);

			   if ( tExecBuildCtrl_UMA(action, user, &sctrl, &waitForRc, &pos) != 0 ) {
				   TRACE_TRAFIC("tLdap_SearchRequest - UMA-Specific Control added - oid: %s, value: %s \n", sctrl[0]->ldctl_oid, sctrl[0]->ldctl_value.bv_val);
			   } else {
				   res = tExecBuildCtrl_Generic(action, user, &sctrl, &pos);
			   }

			   TRACE_TRAFIC("tLdap_SearchRequest - fin build control %d \n", res);

               tStatRegulation(key);             

			   if (tcLdapSessionPolicy == LDAP_SES_POLICY_GLOBAL) {
				   // asychronous mode, response by the Select thread attached to ld

				   if ( (sleepCtx = malloc(sizeof(tSleep))) == NULL ) {
					  TRACE_ERROR("can not create sleep ctx for user %s \n", tUserGetNAI(user));
					  rc = 1;

				   } else {
					   TRACE_DEBUG("new sleepCtx=%d\n", sleepCtx);

					   sleepCtx->user	= user;
					   sleepCtx->sce	= sce;
					   sleepCtx->action	= action; 
	
					   if ( rc = tTimerSetUserToSleep( (void *)sleepCtx, tcLdapTimeout) )
						   TRACE_ERROR("can not insert a sleep ctx for user %s \n", tUserGetNAI(user));
	
					   rc = tLdap_SearchRequest_async(tUserGetBase(user), tUserGetScope(user), tUserGetFilter(user),
													  action->attrs, action->cmds + pos,
													  sctrl, sleepCtx,action->unLimitSize);
				   }
				   if (!rc) end = SUSPENDED;

			   } else {
				   // synchronous mode
				   rc = tLdap_SearchRequest(tUserGetBase(user), tUserGetScope(user), tUserGetFilter(user),
											action->attrs, action->cmds + pos, &cmdRes, user->priv.id,
											sctrl, waitForRc,action->unLimitSize);
			   }

			   if (tcLdapSessionPolicy != LDAP_SES_POLICY_GLOBAL || rc) { // action is finished
                   actionAsARequest=1;
				   if (rc == LDAP_TIMEOUT) retry = 1;

				   if (user->cmdRes) tAction_freeCmdRes(&(user->cmdRes));
				   user->cmdRes = cmdRes;
			   }
		   }
		   break;
   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP ASYNC SEARCH RESULT
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Search_Resp:
		   {
		   tCmdRes      *cmdRes = NULL;
           int          waitForRc=LDAP_SUCCESS;


 			   if (reqCtx->rc == LDAP_TIMEOUT) {
				   TRACE_TRAFIC("LDAP_Search_Resp (TIMEOUT) - dn: %s \n", tUserGetBase(user));
				   retry = 1;
				   getAndRemove_Request( tLdap_getLdId(key), sleepCtx );
				   free(sleepCtx);
				   
			   } else {
				   TRACE_TRAFIC("LDAP_Search_Resp (RESULT) - dn: %s \n", tUserGetBase(user));
				   //Parse result
				   rc = tLdap_SearchResult(tUserGetBase(user), tUserGetScope(user), tUserGetFilter(user),
										   action->attrs, action->cmds, &cmdRes, user->priv.id, waitForRc, reqCtx);
				   
				   if (user->cmdRes) tAction_freeCmdRes(&(user->cmdRes));
				   user->cmdRes = cmdRes;	// can be NULL
			   }

			   actionAsARequest=1;
			   tLdap_freeCtx(reqCtx);
		   }
		   break;

   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP MODIFY
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Modify_Rq:
		   {
		   LDAPControl **sctrl = NULL;
		   int 			pos = 0;
		   int 			res;

			   res = tExecBuildCtrl_Generic(action, user, &sctrl, &pos);
			   TRACE_TRAFIC("LDAP_Bind_Rq - fin build control %d \n", res);

			   actionAsARequest=1;
			   if (user->cmdRes)
				   TRACE_TRAFIC("tLdap_ModifyRequest - Call with CmdRes - dn: %s \n", user->cmdRes->base);
               
               tStatRegulation(key);             
               rc = tLdap_ModifyRequest(tUserGetBase(user), action->attrs, sctrl);
			   
               if (user->cmdRes)
				  tAction_freeCmdRes(&(user->cmdRes));
			   user->cmdRes=NULL;	

			   if (sctrl) ldap_controls_free(sctrl); // on nettoye aussi ceci car la stack a fait une copie
		   }
		   break;
   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP ADD
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Add_Rq:
		   {
		   LDAPControl **sctrl = NULL;
		   int 			pos = 0;
		   int 			res;

			   res = tExecBuildCtrl_Generic(action, user, &sctrl, &pos);
			   TRACE_TRAFIC("LDAP_Bind_Rq - fin build control %d \n", res);

			   actionAsARequest=1;
                
               tStatRegulation(key);             
			   rc = tLdap_AddRequest(tUserGetBase(user), action->attrs, sctrl);

			   if (sctrl) ldap_controls_free(sctrl); // on nettoye aussi ceci car la stack a fait une copie
		   }
		   break;
		   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //LDAP DELETE
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case LDAP_Delete_Rq:
		   {
		   LDAPControl **sctrl = NULL;
		   int 			pos = 0;
		   int 			res;

			   res = tExecBuildCtrl_Generic(action, user, &sctrl, &pos);
			   TRACE_TRAFIC("LDAP_Bind_Rq - fin build control %d \n", res);

			   actionAsARequest=1;
                
               tStatRegulation(key);             
			   rc = tLdap_DeleteRequest(tUserGetBase(user), sctrl);

			   if (sctrl) ldap_controls_free(sctrl); // on nettoye aussi ceci car la stack a fait une copie
		   }
		   break;
		   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //RADIUS ACCESS REQUEST
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case RADIUS_Auth_Rq:
		   /* case RADIUS_Auth_Rq with Wrong PassWd*/
		   case RADIUS_AuthWP_Rq:
		   {
		   int authType;
		   int sockFd;
		   int expected = (action->requestId == RADIUS_Auth_Rq ? WAIT_FOR_ACK : WAIT_FOR_RJ);
		   tActionFlags actionFlags = {0,-1,-1,0};

               // has AccountingON/OFF been sent on the user NasId ?
               if (tUserIsAborted(tUserGetId(user))) {
                   // do same as SCE_End and quit scenario
                   tUserFree(tUserGetId(user));
                   end = REACHED;
                   break;
               }

			   // get authType according to chosen policy
			   switch (tcRadiusAuthTypePolicy) {
				case RADIUS_AUTHTYPE_DISTRIB:
					authType = tRadiusAuthTypeGet();
					break;
                case RADIUS_AUTHTYPE_USER:
				case RADIUS_AUTHTYPE_READ:
				default:
					authType = tUserGetAuthType(user);
				}
               
			   TRACE_TRAFIC("authType %d for user %s \n", authType, tUserGetNAI(user));
			    
			   // read Credit Session Action: 0=Postpaid; 1=Initial; 2=Update; 3=Termination;
			   if (action->cmds && action->attrs && strcmp(action->cmds, KEYWD_PREPAID) == 0) {
					
					if (sscanf(action->attrs, "%d %d", &actionFlags.creditSessionAction, &actionFlags.relocation) != 2) {
						TRACE_ERROR("can not get valid Credit Session Action for user %s \n",tUserGetNAI(user));
						rc = 1;
					} else
						TRACE_DEBUG("get valid Credit Session Action (%d %d) for user %s \n",actionFlags.creditSessionAction, actionFlags.relocation, tUserGetNAI(user));
			   } 

			   				   
			   // Authentication required only if authtype different from NONE (value 0)
			   if (authType != AUTHTYPE_NONE) {
   
                   //EmA,18/11/2005: we handle ourself the rigth counters according to AuthType
                   if ( (authType != AUTHTYPE_EAPSIM) && (authType != AUTHTYPE_EAPTTLS) && (authType != AUTHTYPE_EAPAKA) && (authType != AUTHTYPE_EAPTLS)) {
                       actionAsARequest=1;
                   }

				   sockFd = tThread_getRadSockFd(key);
                   TRACE_DEBUG("user = %s thread = %d sockFd = %d\n", tUserGetNAI(user), key, sockFd);

                   if (authType == AUTHTYPE_EAPSIM || authType == AUTHTYPE_EAPAKA 
#ifndef SUPPLICANT_PAP_CHAP
					   || authType == AUTHTYPE_PAP || authType == AUTHTYPE_SIP_CHAP
#endif
					   ) {

				       rc = tRadius_accessRq( expected, sockFd, &retry, user, authType, (tcRadiusFastReauth>=1 ? 1 : 0), &actionFlags);

    			   } else {

                       rc = tSupplicant_accessRq( expected, sockFd, &retry, user, authType, (tcRadiusFastReauth>=1 ? 1 : 0), &actionFlags );

                       if (rc && expected==WAIT_FOR_RJ)
							// scenario will be given up but to avoid CFAC to be reached next time, we must reset unsuccesfull attemps
							// (we don't care the result of this request)
							tSupplicant_accessRq(WAIT_FOR_ACK, sockFd, &retry, user, authType, 0, &actionFlags);
                   }

                   //EmA,18/11/2005: we handle ourself the rigth counters according to AuthType
                   if ( (authType == AUTHTYPE_EAPSIM) || (authType == AUTHTYPE_EAPTTLS) || (authType == AUTHTYPE_EAPAKA) || (authType == AUTHTYPE_EAPTLS) ) {
                       tStatActionTime(action->requestId,rc,retry, tStatTimeDelta(1));
                   }
			   }
		   }
		   break;
   
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   //RADIUS ACCOUNTING REQUEST
		   //いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
		   case RADIUS_AccountStart_Rq:
		   case RADIUS_AccountInterim_Rq:
		   case RADIUS_AccountStop_Rq:
		   case RADIUS_AccountOn_Rq:
		   case RADIUS_AccountOff_Rq:
		   {
		   int          sockFd;
		   tActionFlags actionFlags = {0,-1,-1,0};

               // has AccountingON/OFF been sent on the user NasId ?
               if (tUserIsAborted(tUserGetId(user))) {
                   // do same as SCE_End and quit scenario
                   tUserFree(tUserGetId(user));
                   end = REACHED;
                   break;
               }

			   if (verbose >= 3)
				   TRACE_TRAFIC("AcctStatusType %s for user %s \n", acctStatusTypeName[action->requestId-RADIUS_AccountStart_Rq], tUserGetNAI(user));
			   
			   if (action->requestId == RADIUS_AccountStart_Rq && action->cmds && action->attrs && strcmp(action->cmds, KEYWD_BEINGOFSESSION) == 0) {
					if (sscanf(action->attrs, "%d %d", &actionFlags.beginofsession, &actionFlags.relocation) != 2) {
						TRACE_ERROR("can not get valid Begin-Of-Session parameters for user %s \n",tUserGetNAI(user));
						rc = 1;
					} else
						TRACE_DEBUG("set valid Begin-Of-Session Action (%d,%d) into actionFlags \n", actionFlags.beginofsession, actionFlags.relocation);
			   } 

			   if (action->requestId == RADIUS_AccountStop_Rq && action->cmds && action->attrs && strcmp(action->cmds, KEYWD_SESSIONCONTINUE) == 0) {
					if (sscanf(action->attrs, "%d %d", &actionFlags.sessioncontinue, &actionFlags.relocation) != 2) {
						TRACE_ERROR("can not get valid Session-Continue parameters for user %s \n",tUserGetNAI(user));
						rc = 1;
					} else
						TRACE_DEBUG("set valid Session-Continue Action (%d,%d) into actionFlags \n", actionFlags.sessioncontinue, actionFlags.relocation);
			   } 

			   actionAsARequest=1;
			   sockFd = tThread_getRadSockFd(key);
			   
			   tStatRegulation(key);             
			   rc = tRadius_accountRq( sockFd, &retry, user, action->requestId, &actionFlags );

			   if ( !rc && action->requestId==RADIUS_AccountStart_Rq ) {
				   // memorise session start time
				   tUserSetSessionStartTime( user, time(NULL), actionFlags.relocation );
			   }
		   }
		   break;
   
		   default:
			   TRACE_ERROR("Unknown Action: %d \n", action->requestId);
		   break;

        } //End of switch(action)
        if (actionAsARequest) {
            tStatCount(key);             
            tStatActionTime(action->requestId,rc,retry, 0);
        }
        if (rc) {
            // do not count "no more free user in popul" as a KO scenario !!!
            if (end == NOT_STARTED) break;

			/* EmA,02/07/2008: maybe some troubles with this next loop in case of Ldap async
            while ( action->requestId != SCE_End ) {
                action++;
            }*/

            if (first_sce_stat) {
				// count only once a scenario error
				tExecScenarioEndKo(sce, user, retry);
				first_sce_stat = 0;
			}

            if ( stopOnError & 0x01 ) {
				// skip this branch now (ASAP!)...
				stopOnError &= 0xfe;

				TRACE_ERROR("Stop on error requested (error #%d)\n", rc);
                if (!killcalled) pthread_kill(tThread_getMainThread(), SIGINT);
				sched_yield();	// I don't want this thread to continue immediatly
            }
			if ( (tcLdapSessionPolicy != LDAP_SES_POLICY_GLOBAL) && (rc == LDAP_SERVER_DOWN || rc == LDAP_LOCAL_ERROR)) {

				for (i = 0; i<tcWThreadNb;i++){
					if(tLdapLdTab[i].KeyThead == tThread_getKey()){
						indiceTab=i;
					}
				}
				// synchronous mode & ldap session is broken: there is no Select thread to close the ld, so do it here
				//tLdap_abandon( &tLdap_getLd(tThread_getKey()), 1);
				tLdap_Rebind( &tLdap_getLd(tThread_getKey()), 1);

			}
			// abort scenario if error
            if (tcAbortScenario ) {
				if (user) tUserFree(tUserGetId(user));
				break;
            }
            
        } //End if(rc)

        //Get the next action of the scenario
        action++;
		requestId = action->requestId;

      } //End of While iteration on scenario

      if ( end == REACHED && first_sce_stat )
		 tExecScenarioEnd(sce, user, retry);

   } //End of While != FINISHED
   TRACE_DEBUG("I'm dying... \n");  	
}


