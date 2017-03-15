
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>


#include "common.h"
#include "config.h"
#include "eapol_sm.h"
#include "wpa.h"
#include "eap_i.h"
#include "wpa_supplicant.h"
#include "wpa_supplicant_i.h"
#include "wpa_radius.h"
#include "l2_packet.h"
#include "hostapd.h"
#include "radius.h"
#include "config_types.h"

#include "tradius.h"
#include "tsupplicant.h"
#include "tconf.h"
#include "tthread.h"
#include "tdebug.h"
#include "tstat.h"
#include "libradius.h"

// structures from eapol_test.c
struct eapol_test_data {
	struct wpa_supplicant *wpa_s;

	int eapol_test_num_reauths;
	int no_mppe_keys;
	int num_mppe_ok, num_mppe_mismatch;

	struct radius_msg *last_recv_radius;
	struct in_addr own_ip_addr;
	struct radius_client_data *radius;
	struct hostapd_radius_servers *radius_conf;
    struct tloop_data *tloop;

	u8 *last_eap_radius; /* last received EAP Response from Authentication
			      * Server */
	size_t last_eap_radius_len;

	u8 authenticator_pmk[PMK_LEN];
	size_t authenticator_pmk_len;
	int radius_access_accept_received;
	int radius_access_reject_received;
	int auth_timed_out;

	u8 *eap_identity;

	u8 radius_identifier;
	size_t eap_identity_len;
    int socket;
    tUser * tgenUser;
    int statType;
    int statRetries;
    int requestedStatType;
    //RHL, add it for prepaid traffic
    tActionFlags *  actionFlags;
    int radius_access_accept_received_no_necessary_avp;
    
};

// structures from eloop.c
struct tloop_sock {
	int sock;
	void *tloop_data;
	void *user_data;
	void (*handler)(int sock, void *tloop_ctx, void *sock_ctx);
};

struct tloop_timeout {
	struct timeval time;
	void *tloop_data;
	void *user_data;
	void (*handler)(void *tloop_ctx, void *sock_ctx);
	struct tloop_timeout *next;
};


struct tloop_signal {
	int sig;
	void *user_data;
	void (*handler)(int sig, void *tloop_ctx, void *signal_ctx);
	int signaled;
};

struct tloop_data {
	void *user_data;
	struct tloop_sock *readers;

	struct tloop_timeout *timeout;

	int signal_count;
	struct tloop_signal *signals;
	int signaled;
	int pending_terminate;

	int terminate;
};


// structures from radius client
struct radius_client_data {
	void *ctx;
	struct hostapd_radius_servers *conf;

	int auth_serv_sock; /* socket for authentication RADIUS messages */
	int acct_serv_sock; /* socket for accounting RADIUS messages */
	int auth_serv_sock6;
	int acct_serv_sock6;
	int auth_sock; /* currently used socket */
	int acct_sock; /* currently used socket */

	struct radius_rx_handler *auth_handlers;
	size_t num_auth_handlers;
	struct radius_rx_handler *acct_handlers;
	size_t num_acct_handlers;

	struct radius_msg_list *msgs;
	size_t num_msgs;

	u8 next_radius_identifier;
};

struct hostapd_radius_server {
	/* MIB prefix for shared variables:
	 * @ = radiusAuth or radiusAcc depending on the type of the server */
	struct hostapd_ip_addr addr; /* @ServerAddress */
	int port; /* @ClientServerPortNumber */
	u8 *shared_secret;
	size_t shared_secret_len;

	/* Dynamic (not from configuration file) MIB data */
	int index; /* @ServerIndex */
	int round_trip_time; /* @ClientRoundTripTime; in hundredths of a
			      * second */
	u32 requests; /* @Client{Access,}Requests */
	u32 retransmissions; /* @Client{Access,}Retransmissions */
	u32 access_accepts; /* radiusAuthClientAccess(int)tcRadiusTimeout*100Accepts */
	u32 access_rejects; /* radiusAuthClientAccessRejects */
	u32 access_challenges; /* radiusAuthClientAccessChallenges */
	u32 responses; /* radiusAccClientResponses */
	u32 malformed_responses; /* @ClientMalformed{Access,}Responses */
	u32 bad_authenticators; /* @ClientBadAuthenticators */
	u32 timeouts; /* @ClientTimeouts */
	u32 unknown_types; /* @ClientUnknownTypes */
	u32 packets_dropped; /* @ClientPacketsDropped */
	/* @ClientPendingRequests: length of hapd->radius->msgs for matching
	 * msg_type */
};

struct hostapd_radius_servers {
	/* RADIUS Authentication and Accounting servers in priority order */
	struct hostapd_radius_server *auth_servers, *auth_server;
	int num_auth_servers;
	struct hostapd_radius_server *acct_servers, *acct_server;
	int num_acct_servers;

	int retry_primary_interval;
	int acct_interim_interval;

	int msg_dumps;
};


typedef enum {
	RADIUS_AUTH,
	RADIUS_ACCT,
	RADIUS_ACCT_INTERIM /* used only with radius_client_send(); just like
			     * RADIUS_ACCT, but removes any pending interim
			     * RADIUS Accounting packages for the same STA
			     * before sending the new interim update */
} RadiusType;

typedef enum {
	RADIUS_RX_PROCESSED,
	RADIUS_RX_QUEUED,
	RADIUS_RX_UNKNOWN,
	RADIUS_RX_INVALID_AUTHENTICATOR
} RadiusRxResult;


struct radius_rx_handler {
	RadiusRxResult (*handler)(struct radius_msg *msg,
				  struct radius_msg *req,
				  u8 *shared_secret, size_t shared_secret_len,
				  void *data);
	void *data;
};


/* RADIUS message retransmit list */
struct radius_msg_list {
	u8 addr[ETH_ALEN]; /* STA/client address; used to find RADIUS messages
			    * for the same STA. */
	struct radius_msg *msg;
	RadiusType msg_type;
	time_t first_try;
	time_t next_try;
	int attempts;
	int next_wait;
	struct timeval last_attempt;

	u8 *shared_secret;
	size_t shared_secret_len;

	/* TODO: server config with failover to backup server(s) */

	struct radius_msg_list *next;
};

// prototypes from eapol_test.c

static void send_eap_request_identity(void *tloop_ctx, void *timeout_ctx);
// set the user configuration related to authentication
struct wpa_config * wpa_config_network_set(tUser *    	  aUser, int waitFor, tActionFlags *  actionFlags);
// Add for eaptls, set the user configuration related to authentication
struct wpa_config * wpa_config_network_set_eaptls(tUser * aUser, int waitFor);
// initialize port, secret and server address
void wpa_init_conf(struct eapol_test_data *e,
			  struct wpa_supplicant *wpa_s, const char *authsrv,
			  int port, const char *secret, int sockFd);
// set the context of authentication execution
static int test_eapol(struct eapol_test_data *e, struct wpa_supplicant *wpa_s,
		      struct wpa_ssid *ssid);
// callback EAPOL completed
static void eapol_test_eapol_done_cb(void *ctx);
// send the messages
static int eapol_test_eapol_send(void *ctx, int type, const u8 *buf,
				 size_t len);
// format the radius message
static void ieee802_1x_encapsulate_radius(struct eapol_test_data *e,
					  const u8 *eap, size_t len, struct wpa_ssid *conf);
void hostapd_logger(void *ctx, u8 *addr, unsigned int module, int level,
		    char *fmt, ...);
void hexdump(const char *title, const u8 *buf,
			 size_t len);
static void eapol_test_set_config_blob(void *ctx,
				       struct wpa_config_blob *blob);
static const struct wpa_config_blob *
eapol_test_get_config_blob(void *ctx, const char *name);
static void eapol_sm_reauth(void *tloop_ctx, void *timeout_ctx);
void debug_print_timestamp(void);
static void eapol_sm_cb(struct eapol_sm *eapol, int success, void *ctx);
static void eapol_test_timeout(void *tloop_ctx, void *timeout_ctx);
static void eapol_test_terminate(int sig, void *tloop_ctx,
				 void *signal_ctx);
static RadiusRxResult
ieee802_1x_receive_auth(struct radius_msg *msg, struct radius_msg *req,
			u8 *shared_secret, size_t shared_secret_len,
			void *data);
static int eapol_test_compare_pmk(struct eapol_test_data *e);
static void ieee802_1x_get_keys(struct eapol_test_data *e,
				struct radius_msg *msg, struct radius_msg *req,
				u8 *shared_secret, size_t shared_secret_len);
// add for ttls cpy vsa
void copyVSAAttrValue_TTLS(char* destVSA, char* srcVSA, int length, int isAdd0x);				

// RHL | 08/26/2008 | used to get wimax vsa such as AAA-Session-ID and PPAQ for
// 			testing Prepaid charging with eap-ttls
// return: 1: normal end; -1: no AAA-Session-ID in AA, -2: no PPAQ in AA
static int ieee802_1x_get_wimax_vsa(struct eapol_test_data *e,
				struct radius_msg *msg, int creditSessionAction);

/* RHL; Sep 16, 2008; It will put the Wimax VSA value to ssid*/
int ieee802_1x_put_wimax_vsa(  struct wpa_ssid *ssid,
                  tUser *    	aUser,
		  int 	        creditSessionAction);
		  
static void ieee802_1x_decapsulate_radius(struct eapol_test_data *e);
const char * hostapd_ip_txt(const struct hostapd_ip_addr *addr, char *buf,
			    size_t buflen);
static void test_eapol_clean(struct eapol_test_data *e,
			     struct wpa_supplicant *wpa_s);



static void radius_client_deinit(struct radius_client_data*);
static char *eap_type_text(u8);

// radius client prototypes
static int
radius_change_server(struct radius_client_data *radius,
		     struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int sock6, int auth);
static int radius_client_init_acct(struct radius_client_data *radius);
static int radius_client_init_auth(struct radius_client_data *radius);
struct radius_client_data *
radius_client_init(void *ctx, struct hostapd_radius_servers *conf);
int radius_client_register(struct radius_client_data *radius,
			   RadiusType msg_type,
			   RadiusRxResult (*handler)(struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data);
static void radius_client_handle_send_error(struct radius_client_data *radius,
					    int s, RadiusType msg_type);
static int radius_client_retransmit(struct radius_client_data *radius,
				    struct radius_msg_list *entry, time_t now);
static void radius_client_timer(void *tloop_ctx, void *timeout_ctx);
static void radius_client_update_timeout(struct radius_client_data *radius);
static void radius_client_list_add(struct radius_client_data *radius,
				   struct radius_msg *msg,
				   RadiusType msg_type, u8 *shared_secret,
				   size_t shared_secret_len, u8 *addr);
static void radius_client_list_del(struct radius_client_data *radius,
				   RadiusType msg_type, u8 *addr);
static void radius_retry_primary_timer(void *tloop_ctx, void *timeout_ctx);
int radius_client_send(struct radius_client_data *radius,
		       struct radius_msg *msg, RadiusType msg_type, u8 *addr);
static void radius_client_receive(int sock, void *tloop_ctx, void *sock_ctx);
u8 radius_client_get_id(struct radius_client_data *radius);
void radius_client_flush(struct radius_client_data *radius);
static int
radius_change_server(struct radius_client_data *radius,
		     struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int sock6, int auth);


// tloop prototypes  (from eloop)
struct tloop_data * tloop_init(void *user_data);
int tloop_register_timeout(struct tloop_data* tloop,
                           unsigned int secs, unsigned int usecs,
			   void (*handler)(void *tloop_ctx, void *timeout_ctx),
			   void *tloop_data, void *user_data);
void tloop_run(struct tloop_data* tloop);
void tloop_destroy(struct tloop_data* tloop);
void tloop_terminate(struct tloop_data* tloop);
void tloop_unregister_read_sock(struct tloop_data* tloop, int sock);
int tloop_register_read_sock(struct tloop_data* tloop, int sock,
			     void (*handler)(int sock, void *tlooptcGetNAI_ctx,
					     void *sock_ctx),
			     void *tloop_data, void *user_data);
int tloop_terminated(struct tloop_data* tloop);


const char *as_secret = "radius";
extern int wpa_debug_level;
extern int wpa_debug_show_keys;


struct wpa_driver_ops *wpa_supplicant_drivers[] = { };

static unsigned char ident = 0;

unsigned char random_own_addr_last = 2;

/* timeout global for an authentication */
int authen_timeout;
int authenWP_timeout; 

// EmA,12/09/2008: common to TTLS & TLS
static int tls_certs_count = -1;

/* mutex to protect the global data ident: the RADIUS identifier */
pthread_mutex_t            identMutex = PTHREAD_MUTEX_INITIALIZER;

/* Defaults for RADIUS retransmit values (exponential backoff) */
/*#define RADIUS_CLIENT_FIRST_WAIT 3  seconds */
/*#define RADIUS_CLIENT_MAX_WAIT 120  seconds */
/*#define RADIUS_CLIENT_MAX_RETRIES 10 
 maximum number of retransmit attempts
				      * before entry is removed from retransmit
				      * list */
#define RADIUS_CLIENT_MAX_ENTRIES 30 /* maximum number of entries in retransmit
				      * list (oldest will be removed, if this
				      * limit is exceeded) */
#define RADIUS_CLIENT_NUM_FAILOVER 4 /* try to change RADIUS server after this
				      * many failed retry attempts */


#define TLOOP_ALL_CTX (void *) -1

/******************************************************************************/
static char *eap_type_text(u8 type)
/******************************************************************************/
{
	switch (type) {
	case EAP_TYPE_IDENTITY: return "Identity";
	case EAP_TYPE_NOTIFICATION: return "Notification";
	case EAP_TYPE_NAK: return "Nak";
	case EAP_TYPE_TLS: return "TLS";
	case EAP_TYPE_TTLS: return "TTLS";
	case EAP_TYPE_PEAP: return "PEAP";
	case EAP_TYPE_SIM: return "SIM";
	case EAP_TYPE_GTC: return "GTC";
	case EAP_TYPE_MD5: return "MD5";
	case EAP_TYPE_OTP: return "OTP";
	default: return "Unknown";
	}
}

// radius_client part
/******************************************************************************/
static void radius_client_msg_free(struct radius_msg_list *req)
/******************************************************************************/
{
	radius_msg_free(req->msg);
	free(req->msg);
	free(req);
}

/******************************************************************************/
static void radius_client_deinit(struct radius_client_data *radius)
/******************************************************************************/
{
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
	if (!radius)
		return;

	tloop_cancel_timeout(e->tloop, radius_retry_primary_timer, radius, NULL);

	radius_client_flush(radius);
	free(radius->auth_handlers);
	free(radius->acct_handlers);
	free(radius);
}



/******************************************************************************/
int tSupplicantInit()
/******************************************************************************/
{

    // get Radius secret from environment variable RAD_SECRET
    as_secret = RADIUS_CLIENT_HOST_PASSWD;

/* EmA,27/11/2007: MaxDelay has nothing to deal with the timeout !!!
    // Is this maximum duration compatible with the retry number and the retry timeout ?
    // find the maximum duration in milliseconds for an authentication: RADIUS_Auth_Rq or RADIUS_AuthWP_Rq
    authen_timeout = ProfileGetInt( inifile, "MaxDelay", "RADIUS_Auth_Rq", 40000); 
    if (authen_timeout <= (tcRadiusRetries * 1000 * tcRadiusTimeout)){
        TRACE_CRITICAL("tgen.ini inconsistency: MaxDelay (in ms) for RADIUS_Auth_Rq should be greater than Radius_timeout (in s) * Radius_retries\n");
        return 1;
    }
    authenWP_timeout = ProfileGetInt( inifile, "MaxDelay", "RADIUS_AuthWP_Rq", 40000);
    if (authen_timeout <= (tcRadiusRetries * 1000 * tcRadiusTimeout)){
        TRACE_CRITICAL("tgen.ini inconsistency: MaxDelay (in ms) for RADIUS_AuthWP_Rq should be greater than Radius_timeout (in s) * Radius_retries\n");
        return 1;
    }
*/
    return 0;

}


/******************************************************************************/
static void tSupplicant_abandon()
/******************************************************************************/
{
int      threadId=tThread_getKey();
       
    if (verbose >= 2)
        TRACE_CORE("tradius abandon on thread: %d\n", threadId);
    
    /* Close current socket */
    close( tThread_getRadSockFd(threadId) );
    
    /* Create socket for sending request */             
    tThread_getRadSockFd(threadId) =  socket(AF_INET, SOCK_DGRAM, 0);
    if ( tThread_getRadSockFd(threadId) < 0) {
        perror("tSupplicantInit: socket creation failure");
		exit(0);
	}
    

}

/******************************************************************************/
/*RHL | Sep 16, 2008 | add creditSesAction into tActionFlags*/
/*                     for prepaid charging traffic with eapttls              */
int tSupplicant_accessRq( 
                      int             waitFor,
                      int       	  sockFd,
                      int *			  retries,
                      tUser *    	  aUser,
                      int			  authType,
                      int             fasteap,
		      tActionFlags *  actionFlags)
/******************************************************************************/
{
    // gives input data in wpa_s format
    struct eapol_test_data *eapol_test;
    struct wpa_supplicant *wpa_s;
    int c, ret = 0, wait_for_monitor = 0, save_config = 0;
	char *conf = NULL;
    struct hostapd_radius_server *radiusServer;
    struct hostapd_radius_servers * radiusConf;
    char *    		aNai = tUserGetNAI(aUser);
    int timeout;
    int printed = 0;
	int temp;
    int creditSessionAction = actionFlags->creditSessionAction;  
    TRACE_DEBUG("Enter into tSupplicant_accessRq , authType = %d, fasteap = %d, creditSessionAction = %d\n",authType,fasteap,creditSessionAction);

    if (debug || verbose >= 3) {
        wpa_debug_level = 0;
    } else
        wpa_debug_level = 10;
    eapol_test = (struct eapol_test_data *)malloc(sizeof(struct eapol_test_data));
    memset(eapol_test, 0, sizeof(*eapol_test));
    wpa_s = (struct wpa_supplicant *)malloc(sizeof(struct wpa_supplicant));
    eapol_test->tloop = tloop_init(wpa_s);
    eapol_test->socket = sockFd;
    eapol_test->tgenUser = aUser;
    
    //RHL, add it for prepaid traffic
    eapol_test->actionFlags = actionFlags;

    memset(wpa_s, 0, sizeof(*wpa_s));
	eapol_test->wpa_s = wpa_s;

	// RHL; 01/08/2008; add the brance to generate calling-station-id randomly for eap-tls
	wpa_s->own_addr[5] = 2;
	
	if (tls_certs_count == -1) {
		tls_certs_count = ProfileGetInt( inifile, "Radius", "tls_certs_count", "", 0);
        srand((int)time(0)); 
	}
    	if (tls_certs_count == 0) {
    		TRACE_DEBUG("wpa_init_conf: The calling-station-id will be fixed (00-00-00-00-00-02) due to tls_certs_count is not defined in tgen.ini to support eap-tls [Radius]\n");
    		random_own_addr_last = wpa_s->own_addr[5];
	} else {
		TRACE_DEBUG("wpa_init_conf: The calling-station-id will be random (00-00-00-00-00-xx). Note that the xx is 1-%d \n",tls_certs_count);
    		int random_addr; 
        	//random_addr = 1+(int)(50.0*rand()/(RAND_MAX+1.0)); 
		random_addr = 1+ rand() % tls_certs_count;
        TRACE_TRAFIC(" The random_own_addr_last is %d \n",random_addr);
		
        	wpa_s->own_addr[5] = (unsigned char)random_addr; 
		random_own_addr_last = wpa_s->own_addr[5];
	}
	
    // set the user input data for authentication
	if ( authType == AUTHTYPE_EAPTLS ){
		TRACE_DEBUG("tSupplicant_accessRq for eap-tls\n");
		wpa_s->conf = wpa_config_network_set_eaptls(aUser, waitFor);
	} else {
		// the default case, mainly for eap-ttls
		TRACE_DEBUG("tSupplicant_accessRq for eap-ttls\n");
		wpa_s->conf = wpa_config_network_set(aUser, waitFor, actionFlags);
	}

    if (wpa_s->conf == NULL) {
		TRACE_ERROR("%s:%d => tSupplicant_accessRq: failure in building wpa_s.conf\n", __FILE__, __LINE__);
		return 1;
	}
	if (wpa_s->conf->ssid == NULL) {
		TRACE_ERROR("%s:%d => tSupplicant_accessRq: failure in building wpa_s.conf->ssid\n", __FILE__, __LINE__);
		return 1;
	}

	// Customizing for each user the Nas-IP-Address
	temp = MIN( 255, (aUser->priv.id % tcRadiusNbNas) + 1);
	TRACE_DEBUG("Auth debug, UserId=%d temp=%d\n", aUser->priv.id, temp );
	eapol_test->own_ip_addr.s_addr = htonl((127 << 24) | temp);

    wpa_init_conf(eapol_test, wpa_s, tcServerHost[tcActiveServerId], tcServerRADIUSPort, as_secret, sockFd);

    if (test_eapol(eapol_test, wpa_s, wpa_s->conf->ssid)) {
        TRACE_ERROR("%s:%d => tSupplicant_accessRq: failure in test_eapol\n", __FILE__, __LINE__);
        return 1;
    }

    // enable fast re-auth e.g. session resumption if fasteap == 1
    if (fasteap) {
        eapol_test -> eapol_test_num_reauths = tcRadiusFastReauth;
    } else {
        eapol_test -> eapol_test_num_reauths = -1;
    }

    TRACE_DEBUG("tSupplicant_accessRq for user = %s\n", aNai);

    // begin authentication stats (timer 1)
	tStatTimeBegin(1);

    // send the initial EAP response id
    send_eap_request_identity(wpa_s, NULL);

    // find the maximum duration in seconds for an authentication: RADIUS_Auth_Rq or RADIUS_AuthWP_Rq
	timeout = tcRadiusTimeout*tcRadiusRetries; 
    if (waitFor == WAIT_FOR_ACK) {
//        timeout = authen_timeout;
       eapol_test ->requestedStatType = RADIUS_Auth_Rq;
    } else {
//        timeout = authenWP_timeout;
        eapol_test ->requestedStatType = RADIUS_AuthWP_Rq;
    }
//    timeout = timeout / 1000;

    // if fast re-auth, a tloop is active for 1 auth + nb re-auth
    if (fasteap) {
        timeout = timeout * (tcRadiusFastReauth+1);
    }

    // authentication + subsequent re-authentications max duration timeout
    tloop_register_timeout(eapol_test->tloop, timeout, 0, eapol_test_timeout, eapol_test, NULL);

    // activate the socket
    tloop_run(eapol_test->tloop);

    // when tloop_run is exited authentication + subsequent re-authentications are ended
    // stop authentication stats
    tStatTimeEnd(1);

     // if the authentif + subs re-authentif. last more than timeout, it is KO
    if (ret == 0 && eapol_test->auth_timed_out == 1){
        ret = 1;
    }

    // if a reject was received, the authentification is KO
    if (ret == 0 && eapol_test->radius_access_reject_received == 1) {
        ret = 1;
    }
    
    // test the PMK mismatch
    if (ret == 0 && eapol_test_compare_pmk(eapol_test) == 1)
        ret = 1;
	
    // Access-Accept was received but NO Necessary AVPs such as AAA-Session-ID or PPAQ, the authentification is KO
    if (ret == 0 && eapol_test->radius_access_accept_received_no_necessary_avp == 1)
    	ret = 1;
   
    /*if (save_config)
        wpa_config_write(conf, wpa_s.conf);  */

    // update retries
    radiusConf = eapol_test->radius_conf;
    radiusServer = radiusConf->auth_server;
    *retries = radiusServer->retransmissions;

    
    
    // free eapol_test resources
    test_eapol_clean(eapol_test, wpa_s);

    // free tloop resources
    if (eapol_test->tloop) {
        tloop_destroy(eapol_test->tloop);
    }

    

    // PMK mismatch, auth is KO
    //if (ret == 0 && eapol_test->num_mppe_ok == 0 && eapol_test->num_mppe_mismatch == 1)
    //    ret = 1;

	// EmA,15/10/2008: FR SDMAAAFAG221459
    if (ret == 1) {
        if (eapol_test->auth_timed_out){
    	    TRACE_ERROR("Access Request timeout for user %s\n", aNai);
            printed = 1;
        }
    	if (!printed && eapol_test->radius_access_reject_received){
			if (waitFor == WAIT_FOR_RJ) {
				TRACE_TRAFIC("Access Request rejected for user %s\n", aNai);
				ret = 0;
			} else
				TRACE_ERROR("Access Request rejected for user %s\n", aNai);
			printed = 1;
        }
        if (!printed && eapol_test->num_mppe_mismatch)
            TRACE_ERROR("Access Request failed for user %s due to PMK mismatch\n", aNai);
	if (!printed && eapol_test->radius_access_accept_received_no_necessary_avp)
            TRACE_ERROR("Access Request failed for user %s due to lack of AAA-Session-ID or PPAQ in accept message\n", aNai);
	    
    } else {
		if (waitFor == WAIT_FOR_RJ && !eapol_test->radius_access_reject_received){
			TRACE_ERROR("Expected Access Reject not received for user %s\n", aNai);
			ret = 1;
		}

        TRACE_TRAFIC("SUCCESS for user %s:\n", aNai); 

	}

	free (eapol_test);

    // it is necessary to close the socket before using tRadius_accountingRq
	tSupplicant_abandon();

    return ret;
}
/******************************************************************************/
static void send_eap_request_identity(void *tloop_ctx, void *timeout_ctx)
/******************************************************************************/
{
	struct wpa_supplicant *wpa_s = tloop_ctx;
	u8 buf[100], *pos;
	struct ieee802_1x_hdr *hdr;
	struct eap_hdr *eap;

	hdr = (struct ieee802_1x_hdr *) buf;
	hdr->version = EAPOL_VERSION;
	hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
	hdr->length = htons(5);


	eap = (struct eap_hdr *) (hdr + 1);
	eap->code = EAP_CODE_REQUEST;
        eap->identifier = 0;
        eap->length = htons(5);
	pos = (u8 *) (eap + 1);
	*pos = EAP_TYPE_IDENTITY;

	TRACE_DEBUG("%s:%d => Sending fake EAP-Request-Identity\n", __FILE__, __LINE__);
	eapol_sm_rx_eapol(wpa_s->eapol, wpa_s->bssid, buf,
			  sizeof(*hdr) + 5);

    
}
// RHL; Sep 16, 2008; Add VSA Wimaxcapacity, servicetype, session_termination_capability, 
//                    ppac into wpa_ssid to test Prepaid charging with TTLS
/******************************************************************************/
struct wpa_config * wpa_config_network_set(tUser *    	  aUser, int waitFor, tActionFlags *  actionFlags)
/******************************************************************************/
{
	int errors = 0; 
  	struct wpa_ssid *ssid;
    struct wpa_config *config;
	int prio;
    u8 *methods = NULL, *tmp;
    size_t num_methods = 0;
    static char    ca_cert[256] = "not_read";
    static char    ca_path[256] = "not_read";
    static char    etp2[256] = "not_read";
    static char    ai[256] = "not_read";
    int cert_defined = 0;
    int path_defined = 0;
    int creditSessionAction = actionFlags->creditSessionAction;
    TRACE_DEBUG("Enter into wpa_config_network_set, creditSessionAction = %d\n",creditSessionAction);

	config = wpa_config_alloc_empty(NULL, NULL);
	if (config == NULL)
		return NULL;

    // set the "network" config , only 1 config so id = 0
    ssid = (struct wpa_ssid *) malloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	memset(ssid, 0, sizeof(*ssid));
    ssid->id = 0;

    wpa_config_set_network_defaults(ssid);

    // ssid="client_EAP-TTLS"
    ssid->ssid = (u8*) malloc(strlen("client_EAP-TTLS")+1);
    strcpy(ssid->ssid, "client_EAP-TTLS");  
    ssid ->ssid_len = strlen(ssid->ssid);

    // key_mgmt=WPA-EAP
    ssid->key_mgmt = 1; 

    // eap=TTLS
    ssid->non_leap = 1; 
    tmp = methods;
    methods = realloc(methods, 2);
    if (methods == NULL) {
        free(tmp);
        return NULL;
    }
    methods[0] = EAP_TYPE_TTLS;
    methods[1] = EAP_TYPE_NONE;
    ssid->eap_methods = methods;
    // identity =

    ssid->identity = (u8*) malloc(strlen(tUserGetNAI(aUser))+1);
    strcpy(ssid->identity, tUserGetNAI(aUser));
    ssid->identity_len = strlen(ssid->identity);

    // password = 
    if (waitFor == WAIT_FOR_ACK) {
        ssid->password = (u8*) malloc(strlen(tUserGetPasswd(aUser))+1);
        strcpy(ssid->password, tUserGetPasswd(aUser));
    } else {
        ssid->password = (u8*) malloc(strlen("badPasswd")+1);
        strcpy(ssid->password, "badPasswd");
    }
    ssid->password_len = strlen(ssid->password);

    //  ca_cert = 
	if (strcmp (ca_cert, "not_read") == 0) ProfileGetString( inifile, "Radius", "ca_cert", "", ca_cert, sizeof(ca_cert) );
	if (strcmp (ca_cert, "") != 0) {
		ssid->ca_cert = (u8*)malloc(strlen(ca_cert)+1);
		strcpy(ssid->ca_cert, ca_cert);
//		ca_cert[0] = '\0';
		cert_defined = 1;
	}
	//  ca_path = 
	if (strcmp (ca_path, "not_read") == 0) ProfileGetString( inifile, "Radius", "ca_path", "", ca_path, sizeof(ca_path) );
	if (strcmp (ca_path, "") != 0) {
		ssid->ca_path = (u8*)malloc(strlen(ca_path)+1);
		strcpy(ssid->ca_path, ca_path);
//		ca_path[0] = '\0';
        path_defined = 1;
    }
    if (!cert_defined && !path_defined) {
        TRACE_ERROR("wpa_config_network_set: ca_cert or ca_path should be defined in tgen.ini [Radius]\n");
        errors++;
    }

    // phase2="auth=CHAP"
    if (strcmp (etp2, "not_read") == 0) ProfileGetString( inifile, "Radius", "eap_ttls_phase2", "", etp2, sizeof(etp2));
    if (strcmp (etp2, "") == 0) {
        TRACE_ERROR("wpa_config_network_set: eap_ttls_phase2 should be defined in tgen.ini [Radius]\n");
        errors++;
    } else {
        ssid->phase2 = (u8*)malloc(strlen("auth=") + strlen(etp2)+1);
        strcpy(ssid->phase2, "auth=");
        strcat(ssid->phase2, etp2);
//        cert[0] = '\0';
    }

    // anonymous_identity
    if (strcmp (ai, "not_read") == 0) ProfileGetString( inifile, "Radius", "anonymous_identity", "", ai, sizeof(ai));
    if (strcmp (ai, "") == 0) {
        TRACE_ERROR("wpa_config_network_set: anonymous_identity should be defined in tgen.ini [Radius]\n");
        errors++;
    } else {
        ssid->anonymous_identity = (u8*)malloc(strlen(ai)+1);
        strcpy(ssid->anonymous_identity, ai);
        ssid->anonymous_identity_len = strlen(ai);
    }
    // RHL; Sep 16, 2008; Add VSA Wimaxcapacity, servicetype, ppac, session_termination_capability into wpa_ssid to test Prepaid charging with TTLS
    if(ieee802_1x_put_wimax_vsa(ssid,aUser,creditSessionAction) < 0)
    	errors++;
    TRACE_DEBUG("wpa_config_network_set: put the WiMAX VSA for TTLS\n");	
    // eap_workaround=0
    ssid->eap_workaround = 0;

    ssid ->pnext = NULL;

    if (wpa_config_add_prio_network(config, ssid)) {
        TRACE_ERROR("wpa_config_network_set: failed to add network block to priority list\n");
        errors++;
    }

	config->ssid = ssid;
	for (prio = 0; prio < config->num_prio; prio++) {
		ssid = config->pssid[prio];
		while (ssid) {
			ssid = ssid->pnext;
		}
	}
	if (errors) {
		wpa_config_free(config);
		config = NULL;
	}

	return config;
}



/************************************************************************************************/
/* RHL; Aug 1, 2008; it is used to form the wpa_ssid info for eap-tls 	      			*/
/* It has two main cases: 									*/
/* 1, use the default certificate together with calling-station-id 00-00-00-00-00-02		*/
/* 2, use pre-generated certificates together with random calling-station-id 00-00-00-00-00-xx	*/
/************************************************************************************************/
/* RHL; Sep 3, 2008; Add  VSA Wimaxcapacity and servicetype into wpa_ssid to test OnlineSubscription RT part	*/
/************************************************************************************************/
struct wpa_config * wpa_config_network_set_eaptls(tUser *    	  aUser, int waitFor)
{
	int errors = 0; 
  	struct wpa_ssid *ssid;
    struct wpa_config *config;
	int prio;
    u8 *methods = NULL, *tmp;
    size_t num_methods = 0;

    static char ca_cert_tls[256] = "not_read";
    int cert_defined = 0;
    static char tls_certs_parent_path[256] = "not_read";
    int path_defined = 0;

	static char client_cert_tls_default[256] = "not_read";
    int client_cert_defined = 0;
	static char private_key_tls_default[256] = "not_read";
    int private_key_defined = 0;
	static char private_key_passwd_tls_default[256] = "not_read";
    int private_key_passwd_defined = 0;

    static char servicetype_ols[16] = "not_read";
    static char wimaxcapability_ols[256] = "not_read";
    
	TRACE_DEBUG("Enter into wpa_config_network_set_eaptls\n");
	 
	config = wpa_config_alloc_empty(NULL, NULL);
	if (config == NULL)
		return NULL;

    // set the "network" config , only 1 config so id = 0
    ssid = (struct wpa_ssid *) malloc(sizeof(*ssid));
	if (ssid == NULL)
		return NULL;
	memset(ssid, 0, sizeof(*ssid));
    ssid->id = 0;

    wpa_config_set_network_defaults(ssid);

    // ssid="client_EAP-TLS"
    ssid->ssid = (u8*) malloc(strlen("client_EAP-TLS")+1);
    strcpy(ssid->ssid, "client_EAP-TLS");  
    ssid ->ssid_len = strlen(ssid->ssid);

    // key_mgmt=WPA-EAP
    ssid->key_mgmt = 1; 

    // eap=TLS
    ssid->non_leap = 1; 
    tmp = methods;
    methods = realloc(methods, 2);
    if (methods == NULL) {
        free(tmp);
        return NULL;
    }
    methods[0] = EAP_TYPE_TLS;
    methods[1] = EAP_TYPE_NONE;
    ssid->eap_methods = methods;
    
    
    // identity =
    ssid->identity = (u8*) malloc(strlen(tUserGetNAI(aUser))+1);
    strcpy(ssid->identity, tUserGetNAI(aUser));
    ssid->identity_len = strlen(ssid->identity);
    TRACE_TRAFIC("wpa_config_network_set_eaptls: The NAI is %s \n", tUserGetNAI(aUser));
		
    // RHL; Sep 3, 2008; Add VSA Wimaxcapacity and servicetype into wpa_ssid to test OnlineSubscription RT part
	if (strcmp (servicetype_ols, "not_read") == 0) ProfileGetString( inifile, "Radius", "servicetype_ols", "2", servicetype_ols, sizeof(servicetype_ols) );
	if (strcmp (servicetype_ols, "") != 0) {
    ssid->servicetype = (u8*)malloc(strlen(servicetype_ols)+1);
    strcpy(ssid->servicetype, servicetype_ols);
    TRACE_DEBUG("wpa_config_network_set_eaptls: The servicetype is %s \n", servicetype_ols);
	}
    
    if (strcmp (wimaxcapability_ols, "not_read") == 0) ProfileGetString( inifile, "Radius", "wimaxcapability_ols", "", wimaxcapability_ols, sizeof(wimaxcapability_ols) );
	if (strcmp (wimaxcapability_ols, "") != 0) {
    ssid->wimaxcapability = (u8*)malloc(strlen(wimaxcapability_ols)+1);
    strcpy(ssid->wimaxcapability,wimaxcapability_ols);
    TRACE_DEBUG("wpa_config_network_set_eaptls: The wimaxcapability is %s \n", wimaxcapability_ols);
	}
	
	/*
    // password = 
    if (waitFor == WAIT_FOR_ACK) {
        ssid->password = (u8*) malloc(strlen(tUserGetPasswd(aUser))+1);
        strcpy(ssid->password, tUserGetPasswd(aUser));
    } else {
        ssid->password = (u8*) malloc(strlen("badPasswd")+1);
        strcpy(ssid->password, "badPasswd");
    }
    ssid->password_len = strlen(ssid->password);
	*/
    
    //  ca_cert = 
    if (strcmp (ca_cert_tls, "not_read") == 0) ProfileGetString( inifile, "Radius", "ca_cert_tls", "", ca_cert_tls, sizeof(ca_cert_tls) );
    if (strcmp (ca_cert_tls, "") != 0) {
        ssid->ca_cert = (u8*)malloc(strlen(ca_cert_tls)+1);
        strcpy(ssid->ca_cert, ca_cert_tls);
//        cert[0] = '\0';
        cert_defined = 1;
    }
    /*
 	//  ca_path = 
    ProfileGetString( inifile, "Radius", "ca_path_tls", "", cert, sizeof(cert) );
    if (strcmp (cert, "") != 0) {
       	ssid->ca_path = (u8*)malloc(strlen(cert)+1);
        strcpy(ssid->ca_path, cert);
        cert[0] = '\0';
        path_defined = 1;
    }
    */
    if (!cert_defined) {
        TRACE_ERROR("wpa_config_network_set_eaptls: ca_cert_tls should be defined in tgen.ini [Radius]\n");
        errors++;
    }	


	if (tls_certs_count == -1) tls_certs_count = ProfileGetInt( inifile, "Radius", "tls_certs_count", "", -1);
    if (tls_certs_count == -1) {
    	TRACE_ERROR("wpa_config_network_set_eaptls: tls_certs_count should be defined in tgen.ini to support eap-tls [Radius]\n");
    }
    
    //  tls_certs_parent_path = 
    if (strcmp (tls_certs_parent_path, "not_read") == 0) ProfileGetString( inifile, "Radius", "tls_certs_parent_path", "", tls_certs_parent_path, sizeof(tls_certs_parent_path) );

	if (tls_certs_count > 0 && strcmp (tls_certs_parent_path, "") != 0) {
    	
	//if (strcmp(tls_certs_parent_path[strlen(tls_certs_parent_path)-1],"/") != 0)
	//	strcat(tls_certs_parent_path,"/");
	
	
	// The random valud is generated in wpa_init_conf() and set into one global variable
    	// int index = rand() % tls_certs_count;
		TRACE_TRAFIC("wpa_config_network_set_eaptls: The random tls certificate index is %02x \n", random_own_addr_last);
	
	// here the cacert should be the CACert.pem of the server side certificate
	/*
	char cacert[128] = "";
	sprintf(cacert, "%s%s%d%s",tls_certs_parent_path,"cacert",index,".pem");
	TRACE_CORE("wpa_config_network_set_eaptls: ssid->ca_cert = %s\n", cacert);
	ssid->ca_cert = (u8*)malloc(strlen(cacert)+1);
	strcpy(ssid->ca_cert, cacert);//cacert.pem
	*/
	
	char client_cert[128] = "";
	sprintf(client_cert, "%s%s%02x%s",tls_certs_parent_path,"client_cert",random_own_addr_last,".pem");
	TRACE_CORE("wpa_config_network_set_eaptls: ssid->client_cert = %s\n", client_cert);
	ssid->client_cert = (u8*)malloc(strlen(client_cert)+1);
	strcpy(ssid->client_cert, client_cert);//client_cert.pem
	
	char privkey1[128] = "";
	sprintf(privkey1, "%s%s%02x%s",tls_certs_parent_path,"privkey1_",random_own_addr_last,".pem");
	TRACE_CORE("wpa_config_network_set_eaptls: ssid->private_key = %s\n", privkey1);
	ssid->private_key = (u8*)malloc(strlen(privkey1)+1);
	strcpy(ssid->private_key, privkey1);//privkey1.pem
	
		//  private_key_passwd = 
		if (strcmp (private_key_passwd_tls_default, "not_read") == 0) ProfileGetString(inifile, "Radius", "private_key_passwd_tls_default", "", private_key_passwd_tls_default, sizeof(private_key_passwd_tls_default));
		if (strcmp(private_key_passwd_tls_default, "") != 0) {
			ssid->private_key_passwd = (u8*)malloc(strlen(private_key_passwd_tls_default)+1);
			strcpy(ssid->private_key_passwd, private_key_passwd_tls_default);
//			cert[0] = '\0';
		private_key_passwd_defined = 1;
	} else {
		TRACE_ERROR("wpa_config_network_set_eaptls: private_key_passwd_tls_default should be defined in tgen.ini [Radius]\n");
        	errors++;
	}
	
    } else {
    	TRACE_DEBUG("wpa_config_network_set_eaptls: it has to use the Default attributes to test eap-tls. \n");
	
    	//  client_cert = 
    	if (strcmp (client_cert_tls_default, "not_read") == 0) ProfileGetString( inifile, "Radius", "client_cert_tls_default", "", client_cert_tls_default, sizeof(client_cert_tls_default) );
    	if (strcmp (client_cert_tls_default, "") != 0) {
        	ssid->client_cert = (u8*)malloc(strlen(client_cert_tls_default)+1);
        	strcpy(ssid->client_cert, client_cert_tls_default);
//        	cert[0] = '\0';
        	client_cert_defined = 1;
    	}

    	//  private_key = 
    	if (strcmp (private_key_tls_default, "not_read") == 0) ProfileGetString(inifile, "Radius", "private_key_tls_default", "", private_key_tls_default, sizeof(private_key_tls_default));
		if (strcmp(private_key_tls_default, "") != 0) {
			ssid->private_key = (u8*)malloc(strlen(private_key_tls_default)+1);
			strcpy(ssid->private_key, private_key_tls_default);
//			cert[0] = '\0';
		private_key_defined = 1;
	}

    	//  private_key_passwd = 
    	if (strcmp (private_key_passwd_tls_default, "not_read") == 0) ProfileGetString(inifile, "Radius", "private_key_passwd_tls_default", "", private_key_passwd_tls_default, sizeof(private_key_passwd_tls_default));
		if (strcmp(private_key_passwd_tls_default, "") != 0) {
			ssid->private_key_passwd = (u8*)malloc(strlen(private_key_passwd_tls_default)+1);
			strcpy(ssid->private_key_passwd, private_key_passwd_tls_default);
//			cert[0] = '\0';
		private_key_passwd_defined = 1;
	}
	
	if (!client_cert_defined || !private_key_defined || !private_key_passwd_defined ) {
		TRACE_ERROR("wpa_config_network_set_eaptls: the default client_cert, private_key and private_key_passwd should be defined in tgen.ini to support eap-tls [Radius]\n");
		errors++;
	}
    }
 
    //proto=RSN
    ssid->proto = WPA_PROTO_RSN;
    
    //pairwise=CCMP TKIP
    ssid->pairwise_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
    
    //group=CCMP TKIP
    ssid->group_cipher = WPA_CIPHER_CCMP | WPA_CIPHER_TKIP;
   
    
    // eap_workaround=0
    ssid->eap_workaround = 0;

    ssid ->pnext = NULL;

    if (wpa_config_add_prio_network(config, ssid)) {
        TRACE_ERROR("wpa_config_network_set_eaptls: failed to add network block to priority list\n");
        errors++;
    }

	config->ssid = ssid;
	for (prio = 0; prio < config->num_prio; prio++) {
		ssid = config->pssid[prio];
		while (ssid) {
			ssid = ssid->pnext;
		}
	}
	if (errors) {
		wpa_config_free(config);
		config = NULL;
	}
	
	TRACE_DEBUG("\n Leaving wpa_config_network_set_eaptls\n");

	return config;
}


/******************************************************************************/
void wpa_init_conf(struct eapol_test_data *e,
			  struct wpa_supplicant *wpa_s, const char *authsrv,
			  int port, const char *secret, int sockFd)
/******************************************************************************/
{
	struct hostapd_radius_server *as;
	int res;

	wpa_s->bssid[5] = 1;
	//wpa_s->own_addr[5] = 2;
		
//	e->own_ip_addr.s_addr = htonl((127 << 24) | 1);
	strncpy(wpa_s->ifname, "test", sizeof(wpa_s->ifname));

	e->radius_conf = malloc(sizeof(struct hostapd_radius_servers));
    if (e->radius_conf == NULL) {
        TRACE_CORE("%s:%d => wpa_init_conf: Could not malloc radius_conf\n", __FILE__, __LINE__);
    }
	assert(e->radius_conf != NULL);
	memset(e->radius_conf, 0, sizeof(struct hostapd_radius_servers));
	e->radius_conf->num_auth_servers = 1;
	as = malloc(sizeof(struct hostapd_radius_server));
    if (as == NULL) {
        TRACE_CORE("%s:%d => wpa_init_conf: Could not malloc as\n", __FILE__, __LINE__);
    }
	assert(as != NULL);
	memset(as, 0, sizeof(*as));
	inet_aton(authsrv, &as->addr.u.v4);
	as->addr.af = AF_INET;
	as->port = port;
	as->shared_secret = (u8 *) strdup(as_secret);
	as->shared_secret_len = strlen(as_secret);
	e->radius_conf->auth_server = as;
	e->radius_conf->auth_servers = as;
	e->radius_conf->msg_dumps = 1;

    // initialize other eapol_test field
    e->last_recv_radius = NULL;
    e->last_eap_radius_len = 0;
    e->last_eap_radius = NULL;
    e->radius_access_accept_received = 0;
    e->radius_access_reject_received = 0;
    e->num_mppe_mismatch = 0;
    e->num_mppe_ok = 0;
    e->eap_identity = NULL;
    e->eap_identity_len = 0;
    
    //RHL, add for prepaid traffic
    //e->actionFlags = NULL;//MUST NOT set it to NULL here
    e->radius_access_accept_received_no_necessary_avp = 0;
    

	e->radius = radius_client_init(e, e->radius_conf);
    if (e->radius == NULL) {
        TRACE_CORE("%s:%d => wpa_init_conf: radius_client_init KO\n", __FILE__, __LINE__);
    }

	assert(e->radius != NULL);

	res = radius_client_register(e->radius, RADIUS_AUTH,
				     ieee802_1x_receive_auth, e);

    if (res != 0) {
        TRACE_CORE("%s:%d => wpa_init_conf: radius_client_register KO\n", __FILE__, __LINE__);
    }
	assert(res == 0);
}
/******************************************************************************/
static int test_eapol(struct eapol_test_data *e, struct wpa_supplicant *wpa_s,
		      struct wpa_ssid *ssid)
/******************************************************************************/
{
	struct eapol_config *eapol_conf;
	struct eapol_ctx *ctx;

	ctx = malloc(sizeof(*ctx));
	if (ctx == NULL) {
		TRACE_ERROR("%s:%d => Failed to allocate EAPOL context.\n", __FILE__, __LINE__);
		return -1;
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->ctx = wpa_s;
	ctx->msg_ctx = wpa_s;
	ctx->scard_ctx = wpa_s->scard;
	ctx->cb = eapol_sm_cb;
	ctx->cb_ctx = e;
	//ctx->eapol_send_ctx = wpa_s;
    ctx->eapol_send_ctx = e;
	ctx->preauth = 0;
	ctx->eapol_done_cb = eapol_test_eapol_done_cb;
	ctx->eapol_send = eapol_test_eapol_send;
	ctx->set_config_blob = eapol_test_set_config_blob;
	ctx->get_config_blob = eapol_test_get_config_blob;
	ctx->opensc_engine_path = wpa_s->conf->opensc_engine_path;
	ctx->pkcs11_engine_path = wpa_s->conf->pkcs11_engine_path;
	ctx->pkcs11_module_path = wpa_s->conf->pkcs11_module_path;

	wpa_s->eapol = eapol_sm_init(ctx);
	if (wpa_s->eapol == NULL) {
		free(ctx);
		TRACE_ERROR("%s:%d => Failed to initialize EAPOL state machines.\n", __FILE__, __LINE__);
		return -1;
	}
	wpa_s->current_ssid = ssid;

    eapol_conf = (struct eapol_config *)malloc(sizeof(struct eapol_config));
    if (eapol_conf == NULL) {
        TRACE_ERROR("%s:%d => Failed to allocate eapol_conf context.\n", __FILE__, __LINE__);
        return -1;
    }

	memset(eapol_conf, 0, sizeof(*eapol_conf));
	eapol_conf->accept_802_1x_keys = 1;
	eapol_conf->required_keys = 0;
	eapol_conf->fast_reauth = wpa_s->conf->fast_reauth;
	eapol_conf->workaround = ssid->eap_workaround;
	eapol_sm_notify_config(wpa_s->eapol, ssid, eapol_conf);
    free(eapol_conf);
	eapol_sm_register_scard_ctx(wpa_s->eapol, wpa_s->scard);


	eapol_sm_notify_portValid(wpa_s->eapol, FALSE);
	/* 802.1X::portControl = Auto */
	eapol_sm_notify_portEnabled(wpa_s->eapol, TRUE);
	return 0;
}
/******************************************************************************/
static void eapol_test_eapol_done_cb(void *ctx)
/******************************************************************************/
{
    TRACE_DEBUG("%s:%d => eapol_test_eapol_done_cb: EAPOL processing complete\n", __FILE__, __LINE__);
}
/******************************************************************************/
static int eapol_test_eapol_send(void *ctx, int type, const u8 *buf,
				 size_t len)
/******************************************************************************/
{
    char ligne[120];
    char hexa[3];
    int i;

    struct eapol_test_data *e = ctx;
	struct wpa_supplicant *wpa_s = e->wpa_s;
    struct wpa_ssid *conf = wpa_s->conf->ssid;
    TRACE_DEBUG("eapol_test_eapol_send: WPA: eapol_test_eapol_send(type=%d len=%d)\n", type, len);
	if (type == IEEE802_1X_TYPE_EAP_PACKET) {
        hexdump("TX EAP -> RADIUS", buf, len);
		ieee802_1x_encapsulate_radius(e, buf, len, conf);
	}
	return 0;
}

/******************************************************************************/
static void ieee802_1x_encapsulate_radius(struct eapol_test_data *e,
					  const u8 *eap, size_t len, struct wpa_ssid *conf)
/******************************************************************************/
{
	struct radius_msg *msg;
	char buf[128];
	const struct eap_hdr *hdr;
	const u8 *pos;
    int length;
    tUser *aUser;


    TRACE_DEBUG("%s:%d => ieee802_1x_encapsulate_radius: Encapsulating EAP message into a RADIUS packet\n", __FILE__, __LINE__);

    TRACE_DEBUG("the conf->ssid = %s \n",(u8*)conf->ssid);
    if (strcmp(conf->ssid,"client_EAP-TLS") == 0) {
        // RHL; 01/08/2008; add RADIUS_AccessEapTls_Rq statType 
	e->statType = RADIUS_AccessEapTls_Rq;
    } else {
    	// prepare statistics. It is EAP-TTLS if it is not EAP Identity
    	e->statType = RADIUS_AccessEapTtls_Rq;
    }
    TRACE_DEBUG("the e->statType = %02x \n", e->statType);
    e->statRetries = 0;

	e->radius_identifier = radius_client_get_id(e->radius);
	msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST,
			     e->radius_identifier);
	if (msg == NULL) {
        TRACE_ERROR("%s:%d => ieee802_1x_encapsulate_radius: Could not create net RADIUS packet\n", __FILE__, __LINE__);
		return;
	}

	radius_msg_make_authenticator(msg, (u8 *) e, sizeof(*e));

    hdr = (const struct eap_hdr *) eap;
	pos = (const u8 *) (hdr + 1);
	if (len > sizeof(*hdr) && hdr->code == EAP_CODE_RESPONSE &&
	    pos[0] == EAP_TYPE_IDENTITY) {
		pos++;
        if (e->eap_identity) {
            free(e->eap_identity);
        }
		e->eap_identity_len = len - sizeof(*hdr) - 1;
		e->eap_identity = malloc(e->eap_identity_len);
		if (e->eap_identity) {
			memcpy(e->eap_identity, pos, e->eap_identity_len);
			hexdump("Learned identity from "
				    "EAP-Response-Identity",
				    e->eap_identity, e->eap_identity_len);
		}
        e -> statType = RADIUS_AccessEapId_Rq;
	}

	if (e->eap_identity &&
	    !radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME,
				 e->eap_identity, e->eap_identity_len)) {
		fprintf(stderr, "Could not add User-Name\n");
		goto fail;
	}

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_NAS_IP_ADDRESS,
				 (u8 *) &e->own_ip_addr, 4)) {
		fprintf(stderr, "Could not add NAS-IP-Address\n");
		goto fail;
	}

	
    // RHL; Dec 5, 2008; put Service_type as the condition to add AVP
    // Not put some AVP such as EAP-Message if service type is Authorize-Only
       //servicetype is AuthorizeOnly(0x11=17)
    if (strcmp(conf->servicetype,ServiceType_AuthorizeOnly_TTLS) != 0){
	

    	snprintf(buf, sizeof(buf), RADIUS_802_1X_ADDR_FORMAT,
		 MAC2STR(e->wpa_s->own_addr));
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CALLING_STATION_ID,
				 (u8 *) buf, strlen(buf))) {
		fprintf(stderr, "Could not add Calling-Station-Id\n");
        goto fail;
	}

	/* TODO: should probably check MTU from driver config; 2304 is max for
	 * IEEE 802.11, but use 1400 to avoid problems with too large packets
	 */
	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_FRAMED_MTU, 1400)) {
		TRACE_ERROR("Could not add Framed-MTU\n");
		goto fail;
	}

	if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_NAS_PORT_TYPE,
				       RADIUS_NAS_PORT_TYPE_IEEE_802_11)) {
		TRACE_ERROR("Could not add NAS-Port-Type\n");
		goto fail;
	}

	snprintf(buf, sizeof(buf), "CONNECT 11Mbps 802.11b");
	if (!radius_msg_add_attr(msg, RADIUS_ATTR_CONNECT_INFO,
				 (u8 *) buf, strlen(buf))) {
		TRACE_ERROR("Could not add Connect-Info\n");
		goto fail;
	}

	if (eap && !radius_msg_add_eap(msg, eap, len)) {
		TRACE_ERROR("Could not add EAP-Message\n");
		goto fail;
	}
     }//end of strcmp(conf->servicetype,ServiceType_AuthorizeOnly_TTLS)

	/* State attribute must be copied if and only if this packet is
	 * Access-Request reply to the previous Access-Challenge */
    
	if (e->last_recv_radius && e->last_recv_radius->hdr->code ==
	    RADIUS_CODE_ACCESS_CHALLENGE) {
		int res = radius_msg_copy_attr(msg, e->last_recv_radius,
					       RADIUS_ATTR_STATE);
    	if (res < 0) {
			TRACE_ERROR("Could not copy State attribute from previous Access-Challenge\n");
			goto fail;
		}
		/*if ((verbose >= 3) && (res > 0)) {
			fprintf(stderr, " Copied RADIUS State Attribute\n");
		}*/
	} else {
        // CC 06/04/2006 add State if defined
        if (conf->state) {
            length = strlen(conf->state);
        }
        else
            length = 0;
	
	// RHL; Nov 19, 2008; do re-authentication if available in user ctx
	//need set the aUser first
	aUser = e ->tgenUser;
        if (e ->eapol_test_num_reauths >= 0 || tUserGetStateAttribLength(aUser, 0) > 0) {
            //aUser = e ->tgenUser;
            if (!radius_msg_add_attr(msg, RADIUS_ATTR_STATE,
                                 tUserGetStateAttrib(aUser, 0), 
                                 tUserGetStateAttribLength(aUser, 0))) {
                TRACE_ERROR("Could not add State %s\n", tUserGetStateAttrib(aUser, 0));
                goto fail;
            }
            TRACE_DEBUG("Add State attrib in case of re-auth for user %s; State = %s\n",
                       tUserGetNAI(aUser), tUserGetStateAttrib(aUser, 0));
        }

    }
    
      /* RHL 08/26/2008 add Service-Type, WIMAX-CAPABILITY,
      * Session-Termination-Capability, PPAC like in /mds_tests/uma/Common/WpaSupplicant/eapol_test.c
      */
      	char hexa[20]= "0x";
       	int servicetype;  
    	//RADIUS_ATTR_SERVICE_TYPE
	if (conf->servicetype)
	{
	         TRACE_DEBUG("the conf->servicetype = %s \n", conf->servicetype);
		memcpy(&hexa[2], conf->servicetype,strlen(conf->servicetype));
		servicetype = strtoul(hexa, (char **)NULL, 16);
		if (!radius_msg_add_attr_int32(msg, RADIUS_ATTR_SERVICE_TYPE,servicetype) ){
			printf("Could not add ServiceType\n");
			goto fail;
        	}
    	}
	
	//RADIUS_VENDOR_ATTR_WIMAX_CAPABILITY
    	if (conf->wimaxcapability)
      	{
		if (!radius_msg_add_wimax_vsa(msg,RADIUS_VENDOR_ATTR_WIMAX_CAPABILITY,conf->wimaxcapability) )
		{
			printf("Could not add WimaxCapability\n");
		    	goto fail;
              	}
      	}

	//RADIUS_VENDOR_ATTR_SESSION_TERMINATION_CAPABILITY
    	if (conf->session_termination_capability)
      	{
		if (!radius_msg_add_wimax_vsa(msg,RADIUS_VENDOR_ATTR_SESSION_TERMINATION_CAPABILITY,conf->session_termination_capability) )
		{
			printf("Could not add Session-Termination-Capability\n");
		    	goto fail;
              	}
      	}
	
	//RADIUS_VENDOR_ATTR_PPAC	
    	if (conf->ppac)
      	{
		if (!radius_msg_add_wimax_vsa(msg,RADIUS_VENDOR_ATTR_PPAC,conf->ppac) )
		{
			printf("Could not add PPAC\n");
		    	goto fail;
              	}
      	}
	
	 /* RHL 09/16/2008 add AAA-Session-ID, PPAQ*/
	//RADIUS_VENDOR_ATTR_AAA_SESSION_ID	
    	if (conf->aaa_session_id)
      	{
		if (!radius_msg_add_wimax_vsa(msg,RADIUS_VENDOR_ATTR_AAA_SESSION_ID,conf->aaa_session_id) )
		{
			printf("Could not add AAA-Session-ID\n");
		    	goto fail;
              	}
      	}
	
	//RADIUS_VENDOR_ATTR_PPAQ	
    	if (conf->ppaq)
      	{
		if (!radius_msg_add_wimax_vsa(msg,RADIUS_VENDOR_ATTR_PPAQ,conf->ppaq) )
		{
			printf("Could not add PPAQ\n");
		    	goto fail;
              	}
      	}
//    pthread_mutex_unlock(&stateMutex);
    

	radius_client_send(e->radius, msg, RADIUS_AUTH, e->wpa_s->own_addr);
	return;

 fail:
	radius_msg_free(msg);
	free(msg);
}
/******************************************************************************/
void hostapd_logger(void *ctx, u8 *addr, unsigned int module, int level,
		    char *fmt, ...)
/******************************************************************************/
{

	char *format;
	int maxlen;
	va_list ap;

    if (!debug) {
        return;
    }

	maxlen = strlen(fmt) + 100;
	format = malloc(maxlen);
	if (!format)
    	return;

	va_start(ap, fmt);


	if (addr)
		snprintf(format, maxlen, "STA " MACSTR ": %s",
			 MAC2STR(addr), fmt);
	else
		snprintf(format, maxlen, "%s", fmt);

	vprintf(format, ap);
	fprintf(stderr, "\n");

	free(format);

	va_end(ap);
}
/******************************************************************************/
void hexdump(const char *title, const u8 *buf,
			 size_t len)
/******************************************************************************/
{
    size_t i;
    if (!debug)
        return;         
    debug_print_timestamp();
    fprintf(stderr, "%s - hexdump(len=%lu):\n", title, (unsigned long) len);
    for (i = 0; i < len; i++)
        fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}
/******************************************************************************/
void debug_print_timestamp(void)
/******************************************************************************/
{
        struct timeval tv;
        char buf[16];

        if (!debug)
            return;

        gettimeofday(&tv, NULL);
        if (strftime(buf, sizeof(buf), "%b %d %H:%M:%S",
                 localtime((const time_t *) &tv.tv_sec)) <= 0) {
            snprintf(buf, sizeof(buf), "%u", (int) tv.tv_sec);
        }
        fprintf(stderr, "%s.%06u: ", buf, (unsigned int) tv.tv_usec);
}
/******************************************************************************/
static void eapol_test_set_config_blob(void *ctx,
				       struct wpa_config_blob *blob)
/******************************************************************************/
{
	return;
}

/******************************************************************************/
static const struct wpa_config_blob *
eapol_test_get_config_blob(void *ctx, const char *name)
/******************************************************************************/
{
	return;
}
/******************************************************************************/
static void eapol_sm_reauth(void *tloop_ctx, void *timeout_ctx)
/******************************************************************************/
{
	struct eapol_test_data *e = tloop_ctx;
    int retry;
	TRACE_DEBUG("\n\n\n\n\neapol_test: Triggering EAP reauthentication\n");
	e->radius_access_accept_received = 0;
    // end of authentication or previous re-authentication
    tStatTimeEnd(1);
    // update retries nb
    retry = e->radius_conf->auth_server->retransmissions;
    e->radius_conf->auth_server->retransmissions = 0;

    // stats for RADIUS_Auth_Rq or RADIUS_AuthWP_Rq
    tStatActionTime(e->requestedStatType,0,retry, tStatTimeDelta(1));
    // beginning of next re-authentication
    tStatTimeBegin(1);
	send_eap_request_identity(e->wpa_s, NULL);
}
/******************************************************************************/
static void eapol_sm_cb(struct eapol_sm *eapol, int success, void *ctx)
/******************************************************************************/
{
	struct eapol_test_data *e = ctx;
	TRACE_DEBUG("eapol_sm_cb: success=%d\n", success);
	e->eapol_test_num_reauths--;
	if (e->eapol_test_num_reauths < 0) {
		tloop_terminate(e->tloop);

    }
	else {
		eapol_test_compare_pmk(e);
		tloop_register_timeout(e->tloop, 0, 100000, eapol_sm_reauth, e, NULL);
	}
}
/******************************************************************************/
static void eapol_test_timeout(void *tloop_ctx, void *timeout_ctx)
/******************************************************************************/
{
    // timeout for the present set of authentication + subsequent fast re-authentication
	struct eapol_test_data *e = tloop_ctx;
    debug_print_timestamp();
    if (verbose >= 3) {
        TRACE_CORE("EAPOL test timed out\n");
    }
	e->auth_timed_out = 1;
	tloop_terminate(e->tloop);
}


/* Process the RADIUS frames from Authentication Server */
/******************************************************************************/
static RadiusRxResult
ieee802_1x_receive_auth(struct radius_msg *msg, struct radius_msg *req,
			u8 *shared_secret, size_t shared_secret_len,
			void *data)
/******************************************************************************/
{
	struct eapol_test_data *e = data;
    
	//Add by RHL, 
	//IF creditSessionAction is 2 (Update session) or 3(Termination), don't verify the Message-Authenticator
	int creditSessionAction = 0;
	int rc_checkWimaxVSA = 1;
	if (e->actionFlags) {
		creditSessionAction = e->actionFlags->creditSessionAction;
		TRACE_DEBUG("creditSessionAction is %d\n",creditSessionAction);
		TRACE_DEBUG("IF creditSessionAction is 2 (Update session) or 3(Termination), don't verify the Message-Authenticator \n",creditSessionAction);
	}
	/* RFC 2869, Ch. 5.13: valid Message-Authenticator attribute MUST be
	 * present when packet contains an EAP-Message attribute */
	if (msg->hdr->code == RADIUS_CODE_ACCESS_REJECT &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_MESSAGE_AUTHENTICATOR, NULL,
				0) < 0 &&
	    radius_msg_get_attr(msg, RADIUS_ATTR_EAP_MESSAGE, NULL, 0) < 0) {
		TRACE_DEBUG("Allowing RADIUS Access-Reject without Message-Authenticator since it does not include EAP-Message\n");
	} else if ((creditSessionAction < 2)&& radius_msg_verify(msg, shared_secret, shared_secret_len,
				     req, 1)) {
        	if (verbose >= 3) {
            		TRACE_ERROR("Incoming RADIUS packet did not have correct Message-Authenticator - dropped\n");
        	}
		return RADIUS_RX_UNKNOWN;
	}
	
	if (msg->hdr->code == RADIUS_CODE_ACCESS_ACCEPT){			    
		
		// RHL | 09/26/2008, get&check wimax vsa for prepaid session control actions (1,2,3)
		if ((creditSessionAction == 1 || creditSessionAction == 2) && ieee802_1x_get_wimax_vsa(e,msg,creditSessionAction) <= 0){
            		TRACE_ERROR("Incoming RADIUS packet did not have AAA-Session-ID or PPAQ\n");
        		
			//let it is one failed case even got Access-Accept but no AAA-Session-ID or PPAQ
			e->radius_access_accept_received_no_necessary_avp = 1;
		}else{
			TRACE_DEBUG("Incoming RADIUS packet has AAA-Session-ID and PPAQ\n");
		}
	}	
	
	if (msg->hdr->code != RADIUS_CODE_ACCESS_ACCEPT &&
	    msg->hdr->code != RADIUS_CODE_ACCESS_REJECT &&
	    msg->hdr->code != RADIUS_CODE_ACCESS_CHALLENGE) {
        if (verbose >= 3) {
            TRACE_ERROR("Unknown RADIUS message code\n");
        }
		return RADIUS_RX_UNKNOWN;
	}

	e->radius_identifier = -1;
	TRACE_DEBUG("RADIUS packet matching with station\n");
	if (e->last_recv_radius) {
		radius_msg_free(e->last_recv_radius);
		free(e->last_recv_radius);
	}

	e->last_recv_radius = msg;
    
	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		e->radius_access_accept_received = 1;
		ieee802_1x_get_keys(e, msg, req, shared_secret,
				    shared_secret_len);
		
		break;
	case RADIUS_CODE_ACCESS_REJECT:
		e->radius_access_reject_received = 1;
		break;
	}

	ieee802_1x_decapsulate_radius(e);
    

	if ((msg->hdr->code == RADIUS_CODE_ACCESS_ACCEPT &&
	     e->eapol_test_num_reauths < 0) ||
	    msg->hdr->code == RADIUS_CODE_ACCESS_REJECT) {
		tloop_terminate(e->tloop);
	}
    
	return RADIUS_RX_QUEUED;
}
/******************************************************************************/
static int eapol_test_compare_pmk(struct eapol_test_data *e)
/******************************************************************************/
{
	u8 pmk[PMK_LEN];
	int ret = 1;
	
	// RHL | 08/02/2008 | Omit mppe as one work around to display rightly.
	e->no_mppe_keys = 1;
	
	if (eapol_sm_get_key(e->wpa_s->eapol, pmk, PMK_LEN) == 0) {
		hexdump("PMK from EAPOL", pmk, PMK_LEN);
		if (memcmp(pmk, e->authenticator_pmk, PMK_LEN) != 0)
			TRACE_DEBUG("WARNING: PMK mismatch\n");
		else if (e->radius_access_accept_received)
			ret = 0;
	} else if (e->authenticator_pmk_len == 16 &&
		   eapol_sm_get_key(e->wpa_s->eapol, pmk, 16) == 0) {
		hexdump("LEAP PMK from EAPOL", pmk, 16);
		if (memcmp(pmk, e->authenticator_pmk, 16) != 0)
			TRACE_DEBUG("WARNING: PMK mismatch\n");
		else if (e->radius_access_accept_received)
			ret = 0;
	} 
	// else
	// RHL | 08/02/2008 | Omit mppe as one work around to display rightly.
	if (e->radius_access_accept_received && e->no_mppe_keys) {
		/* No keying material expected */
		ret = 0;
	}
	TRACE_DEBUG("ret = %d; e->radius_access_accept_received = %d\n",ret, e->radius_access_accept_received);
	if (ret)
		e->num_mppe_mismatch++;
	else if (!e->no_mppe_keys)
		e->num_mppe_ok++;

	return ret;
}
/******************************************************************************/
static void ieee802_1x_get_keys(struct eapol_test_data *e,
				struct radius_msg *msg, struct radius_msg *req,
				u8 *shared_secret, size_t shared_secret_len)
/******************************************************************************/
{
	struct radius_ms_mppe_keys *keys;

	keys = radius_msg_get_ms_keys(msg, req, shared_secret,
				      shared_secret_len);
	if (keys && keys->send == NULL && keys->recv == NULL) {
		free(keys);
		keys = radius_msg_get_cisco_keys(msg, req, shared_secret,
						 shared_secret_len);
	}

	if (keys) {
		if (keys->send) {
			hexdump("MS-MPPE-Send-Key (sign)",
				    keys->send, keys->send_len);
		}
		if (keys->recv) {
			hexdump("MS-MPPE-Recv-Key (crypt)",
				    keys->recv, keys->recv_len);
			e->authenticator_pmk_len =
				keys->recv_len > PMK_LEN ? PMK_LEN :
				keys->recv_len;
			memcpy(e->authenticator_pmk, keys->recv,
			       e->authenticator_pmk_len);
		}

		free(keys->send);
		free(keys->recv);
		free(keys);
	}
}

/******************************************************************************/
// RHL | 08/26/2008 | used to get wimax vsa such as AAA-Session-ID and PPAQ for
// 			testing Prepaid charging with eap-ttls
// return: 1: normal end; -1: no AAA-Session-ID in AA, -2: no PPAQ in AA
static int ieee802_1x_get_wimax_vsa(struct eapol_test_data *e,
				struct radius_msg *msg, int creditSessionAction)
/******************************************************************************/
{
		u8 *ppaq;
		size_t ppaqlen;
		u8 *aaa_session_id;
		size_t aaa_session_idlen;
		int rc = 1;
		
		tUser * aUser = e->tgenUser;
		char  * aNai = tUserGetNAI(aUser);
		
		
		 //
		 // AAA-Session-ID attribute
		 //
		 aaa_session_id = radius_msg_get_wimax_vsa(msg, RADIUS_VENDOR_ID_WIMAX,RADIUS_VENDOR_ATTR_AAA_SESSION_ID,&aaa_session_idlen);
		 if (aaa_session_id != NULL ) {
			 if ( tUserGetAAASessionIdLength(aUser) && strcmp(tUserGetAAASessionId(aUser), (char *)aaa_session_id)!=0 ) {
				 // there was already a different AAA-Sess-Id stored
				 // can not get valid AAA-Session-ID, throw error
				 char buf1[32];
				 char buf2[32];
				 strncpy(buf1, (char *)aaa_session_id, aaa_session_idlen);
				 strncpy(buf2, tUserGetAAASessionId(aUser), tUserGetAAASessionIdLength(aUser));
				 TRACE_ERROR("ieee802_1x_get_wimax_vsa on %s: received AAA-Session-ID=%s differs from precedently stored one=%s\n", aNai, buf1, buf2 );
				 // go on with new value...
				 //return -1;
			 }
			 tUserSetAAASessionId(aUser, (char *)aaa_session_id, aaa_session_idlen);

		 } else {
			 tUserSetAAASessionId(aUser, "", 0);	
			 if (verbose >= 2)
				TRACE_ERROR("ieee802_1x_get_wimax_vsa on %s: no AAA-Session-ID attribute found\n", aNai);
  			 if (creditSessionAction == 1)
				rc = -1;
		 }
		 TRACE_DEBUG("ieee802_1x_get_wimax_vsa: After analysis of AAA-Session-ID attribute, rc = %d, note 1 means normal\n", rc);

		 ppaq = radius_msg_get_wimax_vsa(msg, RADIUS_VENDOR_ID_WIMAX,RADIUS_VENDOR_ATTR_PPAQ,&ppaqlen);	
		 if (creditSessionAction == 1 || creditSessionAction == 2) {
			//
			// PPAQ attribute
			//
			if (ppaq != NULL) {
				tUserSetPPAQ(aUser, (char *)ppaq, ppaqlen);
			} else {
				tUserSetPPAQ(aUser, "", 0);	
				TRACE_ERROR("ieee802_1x_get_wimax_vsa on %s: no PPAQ attribute found when creditSessionAction is %d\n", aNai,creditSessionAction);
				rc = -2;
		    	}
			TRACE_DEBUG("ieee802_1x_get_wimax_vsa: After analysis of PPAQ attribute, rc = %d, note 1 means normal\n", rc);
		 }
		 
		  // end of Wimax session (prepaid case only)
   		if (creditSessionAction == 3) {
	   		// clear the related attrs in the session in order not impact running the same user next time
	   		tUserSetAAASessionId(aUser, "", 0);	
	   		tUserSetPPAQ(aUser, "", 0);
   		}
   
		//clear data	
		if (ppaq != NULL) {
			free(ppaq);
		}
		if (aaa_session_id != NULL){
		 	free(aaa_session_id);
		}
		
		return rc;
}

/******************************************************************************/
static void ieee802_1x_decapsulate_radius(struct eapol_test_data *e)
/******************************************************************************/
{
	u8 *eap;
	size_t len;
	struct eap_hdr *hdr;
	int eap_type = -1;
	char buf[64];
	struct radius_msg *msg;

	if (e->last_recv_radius == NULL)
		return;

    msg = e->last_recv_radius;
//    pthread_mutex_unlock(&stateMutex);

	eap = radius_msg_get_eap(msg, &len);
	if (eap == NULL) {
		/* draft-aboba-radius-rfc2869bis-20.txt, Chap. 2.6.3:
		 * RADIUS server SHOULD NOT send Access-Reject/no EAP-Message
		 * attribute */
		TRACE_DEBUG("%s:%d => could not extract EAP-Message from RADIUS message\n", __FILE__, __LINE__);
		free(e->last_eap_radius);
		e->last_eap_radius = NULL;
		e->last_eap_radius_len = 0;
		return;
	}

	if (len < sizeof(*hdr)) {
		TRACE_DEBUG("%s:%d => too short EAP packet received from authentication server\n", __FILE__, __LINE__);
		free(eap);
		return;
	}

	if (len > sizeof(*hdr))
		eap_type = eap[sizeof(*hdr)];

	hdr = (struct eap_hdr *) eap;
	switch (hdr->code) {
	case EAP_CODE_REQUEST:
		snprintf(buf, sizeof(buf), "EAP-Request-%s (%d)",
			 eap_type >= 0 ? eap_type_text(eap_type) : "??",
			 eap_type);
		break;
	case EAP_CODE_RESPONSE:
		snprintf(buf, sizeof(buf), "EAP Response-%s (%d)",
			 eap_type >= 0 ? eap_type_text(eap_type) : "??",
			 eap_type);
		break;
	case EAP_CODE_SUCCESS:
		snprintf(buf, sizeof(buf), "EAP Success");
		/* LEAP uses EAP Success within an authentication, so must not
		 * stop here with tloop_terminate(); */
		break;
	case EAP_CODE_FAILURE:
		snprintf(buf, sizeof(buf), "EAP Failure");
		tloop_terminate(e->tloop);
		break;
	default:
		snprintf(buf, sizeof(buf), "unknown EAP code");
		hexdump("Decapsulated EAP packet", eap, len);
		break;
	}
	TRACE_DEBUG("decapsulated EAP packet (code=%d " "id=%d len=%d) from RADIUS server: %s\n",
		      hdr->code, hdr->identifier, ntohs(hdr->length), buf);

	/* sta->eapol_sm->be_auth.idFromServer = hdr->identifier; */

    if (e->last_eap_radius) {
        free(e->last_eap_radius);
    }
	e->last_eap_radius = eap;
	e->last_eap_radius_len = len;

	{
		struct ieee802_1x_hdr *hdr;
		hdr = malloc(sizeof(*hdr) + len);
        if (hdr == NULL) {
            fprintf(stderr, "%s:%d => ieee802_1x_decapsulate_radius: Could not malloc hdr\n", __FILE__, __LINE__);
        }
		assert(hdr != NULL);
		hdr->version = EAPOL_VERSION;
		hdr->type = IEEE802_1X_TYPE_EAP_PACKET;
		hdr->length = htons(len);
		memcpy((u8 *) (hdr + 1), eap, len);
		eapol_sm_rx_eapol(e->wpa_s->eapol, e->wpa_s->bssid,
				  (u8 *) hdr, sizeof(*hdr) + len);
		free(hdr);
	}
}
/******************************************************************************/
const char * hostapd_ip_txt(const struct hostapd_ip_addr *addr, char *buf,
			    size_t buflen)
/******************************************************************************/
{
	if (buflen == 0 || addr == NULL)
		return NULL;

	if (addr->af == AF_INET) {
		snprintf(buf, buflen, "%s", inet_ntoa(addr->u.v4));
	} else {
		buf[0] = '\0';
	}
#ifdef CONFIG_IPV6
	if (addr->af == AF_INET6) {
		if (inet_ntop(AF_INET6, &addr->u.v6, buf, buflen) == NULL)
			buf[0] = '\0';
	}
#endif /* CONFIG_IPV6 */

	return buf;
}

static void test_eapol_clean(struct eapol_test_data *e,
			     struct wpa_supplicant *wpa_s)
{
	radius_client_deinit(e->radius);

	free(e->last_eap_radius);
    e->last_eap_radius = NULL;
    e->last_eap_radius_len = 0;
	if (e->last_recv_radius) {
		radius_msg_free(e->last_recv_radius);
		free(e->last_recv_radius);
        e->last_recv_radius = NULL;
	}

	free(e->eap_identity);
	e->eap_identity = NULL;
	eapol_sm_deinit(wpa_s->eapol);
	wpa_s->eapol = NULL;
	if (e->radius_conf && e->radius_conf->auth_server) {
		free(e->radius_conf->auth_server->shared_secret);
		free(e->radius_conf->auth_server);
	}
	free(e->radius_conf);
	e->radius_conf = NULL;
	wpa_config_free(wpa_s->conf);
    free(wpa_s);
//    free(e);

}

/******************************************************************************/
int radius_client_register(struct radius_client_data *radius,
			   RadiusType msg_type,
			   RadiusRxResult (*handler)(struct radius_msg *msg,
						     struct radius_msg *req,
						     u8 *shared_secret,
						     size_t shared_secret_len,
						     void *data),
			   void *data)
/******************************************************************************/
{
	struct radius_rx_handler **handlers, *newh;
	size_t *num;

	if (msg_type == RADIUS_ACCT) {
		handlers = &radius->acct_handlers;
		num = &radius->num_acct_handlers;
	} else {
		handlers = &radius->auth_handlers;
		num = &radius->num_auth_handlers;
	}

	newh = (struct radius_rx_handler *)
		realloc(*handlers,
			(*num + 1) * sizeof(struct radius_rx_handler));
	if (newh == NULL)
		return -1;

	newh[*num].handler = handler;
	newh[*num].data = data;
	(*num)++;
	*handlers = newh;

	return 0;
}

/******************************************************************************/
static void radius_client_handle_send_error(struct radius_client_data *radius,
					    int s, RadiusType msg_type)
/******************************************************************************/
{
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
#ifndef CONFIG_NATIVE_WINDOWS
	int _errno = errno;
	perror("send[RADIUS]");
	if (_errno == ENOTCONN || _errno == EDESTADDRREQ || _errno == EINVAL) {
		hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_INFO,
			       "Send failed - maybe interface status changed - try to connect again\n");
		tloop_unregister_read_sock(e->tloop, s);
		close(s);
		if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM)
			radius_client_init_acct(radius);
		else
			radius_client_init_auth(radius);
	}
#endif /* CONFIG_NATIVE_WINDOWS */
}

/******************************************************************************/
static int radius_client_retransmit(struct radius_client_data *radius,
				    struct radius_msg_list *entry, time_t now)
/******************************************************************************/
{
	struct hostapd_radius_servers *conf = radius->conf;
	int s;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (entry->msg_type == RADIUS_ACCT ||
	    entry->msg_type == RADIUS_ACCT_INTERIM) {
		s = radius->acct_sock;
		if (entry->attempts == 0)
			conf->acct_server->requests++;
		else {
			conf->acct_server->timeouts++;
			conf->acct_server->retransmissions++;
		}
	} else {
		s = radius->auth_sock;
		if (entry->attempts == 0)
			conf->auth_server->requests++;
		else {
			conf->auth_server->timeouts++;
			conf->auth_server->retransmissions++;
		}
	}

	/* retransmit; remove entry if too many attempts */
	entry->attempts++;
	hostapd_logger(e->wpa_s, entry->addr, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "Resending RADIUS message (id=%d)\n",
		       entry->msg->hdr->identifier);

	gettimeofday(&entry->last_attempt, NULL);
	if (send(s, entry->msg->buf, entry->msg->buf_used, 0) < 0)
		radius_client_handle_send_error(radius, s, entry->msg_type);

	entry->next_try = now + entry->next_wait;
	entry->next_wait = tcRadiusTimeout;
    /*   not possible since next_wait is not exonential as in WpaSuppliquant
	if (entry->next_wait > RADIUS_CLIENT_MAX_WAIT)
		entry->next_wait = RADIUS_CLIENT_MAX_WAIT; */
        e->statRetries++;
	if (entry->attempts > tcRadiusRetries) {
		TRACE_ERROR("Removing un-ACKed RADIUS message due to too many failed retransmit attempts for user %s (id=%d)\n", 
		       tUserGetNAI(e->tgenUser), entry->msg->hdr->identifier);
                tStatTimeEnd(0);
                tStatCount(tThread_getKey());
                tStatActionTime(e->statType, 1, e->statRetries, 0 );
		e->auth_timed_out = 1;
                tloop_terminate(e->tloop);
		
		return 1;
	}
    
	return 0;
}

/******************************************************************************/
static void radius_client_timer(void *tloop_ctx, void *timeout_ctx)
/******************************************************************************/
{
	struct radius_client_data *radius = tloop_ctx;
	struct hostapd_radius_servers *conf = radius->conf;
	time_t now, first;
	struct radius_msg_list *entry, *prev, *tmp;
	int auth_failover = 0, acct_failover = 0;
	char abuf[50];
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	entry = radius->msgs;
	if (!entry)
		return;

	time(&now);
	first = 0;

	prev = NULL;
	while (entry) {
		if (now >= entry->next_try &&
		    radius_client_retransmit(radius, entry, now)) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}

		if (entry->attempts > RADIUS_CLIENT_NUM_FAILOVER) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				acct_failover++;
			else
				auth_failover++;
		}

		if (first == 0 || entry->next_try < first)
			first = entry->next_try;

		prev = entry;
		entry = entry->next;
	}

	if (radius->msgs) {
		if (first < now)
			first = now;
		tloop_register_timeout(e->tloop, first - now, 0,
				       radius_client_timer, radius, NULL);
		hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_DEBUG, "Next RADIUS client retransmit in %ld seconds\n",
			       (long int) (first - now));
	}

	if (auth_failover && conf->num_auth_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = conf->auth_server;
		hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Authentication server %s:%d - failover\n",
			       hostapd_ip_txt(&old->addr, abuf, sizeof(abuf)),
			       old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_AUTH)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &(conf->auth_servers[conf->num_auth_servers - 1]))
			next = conf->auth_servers;
		conf->auth_server = next;
		radius_change_server(radius, next, old,
				     radius->auth_serv_sock,
				     radius->auth_serv_sock6, 1);
	}

	if (acct_failover && conf->num_acct_servers > 1) {
		struct hostapd_radius_server *next, *old;
		old = conf->acct_server;
		hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_NOTICE,
			       "No response from Accounting server %s:%d - failover\n",
			       hostapd_ip_txt(&old->addr, abuf, sizeof(abuf)),
			       old->port);

		for (entry = radius->msgs; entry; entry = entry->next) {
			if (entry->msg_type == RADIUS_ACCT ||
			    entry->msg_type == RADIUS_ACCT_INTERIM)
				old->timeouts++;
		}

		next = old + 1;
		if (next > &conf->acct_servers[conf->num_acct_servers - 1])
			next = conf->acct_servers;
		conf->acct_server = next;
		radius_change_server(radius, next, old,
				     radius->acct_serv_sock,
				     radius->acct_serv_sock6, 0);
	}
}

/******************************************************************************/
static void radius_client_update_timeout(struct radius_client_data *radius)
/******************************************************************************/
// It is related to requests without responses
{
	time_t now, first;
	struct radius_msg_list *entry;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	tloop_cancel_timeout(e->tloop, radius_client_timer, radius, NULL);

	if (radius->msgs == NULL) {
		return;
	}

	first = 0;
	for (entry = radius->msgs; entry; entry = entry->next) {
		if (first == 0 || entry->next_try < first)
			first = entry->next_try;
	}

	time(&now);
	if (first < now)
		first = now;
   
	tloop_register_timeout(e->tloop, first - now, 0, radius_client_timer, radius,
			       NULL); 
	hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "Next RADIUS client retransmit in %ld seconds\n", (long int) (first - now));
}

/******************************************************************************/
static void radius_client_list_add(struct radius_client_data *radius,
				   struct radius_msg *msg,
				   RadiusType msg_type, u8 *shared_secret,
				   size_t shared_secret_len, u8 *addr)
/******************************************************************************/
{
	struct radius_msg_list *entry, *prev;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (tloop_terminated(e->tloop)) {
		/* No point in adding entries to retransmit queue since event
		 * loop has already been terminated. */
		radius_msg_free(msg);
		free(msg);
		return;
	}

	entry = malloc(sizeof(*entry));
	if (entry == NULL) {
		TRACE_DEBUG("Failed to add RADIUS packet into retransmit list\n");
		radius_msg_free(msg);
		free(msg);
		return;
	}

	memset(entry, 0, sizeof(*entry));
	if (addr)
		memcpy(entry->addr, addr, ETH_ALEN);
	entry->msg = msg;
	entry->msg_type = msg_type;
	entry->shared_secret = shared_secret;
	entry->shared_secret_len = shared_secret_len;
	time(&entry->first_try);
	// entry->next_try = entry->first_try + RADIUS_CLIENT_FIRST_WAIT;
    entry->next_try = entry->first_try + tcRadiusTimeout;
	entry->attempts = 1;
	gettimeofday(&entry->last_attempt, NULL);
    // entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
    // not exponential in TGEN
	entry->next_wait = tcRadiusTimeout;
	entry->next = radius->msgs;
	radius->msgs = entry;
	radius_client_update_timeout(radius);

	if (radius->num_msgs >= RADIUS_CLIENT_MAX_ENTRIES) {
		TRACE_DEBUG("Removing the oldest un-ACKed RADIUS packet due to retransmit list limits.\n");
		prev = NULL;
		while (entry->next) {
			prev = entry;
			entry = entry->next;
		}
		if (prev) {
			prev->next = NULL;
			radius_client_msg_free(entry);
		}
	} else
		radius->num_msgs++;
}

/******************************************************************************/
static void radius_client_list_del(struct radius_client_data *radius,
				   RadiusType msg_type, u8 *addr)
/******************************************************************************/
{
	struct radius_msg_list *entry, *prev, *tmp;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (addr == NULL)
		return;

	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg_type == msg_type &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			tmp = entry;
			entry = entry->next;
			hostapd_logger(e->wpa_s, addr,
				       HOSTAPD_MODULE_RADIUS,
				       HOSTAPD_LEVEL_DEBUG,
				       "Removing matching RADIUS message\n");
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}

/******************************************************************************/
int radius_client_send(struct radius_client_data *radius,
		       struct radius_msg *msg, RadiusType msg_type, u8 *addr)
/******************************************************************************/
{
	struct hostapd_radius_servers *conf = radius->conf;
	u8 *shared_secret;
	size_t shared_secret_len;
	char *name;
	int s, res;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (msg_type == RADIUS_ACCT_INTERIM) {
		/* Remove any pending interim acct update for the same STA. */
		radius_client_list_del(radius, msg_type, addr);
	}

	if (msg_type == RADIUS_ACCT || msg_type == RADIUS_ACCT_INTERIM) {
		shared_secret = conf->acct_server->shared_secret;
		shared_secret_len = conf->acct_server->shared_secret_len;
		radius_msg_finish_acct(msg, shared_secret, shared_secret_len);
		name = "accounting";
		s = radius->acct_sock;
		conf->acct_server->requests++;
	} else {
		shared_secret = conf->auth_server->shared_secret;
		shared_secret_len = conf->auth_server->shared_secret_len;
		radius_msg_finish(msg, shared_secret, shared_secret_len);
		name = "authentication";
		s = radius->auth_sock;
		conf->auth_server->requests++;
	}

	hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "Sending RADIUS message to %s server\n", name);
	if (verbose >= 3 && conf->msg_dumps)
		radius_msg_dump(msg);

    tStatRegulation(tThread_getKey());
    tStatTimeBegin(0);
    res = send(s, msg->buf, msg->buf_used, 0);    

	if (res < 0)
		radius_client_handle_send_error(radius, s, msg_type);

	radius_client_list_add(radius, msg, msg_type, shared_secret,
			       shared_secret_len, addr);

	return res;
}

/******************************************************************************/
static void radius_client_receive(int sock, void *tloop_ctx, void *sock_ctx)
/******************************************************************************/
{
	struct radius_client_data *radius = tloop_ctx;
	struct hostapd_radius_servers *conf = radius->conf;
	RadiusType msg_type = (RadiusType) sock_ctx;
	int len, i, roundtrip;
	unsigned char buf[3000];
	struct radius_msg *msg;
	struct radius_rx_handler *handlers;
	size_t num_handlers;
	struct radius_msg_list *req, *prev_req;
	struct timeval tv;
	struct hostapd_radius_server *rconf;
	int invalid_authenticator = 0;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
    int classLen;
    char * classAtt;
    int stateLen;
    char * stateAtt;
    tUser * aUser;

    tStatTimeEnd(0);
    tStatCount(tThread_getKey());

	if (msg_type == RADIUS_ACCT) {
		handlers = radius->acct_handlers;
		num_handlers = radius->num_acct_handlers;
		rconf = conf->acct_server;
	} else {
		handlers = radius->auth_handlers;
		num_handlers = radius->num_auth_handlers;
		rconf = conf->auth_server;
	}

	len = recv(sock, buf, sizeof(buf), MSG_DONTWAIT);
	if (len < 0) {
		perror("recv[RADIUS]");
		return;
	}

    if (verbose >= 3) {
        hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "Received %d bytes from RADIUS server\n", len);
    }
	
	if (len == sizeof(buf)) {
        if (verbose >= 3) {
            TRACE_TRAFIC("Possibly too long UDP frame for our buffer - dropping it\n");
        }
		return;
	}

	msg = radius_msg_parse(buf, len);

    
	if (msg == NULL) {
        if (verbose >= 3) {
            TRACE_ERROR("Parsing incoming RADIUS frame failed\n");
        }
		rconf->malformed_responses++;
		return;
	}

    if (verbose >= 3) {
        hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
                   HOSTAPD_LEVEL_DEBUG, "Received RADIUS message\n");
    }
    if (verbose >= 3 && conf->msg_dumps)
    radius_msg_dump(msg);

	switch (msg->hdr->code) {
	case RADIUS_CODE_ACCESS_ACCEPT:
		rconf->access_accepts++;
        // test if attribute class is present
        classLen = radius_msg_get_attr(msg, RADIUS_ATTR_CLASS, NULL, 0);
        if (classLen > 0) {
            classAtt = (char *) malloc(classLen * sizeof(char));
            classLen = radius_msg_get_attr(msg, RADIUS_ATTR_CLASS, classAtt, classLen);
            aUser = e -> tgenUser;
            tUserSetClassAttrib(aUser, classAtt, classLen, 0);
            free (classAtt);
        }
        // test if attribute state is present
        stateLen = radius_msg_get_attr(msg, RADIUS_ATTR_STATE, NULL, 0);
        if (stateLen > 0) {
            stateAtt = (char *) malloc(stateLen * sizeof(char));
            stateLen = radius_msg_get_attr(msg, RADIUS_ATTR_CLASS, stateAtt, stateLen);
            aUser = e -> tgenUser;
            tUserSetStateAttrib(aUser, stateAtt, stateLen, 0);
            free(stateAtt);
        }


		break;
	case RADIUS_CODE_ACCESS_REJECT:
		rconf->access_rejects++;
		break;
	case RADIUS_CODE_ACCESS_CHALLENGE:
		rconf->access_challenges++;
		break;
	case RADIUS_CODE_ACCOUNTING_RESPONSE:
		rconf->responses++;
		break;
	}

	prev_req = NULL;
	req = radius->msgs;
	while (req) {
		/* TODO: also match by src addr:port of the packet when using
		 * alternative RADIUS servers (?) */
		if ((req->msg_type == msg_type ||
		     (req->msg_type == RADIUS_ACCT_INTERIM &&
		      msg_type == RADIUS_ACCT)) &&
		    req->msg->hdr->identifier == msg->hdr->identifier)
			break;

		prev_req = req;
		req = req->next;
	}
	if (req == NULL) {
        if (verbose >= 3) {
            hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
			       HOSTAPD_LEVEL_DEBUG,
			       "No matching RADIUS request found (type=%d id=%d) - dropping packet\n",
			       msg_type, msg->hdr->identifier);
        }
		goto fail;
	}

	gettimeofday(&tv, NULL);
	roundtrip = (tv.tv_sec - req->last_attempt.tv_sec) * 100 +
		(tv.tv_usec - req->last_attempt.tv_usec) / 10000;
    if (verbose >= 3) {
        hostapd_logger(e->wpa_s, req->addr, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG,
		       "Received RADIUS packet matched with a pending request, round trip time %d.%02d sec\n",
		       roundtrip / 100, roundtrip % 100);
    }
	
	rconf->round_trip_time = roundtrip;

    // update stats after reception

    tStatActionTime(e->statType, 0, e->statRetries, 0 );

	/* Remove ACKed RADIUS packet from retransmit list */
	if (prev_req)
		prev_req->next = req->next;
	else
		radius->msgs = req->next;
	radius->num_msgs--;

	for (i = 0; i < num_handlers; i++) {
		RadiusRxResult res;
		res = handlers[i].handler(msg, req->msg, req->shared_secret,
					  req->shared_secret_len,
					  handlers[i].data);
		switch (res) {
		case RADIUS_RX_PROCESSED:
			radius_msg_free(msg);
			free(msg);
			/* continue */
        case RADIUS_RX_QUEUED:
            // standard case
			radius_client_msg_free(req);
			return;
		case RADIUS_RX_INVALID_AUTHENTICATOR:
			invalid_authenticator++;
			/* continue */
		case RADIUS_RX_UNKNOWN:
			/* continue with next handler */
			break;
		}
	}

	if (invalid_authenticator)
		rconf->bad_authenticators++;
	else
		rconf->unknown_types++;
    if (verbose >= 3) {
        hostapd_logger(e->wpa_s, req->addr, HOSTAPD_MODULE_RADIUS,
		       HOSTAPD_LEVEL_DEBUG, "No RADIUS RX handler found (type=%d code=%d id=%d)%s - dropping packet\n",
		       msg_type, msg->hdr->code, msg->hdr->identifier,
		       invalid_authenticator ? " [INVALID AUTHENTICATOR]" :
		       "\n");
    }
	radius_client_msg_free(req);

    

 fail:
	radius_msg_free(msg);
	free(msg);
    tStatActionTime(e->statType, 1, e->statRetries, 0 );
}

/******************************************************************************/
u8 radius_client_get_id(struct radius_client_data *radius)
/******************************************************************************/
{
	struct radius_msg_list *entry, *prev, *remove;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
	
    u8 id;
    pthread_mutex_lock(&identMutex);
    if ((radius->next_radius_identifier == 0) 
        ||
        ((radius->next_radius_identifier % 6) == 5)) {
        radius->next_radius_identifier = ident;
        ident = ident + 6;
        // if 252 is used, the access accept would be 252 + 4 e.g. 0 which is the same
        // identifier as the next foreseen which is really wrong
        if (ident == 252) {
            ident = 0;
        }
    }
    id = radius->next_radius_identifier++;
    pthread_mutex_unlock(&identMutex);

	/* remove entries with matching id from retransmit list to avoid
	 * using new reply from the RADIUS server with an old request */
	entry = radius->msgs;
	prev = NULL;
	while (entry) {
		if (entry->msg->hdr->identifier == id) {
            if (verbose >= 1) {
                hostapd_logger(e->wpa_s, entry->addr,
				       HOSTAPD_MODULE_RADIUS,
				       HOSTAPD_LEVEL_DEBUG,
				       "Removing pending RADIUS message, since its id (%d) is reused\n", id);
            }
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;
			remove = entry;
		} else
			remove = NULL;
		prev = entry;
		entry = entry->next;

		if (remove) {
            radius_client_msg_free(remove);
        }
			
	}

	return id;
}

/******************************************************************************/
void radius_client_flush(struct radius_client_data *radius)
/******************************************************************************/
{
	struct radius_msg_list *entry, *prev;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (!radius)
		return;

	tloop_cancel_timeout(e->tloop, radius_client_timer, radius, NULL);

	entry = radius->msgs;
	radius->msgs = NULL;
	radius->num_msgs = 0;
	while (entry) {
		prev = entry;
		entry = entry->next;
		radius_client_msg_free(prev);
	}
}

/******************************************************************************/
static int
radius_change_server(struct radius_client_data *radius,
		     struct hostapd_radius_server *nserv,
		     struct hostapd_radius_server *oserv,
		     int sock, int sock6, int auth)
/******************************************************************************/
{
	struct sockaddr_in serv;
#ifdef CONFIG_IPV6
	struct sockaddr_in6 serv6;
#endif /* CONFIG_IPV6 */
	struct sockaddr *addr;
	socklen_t addrlen;
	char abuf[50];
	int sel_sock;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

    if (verbose >= 3) {
        hostapd_logger(e->wpa_s, NULL, HOSTAPD_MODULE_RADIUS,
                   HOSTAPD_LEVEL_INFO,
                   "%s server %s:%d\n",
                   auth ? "Authentication" : "Accounting",
                   hostapd_ip_txt(&nserv->addr, abuf, sizeof(abuf)),
                   nserv->port);

    }
	
	if (!oserv || nserv->shared_secret_len != oserv->shared_secret_len ||
	    memcmp(nserv->shared_secret, oserv->shared_secret,
		   nserv->shared_secret_len) != 0) {
		/* Pending RADIUS packets used different shared
		 * secret, so they would need to be modified. Could
		 * update all message authenticators and
		 * User-Passwords, etc. and retry with new server. For
		 * now, just drop all pending packets. */
		radius_client_flush(radius);
	} else {
		/* Reset retry counters for the new server */
		struct radius_msg_list *entry;
		entry = radius->msgs;
		while (entry) {
			/*entry->next_try = entry->first_try +
				RADIUS_CLIENT_FIRST_WAIT; */
            entry->next_try = entry->first_try + tcRadiusTimeout;
			entry->attempts = 0;
			// entry->next_wait = RADIUS_CLIENT_FIRST_WAIT * 2;
            // not exponential
            entry->next_wait = tcRadiusTimeout;
			entry = entry->next;
		}
		if (radius->msgs) {
			tloop_cancel_timeout(e->tloop, radius_client_timer, radius,
					     NULL);
            tloop_register_timeout(e->tloop, (int)tcRadiusTimeout, 0,
                           radius_client_timer, radius,
                           NULL);
		}
	}
	switch (nserv->addr.af) {
	case AF_INET:
		memset(&serv, 0, sizeof(serv));
		serv.sin_family = AF_INET;
		serv.sin_addr.s_addr = nserv->addr.u.v4.s_addr;
		serv.sin_port = htons(nserv->port);
		addr = (struct sockaddr *) &serv;
		addrlen = sizeof(serv);
		sel_sock = sock;
		break;
#ifdef CONFIG_IPV6
	case AF_INET6:
		memset(&serv6, 0, sizeof(serv6));
		serv6.sin6_family = AF_INET6;
		memcpy(&serv6.sin6_addr, &nserv->addr.u.v6,
		       sizeof(struct in6_addr));
		serv6.sin6_port = htons(nserv->port);
		addr = (struct sockaddr *) &serv6;
		addrlen = sizeof(serv6);
		sel_sock = sock6;
		break;
#endif /* CONFIG_IPV6 */
	default:
		return -1;
	}

	if (connect(sel_sock, addr, addrlen) < 0) {
		perror("connect[radius]");
		return -1;
	}
	if (auth)
		radius->auth_sock = sel_sock;
	else
		radius->acct_sock = sel_sock;

	return 0;
}

/******************************************************************************/
static void radius_retry_primary_timer(void *tloop_ctx, void *timeout_ctx)
/******************************************************************************/
{
	struct radius_client_data *radius = tloop_ctx;
	struct hostapd_radius_servers *conf = radius->conf;
	struct hostapd_radius_server *oserv;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	if (radius->auth_sock >= 0 && conf->auth_servers &&
	    conf->auth_server != conf->auth_servers) {
		oserv = conf->auth_server;
		conf->auth_server = conf->auth_servers;
		radius_change_server(radius, conf->auth_server, oserv,
				     radius->auth_serv_sock,
				     radius->auth_serv_sock6, 1);
	}

	if (radius->acct_sock >= 0 && conf->acct_servers &&
	    conf->acct_server != conf->acct_servers) {
		oserv = conf->acct_server;
		conf->acct_server = conf->acct_servers;
		radius_change_server(radius, conf->acct_server, oserv,
				     radius->acct_serv_sock,
				     radius->acct_serv_sock6, 0);
	}

	if (conf->retry_primary_interval)
		tloop_register_timeout(e->tloop, conf->retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);
}

/******************************************************************************/
static int radius_client_init_auth(struct radius_client_data *radius)
/******************************************************************************/
{
	struct hostapd_radius_servers *conf = radius->conf;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
	int ok = 0;

    radius->auth_serv_sock = e->socket;

	radius_change_server(radius, conf->auth_server, NULL,
			     radius->auth_serv_sock, radius->auth_serv_sock6,
			     1);

	if (radius->auth_serv_sock >= 0 &&
	    tloop_register_read_sock(e->tloop, radius->auth_serv_sock,
				     radius_client_receive, radius,
				     (void *) RADIUS_AUTH)) {
		TRACE_ERROR("Could not register read socket for authentication server\n");
		return -1;
	}

#ifdef CONFIG_IPV6
	if (radius->auth_serv_sock6 >= 0 &&
	    tloop_register_read_sock(e->tloop, radius->auth_serv_sock6,
				     radius_client_receive, radius,
				     (void *) RADIUS_AUTH)) {
		if (librad_debug) TRACE_ERROR("Could not register read socket for authentication server\n");
		return -1;
	}
#endif /* CONFIG_IPV6 */
	return 0;
}

/******************************************************************************/
static int radius_client_init_acct(struct radius_client_data *radius)
/******************************************************************************/
{
	struct hostapd_radius_servers *conf = radius->conf;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;
	int ok = 0;

	radius->acct_serv_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (radius->acct_serv_sock < 0)
		perror("socket[PF_INET,SOCK_DGRAM]");
	else
		ok++;

	radius_change_server(radius, conf->acct_server, NULL,
			     radius->acct_serv_sock, radius->acct_serv_sock6,
			     0);

	if (radius->acct_serv_sock >= 0 &&
	    tloop_register_read_sock(e->tloop, radius->acct_serv_sock,
				     radius_client_receive, radius,
				     (void *) RADIUS_ACCT)) {
		if (librad_debug) TRACE_ERROR("Could not register read socket for accounting server\n");
		return -1;
	}

#ifdef CONFIG_IPV6
	if (radius->acct_serv_sock6 >= 0 &&
	    tloop_register_read_sock(e->tloop, radius->acct_serv_sock6,
				     radius_client_receive, radius,
				     (void *) RADIUS_ACCT)) {
		if (librad_debug) TRACE_ERROR("Could not register read socket for accounting server\n");
		return -1;
	}
#endif /* CONFIG_IPV6 */

	return 0;
}

/******************************************************************************/
struct radius_client_data *
radius_client_init(void *ctx, struct hostapd_radius_servers *conf)
/******************************************************************************/
{
	struct radius_client_data *radius;
    struct eapol_test_data *e = (struct eapol_test_data *)ctx;

	radius = malloc(sizeof(struct radius_client_data));
	if (radius == NULL)
		return NULL;

	memset(radius, 0, sizeof(struct radius_client_data));
	radius->ctx = ctx;
	radius->conf = conf;

	radius->auth_serv_sock = radius->acct_serv_sock =
		radius->auth_serv_sock6 = radius->acct_serv_sock6 =
		radius->auth_sock = radius->acct_sock = -1;

	if (conf->auth_server && radius_client_init_auth(radius)) {
		radius_client_deinit(radius);
		return NULL;
	}

	if (conf->acct_server && radius_client_init_acct(radius)) {
		radius_client_deinit(radius);
		return NULL;
	}

	if (conf->retry_primary_interval)
		tloop_register_timeout(e->tloop, conf->retry_primary_interval, 0,
				       radius_retry_primary_timer, radius,
				       NULL);

	return radius;
}

/******************************************************************************/
void radius_client_flush_auth(struct radius_client_data *radius, u8 *addr)
/******************************************************************************/
{
	struct radius_msg_list *entry, *prev, *tmp;
    struct eapol_test_data *e = (struct eapol_test_data *)radius->ctx;

	prev = NULL;
	entry = radius->msgs;
	while (entry) {
		if (entry->msg_type == RADIUS_AUTH &&
		    memcmp(entry->addr, addr, ETH_ALEN) == 0) {
            if (verbose >= 3) {
                hostapd_logger(e->wpa_s, addr,
				       HOSTAPD_MODULE_RADIUS,
				       HOSTAPD_LEVEL_DEBUG,
				       "Removing pending RADIUS authentication message for removed client\n");
            }
			if (prev)
				prev->next = entry->next;
			else
				radius->msgs = entry->next;

			tmp = entry;
			entry = entry->next;
			radius_client_msg_free(tmp);
			radius->num_msgs--;
			continue;
		}

		prev = entry;
		entry = entry->next;
	}
}


// tloop part (issued from eloop)
/******************************************************************************/
struct tloop_data * tloop_init(void *user_data)
/******************************************************************************/
{
    struct tloop_data * tloop;

    tloop = (struct tloop_data *) malloc(sizeof(*tloop));
    if (tloop == NULL) {
        TRACE_ERROR("%s:%d => Could not allocate tloop context\n", __FILE__, __LINE__);
        return NULL;
    }
	memset(tloop, 0, sizeof(*tloop));
	tloop->user_data = user_data;
    tloop->readers = NULL;
    tloop->timeout = NULL;
    tloop->signals = NULL;
    return tloop;
}
/******************************************************************************/
int tloop_register_timeout(struct tloop_data* tloop,
                           unsigned int secs, unsigned int usecs,
			   void (*handler)(void *tloop_ctx, void *timeout_ctx),
			   void *tloop_data, void *user_data)
/******************************************************************************/
{
	struct tloop_timeout *timeout, *tmp, *prev;

	timeout = (struct tloop_timeout *) malloc(sizeof(*timeout));
	if (timeout == NULL)
		return -1;
	gettimeofday(&timeout->time, NULL);
	timeout->time.tv_sec += secs;
	timeout->time.tv_usec += usecs;
	while (timeout->time.tv_usec >= 1000000) {
		timeout->time.tv_sec++;
		timeout->time.tv_usec -= 1000000;
	} 
	timeout->tloop_data = tloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;
	timeout->next = NULL;

	if (tloop->timeout == NULL) {
		tloop->timeout = timeout;
		return 0;
	}

	prev = NULL;
	tmp = tloop->timeout;
	while (tmp != NULL) {
		if (timercmp(&timeout->time, &tmp->time, <))
			break;
		prev = tmp;
		tmp = tmp->next;
	}

	if (prev == NULL) {
		timeout->next = tloop->timeout;
		tloop->timeout = timeout;
	} else {
		timeout->next = prev->next;
		prev->next = timeout;
	}

	return 0;
}
/******************************************************************************/
void tloop_run(struct tloop_data* tloop)
/******************************************************************************/
{
	fd_set *rfds;
	int i, res;
	struct timeval tv, now;

	rfds = malloc(sizeof(*rfds));
	if (rfds == NULL) {
		TRACE_ERROR("tloop_run - malloc failed\n");
		return;
	}

  /*  while (!tloop->terminate &&
		(tloop->timeout)) { */
    while (!tloop->terminate) {
		if (tloop->timeout) {
			gettimeofday(&now, NULL);
			if (timercmp(&now, &(tloop->timeout->time), <))
				timersub(&(tloop->timeout->time), &now, &tv);
			else
				tv.tv_sec = tv.tv_usec = 0;
#if 0
			if (librad_debug) TRACE_ERROR("next timeout in %lu.%06lu sec\n",
			       tv.tv_sec, tv.tv_usec);
#endif
		}

		FD_ZERO(rfds);
        FD_SET(tloop->readers->sock, rfds);
		res = select(tloop->readers->sock + 1, rfds, NULL, NULL,
			     tloop->timeout ? &tv : NULL); 
		/*res = select(FD_SETSIZE, rfds, NULL, NULL,
			     eloop.timeout ? &tv : NULL); */
		if (res < 0 && errno != EINTR) {
			perror("select");
			free(rfds);
			return;
		}

		/* check if some registered timeouts have occurred */
		if (tloop->timeout) {
			struct tloop_timeout *tmp;

			gettimeofday(&now, NULL);
			if (!timercmp(&now, &(tloop->timeout->time), <)) {
				tmp = tloop->timeout;
				tloop->timeout = tloop->timeout->next;
				tmp->handler(tmp->tloop_data,
					     tmp->user_data);
				free(tmp);
			}

		}

		if (res <= 0)
			continue;
        if (FD_ISSET(tloop->readers->sock, rfds)) {
            tloop->readers->handler(
                tloop->readers->sock,
                tloop->readers->tloop_data,
                tloop->readers->user_data);
        }
	}

	free(rfds);
}
/******************************************************************************/
void tloop_destroy(struct tloop_data* tloop)
/******************************************************************************/
{
	struct tloop_timeout *timeout, *prev;

	timeout = tloop->timeout;
	while (timeout != NULL) {
		prev = timeout;
		timeout = timeout->next;
		free(prev);
	}
    if (tloop->readers) {
        free(tloop->readers);
        tloop->readers = NULL;
    }
    if (tloop->signals) {
        free(tloop->signals);
        tloop->signals = NULL;
    }
    free(tloop);
}

/******************************************************************************/
void tloop_terminate(struct tloop_data* tloop)
/******************************************************************************/
{
	tloop->terminate = 1;    
}
/******************************************************************************/
void tloop_unregister_read_sock(struct tloop_data* tloop, int sock)
/******************************************************************************/
{
	int i;

	if (tloop->readers == NULL)
        return;

    if (tloop->readers->sock == sock) {
        free(tloop->readers);
        tloop->readers = NULL;
    }
}
/******************************************************************************/
int tloop_cancel_timeout(struct tloop_data* tloop, 
                         void (*handler)(void *tloop_ctx, void *sock_ctx),
			 void *tloop_data, void *user_data)
/******************************************************************************/
{
	struct tloop_timeout *timeout, *prev, *next;
	int removed = 0;

	prev = NULL;
	timeout = tloop->timeout;
	while (timeout != NULL) {
		next = timeout->next;

		if (timeout->handler == handler &&
		    (timeout->tloop_data == tloop_data ||
		     tloop_data == TLOOP_ALL_CTX) &&
		    (timeout->user_data == user_data ||
		     user_data == TLOOP_ALL_CTX)) {
			if (prev == NULL)
				tloop->timeout = next;
			else
				prev->next = next;
			free(timeout);
			removed++;
		} else
			prev = timeout;

		timeout = next;
	}

	return removed;
}
/******************************************************************************/
int tloop_register_read_sock(struct tloop_data* tloop, int sock,
			     void (*handler)(int sock, void *tloop_ctx,
					     void *sock_ctx),
			     void *tloop_data, void *user_data)
/******************************************************************************/
{
	struct tloop_sock *tmp;

	tmp = (struct tloop_sock *) malloc (sizeof(struct tloop_sock));
	if (tmp == NULL) {
        TRACE_ERROR("tloop_register_read_sock: Could not malloc tloop_sock\n");
        return -1;
    }

	tmp->sock = sock;
	tmp->tloop_data = tloop_data;
	tmp->user_data = user_data;
	tmp->handler = handler;
	tloop->readers = tmp;
	return 0;
}
/******************************************************************************/
int tloop_terminated(struct tloop_data* tloop)
/******************************************************************************/
{
	return tloop->terminate;
}

/************************************************************************************/
/* RHL, It will copy the char(s) type value from source to the dest*/
/* parameter: char* destVSA: the dest of attr value. it need set it as array of char[n]*/
/* parameter: char* srcVSA: the source of attr value */
/* parameter: length: it's the length of the vsa */
void copyVSAAttrValue_TTLS(char* destVSA, char* srcVSA, int length, int isAdd0x){
/************************************************************************************/
    int t = 0;
    char * pVSA;
    TRACE_DEBUG("copyVSAAttrValue_TTLS:destVSA=%02x, srcVSA=%02x,length=%d\n",(unsigned char* )destVSA,(unsigned char* ) srcVSA, length );

    if (length == 0){
    	destVSA = NULL;
    	return;
    }
    // TTLS will not add the 0x at the begining
    if(isAdd0x)
    	strcpy(destVSA, "0x");
    pVSA = destVSA; 
    for (t = 0; t < length; t++) {
    	sprintf(pVSA, "%02x", (unsigned char)srcVSA[t]);
    	pVSA += 2;
    }

}

/*******************************************************************************/
/* RHL; Sep 16, 2008; It will put the Wimax VSA value to ssid*/
int ieee802_1x_put_wimax_vsa(  struct wpa_ssid *ssid,
                  tUser *    	aUser,
		  int 	        creditSessionAction)
/******************************************************************************/
{
	
	char *  aNai = tUserGetNAI(aUser);
        char aaa_session_id[32];
   
	// add credit session action for prepaid charing feature,
	
	//add WIMAX session Id if available
   	if ( tUserGetAAASessionIdLength(aUser) ) {
	   copyVSAAttrValue_TTLS((char*)aaa_session_id, tUserGetAAASessionId(aUser), tUserGetAAASessionIdLength(aUser),0);
	   TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding AAA-Session-ID= %s \n", aNai, aaa_session_id);	 
	   ssid->aaa_session_id = (u8*)malloc(strlen(aaa_session_id)+1);
	   strcpy(ssid->aaa_session_id, aaa_session_id);
   	} else {
	   aaa_session_id[0] = 0;
	   if ( creditSessionAction >= 2) {
		   // can not get valid AAA-Session-ID, throw error
		   TRACE_ERROR("ieee802_1x_put_wimax_vsa on %s: can not get valid AAA-Session-ID for creditSessionAction=%d\n",aNai,creditSessionAction);
		   return -1;
	   }
   	}

	// handle Service-Type attribute for Wimax
   	// It should be decorrelated from any particular AuthType
   	if (creditSessionAction >= 2) {
	   ssid->servicetype = (u8*)malloc(strlen(ServiceType_AuthorizeOnly_TTLS)+1);
	   strcpy(ssid->servicetype, ServiceType_AuthorizeOnly_TTLS);
	   TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The servicetype is %s \n", ServiceType_AuthorizeOnly_TTLS);
	} else if (creditSessionAction != 1 && aaa_session_id[0]) {
	  // RHL, Oct 22, 2008; Add the condition creditSessionAction != 1  to avoid the error 
	  // when Termination failed and then no Initial case calling this user next time
	   ssid->servicetype = (u8*)malloc(strlen(ServiceType_AuthenticateOnly_TTLS)+1);
	   strcpy(ssid->servicetype, ServiceType_AuthenticateOnly_TTLS);
	   TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The servicetype is %s \n", ServiceType_AuthenticateOnly_TTLS);
   	} else {   
	   ssid->servicetype = (u8*)malloc(strlen(ServiceType_Framed_TTLS)+1);
	   strcpy(ssid->servicetype, ServiceType_Framed_TTLS);
	   TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The servicetype is %s \n", ServiceType_Framed_TTLS);
   	}
   	
	// wimaxcapability
	ssid->wimaxcapability = (u8*)malloc(strlen(CreditSessionInitial_WIMAXCAPABILITY_TTLS)+1);
	strcpy(ssid->wimaxcapability,CreditSessionInitial_WIMAXCAPABILITY_TTLS);
	TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The wimaxcapability is %s \n", CreditSessionInitial_WIMAXCAPABILITY_TTLS);
    

	// it will send different additional attributes according to session type
	// 1: Initial; 2: Update; 3: Termination;
	if (creditSessionAction == 1) {
		//Initial
	    	TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding prepaid related attrs for Initial Session\n",aNai);
	    	// RHL; Sep 16, 2008; Add VSA servicetype, wimaxcapability, ppac, session_termination_capability into wpa_ssid to test Prepaid charging with TTLS
      
            	//ppac
	    	ssid->ppac = (u8*)malloc(strlen(CreditSessionInitial_PPAC_TTLS)+1);
	    	strcpy(ssid->ppac, CreditSessionInitial_PPAC_TTLS);
	    	TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The ppac is %s \n", CreditSessionInitial_PPAC_TTLS);
		    
		//session_termination_capability
		ssid->session_termination_capability = (u8*)malloc(strlen(CreditSessionInitial_SessionTerminationCapability_TTLS)+1);
		strcpy(ssid->session_termination_capability,CreditSessionInitial_SessionTerminationCapability_TTLS);
		TRACE_DEBUG("ieee802_1x_put_wimax_vsa: The session_termination_capability is %s \n", CreditSessionInitial_SessionTerminationCapability_TTLS);

	} else if (creditSessionAction == 2) {
		//Update
		TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding prepaid related attrs for Update Session\n",aNai);
			 
		if (tUserGetPPAQLength(aUser)) {
			char ppaq[128];
			copyVSAAttrValue_TTLS((char*)ppaq,tUserGetPPAQ(aUser),tUserGetPPAQLength(aUser),0);
			//get PPAQ, add "080304"
			strcat(ppaq ,PPAQ_UpdateReason_QuotaReached);

			TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding PPAQ = %s\n",aNai,ppaq);	 
			ssid->ppaq = (u8*)malloc(strlen(ppaq)+1);
			 strcpy(ssid->ppaq, ppaq);
		} else {
			// can not get valid PPAQ, throw error
			TRACE_ERROR("ieee802_1x_put_wimax_vsa on %s: can not get valid PPAQ for creditSessionAction=%d\n",aNai,creditSessionAction);
			return -1;
		}
	} else if (creditSessionAction == 3) {
		//Termination
		TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding prepaid related attrs for Termination Session\n",aNai);

		if (tUserGetPPAQLength(aUser)) {
			char ppaq[128];
			copyVSAAttrValue_TTLS((char*)ppaq,tUserGetPPAQ(aUser),tUserGetPPAQLength(aUser),0);
			//get PPAQ, add "080304"
			strcat(ppaq ,PPAQ_UpdateReason_AccessServiceTerminated);

			TRACE_DEBUG("ieee802_1x_put_wimax_vsa on %s: adding PPAQ = %s\n",aNai,ppaq);	 
			ssid->ppaq = (u8*)malloc(strlen(ppaq)+1);
			strcpy(ssid->ppaq, ppaq);
		} else {
			// can not get valid PPAQ, throw error
			TRACE_ERROR("ieee802_1x_put_wimax_vsa on %s: can not get valid PPAQ for creditSessionAction=%d\n",aNai,creditSessionAction);
			return -1;
		}	 
	}
	return 1;
}

