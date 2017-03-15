/*
* radeapclient.c    EAP specific radius packet debug tool.
*
* Version:    $Id: radeapclient.c,v 1.3 2003/11/06 15:41:21 aland Exp $
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*
* Copyright 2000  The FreeRADIUS server project
* Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
* Copyright 2000  Alan DeKok <aland@ox.org>
*/
/*
07/09/2005 | CC | UMA dev | add fast reauthentication
*/
static const char rcsid[] = "$Id: radeapclient.c,v 1.3 2003/11/06 15:41:21 aland Exp $";

#define ENCR_DATA_LEN_MAX   200
#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include    <fcntl.h>      /* EmA,18/06/01 */
#include    <sys/timeb.h>      /* EmA,18/06/01 For precise time function & struct */

#if HAVE_UNISTD_H
#    include <unistd.h>
#endif

#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>

#if HAVE_NETINET_IN_H
#    include <netinet/in.h>
#endif

#if HAVE_SYS_SELECT_H
#    include <sys/select.h>
#endif

#if HAVE_GETOPT_H
#    include <getopt.h>
#endif

#include "conf.h"
#include "radpaths.h"
#include "missing.h"
#include "../include/md5.h"

#include "eap_types.h"
#include "eap_sim.h"

static int retries = 10;
static float timeout = 3;
static const char *secret = NULL;
/*EmA: static */ int do_output = 1;
static int do_summary = 0;
static int filedone = 0;
static long totalOK = 0;
static long totalREJ = 0;
static long totalresend = 0;
static long totaltimeOK = 0;
static long totaltimeREJ = 0;
static int mintimeOK = 10000;
static int maxtimeOK = 0;
static int meantimeOK = 0;
static int mintimeREJ = 10000;
static int maxtimeREJ = 0;
static int meantimeREJ = 0;
int estart = 0; /* a client error is sent at start reception */
int estartNotif = 0;
int echallenge = 0; /* a client error is sent at challenge reception */
int ecounterTooSmall = 0; /* a counter too small is sent in reauth */
int atEncrData = 0; /* add AT_ENCR_DATA, AT_IV, AT_RESULT_IND in SIM-Challenge */
int doNotRespond = 0; /* do not respond to SIM start request */
int haveSendRejectOrSyncFailure = 0; 
int eAkaReject = 0; /* a client error is sent at start reception */
int eAkaSyncFailure = 0; /* a client error is sent at start reception */

static char filesecret[256];
const char *progname = "radeapclient";
/* lrad_randctx randctx; */
radlog_dest_t radlog_dest = RADLOG_STDERR;
int debug_flag = 0;
struct main_config_t mainconfig;
char password[256];
char eapid[80];

struct eapsim_keys eapsim_mk;
static int process_eap_clienterror (RADIUS_PACKET *req,
                                    RADIUS_PACKET *rep);
/************************************************************************************/
static void usage(void)
/************************************************************************************/
{
    fprintf(stderr, "Usage: radeapclient [options] server[:port] <command> [<secret>]\n");
    
    fprintf(stderr, "  <command>    One of auth, acct, status, or disconnect.\n");
    fprintf(stderr, "  -c count    Send each packet 'count' times.\n");
    fprintf(stderr, "  -d raddb    Set dictionary directory.\n");
    fprintf(stderr, "  -f file     Read packets from file, not stdin.\n");
    fprintf(stderr, "  -r retries  If timeout, retry sending the packet 'retries' times.\n");
    fprintf(stderr, "  -t timeout  Wait 'timeout' seconds before retrying (may be a floating point number).\n");
    fprintf(stderr, "  -i id       Set request id to 'id'.  Values may be 0..255\n");
    fprintf(stderr, "  -S file     read secret from file, not command line.\n");
    fprintf(stderr, "  -q          Do not print anything out.\n");
    fprintf(stderr, "  -s          Print out summary information of auth results.\n");
    fprintf(stderr, "  -v          Show program version information.\n");
    fprintf(stderr, "  -x          Debugging mode.\n");
    fprintf(stderr, "  -a er  Reply to start request by client-error with error er.\n");
    fprintf(stderr, "  -b er  Reply to challenge request by client-error with error er.\n");
    fprintf(stderr, "  -e Reply to reauth request by reauth response with at_counter_too_small\n");
    fprintf(stderr, "  -E Reply to reauth request by reauth response with at_counter_too_small with wrong counter\n");
    fprintf(stderr, "  -b er  Reply to reauth request by reauth response with counter er.\n");
    fprintf(stderr, "  -g  Add AT_ENCR_DATA, AT_IV, AT_RESULT_IND in SIM-CHALLENGE.\n");
    fprintf(stderr, "  -n  Do not respond to SIM start request.\n");
    
    
    exit(1);
}

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
static int getport(const char *name)
/************************************************************************************/
{
    struct    servent        *svp;
    
    svp = getservbyname (name, "udp");
    if (!svp) {
        return 0;
    }
    
    return ntohs(svp->s_port);
}

/************************************************************************************/
//EmA,15/01/2004: Same as RADCLIENT
static int send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep)
/************************************************************************************/
{
    int i;
    struct timeval    tv;
    struct timeb tbeg, tend;
    long     ms_delay;
    RADIUS_PACKET *rep2;
    int    res_rad_decode;
    
    ftime(&tbeg);
    
    for (i = 0; i < retries; i++) {
        fd_set        rdfdesc;
        
        rad_send(req, NULL, secret);
        
        /* And wait for reply, timing out as necessary */
        FD_ZERO(&rdfdesc);
        FD_SET(req->sockfd, &rdfdesc);
        
        tv.tv_sec = (int)timeout;
        tv.tv_usec = 1000000 * (timeout - (int)timeout);
        
        /* Something's wrong if we don't get exactly one fd. */
        if (select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
            continue;
        }
        
        *rep = rad_recv(req->sockfd);
        if (*rep != NULL) {
            
        /*
        *    If we get a response from a machine
        *    which we did NOT send a request to,
        *    then complain.
            */
            if (((*rep)->src_ipaddr != req->dst_ipaddr) ||
                ((*rep)->src_port != req->dst_port)) {
                char src[64], dst[64];
                
                ip_ntoa(src, (*rep)->src_ipaddr);
                ip_ntoa(dst, req->dst_ipaddr);
                fprintf(stderr, "radclient: ERROR: Sent request to host %s:%d, got response from host %s:%d\n!",
                    dst, req->dst_port,
                    src, (*rep)->src_port);
                exit(1);
            }
            
            if ( ! do_summary ) {
                do {
                    rep2 = NULL;
                    
                    /* And wait for reply, timing out as necessary */
                    FD_ZERO(&rdfdesc);
                    FD_SET(req->sockfd, &rdfdesc);
                    
                    tv.tv_sec = 0;
                    tv.tv_usec = 100000;  // 100 ms
                    
                    /* Something's wrong if we don't get exactly one fd. */
                    if (select(req->sockfd + 1, &rdfdesc, NULL, NULL, &tv) != 1) {
                        continue;
                    }
                    
                    rep2 = rad_recv(req->sockfd);
                    
                    if (rep2 != NULL) {
                        fprintf(stderr, "radclient: one redundant response from server\n");
                    }
                    
                } while (rep2 != NULL);
            }
            
            break;
            
        } else {    /* NULL: couldn't receive the packet */
            librad_perror("radclient:");
            exit(1);
        }
    }
    
    ftime(&tend);
    
    /* No response or no data read (?) */
    if (i == retries) {
        fprintf(stderr, "radclient: no response from server\n");
        exit(1);
    }
    
    res_rad_decode = rad_decode(*rep, req, secret);
    
    if (res_rad_decode == 1) {    // invalid signature
        librad_perror("rad_decode");
        
        if (!librad_debug) {
            // prints out the value pairs of sended request
            printf("Request was ID %d, code %d, length = %d\n",
                req->id, req->code, req->data_len);
            vp_printlist(stdout, req->vps);
        }
        
    } else if (res_rad_decode != 0) {    // ex: -1 == not enough memory
        librad_perror("rad_decode");
        exit(1);
    }
    
    if (!librad_debug && do_output) {
        // if -x, libradius debug already prints out the value pairs for us
        // if -q, don't print normal cases
        printf("Received response ID %d, code %d, length = %d\n",
            (*rep)->id, (*rep)->code, (*rep)->data_len);
        vp_printlist(stdout, (*rep)->vps);
    }
    
    /* count of packets */
    ms_delay = 1000 * (tend.time - tbeg.time) + (tend.millitm - tbeg.millitm);
    
    totalresend += i;
    if((*rep)->code == PW_AUTHENTICATION_ACK) {
        totalOK++;
        totaltimeOK += ms_delay;
        if ( ms_delay < mintimeOK ) mintimeOK = ms_delay;
        if ( ms_delay > maxtimeOK ) maxtimeOK = ms_delay;
    } else {
        totalREJ++;
        totaltimeREJ += ms_delay;
        if ( ms_delay < mintimeREJ ) mintimeREJ = ms_delay;
        if ( ms_delay > maxtimeREJ ) maxtimeREJ = ms_delay;
    }
    
    return 0;
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
static int process_eap_start(RADIUS_PACKET *req,
                             RADIUS_PACKET *rep)
                             /************************************************************************************/
{
    VALUE_PAIR *vp, *newvp;
    VALUE_PAIR *anyidreq_vp, *fullauthidreq_vp, *permanentidreq_vp;
    uint16_t *versions, selectedversion;
    unsigned int i,versioncount;
    
    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    if((vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_VERSION_LIST)) == NULL) {
        fprintf(stderr, "illegal start message has no VERSION_LIST\n");
        return 0;
    }
    
    versions = (uint16_t *)vp->strvalue;
    
    /* verify that the attribute length is big enough for a length field */
    if(vp->length < 4)
    {
        fprintf(stderr, "start message has illegal VERSION_LIST. Too short: %d\n", vp->length);
        return 0;
    }
    
    versioncount = ntohs(versions[0]);
    /* verify that the attribute length is big enough for the given number
    * of versions present.
    */
    // EmA,09/01/04: versioncount is already in Octets nb and not in Shorts nb
    //    if((unsigned)vp->length <= (versioncount * sizeof(uint16_t) + 2))
    if((unsigned)vp->length <= (versioncount + 2))
    {
        fprintf(stderr, "start message is too short. Claimed %d versions does not fit in %d bytes\n", versioncount, vp->length);
        return 0;
    }
    
    /*
    * record the versionlist for the MK calculation.
    */
    // EmA,09/01/04: versioncount is already in Octets nb and not in Shorts nb
    //    eapsim_mk.versionlistlen = versioncount*2;
    eapsim_mk.versionlistlen = versioncount;
    memcpy(eapsim_mk.versionlist, (unsigned char *)(versions+1),
		eapsim_mk.versionlistlen);
    
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
        fprintf(stderr, "eap-sim start message. No compatible version found. We need %d\n", EAP_SIM_VERSION);
        for(i=0; i < versioncount; i++)
        {
            fprintf(stderr, "\tfound version %d\n",
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
        fprintf(stderr, "start message has %sanyidreq, %sfullauthid and %spermanentid. Illegal combination.\n",
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
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_SELECTED_VERSION,
        PW_TYPE_OCTETS);
    versions = (uint16_t *)newvp->strvalue;
    versions[0] = htons(selectedversion);
    newvp->length = 2;
    pairreplace(&(rep->vps), newvp);
    
    /* record the selected version */
    memcpy(eapsim_mk.versionselect, (unsigned char *)versions, 2);
    
    vp = newvp = NULL;
    {
        
    /*
    * insert a nonce_mt that we make up.
        */
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT,
            PW_TYPE_OCTETS);
        newvp->strvalue[0]=0;
        newvp->strvalue[1]=0;
        newvp->length = 18;  /* 16 bytes of nonce + padding */
        
        memcpy(&newvp->strvalue[2], eapsim_mk.nonce_mt, 16);
        
        pairreplace(&(rep->vps), newvp);
    }
    
    {
        uint16_t *pidlen, idlen;
        
        /*
        * insert the identity here.
        */
        vp = pairfind(rep->vps, PW_USER_NAME);
        if(vp == NULL)
        {
            fprintf(stderr, "eap-sim: We need to have a User-Name attribute!\n");
            return 0;
        }
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY,
            PW_TYPE_OCTETS);
        if (strlen(eapid) == 0) {
            /* insert User-Name if EAP-Sim-Identity not given */
            idlen = strlen(vp->strvalue);
            pidlen = (uint16_t *)newvp->strvalue;
            *pidlen = htons(idlen);
            newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], vp->strvalue, idlen);
        } else {
            /* insert EAP-Sim-Identity if given */
            idlen = strlen(eapid);
            pidlen = (uint16_t *)newvp->strvalue;
            *pidlen = htons(idlen);
            newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], eapid, idlen);
        }
        pairreplace(&(rep->vps), newvp);
        
        /* record it */
        idlen = strlen(vp->strvalue);
        memcpy(eapsim_mk.identity, vp->strvalue, idlen);
        eapsim_mk.identitylen = idlen;
    }
    
    return 1;
}

/************************************************************************************/
/*
* we got an EAP-Request/Sim/Start message in a legal state.
*
* pick a supported version, put it into the reply, and insert a nonce.
*/
static int process_eap_aka_identity(RADIUS_PACKET *req,
                             RADIUS_PACKET *rep)
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
        fprintf(stderr, "start message has %sanyidreq, %sfullauthid and %spermanentid. Illegal combination.\n",
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
            fprintf(stderr, "eap-sim: We need to have a User-Name attribute!\n");
            return 0;
        }
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY,
            PW_TYPE_OCTETS);
        if (strlen(eapid) == 0) {
            /* insert User-Name if EAP-Sim-Identity not given */
            idlen = strlen(vp->strvalue);
            pidlen = (uint16_t *)newvp->strvalue;
            *pidlen = htons(idlen);
            newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], vp->strvalue, idlen);
        } else {
            /* insert EAP-Sim-Identity if given */
            idlen = strlen(eapid);
            pidlen = (uint16_t *)newvp->strvalue;
            *pidlen = htons(idlen);
            newvp->length = idlen + 2;
            memcpy(&newvp->strvalue[2], eapid, idlen);
        }
        pairreplace(&(rep->vps), newvp);
        
        /* record it */
        memcpy(eapsim_mk.identity, &newvp->strvalue[2], idlen);
        eapsim_mk.identitylen = idlen;
/*		
        newvp = paircreate(PW_USER_NAME, PW_TYPE_STRING);
        memcpy(newvp->strvalue,eapsim_mk.identity, eapsim_mk.identitylen);
        newvp->length = eapsim_mk.identitylen;
        pairreplace(&(rep->vps), newvp);
*/		
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
                                 RADIUS_PACKET *rep)
{
    VALUE_PAIR *newvp;

    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapaka_synchronization_failure;
    pairreplace(&(rep->vps), newvp);
	
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_AUTS, PW_TYPE_OCTETS);
    memcpy(&newvp->strvalue[0],eapsim_mk.auts, EAP_AKA_AUTS_LEN);
    newvp->length = EAP_AKA_AUTS_LEN;
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
static int process_eap_challenge(RADIUS_PACKET *req,
                                 RADIUS_PACKET *rep)
                                 /************************************************************************************/
{
    VALUE_PAIR *newvp;
    VALUE_PAIR *mac, *randvp;
    VALUE_PAIR *sres1,*sres2,*sres3;
    VALUE_PAIR *Kc1, *Kc2, *Kc3;
    uint8_t calcmac[20];
    uint16_t *encrData;
    VALUE_PAIR *encr, *iv;
    
    unsigned char decrypt[ENCR_DATA_LEN_MAX];
    unsigned char reauthid[ENCR_DATA_LEN_MAX];
    int reauthLen;
    
    /* look for the AT_MAC and the challenge data */
    mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
    randvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND);
    if(mac == NULL || rand == NULL) {
        fprintf(stderr, "radeapclient: challenge message needs to contain RAND and MAC\n");
        return 0;
    }
    
    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        fprintf(stderr, "radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
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
        fprintf(stderr, "radeapclient: needs to have sres1, 2 and 3 set.\n");
        return 0;
    }
    memcpy(eapsim_mk.sres[0], sres1->strvalue, sizeof(eapsim_mk.sres[0]));
    memcpy(eapsim_mk.sres[1], sres2->strvalue, sizeof(eapsim_mk.sres[1]));
    memcpy(eapsim_mk.sres[2], sres3->strvalue, sizeof(eapsim_mk.sres[2]));
    
    Kc1 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC1);
    Kc2 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC2);
    Kc3 = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_KC3);
    
    if(Kc1 == NULL ||
        Kc2 == NULL ||
        Kc3 == NULL) {
        fprintf(stderr, "radeapclient: needs to have Kc1, 2 and 3 set.\n");
        return 0;
    }
    memcpy(eapsim_mk.Kc[0], Kc1->strvalue, sizeof(eapsim_mk.Kc[0]));
    memcpy(eapsim_mk.Kc[1], Kc2->strvalue, sizeof(eapsim_mk.Kc[1]));
    memcpy(eapsim_mk.Kc[2], Kc3->strvalue, sizeof(eapsim_mk.Kc[2]));
    
    /* all set, calculate keys */
    eapsim_calculate_keys(&eapsim_mk);
    
    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys */
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    FILE *fp;
    if ((fp = fopen( nom, "w")) == NULL)
        fprintf (stderr, "Pb for opening ${PATH_RESULT}/.tmpKeys");;
    if ((fwrite(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fwrite(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        fprintf(stderr, "Pb for writing in ${PATH_RESULT}/.tmpKeys");
    fclose(fp);
    
    if (librad_debug) eapsim_dump_mk(&eapsim_mk);
    
    /* verify the MAC, now that we have all the keys. */
    if(eapsim_checkmac(req->vps, eapsim_mk.K_aut,
        eapsim_mk.nonce_mt, sizeof(eapsim_mk.nonce_mt),
        calcmac)) {
        if (librad_debug) printf("MAC check succeed\n");
    } else {
        if (librad_debug) {
            int i, j;
            j=0;
            printf("calculated MAC (");
            for (i = 0; i < 20; i++) {
                if(j==4) {
                    printf("_");
                    j=0;
                }
                j++;
                
                printf("%02x", calcmac[i]);
            }
            printf(" did not match\n");
        }
        // EmA,15/12/2003: do not stop on MAC check mismatch
        //        return 0;
    }
    
    /* decrypt AT_ENCR_DATA */
    if (encr && iv) {
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk.K_encr);
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[0] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            reauthLen = decrypt[3] | (decrypt[2]<<8);
            memcpy(reauthid, &decrypt[4], reauthLen);
            reauthid[reauthLen] = 0;
            /* no verification of AT_PADDING */
            int i;
            printf("User-Name=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
            printf("EAP-Type-Identity=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
        }
    }
    
    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapsim_challenge;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
        PW_TYPE_OCTETS);
    memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*0, sres1->strvalue, EAPSIM_SRES_SIZE);
    memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*1, sres2->strvalue, EAPSIM_SRES_SIZE);
    memcpy(newvp->strvalue+EAPSIM_SRES_SIZE*2, sres3->strvalue, EAPSIM_SRES_SIZE);
    newvp->length = EAPSIM_SRES_SIZE*3;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
    memcpy(newvp->strvalue,    eapsim_mk.K_aut, EAPSIM_AUTH_SIZE);
    newvp->length = EAPSIM_AUTH_SIZE;
    pairreplace(&(rep->vps), newvp);
    
    if (atEncrData == 1) {
        /* insert AT_ENCR_DATA into response. */
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA,
            PW_TYPE_OCTETS);
        encrData = (uint16_t *)newvp->strvalue;
        encrData[0] = htons(0);
        encrData[1] = htons(2);
        newvp->length = 4;
        pairreplace(&(rep->vps), newvp);
        /* insert AT_IV into response. */
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV,
            PW_TYPE_OCTETS);
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
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RESULT_IND,
            PW_TYPE_OCTETS);
        encrData = (uint16_t *)newvp->strvalue;
        encrData[0] = htons(0);
        pairreplace(&(rep->vps), newvp);
        
    }
    
    return 1;
}

/************************************************************************************/
/*
* we got an EAP-Request/AKA/Challenge message in a legal state.
*
* use the RAND challenge to produce the SRES result, and then
* use that to generate a new MAC.
*
* for the moment, we ignore the RANDs, then just plug in the SRES
* values.
*
*/
static int process_eap_aka_challenge(RADIUS_PACKET *req,
                                     RADIUS_PACKET *rep)
                                     /************************************************************************************/
{
    VALUE_PAIR *newvp;
    VALUE_PAIR *mac, *randvp,*autnvp;
    VALUE_PAIR *res=NULL,*ik=NULL,*ck=NULL,*autn=NULL,*auts=NULL;
    uint8_t calcmac[20];
    uint16_t *encrData;
    VALUE_PAIR *encr, *iv;
    VALUE_PAIR *username;
    
    unsigned char decrypt[ENCR_DATA_LEN_MAX];
    unsigned char reauthid[ENCR_DATA_LEN_MAX];
    int reauthLen;
    
    /* look for the AT_MAC and the challenge data */
    mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
    randvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RAND);
    autnvp= pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_AUTN);
    
    if(mac == NULL || randvp == NULL || autnvp == NULL) {
        fprintf(stderr, "radeapclient: challenge message needs to contain RAND and MAC and AUTN\n");
        return 0;
    }
    
    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        fprintf(stderr, "radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
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
    if (haveSendRejectOrSyncFailure)
    {
        autn = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTN1);
        res = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_RES1);
        ik = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_IK1);
        ck = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_CK1);
        auts = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTS1);
    }
    else
    {
        autn = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTN);
        res = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_RES);
        ik = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_IK);
        ck = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_CK);
        auts = pairfind(rep->vps, ATTRIBUTE_EAP_AKA_AUTS);
    }
    
    if(res == NULL ||
        autn == NULL ||
        ik == NULL ||
        ck == NULL) {
        printf("radeapclient: needs to have res, ik and ck set.\n");
	 return process_eap_aka_authentication_reject(req, rep);
    }
//    username = pairfind(rep->vps, ATTRIBUTE_EAP_BASE+PW_EAP_IDENTITY);
    username = pairfind(rep->vps, PW_USER_NAME);
    if(username == NULL)
    {
        fprintf(stderr, "radeapclient: We need to have a User-Name attribute!\n");
        return 0;
    }
    memcpy(eapsim_mk.identity, username->strvalue, strlen(username->strvalue));
    eapsim_mk.identitylen = strlen(username->strvalue);
    if (strlen(eapid)!=0)	
    {
        eapsim_mk.identitylen = strlen(eapid);
    	 memcpy(eapsim_mk.identity, eapid, eapsim_mk.identitylen);
    }


    memcpy(eapsim_mk.autn, autn->strvalue, sizeof(eapsim_mk.autn));
    memcpy(eapsim_mk.res, res->strvalue, sizeof(eapsim_mk.res));
    eapsim_mk.res_len=res->length;
    memcpy(eapsim_mk.ik, ik->strvalue, sizeof(eapsim_mk.ik));
    memcpy(eapsim_mk.ck, ck->strvalue, sizeof(eapsim_mk.ck));
    printf(" \n");

    if (memcmp(eapsim_mk.autn,&autnvp->strvalue[2],sizeof(eapsim_mk.autn) )!=0)
    {
       int i=0;
       printf(" eapsim_mk.autn=\n");
       for (i = 0; i < EAP_AKA_AUTN_LEN; i++) {
           printf("%02x", eapsim_mk.autn[i]);
       }
       printf(" \nautnvp->strvalue=\n");
       for (i = 0; i < EAP_AKA_AUTN_LEN; i++) {
           printf("%02x", autnvp->strvalue[2+i]);
       }
       printf(stderr, "radeapclient: AUTN not match\n");
       return process_eap_aka_authentication_reject(req, rep);		
    }

    if(auts != NULL)
    {
        haveSendRejectOrSyncFailure++;
        printf("radeapclient: UMTS authentication failed (AUTN seq# -> AUTS).\n");
        memcpy(eapsim_mk.auts, auts->strvalue, sizeof(eapsim_mk.auts));		
        return process_eap_aka_synchronization_failure(req,rep);
    }

    
    /* all set, calculate keys */
    eapaka_calculate_keys(&eapsim_mk);
    
    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys */
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    if (PATH_RESULT==NULL)
    {
        PATH_RESULT=getenv("HOME");
    }
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    FILE *fp;
    if ((fp = fopen( nom, "w")) == NULL)
    {
        fprintf (stderr, "Pb for opening ${PATH_RESULT}/.tmpKeys");;
    }
    else
    {
        if ((fwrite(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
            ||(fwrite(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
            fprintf(stderr, "Pb for writing in ${PATH_RESULT}/.tmpKeys");
        fclose(fp);
    }
    
    if (librad_debug) eapaka_dump_mk(&eapsim_mk);
    
    /* verify the MAC, now that we have all the keys. */
    if(eapsim_checkmac(req->vps, eapsim_mk.K_aut,
        "", 0,
        calcmac)) {
        if (librad_debug) printf("MAC check succeed\n");
    } else {
        if (librad_debug) {
            int i, j;
            j=0;
            printf("calculated MAC (");
            for (i = 0; i < 20; i++) {
                if(j==4) {
                    printf("_");
                    j=0;
                }
                j++;
                
                printf("%02x", calcmac[i]);
            }
            printf(" did not match\n");
        }
        // EmA,15/12/2003: do not stop on MAC check mismatch
        //        return 0;
    }
    
    /* decrypt AT_ENCR_DATA */
    if (encr && iv) {
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk.K_encr);
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[0] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            reauthLen = decrypt[3] | (decrypt[2]<<8);
            memcpy(reauthid, &decrypt[4], reauthLen);
            reauthid[reauthLen] = 0;
            /* no verification of AT_PADDING */
            int i;
            printf("User-Name=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
            printf("EAP-Type-Identity=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
        }
    }
    
    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapaka_challenge;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_AT_RES, PW_TYPE_OCTETS);
    newvp->strvalue[0] = ((uint16_t) (eapsim_mk.res_len)) >> 8;
    newvp->strvalue[1] = ((uint16_t) (eapsim_mk.res_len)) & 0xff;
    memcpy(&newvp->strvalue[2],eapsim_mk.res, EAP_AKA_RES_MAX_LEN);
    newvp->length = 2+EAP_AKA_RES_MAX_LEN;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
        PW_TYPE_OCTETS);
    memset(newvp->strvalue,0x0,EAPSIM_CALCMAC_SIZE);
    newvp->length = 0;
    pairreplace(&(rep->vps), newvp);
    
    newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
    memcpy(newvp->strvalue,    eapsim_mk.K_aut, EAPSIM_AUTH_SIZE);
    newvp->length = EAPSIM_AUTH_SIZE;
    pairreplace(&(rep->vps), newvp);
    pairdelete(&(rep->vps),ATTRIBUTE_EAP_AKA_AUTN);
    
    if (atEncrData == 1) {
        /* insert AT_ENCR_DATA into response. */
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA,
            PW_TYPE_OCTETS);
        encrData = (uint16_t *)newvp->strvalue;
        encrData[0] = htons(0);
        encrData[1] = htons(2);
        newvp->length = 4;
        pairreplace(&(rep->vps), newvp);
        /* insert AT_IV into response. */
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV,
            PW_TYPE_OCTETS);
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
        newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_RESULT_IND,
            PW_TYPE_OCTETS);
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
static int process_eap_reauth(RADIUS_PACKET *req,
                              RADIUS_PACKET *rep)
                              /************************************************************************************/
{
    VALUE_PAIR *newvp;
    VALUE_PAIR *mac;
    uint8_t calcmac[20];
    VALUE_PAIR *encr, *iv;
    int counter=0;
    unsigned char nonce_s[EAPSIM_NONCEMT_SIZE];
    
    
    unsigned char decrypt[ENCR_DATA_LEN_MAX];
    unsigned char reauthid[ENCR_DATA_LEN_MAX];
    int reauthLen;
    
    /* look for the AT_MAC and the challenge data */
    mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
    if(mac == NULL) {
        fprintf(stderr, "radeapclient: reauth message needs to contain RAND and MAC\n");
        return 0;
    }
    
    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        fprintf(stderr, "radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
        return 0;
        
    }
    
    /* all set, calculate keys */
    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys */
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    if (PATH_RESULT==NULL)
    {
        PATH_RESULT=getenv("HOME");
    }
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    FILE *fp;
    if ((fp = fopen( nom, "r")) == NULL)
    {
        fprintf (stderr, "Pb for opening ${PATH_RESULT}/.tmpKeys");;
    }
    else
    {
    if ((fread(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fread(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        fprintf (stderr, "Pb for reading ${PATH_RESULT}/.tmpKeys");
        fclose(fp);
    }
    
    /* verify the MAC, now that we have all the keys. */
    if(eapsim_checkmac(req->vps, eapsim_mk.K_aut,
        0, 0,
        calcmac)) {
        if (librad_debug) printf("MAC check succeed\n");
    } else {
        if (librad_debug) {
            int i, j;
            j=0;
            printf("calculated MAC (");
            for (i = 0; i < 20; i++) {
                if(j==4) {
                    printf("_");
                    j=0;
                }
                j++;
                
                printf("%02x", calcmac[i]);
            }
            printf(" did not match\n");
        }
        // EmA,15/12/2003: do not stop on MAC check mismatch
        //        return 0;
    }
    
    /* decrypt AT_ENCR_DATA */
    if (encr && iv) {
        int i;
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk.K_encr);
        if (decrypt[0] == PW_EAP_SIM_COUNTER) {
            counter =  decrypt[3] | (decrypt[2]<<8);
            printf("AT_COUNTER= %d\n", counter);
        }
        if (decrypt[4] == PW_EAP_SIM_NONCE_S) {
            memcpy(nonce_s, &decrypt[8], EAPSIM_NONCEMT_SIZE);
            printf("AT_NONCE_S=");
            for (i=0; i< EAPSIM_NONCEMT_SIZE; i++)
                printf("%x", nonce_s[i]);
            printf("\n");
        }
        
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[24] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            reauthLen = decrypt[27] | (decrypt[26]<<8);
            memcpy(reauthid, &decrypt[28], reauthLen);
            reauthid[reauthLen] = 0;
            /* no verification of AT_PADDING */
            int i;
            printf("User-Name=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
            printf("EAP-Type-Identity=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
        }
    }
    
    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Reauth */
    /*
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapsim_reauth;
    pairreplace(&(rep->vps), newvp);
    
	  newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
	  PW_TYPE_OCTETS);
	  eapsim_checkmac(req->vps, eapsim_mk.K_aut,
	  nonce_s, sizeof(nonce_s),
	  calcmac);
	  memcpy(&newvp->strvalue[2], nonce_s, EAPSIM_NONCEMT_SIZE);
	  newvp->length = EAPSIM_NONCEMT_SIZE + 2;
    pairreplace(&(rep->vps), newvp);  */
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapsim_reauth;
    pairreplace(&(rep->vps), newvp);
    
    /* mac calculated with NONCE_S received */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
        PW_TYPE_OCTETS);
    memcpy(newvp->strvalue, nonce_s, EAPSIM_NONCEMT_SIZE);
    newvp->length = EAPSIM_NONCEMT_SIZE;
    pairreplace(&(rep->vps), newvp);
    
    /* mac key is K_aut */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
    memcpy(newvp->strvalue,    eapsim_mk.K_aut, EAPSIM_AUTH_SIZE);
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
    
    if (ecounterTooSmall == 1) {
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    }
    else if (ecounterTooSmall == 2) {
        encrData[2] = ((counter+1) & 0xFF00) >> 8;
        encrData[3] = (counter+1) &0xFF;
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    }
    else {
        encrData[4] = PW_EAP_SIM_PADDING;
        encrData[5] = 3;
    }
    
    
    /* cryptage ENCR_DATA */
    unsigned char encrypt[16];
    eapsim_aesencrypt(encrData, 16, encrypt, initVector, eapsim_mk.K_encr);
    
    /* build ENCR_DATA attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, 
        PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], encrypt, 16);
    newvp->length = 18;
    
    pairreplace(&(rep->vps), newvp);
    
    /* build IV attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, 
        PW_TYPE_OCTETS);
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
static int process_eap_aka_reauth(RADIUS_PACKET *req,
                                  RADIUS_PACKET *rep)
                                  /************************************************************************************/
{
    VALUE_PAIR *newvp;
    VALUE_PAIR *mac;
    uint8_t calcmac[20];
    VALUE_PAIR *encr, *iv;
    int counter=0;
    unsigned char nonce_s[EAPSIM_NONCEMT_SIZE];
    
    
    unsigned char decrypt[ENCR_DATA_LEN_MAX];
    unsigned char reauthid[ENCR_DATA_LEN_MAX];
    int reauthLen;
    
    /* look for the AT_MAC and the challenge data */
    mac   = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC);
    if(mac == NULL) {
        fprintf(stderr, "radeapclient: reauth message needs to contain RAND and MAC\n");
        return 0;
    }
    
    /* look for the AT_ENCR_DATA and AT_IV attributes */
    encr = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA);
    iv = pairfind(req->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV);
    if (((encr != NULL) && (iv == NULL))
        ||
        ((encr == NULL) && (iv != NULL))) {
        fprintf(stderr, "radeapclient: challenge message needs to contain ENCR_DATA and IV or none of them\n");
        return 0;
        
    }
    
    /* all set, calculate keys */
    /* set K_aut and K_encr in the file ${PATH_RESULT}/.tmpKeys */
    char *PATH_RESULT, nom[100];
    PATH_RESULT = getenv("PATH_RESULT");
    sprintf(nom, "%s/.tmpKeys",PATH_RESULT); 
    
    FILE *fp;
    if ((fp = fopen( nom, "r")) == NULL)
    {
        fprintf (stderr, "Pb for opening ${PATH_RESULT}/.tmpKeys");;
    }
    else
    {
    if ((fread(eapsim_mk.K_aut, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)
        ||
        (fread(eapsim_mk.K_encr, sizeof(unsigned char), EAPSIM_AUTH_SIZE, fp) != EAPSIM_AUTH_SIZE)) 
        fprintf (stderr, "Pb for reading ${PATH_RESULT}/.tmpKeys");
    fclose(fp);
	}
    
    /* verify the MAC, now that we have all the keys. */
    if(eapsim_checkmac(req->vps, eapsim_mk.K_aut,
        0, 0,
        calcmac)) {
        if (librad_debug) printf("MAC check succeed\n");
    } else {
        if (librad_debug) {
            int i, j;
            j=0;
            printf("calculated MAC (");
            for (i = 0; i < 20; i++) {
                if(j==4) {
                    printf("_");
                    j=0;
                }
                j++;
                
                printf("%02x", calcmac[i]);
            }
            printf(" did not match\n");
        }
        // EmA,15/12/2003: do not stop on MAC check mismatch
        //        return 0;
    }
    
    /* decrypt AT_ENCR_DATA */
    if (encr && iv) {
        int i;
        eapsim_aesdecrypt(&(encr->strvalue[2]),(encr->length)-2,decrypt,&(iv->strvalue[2]), eapsim_mk.K_encr);
        if (decrypt[0] == PW_EAP_SIM_COUNTER) {
            counter =  decrypt[3] | (decrypt[2]<<8);
            printf("AT_COUNTER= %d\n", counter);
        }
        if (decrypt[4] == PW_EAP_SIM_NONCE_S) {
            memcpy(nonce_s, &decrypt[8], EAPSIM_NONCEMT_SIZE);
            printf("AT_NONCE_S=");
            for (i=0; i< EAPSIM_NONCEMT_SIZE; i++)
                printf("%x", nonce_s[i]);
            printf("\n");
        }
        
        /* extract AT_NEXT_REAUTH_ID */
        if (decrypt[24] == PW_EAP_SIM_NEXT_REAUTH_ID) {
            reauthLen = decrypt[27] | (decrypt[26]<<8);
            memcpy(reauthid, &decrypt[28], reauthLen);
            reauthid[reauthLen] = 0;
            /* no verification of AT_PADDING */
            int i;
            printf("User-Name=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
            printf("EAP-Type-Identity=");
            for (i=0; i< reauthLen; i++)
                printf("%c", reauthid[i]);
            printf("\n");
        }
    }
    
    /* form new response clear of any EAP stuff */
    cleanresp(rep);
    
    /* mark the subtype as being EAP-SIM/Response/Reauth */
    /*
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapsim_reauth;
    pairreplace(&(rep->vps), newvp);
    
	  newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
	  PW_TYPE_OCTETS);
	  eapsim_checkmac(req->vps, eapsim_mk.K_aut,
	  nonce_s, sizeof(nonce_s),
	  calcmac);
	  memcpy(&newvp->strvalue[2], nonce_s, EAPSIM_NONCEMT_SIZE);
	  newvp->length = EAPSIM_NONCEMT_SIZE + 2;
    pairreplace(&(rep->vps), newvp);  */
    
    /* mark the subtype as being EAP-SIM/Response/Start */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_SUBTYPE, PW_TYPE_INTEGER);
    newvp->lvalue = eapsim_reauth;
    pairreplace(&(rep->vps), newvp);
    
    /* mac calculated with NONCE_S received */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_MAC,
        PW_TYPE_OCTETS);
    memcpy(newvp->strvalue, nonce_s, EAPSIM_NONCEMT_SIZE);
    newvp->length = EAPSIM_NONCEMT_SIZE;
    pairreplace(&(rep->vps), newvp);
    
    /* mac key is K_aut */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_KEY, PW_TYPE_OCTETS);
    memcpy(newvp->strvalue,    eapsim_mk.K_aut, EAPSIM_AUTH_SIZE);
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
    
    if (ecounterTooSmall == 1) {
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    }
    else if (ecounterTooSmall == 2) {
        encrData[2] = ((counter+1) & 0xFF00) >> 8;
        encrData[3] = (counter+1) &0xFF;
        encrData[4] = PW_EAP_SIM_COUNTER_TOO_SMALL;
        encrData[5] = 1;
        encrData[8] = PW_EAP_SIM_PADDING;
        encrData[9] = 2;
    }
    else {
        encrData[4] = PW_EAP_SIM_PADDING;
        encrData[5] = 3;
    }    
    /* cryptage ENCR_DATA */
    unsigned char encrypt[16];
    eapsim_aesencrypt(encrData, 16, encrypt, initVector, eapsim_mk.K_encr);
    
    /* build ENCR_DATA attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_ENCR_DATA, 
        PW_TYPE_OCTETS);
    newvp->strvalue[0] = 0;
    newvp->strvalue[1] = 0;
    memcpy(&newvp->strvalue[2], encrypt, 16);
    newvp->length = 18;
    
    pairreplace(&(rep->vps), newvp);
    
    /* build IV attribute */
    newvp = paircreate(ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IV, 
        PW_TYPE_OCTETS);
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
static int process_eap_notification(RADIUS_PACKET *req,
                                    RADIUS_PACKET *rep)
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
static int process_eap_clienterror (RADIUS_PACKET *req,
                                    RADIUS_PACKET *rep)
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
    
    /*
    newvp = paircreate(PW_EAP_MESSAGE, PW_TYPE_OCTETS);
    newvp->strvalue = NULL;
    newvp->length = 0;
    pairreplace(&(rep->vps), newvp);
    
	  if (librad_debug) {
	  printf("+++> EAP-sim encoded packet:\n");
	  vp_printlist(stdout, req->vps);
	  }    
    */
    return 1;
}

/************************************************************************************/
/*
* this code runs the EAP-SIM client state machine.
* the *request* is from the server.
* the *reponse* is to the server.
*
*/
static int respond_eap_aka(RADIUS_PACKET *req,
                           RADIUS_PACKET *resp)
                           /************************************************************************************/
{
    enum eapsim_clientstates state, newstate;
    enum eapsim_subtype subtype;
    VALUE_PAIR *vp, *statevp, *radstate, *eapid;
    char statenamebuf[32];
    
    if ((radstate = paircopy2(req->vps, PW_STATE)) == NULL)
    {
        
        // EmA,11/12/03: Do not reject packets without State attribute
        //        return 0;
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
        printf("<+++ EAP-sim decoded packet:\n");
        vp_printlist(stdout, req->vps);
    }    
    
    if((vp = pairfind(req->vps, ATTRIBUTE_EAP_SIM_SUBTYPE)) == NULL)
    {
        return 0;
    }
    subtype = vp->lvalue;
    
    /*
    * look for the appropriate state, and process incoming message
    */
    switch(state) 
    {
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
            if ((estart == 1))
                newstate = process_eap_clienterror(req, resp);
            else
            {
                  newstate = process_eap_aka_reauth(req, resp);
            }
            break;
            
        case eapaka_challenge:
        default:
            newstate = process_eap_clienterror(req, resp);
            /*
            fprintf(stderr, "radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
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
                if ((estart == 1))
                    newstate = process_eap_clienterror(req, resp);
                else
                {
                    newstate = process_eap_aka_identity(req, resp);
                }
                break;
            case eapaka_challenge:
                if (echallenge == 1)
                    newstate = process_eap_clienterror(req, resp);
                else
                {
                     newstate = process_eap_aka_challenge(req, resp);
                }
                /*            newstate = process_eap_challenge(req, resp);
                */
                break;
            case eapsim_reauth:
                if ((estart == 1))
                    newstate = process_eap_clienterror(req, resp);
                else
                {
                    newstate = process_eap_aka_reauth(req, resp);
                }
                break;
                
            case eapsim_notification:
                newstate = process_eap_notification(req, resp);
                break;
                
            default:
                newstate = process_eap_clienterror(req, resp);
                break;
                /*
                fprintf(stderr, "radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
                sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
                sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
                ** invalid state, drop message **
                return 0;
                */
            }
            break;
            
            
            default:
                fprintf(stderr, "radeapclient: sim in illegal state %s\n",
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
static int respond_eap_sim(RADIUS_PACKET *req,
			   RADIUS_PACKET *resp)
/************************************************************************************/
{
	enum eapsim_clientstates state, newstate;
	enum eapsim_subtype subtype;
	VALUE_PAIR *vp, *statevp, *radstate, *eapid;
	char statenamebuf[32];

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
		printf("<+++ EAP-sim decoded packet:\n");
		vp_printlist(stdout, req->vps);
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
            if (doNotRespond ==1) {
                exit(0);
            }
            if (estart == 1)
              	newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_start(req, resp);
			break;
			
		case eapsim_notification:
            if ((echallenge == 1) || (estart == 1))
				newstate = process_eap_clienterror(req, resp);
            else
				newstate = process_eap_notification(req, resp);
			break;
                        
		
        case eapsim_reauth:
        if ((estart == 1))
            newstate = process_eap_clienterror(req, resp);
        else
            newstate = process_eap_reauth(req, resp);
        break;

        case eapsim_challenge:
		default:
			newstate = process_eap_clienterror(req, resp);
/*
			fprintf(stderr, "radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
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
            if (doNotRespond ==1) {
                exit(0);
            }
            if (estart == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_start(req, resp);
/*			newstate = process_eap_start(req, resp);
*/
			break;
			
		case eapsim_challenge:
            if (echallenge == 1)
                newstate = process_eap_clienterror(req, resp);
			else
				newstate = process_eap_challenge(req, resp);
/*			newstate = process_eap_challenge(req, resp);
*/
			break;

		case eapsim_notification:
			newstate = process_eap_notification(req, resp);
			break;
                        
		default:
			newstate = process_eap_clienterror(req, resp);
			break;
/*
			fprintf(stderr, "radeapclient: sim in state %s message %s is illegal. Reply dropped.\n",
				sim_state2name(state, statenamebuf, sizeof(statenamebuf)),
				sim_subtype2name(subtype, subtypenamebuf, sizeof(subtypenamebuf)));
			** invalid state, drop message **
			return 0;
*/
		}
		break;


	default:
		fprintf(stderr, "radeapclient: sim in illegal state %s\n",
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
static int respond_eap_md5(RADIUS_PACKET *req,
                           RADIUS_PACKET *rep)
                           /************************************************************************************/
{
    VALUE_PAIR *vp, *id, *state;
    int valuesize, namesize;
    unsigned char identifier;
    unsigned char *value;
    unsigned char *name;
    MD5_CTX    context;
    char    response[16];
    
    cleanresp(rep);
    
    if ((state = paircopy2(req->vps, PW_STATE)) == NULL)
    {
        fprintf(stderr, "radeapclient: no state attribute found\n");
        return 0;
    }
    
    if ((id = paircopy2(req->vps, ATTRIBUTE_EAP_ID)) == NULL)
    {
        fprintf(stderr, "radeapclient: no EAP-ID attribute found\n");
        return 0;
    }
    identifier = id->lvalue;
    
    if ((vp = pairfind(req->vps, ATTRIBUTE_EAP_BASE+PW_EAP_MD5)) == NULL)
    {
        fprintf(stderr, "radeapclient: no EAP-MD5 attribute found\n");
        return 0;
    }
    
    /* got the details of the MD5 challenge */
    valuesize = vp->strvalue[0];
    value = &vp->strvalue[1];
    name  = &vp->strvalue[valuesize+1];
    namesize = vp->length - (valuesize + 1);
    
    /* sanitize items */
    if(valuesize > vp->length)
    {
        fprintf(stderr, "radeapclient: md5 valuesize if too big (%d > %d)\n",
            valuesize, vp->length);
        return 0;
    }
    
    /* now do the CHAP operation ourself, rather than build the
    * buffer. We could also call rad_chap_encode, but it wants
    * a CHAP-Challenge, which we don't want to bother with.
    */
    librad_MD5Init(&context);
    librad_MD5Update(&context, &identifier, 1);
    librad_MD5Update(&context, password, strlen(password));
    librad_MD5Update(&context, value, valuesize);
    librad_MD5Final(response, &context);
    
    vp = paircreate(ATTRIBUTE_EAP_BASE+PW_EAP_MD5, PW_TYPE_OCTETS);
    vp->strvalue[0]=16;
    memcpy(&vp->strvalue[1], response, 16);
    vp->length = 17;
    
    pairreplace(&(rep->vps), vp);
    
    pairreplace(&(rep->vps), id);
    
    /* copy the state object in */
    pairreplace(&(rep->vps), state);
    
    return 1;
}



/************************************************************************************/
static int sendrecv_eap(RADIUS_PACKET *rep)
/************************************************************************************/
{
    RADIUS_PACKET *req = NULL;
    VALUE_PAIR *vp, *vpnext, *noncemt_vp;
    int tried_eap_md5 = 0;
    
    /* BEGIN patch EmA */
    if ( (noncemt_vp = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT))!=NULL ) {
        // keep a copy of the nonce and clean the vp
        memcpy(eapsim_mk.nonce_mt,  &noncemt_vp->strvalue[2], 16);
        pairdelete(&rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_NONCE_MT);
        
    } else {
        uint32_t nonce[4];
        
        // chose a rand for the nonce
        nonce[0]=lrad_rand();
        nonce[1]=lrad_rand();
        nonce[2]=lrad_rand();
        nonce[3]=lrad_rand();
        
        memcpy(eapsim_mk.nonce_mt, nonce, 16);
    }
    /* END patch EmA */
    memset(eapid,0,80);	
    if ((vp = pairfind(rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY))!=NULL) {
        memcpy(eapid, &vp->strvalue, strlen(vp->strvalue));
        pairdelete(&rep->vps, ATTRIBUTE_EAP_SIM_BASE+PW_EAP_SIM_IDENTITY);
    }
    
    /*
    *    Keep a copy of the the User-Password attribute.
    */
    if ((vp = pairfind(rep->vps, ATTRIBUTE_EAP_MD5_PASSWORD)) != NULL) {
        strNcpy(password, (char *)vp->strvalue, sizeof(vp->strvalue));
        
    } else     if ((vp = pairfind(rep->vps, PW_PASSWORD)) != NULL) {
        strNcpy(password, (char *)vp->strvalue, sizeof(vp->strvalue));
        /*
        *    Otherwise keep a copy of the CHAP-Password attribute.
        */
    } else if ((vp = pairfind(rep->vps, PW_CHAP_PASSWORD)) != NULL) {
        strNcpy(password, (char *)vp->strvalue, sizeof(vp->strvalue));
    } else {
        *password = '\0';
    }
    
again:    
    rep->id++;
    
    if (librad_debug) {
        printf("\n+++> About to send encoded packet:\n");
        vp_printlist(stdout, rep->vps);
    }
    
    /*
    * if there are EAP types, encode them into an EAP-Message
    *
    */
    map_eap_types(rep);
    
    /*
    *  Fix up Digest-Attributes issues
    */
    for (vp = rep->vps; vp != NULL; vp = vp->next) {
        switch (vp->attribute) {
        default:
            break;
            
        case PW_DIGEST_REALM:
        case PW_DIGEST_NONCE:
        case PW_DIGEST_METHOD:
        case PW_DIGEST_URI:
        case PW_DIGEST_QOP:
        case PW_DIGEST_ALGORITHM:
        case PW_DIGEST_BODY_DIGEST:
        case PW_DIGEST_CNONCE:
        case PW_DIGEST_NONCE_COUNT:
        case PW_DIGEST_USER_NAME:
            /* overlapping! */
            memmove(&vp->strvalue[2], &vp->strvalue[0], vp->length);
            vp->strvalue[0] = vp->attribute - PW_DIGEST_REALM + 1;
            vp->length += 2;
            vp->strvalue[1] = vp->length;
            vp->attribute = PW_DIGEST_ATTRIBUTES;
            break;
        }
    }
    
    /*
    *    If we've already sent a packet, free up the old
    *    one, and ensure that the next packet has a unique
    *    ID and authentication vector.
    */
    if (rep->data) {
        free(rep->data);
        rep->data = NULL;
    }
    
    librad_md5_calc(rep->vector, rep->vector,
        sizeof(rep->vector));
    
    if (*password != '\0') {
        if ((vp = pairfind(rep->vps, PW_PASSWORD)) != NULL) {
            strNcpy((char *)vp->strvalue, password, strlen(password) + 1);
            vp->length = strlen(password);
            
        } else if ((vp = pairfind(rep->vps, PW_CHAP_PASSWORD)) != NULL) {
            strNcpy((char *)vp->strvalue, password, strlen(password) + 1);
            vp->length = strlen(password);
            
            rad_chap_encode(rep, (char *) vp->strvalue, rep->id, vp);
            vp->length = 17;
        }
    } /* there WAS a password */
    
    /* send the response, wait for the next request */
    send_packet(rep, &req);
    
    /* okay got back the packet, go and decode the EAP-Message. */
    unmap_eap_types(req);
    
    if (librad_debug) {
        printf("<+++ EAP decoded packet:\n");
        vp_printlist(stdout, req->vps);
    }
    
    /* now look for the code type. */
    for (vp = req->vps; vp != NULL; vp = vpnext) {
        vpnext = vp->next;
        
        switch (vp->attribute) {
        default:
            break;
            
        case ATTRIBUTE_EAP_BASE+PW_EAP_MD5:
            if(respond_eap_md5(req, rep) && tried_eap_md5 < 3)
            {
                tried_eap_md5++;
                goto again;
            }
            break;
        case ATTRIBUTE_EAP_BASE+PW_EAP_SIM:
            if(respond_eap_sim(req, rep))
            {
                goto again;
            }
            break;
        case ATTRIBUTE_EAP_BASE+PW_EAP_AKA:
            if(respond_eap_aka(req, rep))
            {
                goto again;
            }
            break;
        }
    }
    
    return 1;
}


/************************************************************************************/
int main(int argc, char **argv)
/************************************************************************************/
{
    RADIUS_PACKET *req;
    char *p;
    int c;
    int port = 0;
    char *filename = NULL;
    FILE *fp;
    int count = 1;
    int id;
    struct timeb         totalbeg, totalend;
    char radius_dir[256];
    
    /*EmA,22/07/2005
    strcpy(radius_dir, RACINE);
    strcat(radius_dir, RADDBDIR);*/
    strcpy(radius_dir, RADDBDIR);
    
    id = ((int)getpid() & 0xff);
    librad_debug = 0;
    radlog_dest = RADLOG_STDERR;
    
    while ((c = getopt(argc, argv, "a:b:c:d:e:E:f:hi:n:j:gqst:r:S:xv")) != EOF)
    {
        switch(c) {
        case 'c':
            if (!isdigit((int) *optarg)) 
                usage();
            count = atoi(optarg);
            break;
        case 'd':
            strcpy(radius_dir, optarg);
            break;
        case 'f':
            filename = optarg;
            break;
        case 'q':
            do_output = 0;
            break;
        case 'x':
            debug_flag++;
            librad_debug++;
            break;
            
        case 'r':
            if (!isdigit((int) *optarg)) 
                usage();
            retries = atoi(optarg);
            break;
        case 'i':
            if (!isdigit((int) *optarg)) 
                usage();
            id = atoi(optarg);
            if ((id < 0) || (id > 255)) {
                usage();
            }
            break;
        case 's':
            do_summary = 1;
            break;
        case 't':
            if (!isdigit((int) *optarg)) 
                usage();
            timeout = atof(optarg);
            break;
        case 'v':
            printf("radclient: $Id: radeapclient.c,v 1.3 2003/11/06 15:41:21 aland Exp $ built on " __DATE__ " at " __TIME__ "\n");
            exit(0);
            break;
        case 'S':
            fp = fopen(optarg, "r");
            if (!fp) {
                fprintf(stderr, "radclient: Error opening %s: %s\n",
                    optarg, strerror(errno));
                exit(1);
            }
            if (fgets(filesecret, sizeof(filesecret), fp) == NULL) {
                fprintf(stderr, "radclient: Error reading %s: %s\n",
                    optarg, strerror(errno));
                exit(1);
            }
            fclose(fp);
            
            /* truncate newline */
            p = filesecret + strlen(filesecret) - 1;
            while ((p >= filesecret) &&
                (*p < ' ')) {
                *p = '\0';
                --p;
            }
            
            if (strlen(filesecret) < 2) {
                fprintf(stderr, "radclient: Secret in %s is too short\n", optarg);
                exit(1);
            }
            secret = filesecret;
            break;
        case 'a':
            estart = 1;          
            if (!isdigit((int) *optarg)) 
                usage();
            id = atoi(optarg);
            if ((id < 0) || (id > 3)) {
                usage();
            }
            estartNotif = id;
            break;
        case 'b':
            echallenge = 1;          
            if (!isdigit((int) *optarg)) 
                usage();
            id = atoi(optarg);
            if ((id < 0) || (id > 3)) {
                usage();
            }
            estartNotif = id;
            break;
        case 'n':
            doNotRespond = 1;
            break;
        case 'e':
            ecounterTooSmall = 1;          
            break;
        case 'E':
            ecounterTooSmall = 2;          
            break;
        case 'g':
            atEncrData = 1;          
            break;
        case 'h':
        default:
            usage();
            break;
        }
    }
    argc -= (optind - 1);
    argv += (optind - 1);
    
    if ((argc < 3)  ||
        ((secret == NULL) && (argc < 4))) {
        usage();
    }
    
    if (dict_init(radius_dir, RADIUS_DICTIONARY) < 0) {
        librad_perror("radclient");
        return 1;
    }
    
    if ((req = rad_alloc(1)) == NULL) {
        librad_perror("radclient");
        exit(1);
    }
    
#if 0
    { 
        FILE *randinit;
        
        if((randinit = fopen("/dev/urandom", "r")) == NULL)
        {
            perror("/dev/urandom");
        } else {
            fread(randctx.randrsl, 256, 1, randinit);
            fclose(randinit);
        }
    }
    lrad_randinit(&randctx, 1);  
#endif
    
    req->id = id;
    
    /*
    *    Strip port from hostname if needed.
    */
    if ((p = strchr(argv[1], ':')) != NULL) {
        *p++ = 0;
        port = atoi(p);
    }
    
    /*
    *    See what kind of request we want to send.
    */
    if (strcmp(argv[2], "auth") == 0) {
        if (port == 0) port = getport("radius");
        if (port == 0) port = PW_AUTH_UDP_PORT;
        req->code = PW_AUTHENTICATION_REQUEST;
        
    } else if (strcmp(argv[2], "acct") == 0) {
        if (port == 0) port = getport("radacct");
        if (port == 0) port = PW_ACCT_UDP_PORT;
        req->code = PW_ACCOUNTING_REQUEST;
        do_summary = 0;
        
    } else if (strcmp(argv[2], "status") == 0) {
        if (port == 0) port = getport("radius");
        if (port == 0) port = PW_AUTH_UDP_PORT;
        req->code = PW_STATUS_SERVER;
        
    } else if (strcmp(argv[2], "disconnect") == 0) {
        if (port == 0) port = PW_POD_UDP_PORT;
        req->code = PW_DISCONNECT_REQUEST;
        
    } else if (isdigit((int) argv[2][0])) {
        if (port == 0) port = getport("radius");
        if (port == 0) port = PW_AUTH_UDP_PORT;
        req->code = atoi(argv[2]);
    } else {
        usage();
    }
    
    /*
    *    Ensure that the configuration is initialized.
    */
    memset(&mainconfig, 0, sizeof(mainconfig));
    
    /*
    *    Resolve hostname.
    */
    req->dst_port = port;
    req->dst_ipaddr = ip_getaddr(argv[1]);
    if (req->dst_ipaddr == INADDR_NONE) {
        fprintf(stderr, "radclient: Failed to find IP address for host %s\n", argv[1]);
        exit(1);
    }
    
    /*
    *    Add the secret.
    */
    if (argv[3]) secret = argv[3];
    
    /*
    *    Read valuepairs.
    *    Maybe read them, from stdin, if there's no
    *    filename, or if the filename is '-'.
    */
    if (filename && (strcmp(filename, "-") != 0)) {
        fp = fopen(filename, "r");
        if (!fp) {
            fprintf(stderr, "radclient: Error opening %s: %s\n",
                filename, strerror(errno));
            exit(1);
        }
    } else {
        fp = stdin;
    }
    
    /*
    *    Send request.
    */
    if ((req->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("radclient: socket: ");
        exit(1);
    }
    
    ftime(&totalbeg);
    
    while(!filedone) {
        if(req->vps) pairfree(&req->vps);
        
        if ((req->vps = readvp2(fp, &filedone, "radeapclient:"))
            == NULL) {
            break;
        }
        
        sendrecv_eap(req);
    }
    
    ftime(&totalend);
    
    if(do_summary) {
        if (totalOK) meantimeOK = totaltimeOK / totalOK;
        if (totalREJ) meantimeREJ = totaltimeREJ / totalREJ;
        
        printf("\n\tTotal approved auths:\t%ld\n", totalOK);
        printf("\tTotal denied auths:\t%ld\n", totalREJ);
        
        if (totalOK) printf("\n\tResp time (min/avg/max) in ms: %d / %d / %d\n", mintimeOK, meantimeOK, maxtimeOK);
        if (totalREJ) printf("\tResp time (min/avg/max) in ms: %d / %d / %d\n", mintimeREJ, meantimeREJ, maxtimeREJ);
        
        printf("\n\tNb request by sec:\t%ld\n", (1000*count) / (1000*(totalend.time-totalbeg.time) + (totalend.millitm-totalbeg.millitm)) );
        
        printf("\tNb of resend requests:\t%ld\n\n", totalresend);
    }
    return 0;
}


