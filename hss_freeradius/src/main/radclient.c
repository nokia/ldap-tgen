/*
 * radclient.c	General radius packet debug tool.
 *
 * Version:	$Id: radclient.c,v 1.60 2003/10/31 22:31:06 mcr Exp $
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
static const char rcsid[] = "$Id: radclient.c,v 1.60 2003/10/31 22:31:06 mcr Exp $";

#include "autoconf.h"
#include "libradius.h"

#include <stdio.h>
#include <stdlib.h>
#include	<fcntl.h>      /* EmA,18/06/01 */
#include	<sys/timeb.h>      /* EmA,18/06/01 For precise time function & struct */

#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif

#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#	include <sys/select.h>
#endif

#ifdef HAVE_GETOPT_H
#	include <getopt.h>
#endif

#include "conf.h"
#include "radpaths.h"
#include "missing.h"

/* BEGIN EmA,21/08/2002: Added for HTTP Digest authentication */
#include	"digcalc.h"
static char* envvar[PW_SUBATTRIBUTE_USERNAME + 1] = {
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
/* END EmA,21/08/2002: Added for HTTP Digest authentication */

/* EmA,18/06/01 */
static uint8_t			random_vector_pool[AUTH_VECTOR_LEN*2];
/* End EmA */

static int retries = 3;
static float timeout = 3;
static const char *secret = NULL;
static int do_output = 1;
static int do_summary = 0;
/* EmA,18/06/01
static int filedone = 0;
*/
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

/* EmA,11/01/02 */
static long			nb_users;
/* End EmA */

static char filesecret[256];
static char file_tracefile[256] = "";

/************************************************************************************/
/*
 *	Read valuepairs from the fp up to End-Of-File.
 */
static VALUE_PAIR *readvp(FILE *fp)
/************************************************************************************/
{
	char buf[1024];
	int last_token;
	char *p;
	VALUE_PAIR *vp;
	VALUE_PAIR *list;
	int error = 0;

	list = NULL;

	while (!error && fgets(buf, sizeof(buf), fp) != NULL) {

		p = buf;

		/* If we get a '\n' by itself, we assume that's the end of that VP */
		if((buf[0] == '\n') && (list)) {
			return error ? NULL: list;
		} 
		if((buf[0] == '\n') && (!list)) {
			continue;
		} else {
			do {
				if ((vp = pairread(&p, &last_token)) == NULL) {
					librad_perror("radclient:");
					error = 1;
					break;
				}
				pairadd(&list, vp);
			} while (last_token == T_COMMA);
		}
	}
	return error ? NULL: list;
}

/************************************************************************************/
static void usage(void)
/************************************************************************************/
{
	fprintf(stderr, "Usage: radclient [-c count] [-d delay] [-f file] [-r retries] [-t timeout]\n"
			"[-i id] [-qvx] server acct|auth <secret>\n");
	
	fprintf(stderr, " -c count    	Send each packet 'count' times.\n");
	fprintf(stderr, " -d delay    	delay between 2 requests (msec).\n");
	fprintf(stderr, " -f file     	Read packets from file, not stdin.\n");
	fprintf(stderr, " -n num      	Get random user/password from 'users' file which contains 'num' lines.\n");
	fprintf(stderr, " -r retries  	If timeout, retry sending the packet 'retires' times.\n");
	fprintf(stderr, " -t timeout  	Wait 'timeout' seconds before retrying.\n");
	fprintf(stderr, " -i id       	Set request id to 'id'.  Values may be 0..255\n");
	fprintf(stderr, " -S file     	read secret from file, not command line.\n");
	fprintf(stderr, " -o outputFile	name of the output file (for unitary test)\n");
	fprintf(stderr, " -q          	Do not print anything out.\n");
	fprintf(stderr, " -s          	Print out summary information of auth results.\n");
	fprintf(stderr, " -v          	Show program version information.\n");
	fprintf(stderr, " -x          	Debugging mode.\n");

	exit(1);
}

/******************************************************************************/
void TraceFileLog()
/******************************************************************************/
{
	FILE * fp;
    if (!strlen(file_tracefile)) 
        return;

	int fd = open (file_tracefile, O_WRONLY|O_CREAT|O_EXCL, 0600);
	if (fd < 0)
	{
		if ((fd = open (file_tracefile, O_WRONLY|O_EXCL, 0600)) < 0)
		{
			printf( "could not access to file %s\n", file_tracefile );
		}	
	}
	if (fd > 0)
	{
		char         buffer[] = "radClient: response received\n";
		
		fp = fdopen(fd, "a");
		
      fprintf(fp, buffer);
		fclose(fp);
	}
}

/************************************************************************************/
static int getport(const char *name)
/************************************************************************************/
{
	struct	servent		*svp;

	svp = getservbyname (name, "udp");
	if (!svp) {
		return 0;
	}

	return ntohs(svp->s_port);
}

/************************************************************************************/
static int send_packet(RADIUS_PACKET *req, RADIUS_PACKET **rep)
/************************************************************************************/
{
int i;
struct timeval	tv;
struct timeb tbeg, tend;
long	 ms_delay;
RADIUS_PACKET *rep2;
int	res_rad_decode;

	ftime(&tbeg);

	for (i = 0; i < retries; i++) {
		fd_set		rdfdesc;

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
			 *	If we get a response from a machine
			 *	which we did NOT send a request to,
			 *	then complain.
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
					
					if (rep2 != NULL)
						fprintf(stderr, "radclient: one redundant response from server\n");
						
				} while (rep2 != NULL);
			}

			break;

		} else {	/* NULL: couldn't receive the packet */
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

	if (res_rad_decode == 1) {	// invalid signature
		librad_perror("rad_decode");

		if (!librad_debug) {
			// prints out the value pairs of sended request
			printf("Request was ID %d, code %d, length = %d\n",
					req->id, req->code, req->data_len);
			vp_printlist(stdout, req->vps);
		}

	} else if (res_rad_decode != 0) {	// ex: -1 == not enough memory
		librad_perror("rad_decode");
		exit(1);
	}

	if (!librad_debug && do_output) {
		// if -x, libradius debug already prints out the value pairs for us
		// if -q, don't print normal cases
		printf("Received response ID %d, code %d, length = %d\n",
				(*rep)->id, (*rep)->code, (*rep)->data_len);
		TraceFileLog();
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
/*
 *	Create a random vector of AUTH_VECTOR_LEN bytes.
 */
static void random_vector(uint8_t *vector)
/************************************************************************************/
{
	int		i;
	static int	did_srand = 0;
	static int	counter = 0;
#ifdef __linux__
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
			if (librad_debug) printf("Cannot open /dev/urandom, using rand()\n");
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
		if (librad_debug) printf("Read short packet from /dev/urandom, using rand()\n");
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





#ifdef OLD_USERS_VERSION

#define NB_USERS			10000
#define USERNAME_LEN		10
#define PASSWORD_LEN		20
#define LINE_SIZE			(35 + USERNAME_LEN + PASSWORD_LEN)

/************************************************************************************/
static void	get_random_line(char *line)
/* line must point to long enough buffer of char */
/************************************************************************************/
{
long		num_line;
FILE 		*fusers;

	/* open file in binary to be allowed to use fseek */
   if ( (fusers = fopen("users", "rb")) == NULL ) {
		printf("Error opening users file\n");
		exit(1);
	}

	num_line = random() % NB_USERS;
	fseek(fusers, num_line * (LINE_SIZE + 1), SEEK_SET);
	fread(line, LINE_SIZE, 1, fusers);

	fclose(fusers);

	line[LINE_SIZE] = 0;
/* printf("num_line = %ld : %s\n", num_line+1, line); */
}      

/************************************************************************************/
static void	get_name_and_passwd(char *name, char* passwd)
/* name & passwd must point to long enough buffers of char */
/************************************************************************************/
{
char		line[LINE_SIZE + 1];

	/* get a random line in DB file */
	get_random_line(line);

	/* extract username and his password from this line */
	strncpy(name, &line[0], USERNAME_LEN);
	strncpy(passwd, &line[LINE_SIZE - PASSWORD_LEN - 1], PASSWORD_LEN);

	name[USERNAME_LEN] = 0;
	passwd[PASSWORD_LEN] = 0;

/* printf("name=%s , password=%s\n", name, passwd); */
}

#else

#define MAX_LINE_SIZE			256

/************************************************************************************/
static void	get_random_line(char *line)
/* line must point to long enough buffer of char */
/************************************************************************************/
{
long				num_line;
static FILE 	*fusers = NULL;             
int 				i;

	if ( !fusers ) {
		/* open file in binary to be allowed to use fseek */
   	if ( (fusers = fopen("users", "rb")) == NULL ) {
			printf("Error opening users file\n");
			exit(1);
		}
	} else { 
		fseek(fusers, 0, SEEK_SET);
	}

	num_line = random() % nb_users;
	for (i=0; i<=num_line; i++)
		fgets(line, MAX_LINE_SIZE-1, fusers);

	/* fclose(fusers); */

   /*printf("num_line = %ld : %s\n", num_line+1, line);*/
}

/************************************************************************************/
static void	get_name_and_passwd(char *name, char* passwd)
/* name & passwd must point to long enough buffers of char */
/************************************************************************************/
{
char		line[MAX_LINE_SIZE + 1];  
int 		i, j;

	/* get a random line in DB file */
	get_random_line(line);

	/* extract username and his password from this line */
	i = 0;
	j = 0;
	while ( line[i] != ' ' )
		name[j++] = line[i++];
	name[j] = 0;
		
	while ( line[i++] != '"' ) ;

	j = 0;
	while ( line[i] != '"' )
		passwd[j++] = line[i++];
	passwd[j] = 0;

   /*printf("name=%s , password=%s\n", name, passwd);*/
}

#endif



/* Begin EmA,20/08/2002: adding of HTTP-Digest authentication */

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
			
//			printf("subattribute read: T=%d L=%d V=%s\n", subattr[0], subattr[1], subattr + 2);

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
//				printf("%s=%s default value applied\n", envvar[i], env);
				
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

/* End EmA,20/08/2002: adding of HTTP-Digest authentication */


/************************************************************************************/
int main(int argc, char **argv)
/************************************************************************************/
{
	RADIUS_PACKET *req;
	RADIUS_PACKET *rep = NULL;
	char *p;
	int c;
	int port = 0;
	char radius_dir[256];
	char *filename = NULL;
	FILE *fp;
	int count = 1;
	int loop;
/* EmA 25/11/03
	char password[256];
End EmA */
	VALUE_PAIR *vp;
	int id;
/* EmA 19/06/01 */
	int 			sleeptime = 0;		/* default delay between resquests in ms */
	int			sockfd;
	int			code = PW_AUTHENTICATION_REQUEST;
	VALUE_PAIR	*vps;
	uint32_t		dst_ipaddr;
	int	      randomize = 0;
	char			user[257];
	char			passwd[257];
	struct timeb 		totalbeg, totalend;   
/* End EmA */

/*EmA,22/07/2005
	strcpy(radius_dir, RACINE);
	strcat(radius_dir, RADDBDIR);*/
	strcpy(radius_dir, RADDBDIR);

	user[0] = 0;
	passwd[0] = 0;
	
	id = ((int)getpid() & 0xff);
	librad_debug = 0;

	while ((c = getopt(argc, argv, "c:d:f:hi:qst:r:S:o:xvn")) != EOF) switch(c) {
		case 'c':
			if (!isdigit(*optarg)) 
				usage();
			count = atoi(optarg);
			break;
		case 'd':
			if (!isdigit(*optarg))
				usage();
			sleeptime = atoi(optarg);
/*			radius_dir = optarg; 		EmA,19/06/2001 */
			break;
		case 'f':
			filename = optarg;
			break;
		case 'o':
			strcpy(file_tracefile, optarg);
			break;
		case 'q':
			do_output = 0;
			break;
		case 'x':
			librad_debug++;
			break;
		case 'r':
			if (!isdigit(*optarg)) 
				usage();
			retries = atoi(optarg);
			break;
		case 'i':
			if (!isdigit(*optarg)) 
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
			if (!isdigit(*optarg)) 
				usage();
			timeout = atof(optarg);
			break;
		case 'v':
			printf("radclient: $Id: radclient.c,v 1.60 2003/10/31 22:31:06 mcr Exp $ built on " __DATE__ " at " __TIME__ "\n");
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
		case 'n':
			randomize = 1;
			if (!isdigit(*optarg)) 
				usage();
			nb_users = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
			break;
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

	/*
	 *	Strip port from hostname if needed.
	 */
	if ((p = strchr(argv[1], ':')) != NULL) {
		*p++ = 0;
		port = atoi(p);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (strcmp(argv[2], "auth") == 0) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		code = PW_AUTHENTICATION_REQUEST;

	} else if (strcmp(argv[2], "acct") == 0) {
		if (port == 0) port = getport("radacct");
		if (port == 0) port = PW_ACCT_UDP_PORT;
		code = PW_ACCOUNTING_REQUEST;
		do_summary = 0;

	} else if (strcmp(argv[2], "status") == 0) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		code = PW_STATUS_SERVER;

	} else if (strcmp(argv[2], "disconnect") == 0) {
		if (port == 0) port = PW_POD_UDP_PORT;
		code = PW_DISCONNECT_REQUEST;

	} else if (isdigit((int) argv[2][0])) {
		if (port == 0) port = getport("radius");
		if (port == 0) port = PW_AUTH_UDP_PORT;
		code = atoi(argv[2]);
	} else {
		usage();
	}

	/*
	 *	Resolve hostname.
	 */
	dst_ipaddr = ip_getaddr(argv[1]);
	if (dst_ipaddr == INADDR_NONE) {
//EmA		librad_perror("radclient: %s: ", argv[1]);
		fprintf(stderr, "radclient: Failed to find IP address for host %s\n", argv[1]);
		exit(1);
	}

	/*
	 *	Add the secret.
	 */
	if (argv[3]) secret = argv[3];

	/*
	 *	Read valuepairs.
	 *	Maybe read them, from stdin, if there's no
	 *	filename, or if the filename is '-'.
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
	vps = readvp(fp);

	/*
	 *	Create socket for sending request.
	 */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("radclient: socket: ");
		exit(1);
	}

	/* init random seed */
 	srandom(getpid());

	ftime(&totalbeg);

 	/*
  	 *	Loop, sending the packet N times.
  	 */
  	for (loop = 0; loop < count; loop++) {

      if ((req = rad_alloc(1)) == NULL) {
      	librad_perror("radclient");
      	exit(1);
      }

		/* unchangged fields */
		req->code = code;
		req->dst_port = port;
		req->dst_ipaddr = dst_ipaddr;
/*		if(req->vps) pairfree(&req->vps); */
		req->vps = paircopy(vps);
      req->sockfd = sockfd;

		/* fields modified at each request */
      req->id = (id++);
/*		librad_md5_calc(req->vector, req->vector, sizeof(req->vector)); */
		random_vector(req->vector);
	
		/*
		 *	Change name if random option is choosen
		 */
		if (randomize) {
			if ((vp = pairfind(req->vps, PW_USER_NAME)) == NULL)
				usage();

			get_name_and_passwd(user, passwd);

			strNcpy((char *)vp->strvalue, user, strlen(user) + 1);
			vp->length = strlen(user);
		} else if ((vp = pairfind(req->vps, PW_USER_NAME)) != NULL)
			strNcpy(user, (char *)vp->strvalue, vp->length + 1);

		/*
		 *	Encrypt the Password attribute.
		 */
		if ((vp = pairfind(req->vps, PW_PASSWORD)) != NULL) {
			if (randomize) {
				strNcpy((char *)vp->strvalue, passwd, strlen(passwd) + 1);
				vp->length = strlen(passwd);
			} else
				strNcpy(passwd, (char *)vp->strvalue, vp->length + 1);

// EmA,11/12/03: with new version of freeradius (snapshot-16/11/2003), it is included in libradius.a
//			rad_pwencode((char *)vp->strvalue, &(vp->length), secret, (char *)req->vector);
		}
		/*
		 *	Encrypt the CHAP-Password attribute.
		 */
		if ((vp = pairfind(req->vps, PW_CHAP_PASSWORD)) != NULL) {
			if (randomize) {
				strNcpy((char *)vp->strvalue, passwd, strlen(passwd) + 1);
				vp->length = strlen(passwd);
			} else
				strNcpy(passwd, (char *)vp->strvalue, vp->length + 1);

			rad_chap_encode(req, (char *)vp->strvalue, req->id, vp);
			vp->length = HASHLEN + 1;
		}

		/*
		 *	Encrypt the Digest-Response and Digest-Atributes(Body-Digest) attributes if necessary.
		 */
		if ( rad_http_encode(req, user, passwd) ) {
			// suppress Password, Chap-Password and Chap-Challenge
//			pairdelete( &(req->vps), PW_PASSWORD );
			pairdelete( &(req->vps), PW_CHAP_PASSWORD );
			pairdelete( &(req->vps), PW_CHAP_CHALLENGE );
		}

		/*
		 * Send paket and wait for response
		 */
		send_packet(req, &rep);

		/*
		 * Add here analyse of response
		 */
		rad_free(&req);
		rad_free(&rep);

		/* EmA,19/06/2001: Waits a while to avoid auth module mutex lock */
		if (sleeptime) usleep(sleeptime * 1000);
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
