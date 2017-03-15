#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>
#include <netdb.h>

#include "tconf.h"
#include "tserver.h"
#include "tdebug.h"


//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい
// INIT Server
//いいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいいい

/******************************************************************************/
int tServerInit (char *GroupServer)
/******************************************************************************/
{
int    group;
char * pch;

	if (GroupServer == NULL)
		// utilisation de hostname
		return 0;

	if ( (pch = strtok (GroupServer, ",")) == NULL ) {
		TRACE_CRITICAL("init: bad group's list \n");
		return 1;
	}
	while ( pch != NULL ) {
		group = atoi(pch);
		if  ( tServerPopulInit(group) != 0 ) return 1;

		pch = strtok (NULL, ",");
	}
}

/******************************************************************************/
int     tServerPopulInit(int serverIndex)
/******************************************************************************/
{
int 	rc=0;
int 	i=0;
char    ip_server[256] = "";
char    port_server[256] = "";
char    tcserver[256] = "";
char 	section[256] = "";
char    description[256] = "";

    tcClientLDAPBindDN = malloc(256);
	tcClientLDAPPasswd = malloc(256);
    sprintf(section, "Server_%d", serverIndex);

    ProfileGetString( inifile, section, "description", "", description, sizeof(description) );
    ProfileGetString( inifile, section, "ldap_bind_dn", "", tcClientLDAPBindDN, 256);
    ProfileGetString( inifile, section, "ldap_password", "", tcClientLDAPPasswd, 256);
    tcServerLDAPPort = ProfileGetInt( inifile, section, "port", LDAP_SERVER_HOST_PORT);
    nbserver = ProfileGetInt( inifile, section, "nb_server", 0);
    tcSecuredMode = ProfileGetInt( inifile, section, "secured_mode", 0);
    ProfileGetString( inifile, section, "cacert_file", "", tcCaCertFile, 128);
    if (tcWThreadNb<nbserver) {
        TRACE_CORE("WARNING: All the servers are not used because : nbthread(%d) < nbserver(%d)\n", tcWThreadNb,nbserver);
    }
    // read @IP Server
    for (i=0;i<nbserver;i++){
        sprintf(ip_server, "ip_server%d", i+1);
    	ProfileGetString( inifile, section, ip_server, "", tcserver, sizeof(tcserver));
    	if ( tcserver[0] == NULL){
    		TRACE_CRITICAL("nb_server > to number of ip_server in tgen_servers.ini\n");
    		exit(1);
    	}
    	tcServerHost[i] = strdup(tcserver);
        //EmA,02/03/2011: add option to change the server port inside a server set (DDM multi-instance of the same db)
        sprintf(port_server, "port_server%d", i+1);
		tcServerPort[i] = ProfileGetInt( inifile, section, port_server, tcServerLDAPPort);
        if (tcServerHost[i])  {
			struct hostent*     remoteHost;
			unsigned int        hostaddr;
			char                tmpadd[32];
			int					af;

			TRACE_CORE("tcServerHost[%d] = \t%s\n",i, tcServerHost[i]);
			TRACE_CORE("tcServerPort[%d] = \t%d\n",i, tcServerPort[i]);
			af= AF_INET;
			remoteHost = gethostbyname2(tcServerHost[i],af);
			if (!remoteHost) {
				af= AF_INET6;
				remoteHost = gethostbyname2(tcServerHost[i],af);
			}

			TRACE_CORE("ainet = \t%d\n", remoteHost->h_addrtype);
			if (!remoteHost) {
				TRACE_CRITICAL("Unable to resolve hostname: %s\n", tcServerHost[i]);
				exit(1);
			}

			TRACE_TRAFIC("tcServerHost[%d] = \t%s\n", i, tcServerHost[i]);
		}
    }
    return rc;
}
