build ldap-tgen in container:

$ sudo docker build -f Dockerfile.build -t ldap-tgen-build-img .
$ sudo docker run ldap-tgen-build-img make
$ sudo docker container ls -a
CONTAINER ID        IMAGE                 COMMAND             CREATED             STATUS                      PORTS               NAMES
08d8c4e520c9        ldap-tgen-build-img   "make"              20 seconds ago      Exited (0) 14 seconds ago                       optimistic_yonath
$ sudo docker cp 08d8c4e520c9:/home/test/tgen-local build
$ ls build/mds_tests/Common/Tgen/Bin64/
tgen_mas
$ 


run ldap-tgen in container:

sudo docker build -t ldap-tgen-img .
sudo docker run ldap-tgen-img ./tgen_mas


run slapd in container:
docker run --env LDAP_ORGANISATION="Example" --env LDAP_DOMAIN="example.com"  --env LDAP_ADMIN_PASSWORD="test" --detach osixia/openldap:1.1.8


Images are available on docker hub, so you can now just run for testing:

docker run ymartineau/ldap-tgen-img ./tgen_mas


-v volume added to access ldif file that is used to provision database
# docker run --env LDAP_ORGANISATION="Example" --env LDAP_DOMAIN="example.com"  --env LDAP_ADMIN_PASSWORD="test" --detach -v /home/centos/workspace/ldap-tgen:/var/ldap-tgen osixia/openldap:1.1.8

# docker ps
CONTAINER ID        IMAGE                   COMMAND                 CREATED              STATUS              PORTS               NAMES
fb0972465149        osixia/openldap:1.1.8   "/container/tool/run"   About a minute ago   Up About a minute   389/tcp, 636/tcp    inspiring_brattain

# docker exec fb0972465149 ldapadd -D "cn=admin,dc=example,dc=com" -w test -f /var/ldap-tgen/Example.ldif

# docker exec fb0972465149 ldapsearch -x -D "cn=admin,dc=example,dc=com" -w test -b dc=example,dc=com 'uid=abarnes' cn gidNumber

get the ip address of the slapd container:
# docker network inspect bridge
...
        "Containers": {
            "fb0972465149...": {
                "Name": "zen_keller",
                "EndpointID": "00dd8f3bd4efac0dcada0e56d466958b42c6ed3b0d469a4f544e74b34225c88c",
                "MacAddress": "02:42:ac:11:00:03",
                "IPv4Address": "172.17.0.3/16",
                "IPv6Address": ""
            }
        },
...

ip address is of server container is 172.17.0.3



create a local directory on host with ldap-tgen configuration files:

$ mkdir config
$ cd config/


create the following configuration files in this directory:

tgen.ini
--------------------------------------------------------------------------------------------
[Global]

traffic=                4
req_by_sec=             3
nb_threads=             1
quiet_on_error=         0
stop_on_error=          0
no_matted_pair=         1
abort_scenario_on_error=0
time_before_rebind=     1
time_before_stats=      5
user_get_policy=        2
report_period=          300
csv_period=             60

[Ldap]

Ldap_server_port=       389
Ldap_timeout=           10
bind_policy=            3
Ldap_wait_response=     1

[Radius]
Radius_server_port=     1812
Radius_timeout=         3
Radius_retries=         4
Radius_CallingStationId = 01-0F-20-FA-%02X-%02X
Radius_CalledStationId = DS1
authtype_policy=        1
authtype_distrib_0=     0
authtype_distrib_1=     0
authtype_distrib_2=     0
authtype_distrib_3=     0
authtype_distrib_4=     0
authtype_distrib_5=     0
authtype_distrib_6=     30
authtype_distrib_7=     0
authtype_distrib_8=     40
authtype_distrib_9=     30
same_passwd=            0
Radius_nb_nas=          10
no_nas_port=            0
sessionId_binary=       0
fast_reauth =           0
ca_cert = /mds_tests/uma/UnitaryTesting/EapTtls/CAroot.pem
eap_ttls_phase2 = MSCHAPV2
anonymous_identity = @orange.fr
ca_cert_tls=/mds_tests/uma/UnitaryTesting/EapTLS/cacert.pem
tls_certs_parent_path=/mds_tests/mas/Common/DataBasePopulation/Tgen/EAPTLS_Certs/ca_all/
tls_certs_count=0
client_cert_tls_default=/mds_tests/mas/Common/DataBasePopulation/Tgen/EAPTLS_Certs/ca_all/client_cert02.pem
private_key_tls_default=/mds_tests/mas/Common/DataBasePopulation/Tgen/EAPTLS_Certs/ca_all/privkey1_02.pem
private_key_passwd_tls_default=whatever
servicetype_ols=2
wimaxcapability_ols=000105312e30020300030302

[MaxDelay]

LDAP_Bind_Rq=                    20
LDAP_UnBind_Rq=                  20
LDAP_Search_Rq=                  40
LDAP_Modify_Rq=                  40
LDAP_Add_Rq=                     40
LDAP_Delete_Rq=                  40
RADIUS_Auth_Rq=                  150
RADIUS_AuthWP_Rq=                50
RADIUS_AccessEapId_Rq=           50
RADIUS_AccessSimStart_Rq=        50
RADIUS_AccessSimChal_Rq=         50
RADIUS_AccessSimCliErr_Rq=       50
RADIUS_AccessSimNotif_Rq=        50
RADIUS_AccessSimFast_Rq=         50
RADIUS_AccountStart_Rq=          150
RADIUS_AccountStop_Rq=           200
RADIUS_AccountInterim_Rq=        100
RADIUS_AccountOn_Rq=             100
RADIUS_AccountOff_Rq=            100
RADIUS_AccessEapTtls_Rq=         120
RADIUS_AccessEapTls_Rq=          120
RADIUS_AkaIdentity_Rq=		 120
RADIUS_AkaChal_Rq=               120
RADIUS_AkaRej_Rq=                120
RADIUS_AkaSynfail_Rq=            120


$include tgen_opensource.ini
$include tgen_servers.ini




tgen_opensource.ini
--------------------------------------------------------------------------------------------
[Popul_100]

description = example users
min = 2
max = 10
nb = 8
scope=2
pdn = dc=com
rdn_i = dc=example
nai_i = 0
filter_i=(uid=abarnes)
passwd_i = 0
authtype = 0

[Scenario_6]

description = Simple LdapSearch request on a whole user
population = 100
action1 = SCE_Begin
action2 = LDAP_Bind_Rq
action3 = LDAP_Search_Rq,"\0","\*"
action4 = LDAP_UnBind_Rq
action5 = SCE_End

[Trafic_5]

description = Global traffic definition
scenario1 = Scenario_6
rate1 = 100


tgen_servers.ini
--------------------------------------------------------------------------------------------
[Server_1]

description = localhost desc.
ldap_bind_dn = cn=manager,dc=com
ldap_password = secret
nb_server = 1
ip_server1 = 127.0.0.1
port_server1 = 389




then start the ldap-tgen container with a volume to "mount" those config files:


# docker run -it -v /home/centos/workspace/ldap-tgen/config:/root/TestU --env RAD_RACINE=/home/test/tgen-local/hss_freeradius ymartineau/ldap-tgen-img ./tgen_mas -p100 -s6 -t5 172.17.0.3


Troubleshooting:
To avoid the following message:
Terminal is too small (set at least 40x140)

use the "stty size" command to get the size of your current terminal
If you are using a virtualbox machine, switch to full screen and maximize
terminal it should be enough.



troubleshooting:
on host:
# tcpdump -i docker0 -w /tmp/test.pcap
capture file: bind OK, "no such object" error code on search

made another capture with ldapsearch running in another container to compare:
(in this test, server container ip address is 172.17.0.2)
# docker run -it  osixia/openldap:1.1.8 bash
root@7b9f4084a7e1:/# ldapsearch -h 172.17.0.2 -x -D "cn=admin,dc=example,dc=com" -w test -b dc=example,dc=com 'uid=abarnes' cn gidNumber
...
dn: uid=abarnes,ou=People,dc=example,dc=com
cn: Anne-Louise Barnes
gidNumber: 1000

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1




# docker run -it -v /home/centos/workspace/ldap-tgen/config:/root/TestU --env RAD_RACINE=/home/test/tgen-local/hss_freeradius --env LDAPBINDDN="cn=admin,dc=example,dc=com" --env LDAP_SECRET="test" ymartineau/ldap-tgen-img ./tgen_mas -p100 -s6 -t5 172.17.0.2


Parameter -r gives the rate of request per seconds that should be sent.
In rate column, we can see the actual number of requests sent.

TODO use add or update in ldap requests to write to database and check
     performances
TODO use two containers for server
TODO add a load balancer
TODO test it with kubernetes
