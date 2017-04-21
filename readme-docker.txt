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


Images are available on docker hub, so you can now just run:

docker run ymartineau/ldap-tgen-img ./tgen_mas
