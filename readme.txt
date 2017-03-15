ldap-tgen is an LDAP traffic generator.

It can be used for ldap server load testing.
It's configured using .ini files, launched as command line and provides
real time data in terminal.

BUILD INSTRUCTIONS
==================

build on debian-8: install libssl-dev, libncurses5-dev, libldap2-dev, libsasl2-dev 

update ROOT_DIR in mds_tests/Common/Tgen/Src/makefile


export ROOT_DIR=/home/test/ldap-tgen
mkdir mds_tests/Common/Tgen/fake_lib
cd mds_tests/Common/Tgen/fake_lib
ln -s /usr/lib/x86_64-linux-gnu/libssl.so libssl.so.6
ln -s /usr/lib/x86_64-linux-gnu/libcrypto.so libcrypto.so.6
export LD_LIBRARY_PATH=$ROOT_DIR/hss_freeradius/x86_64/lib:$ROOT_DIR/mds_tests/uma/Common/WpaSupplicant/x86_64:$ROOT_DIR/mds_tests/Common/Tgen/fake_lib
cd ../Src/
make clean
make



COMMAND LINE EXAMPLE
====================

to test (cshell):
setenv ROOT_DIR /local/myuser/ldap-tgen
set LD_LIBRARY_PATH = ( $ROOT_DIR/hss_freeradius/x86_64/lib $ROOT_DIR/mds_tests/uma/Common/WpaSupplicant/x86_64 )

cd mds_tests/Common/Tgen/Bin64
./tgen_mas -c /local/myuser/ldap-tgen/mds_tests/Common/Tgen/tgen.ini

(use absolute path for -c parameter to avoid segmentation fault)





dependency: (openldap-2.4.23) openldap library
ldap-tgen relies on ldap-int.h to display ldap message error numbers (ld_errno)
TODO: test with more recent openldap version library (in ldap-tgen/openldap)

dependency: hss_freeradius:
depends on freeradius-1.1.7, which depends on (debian):
libperl-dev - Perl library: development files
libltdl-dev - System independent dlopen wrapper for GNU libtool


cd ../Bin64
tgen command line (check above)
./tgen_mas -c /local/myuser/ldap-tgen/mds_tests/Common/Tgen/tgen.ini

(use absolute path for -c parameter to avoid segmentation fault)





