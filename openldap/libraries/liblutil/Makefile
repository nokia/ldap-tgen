# $OpenLDAP: pkg/ldap/build/top.mk,v 1.103.2.11 2010/04/13 20:22:22 kurt Exp $
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2010 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
##---------------------------------------------------------------------------
#
# Top-level Makefile template
#

PACKAGE= OpenLDAP
VERSION= 2.4.23
RELEASEDATE= 2010/06/30


SHELL = /bin/sh

top_builddir = ../..

srcdir = .
top_srcdir = ../..

prefix = /mds_tests/Common/Openldap/x86_64
exec_prefix = /mds_tests/Common/Openldap/x86_64
ldap_subdir = /openldap

bindir = ${exec_prefix}/bin
datarootdir = ${prefix}/share
datadir = ${datarootdir}$(ldap_subdir)
includedir = ${prefix}/include
infodir = ${datarootdir}/info
libdir = ${exec_prefix}/lib
libexecdir = ${exec_prefix}/libexec
localstatedir = ${prefix}/var
mandir = ${datarootdir}/man
moduledir = ${exec_prefix}/libexec$(ldap_subdir)
sbindir = ${exec_prefix}/sbin
sharedstatedir = ${prefix}/com
sysconfdir = ${prefix}/etc$(ldap_subdir)
schemadir = $(sysconfdir)/schema

PLAT = UNIX
EXEEXT = 
OBJEXT = o

BUILD_LIBS_DYNAMIC = shared

SHTOOL = $(top_srcdir)/build/shtool

INSTALL = $(SHTOOL) install -c
INSTALL_PROGRAM = $(INSTALL)
INSTALL_DATA = $(INSTALL) -m 644
INSTALL_SCRIPT = $(INSTALL)

STRIP = -s

LINT = lint
5LINT = 5lint

MKDEP = $(top_srcdir)/build/mkdep $(MKDEPFLAG) \
	-d "$(srcdir)" -c "$(MKDEP_CC)" -m "$(MKDEP_CFLAGS)"
MKDEP_CC	= cc
MKDEP_CFLAGS = -M

MKVERSION = $(top_srcdir)/build/mkversion -v "$(VERSION)"

LIBTOOL = $(SHELL) $(top_builddir)/libtool
LIBRELEASE = 2.4
LIBVERSION = 7:6:5
LTVERSION = -release $(LIBRELEASE) -version-info $(LIBVERSION)

# libtool --only flag for libraries: platform specific
NT_LTONLY_LIB = # --only-$(BUILD_LIBS_DYNAMIC)
LTONLY_LIB = $(UNIX_LTONLY_LIB)

# libtool --only flag for modules: depends on linkage of module
# The BUILD_MOD macro is defined in each backend Makefile.in file
LTONLY_yes = --tag=disable-shared
LTONLY_mod = --tag=disable-static
LTONLY_MOD = $(LTONLY_$(BUILD_MOD))

# platform-specific libtool flags
NT_LTFLAGS_LIB = -no-undefined -avoid-version -rpath $(libdir)
NT_LTFLAGS_MOD = -no-undefined -avoid-version -rpath $(moduledir)
UNIX_LTFLAGS_LIB = $(LTVERSION) -rpath $(libdir)
UNIX_LTFLAGS_MOD = $(LTVERSION) -rpath $(moduledir)

# libtool flags
LTFLAGS     = $(UNIX_LTFLAGS)
LTFLAGS_LIB = $(UNIX_LTFLAGS_LIB)
LTFLAGS_MOD = $(UNIX_LTFLAGS_MOD)

# LIB_DEFS defined in liblber and libldap Makefile.in files.
# MOD_DEFS defined in backend Makefile.in files.

# platform-specific LINK_LIBS defined in various Makefile.in files.
# LINK_LIBS referenced in library and module link commands.
LINK_LIBS = $(MOD_LIBS) $(UNIX_LINK_LIBS)

LTSTATIC = 

LTLINK   = $(LIBTOOL) --mode=link \
	$(CC) $(LTSTATIC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS)

LTCOMPILE_LIB = $(LIBTOOL) $(LTONLY_LIB) --mode=compile \
	$(CC) $(LT_CFLAGS) $(LT_CPPFLAGS) $(LIB_DEFS) -c

LTLINK_LIB = $(LIBTOOL) $(LTONLY_LIB) --mode=link \
	$(CC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS_LIB)

LTCOMPILE_MOD = $(LIBTOOL) $(LTONLY_MOD) --mode=compile \
	$(CC) $(LT_CFLAGS) $(LT_CPPFLAGS) $(MOD_DEFS) -c

LTLINK_MOD = $(LIBTOOL) $(LTONLY_MOD) --mode=link \
	$(CC) $(LT_CFLAGS) $(LDFLAGS) $(LTFLAGS_MOD)

LTINSTALL = $(LIBTOOL) --mode=install $(INSTALL) 
LTFINISH = $(LIBTOOL) --mode=finish

# Misc UNIX commands used in build environment
AR = ar
BASENAME = basename
CAT = cat
CHMOD = chmod
DATE = date
ECHO = $(SHTOOL) echo
HOSTNAME = $(SHTOOL) echo -e "%h%d"
LN = $(SHTOOL) mkln
LN_H = $(LN)
LN_S = $(LN) -s
MAKEINFO = ${SHELL} /local/anthoin1/src/openldap/build/missing --run makeinfo
MKDIR = $(SHTOOL) mkdir -p
MV = $(SHTOOL) move
PWD = pwd
RANLIB = ranlib
RM = rm -f
SED = sed
SUBST = $(SHTOOL) subst

# For manual pages
# MANCOMPRESS=@MANCOMPRESS@
# MANCOMPRESSSUFFIX=@MANCOMPRESSSUFFIX@
MANCOMPRESS=$(CAT)
MANCOMPRESSSUFFIX=

SOELIM=soelim

INCLUDEDIR= $(top_srcdir)/include
LDAP_INCPATH= -I$(LDAP_INCDIR) -I$(INCLUDEDIR)
LDAP_LIBDIR= $(top_builddir)/libraries

LUTIL_LIBS = 
LTHREAD_LIBS =  -pthread

BDB_LIBS = 
SLAPD_NDB_LIBS = 

LDAP_LIBLBER_LA = $(LDAP_LIBDIR)/liblber/liblber.la
LDAP_LIBLDAP_LA = $(LDAP_LIBDIR)/libldap/libldap.la
LDAP_LIBLDAP_R_LA = $(LDAP_LIBDIR)/libldap_r/libldap_r.la

LDAP_LIBREWRITE_A = $(LDAP_LIBDIR)/librewrite/librewrite.a
LDAP_LIBLUNICODE_A = $(LDAP_LIBDIR)/liblunicode/liblunicode.a
LDAP_LIBLUTIL_A = $(LDAP_LIBDIR)/liblutil/liblutil.a

LDAP_L = $(LDAP_LIBLUTIL_A) \
	$(LDAP_LIBLDAP_LA) $(LDAP_LIBLBER_LA)
SLAPD_L = $(LDAP_LIBLUNICODE_A) $(LDAP_LIBREWRITE_A) \
	$(LDAP_LIBLUTIL_A) $(LDAP_LIBLDAP_R_LA) $(LDAP_LIBLBER_LA)

WRAP_LIBS = 
# AutoConfig generated 
AC_CC	= cc
AC_CFLAGS = -g -O2
AC_DEFS =  # -DHAVE_CONFIG_H
AC_LDFLAGS = 
AC_LIBS = -lresolv 

KRB4_LIBS = 
KRB5_LIBS = 
KRB_LIBS =  
SASL_LIBS = -lsasl2
TLS_LIBS = -lssl -lcrypto
AUTH_LIBS = 
SECURITY_LIBS = $(SASL_LIBS) $(KRB_LIBS) $(TLS_LIBS) $(AUTH_LIBS)
ICU_LIBS = 

MODULES_CPPFLAGS = 
MODULES_LDFLAGS = 
MODULES_LIBS = 
SLAPD_PERL_LDFLAGS = 

SLAPD_SQL_LDFLAGS = 
SLAPD_SQL_INCLUDES = 
SLAPD_SQL_LIBS = 

SLAPD_LIBS =  -luuid      $(ICU_LIBS)

# Our Defaults
CC = $(AC_CC)
DEFS = $(LDAP_INCPATH) $(XINCPATH) $(XDEFS) $(AC_DEFS) $(DEFINES)
CFLAGS = $(AC_CFLAGS) $(DEFS)
LDFLAGS = $(LDAP_LIBPATH) $(AC_LDFLAGS) $(XLDFLAGS)
LIBS = $(XLIBS) $(XXLIBS) $(AC_LIBS) $(XXXLIBS)

LT_CFLAGS = $(AC_CFLAGS)
LT_CPPFLAGS = $(DEFS)

all:		all-common all-local FORCE
install:	install-common install-local FORCE
clean:		clean-common clean-local FORCE
veryclean:	veryclean-common veryclean-local FORCE
depend:		depend-common depend-local FORCE

# empty common rules
all-common:
install-common:
clean-common:
veryclean-common:	clean-common FORCE
depend-common:
lint-common:
lint5-common:

# empty local rules
all-local:
install-local:
clean-local:
veryclean-local:	clean-local FORCE
depend-local:
lint-local:
lint5-local:

veryclean: FORCE
	$(RM) Makefile
	$(RM) -r .libs

Makefile: Makefile.in $(top_srcdir)/build/top.mk

pathtest:
	$(SHTOOL) --version

# empty rule for forcing rules
FORCE:

##---------------------------------------------------------------------------

# Makefile for -llutil
# $OpenLDAP: pkg/ldap/libraries/liblutil/Makefile.in,v 1.38.2.7 2010/04/19 16:53:01 quanah Exp $
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
## 
## Copyright 1998-2010 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.

LIBRARY	= liblutil.a
PROGRAM = testavl

LDAP_INCDIR= ../../include       
LDAP_LIBDIR= ../../libraries

NT_SRCS = ntservice.c
NT_OBJS = ntservice.o slapdmsg.res

UNIX_SRCS = detach.c
UNIX_OBJS = detach.o

XLIBS = $(LIBRARY) $(LDAP_LIBLBER_LA)

SRCS	= base64.c entropy.c sasl.c signal.c hash.c passfile.c \
	md5.c passwd.c sha1.c getpass.c lockf.c utils.c uuid.c sockpair.c \
	avl.c tavl.c ldif.c fetch.c \
	testavl.c \
	meter.c \
	 setproctitle.c getpeereid.c $(UNIX_SRCS)

OBJS	= base64.o entropy.o sasl.o signal.o hash.o passfile.o \
	md5.o passwd.o sha1.o getpass.o lockf.o utils.o uuid.o sockpair.o \
	avl.o tavl.o ldif.o fetch.o \
	meter.o \
	 ${LIBOBJDIR}setproctitle$U.o ${LIBOBJDIR}getpeereid$U.o $(UNIX_OBJS)

testavl: $(XLIBS) testavl.o
	(LTLINK) -o $@ testavl.o $(LIBS)

testtavl: $(XLIBS) testtavl.o
	(LTLINK) -o $@ testtavl.o $(LIBS)

# These rules are for a Mingw32 build, specifically.
# It's ok for them to be here because the clean rule is harmless, and
# slapdmsg.res won't get built unless it's declared in OBJS.

slapdmsg.bin: FORCE
	@if [ ! -f $@ ]; then cp $(srcdir)/$@ .; fi

slapdmsg.res: slapdmsg.rc slapdmsg.bin
	windres $< -O coff -o $@

clean-local:
	$(RM) *.res

# $OpenLDAP: pkg/ldap/build/lib.mk,v 1.23.2.6 2010/04/13 20:22:20 kurt Exp $
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2010 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.
##---------------------------------------------------------------------------
#
# Makefile Template for Libraries
#

all-common: $(LIBRARY) $(PROGRAMS)

version.c: Makefile
	$(RM) $@
	$(MKVERSION) $(LIBRARY) > $@

version.o version.lo: version.c $(OBJS)

install-common: FORCE

lint: lint-local FORCE
	$(LINT) $(DEFS) $(DEFINES) $(SRCS)

lint5: lint5-local FORCE
	$(5LINT) $(DEFS) $(DEFINES) $(SRCS)

#
# In the mingw/cygwin environment, the so and dll files must be
# deleted separately, instead of using the {.so*,*.dll} construct
# that was previously used. It just didn't work.
#
clean-common: 	FORCE
	$(RM) $(LIBRARY) ../$(LIBRARY) $(XLIBRARY) \
		$(PROGRAMS) $(XPROGRAMS) $(XSRCS) $(XXSRCS) \
		*.o *.lo a.out *.exe core version.c .libs/*

depend-common: FORCE
	$(MKDEP) $(DEFS) $(DEFINES) $(SRCS) $(XXSRCS)

lint-local: FORCE
lint5-local: FORCE

Makefile: $(top_srcdir)/build/lib.mk

# $OpenLDAP: pkg/ldap/build/lib-static.mk,v 1.13.2.5 2010/04/13 20:22:20 kurt Exp $
## This work is part of OpenLDAP Software <http://www.openldap.org/>.
##
## Copyright 1998-2010 The OpenLDAP Foundation.
## All rights reserved.
##
## Redistribution and use in source and binary forms, with or without
## modification, are permitted only as authorized by the OpenLDAP
## Public License.
##
## A copy of this license is available in the file LICENSE in the
## top-level directory of the distribution or, alternatively, at
## <http://www.OpenLDAP.org/license.html>.
##---------------------------------------------------------------------------
#
# Makefile Template for Static Libraries
#

$(LIBRARY): version.o
	$(AR) ru $@ $(OBJS) version.o
	@$(RANLIB) $@

Makefile: $(top_srcdir)/build/lib-static.mk
# DO NOT DELETE THIS LINE -- mkdep uses it.
# DO NOT PUT ANYTHING AFTER THIS LINE, IT WILL GO AWAY.


#
# files: -I../../include -I../../include base64.c entropy.c sasl.c signal.c hash.c passfile.c md5.c passwd.c sha1.c getpass.c lockf.c utils.c uuid.c sockpair.c avl.c tavl.c ldif.c fetch.c testavl.c meter.c setproctitle.c getpeereid.c detach.c
# command: cc -M -I.  -I../../include -I../../include base64.c entropy.c sasl.c signal.c hash.c passfile.c md5.c passwd.c sha1.c getpass.c lockf.c utils.c uuid.c sockpair.c avl.c tavl.c ldif.c fetch.c testavl.c meter.c setproctitle.c getpeereid.c detach.c
#

base64.o: base64.c
base64.o: ../../include/portable.h
base64.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
base64.o: ../../include/ac/fdset.h
base64.o: /usr/include/bits/types.h
base64.o: /usr/include/features.h
base64.o: /usr/include/sys/cdefs.h
base64.o: /usr/include/bits/wordsize.h
base64.o: /usr/include/gnu/stubs.h
base64.o: /usr/include/gnu/stubs-64.h
base64.o: /usr/include/bits/typesizes.h
base64.o: ../../include/ldap_cdefs.h
base64.o: ../../include/ldap_features.h
base64.o: ../../include/ac/assert.h
base64.o: /usr/include/assert.h
base64.o: ../../include/ac/localize.h
base64.o: ../../include/ac/assert.h
base64.o: ../../include/ac/stdlib.h
base64.o: /usr/include/stdlib.h
base64.o: /usr/include/sys/types.h
base64.o: /usr/include/time.h
base64.o: /usr/include/endian.h
base64.o: /usr/include/bits/endian.h
base64.o: /usr/include/sys/select.h
base64.o: /usr/include/bits/select.h
base64.o: /usr/include/bits/sigset.h
base64.o: /usr/include/bits/time.h
base64.o: /usr/include/sys/sysmacros.h
base64.o: /usr/include/bits/pthreadtypes.h
base64.o: /usr/include/alloca.h
base64.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
base64.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
base64.o: /usr/include/limits.h
base64.o: /usr/include/bits/posix1_lim.h
base64.o: /usr/include/bits/local_lim.h
base64.o: /usr/include/linux/limits.h
base64.o: /usr/include/bits/posix2_lim.h
base64.o: ../../include/ac/ctype.h
base64.o: /usr/include/ctype.h
base64.o: ../../include/ac/string.h
base64.o: /usr/include/string.h
base64.o: ../../include/ac/socket.h
base64.o: /usr/include/poll.h
base64.o: /usr/include/sys/poll.h
base64.o: /usr/include/bits/poll.h
base64.o: /usr/include/sys/socket.h
base64.o: /usr/include/sys/uio.h
base64.o: /usr/include/bits/uio.h
base64.o: /usr/include/bits/socket.h
base64.o: /usr/include/bits/sockaddr.h
base64.o: /usr/include/asm/socket.h
base64.o: /usr/include/asm-x86_64/socket.h
base64.o: /usr/include/asm/sockios.h
base64.o: /usr/include/asm-x86_64/sockios.h
base64.o: /usr/include/sys/un.h
base64.o: /usr/include/netinet/in.h
base64.o: /usr/include/stdint.h
base64.o: /usr/include/bits/wchar.h
base64.o: /usr/include/bits/in.h
base64.o: /usr/include/bits/byteswap.h
base64.o: /usr/include/netinet/tcp.h
base64.o: /usr/include/arpa/inet.h
base64.o: /usr/include/arpa/nameser.h
base64.o: /usr/include/sys/param.h
base64.o: /usr/include/linux/param.h
base64.o: /usr/include/asm/param.h
base64.o: /usr/include/asm-x86_64/param.h
base64.o: /usr/include/sys/bitypes.h
base64.o: /usr/include/arpa/nameser_compat.h
base64.o: /usr/include/netdb.h
base64.o: /usr/include/rpc/netdb.h
base64.o: /usr/include/bits/netdb.h
base64.o: /usr/include/resolv.h
base64.o: /usr/include/stdio.h
base64.o: /usr/include/libio.h
base64.o: /usr/include/_G_config.h
base64.o: /usr/include/wchar.h
base64.o: /usr/include/gconv.h
base64.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
base64.o: /usr/include/bits/stdio_lim.h
base64.o: /usr/include/bits/sys_errlist.h
base64.o: ../../include/lutil.h
base64.o: ../../include/ldap_cdefs.h
base64.o: ../../include/lber_types.h
entropy.o: entropy.c
entropy.o: ../../include/portable.h
entropy.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
entropy.o: ../../include/ac/fdset.h
entropy.o: /usr/include/bits/types.h
entropy.o: /usr/include/features.h
entropy.o: /usr/include/sys/cdefs.h
entropy.o: /usr/include/bits/wordsize.h
entropy.o: /usr/include/gnu/stubs.h
entropy.o: /usr/include/gnu/stubs-64.h
entropy.o: /usr/include/bits/typesizes.h
entropy.o: ../../include/ldap_cdefs.h
entropy.o: ../../include/ldap_features.h
entropy.o: ../../include/ac/assert.h
entropy.o: /usr/include/assert.h
entropy.o: ../../include/ac/localize.h
entropy.o: ../../include/ac/string.h
entropy.o: /usr/include/string.h
entropy.o: ../../include/ac/time.h
entropy.o: /usr/include/sys/time.h
entropy.o: /usr/include/time.h
entropy.o: /usr/include/bits/time.h
entropy.o: /usr/include/sys/select.h
entropy.o: /usr/include/bits/select.h
entropy.o: /usr/include/bits/sigset.h
entropy.o: ../../include/ac/unistd.h
entropy.o: /usr/include/sys/types.h
entropy.o: /usr/include/endian.h
entropy.o: /usr/include/bits/endian.h
entropy.o: /usr/include/sys/sysmacros.h
entropy.o: /usr/include/bits/pthreadtypes.h
entropy.o: /usr/include/unistd.h
entropy.o: /usr/include/bits/posix_opt.h
entropy.o: /usr/include/bits/confname.h
entropy.o: /usr/include/getopt.h
entropy.o: ../../include/lutil_lockf.h
entropy.o: /usr/include/fcntl.h
entropy.o: /usr/include/bits/fcntl.h
entropy.o: ../../include/lutil.h
entropy.o: ../../include/ldap_cdefs.h
entropy.o: ../../include/lber_types.h
entropy.o: ../../include/lutil_md5.h
sasl.o: sasl.c
sasl.o: ../../include/portable.h
sasl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
sasl.o: ../../include/ac/fdset.h
sasl.o: /usr/include/bits/types.h
sasl.o: /usr/include/features.h
sasl.o: /usr/include/sys/cdefs.h
sasl.o: /usr/include/bits/wordsize.h
sasl.o: /usr/include/gnu/stubs.h
sasl.o: /usr/include/gnu/stubs-64.h
sasl.o: /usr/include/bits/typesizes.h
sasl.o: ../../include/ldap_cdefs.h
sasl.o: ../../include/ldap_features.h
sasl.o: ../../include/ac/assert.h
sasl.o: /usr/include/assert.h
sasl.o: ../../include/ac/localize.h
sasl.o: /usr/include/stdio.h
sasl.o: /usr/include/libio.h
sasl.o: /usr/include/_G_config.h
sasl.o: /usr/include/wchar.h
sasl.o: /usr/include/bits/wchar.h
sasl.o: /usr/include/gconv.h
sasl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
sasl.o: /usr/include/bits/stdio_lim.h
sasl.o: /usr/include/bits/sys_errlist.h
sasl.o: ../../include/ac/stdlib.h
sasl.o: /usr/include/stdlib.h
sasl.o: /usr/include/sys/types.h
sasl.o: /usr/include/time.h
sasl.o: /usr/include/endian.h
sasl.o: /usr/include/bits/endian.h
sasl.o: /usr/include/sys/select.h
sasl.o: /usr/include/bits/select.h
sasl.o: /usr/include/bits/sigset.h
sasl.o: /usr/include/bits/time.h
sasl.o: /usr/include/sys/sysmacros.h
sasl.o: /usr/include/bits/pthreadtypes.h
sasl.o: /usr/include/alloca.h
sasl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
sasl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
sasl.o: /usr/include/limits.h
sasl.o: /usr/include/bits/posix1_lim.h
sasl.o: /usr/include/bits/local_lim.h
sasl.o: /usr/include/linux/limits.h
sasl.o: /usr/include/bits/posix2_lim.h
sasl.o: ../../include/ac/string.h
sasl.o: /usr/include/string.h
sasl.o: ../../include/ac/unistd.h
sasl.o: /usr/include/unistd.h
sasl.o: /usr/include/bits/posix_opt.h
sasl.o: /usr/include/bits/confname.h
sasl.o: /usr/include/getopt.h
sasl.o: ../../include/lutil_lockf.h
sasl.o: /usr/include/sasl/sasl.h
sasl.o: /usr/include/sasl/prop.h
sasl.o: ../../include/ldap.h
sasl.o: ../../include/lber.h
sasl.o: ../../include/lber_types.h
sasl.o: ../../include/ldap_cdefs.h
sasl.o: ../../include/ldap_features.h
sasl.o: ../../include/ldap_pvt.h
sasl.o: ../../include/lber_pvt.h
sasl.o: ../../include/ldap_pvt_uc.h
sasl.o: ../../include/ac/bytes.h
sasl.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
sasl.o: ../../include/lutil_ldap.h
signal.o: signal.c
signal.o: ../../include/portable.h
signal.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
signal.o: ../../include/ac/fdset.h
signal.o: /usr/include/bits/types.h
signal.o: /usr/include/features.h
signal.o: /usr/include/sys/cdefs.h
signal.o: /usr/include/bits/wordsize.h
signal.o: /usr/include/gnu/stubs.h
signal.o: /usr/include/gnu/stubs-64.h
signal.o: /usr/include/bits/typesizes.h
signal.o: ../../include/ldap_cdefs.h
signal.o: ../../include/ldap_features.h
signal.o: ../../include/ac/assert.h
signal.o: /usr/include/assert.h
signal.o: ../../include/ac/localize.h
signal.o: ../../include/ac/string.h
signal.o: /usr/include/string.h
signal.o: ../../include/ac/signal.h
signal.o: /usr/include/signal.h
signal.o: /usr/include/bits/sigset.h
signal.o: /usr/include/bits/signum.h
signal.o: /usr/include/time.h
signal.o: /usr/include/bits/siginfo.h
signal.o: /usr/include/bits/sigaction.h
signal.o: /usr/include/bits/sigcontext.h
signal.o: /usr/include/bits/sigstack.h
signal.o: /usr/include/bits/pthreadtypes.h
signal.o: /usr/include/bits/sigthread.h
hash.o: hash.c
hash.o: ../../include/portable.h
hash.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
hash.o: ../../include/ac/fdset.h
hash.o: /usr/include/bits/types.h
hash.o: /usr/include/features.h
hash.o: /usr/include/sys/cdefs.h
hash.o: /usr/include/bits/wordsize.h
hash.o: /usr/include/gnu/stubs.h
hash.o: /usr/include/gnu/stubs-64.h
hash.o: /usr/include/bits/typesizes.h
hash.o: ../../include/ldap_cdefs.h
hash.o: ../../include/ldap_features.h
hash.o: ../../include/ac/assert.h
hash.o: /usr/include/assert.h
hash.o: ../../include/ac/localize.h
hash.o: ../../include/lutil_hash.h
hash.o: ../../include/lber_types.h
hash.o: ../../include/ldap_cdefs.h
passfile.o: passfile.c
passfile.o: ../../include/portable.h
passfile.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
passfile.o: ../../include/ac/fdset.h
passfile.o: /usr/include/bits/types.h
passfile.o: /usr/include/features.h
passfile.o: /usr/include/sys/cdefs.h
passfile.o: /usr/include/bits/wordsize.h
passfile.o: /usr/include/gnu/stubs.h
passfile.o: /usr/include/gnu/stubs-64.h
passfile.o: /usr/include/bits/typesizes.h
passfile.o: ../../include/ldap_cdefs.h
passfile.o: ../../include/ldap_features.h
passfile.o: ../../include/ac/assert.h
passfile.o: /usr/include/assert.h
passfile.o: ../../include/ac/localize.h
passfile.o: /usr/include/stdio.h
passfile.o: /usr/include/libio.h
passfile.o: /usr/include/_G_config.h
passfile.o: /usr/include/wchar.h
passfile.o: /usr/include/bits/wchar.h
passfile.o: /usr/include/gconv.h
passfile.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
passfile.o: /usr/include/bits/stdio_lim.h
passfile.o: /usr/include/bits/sys_errlist.h
passfile.o: ../../include/ac/stdlib.h
passfile.o: /usr/include/stdlib.h
passfile.o: /usr/include/sys/types.h
passfile.o: /usr/include/time.h
passfile.o: /usr/include/endian.h
passfile.o: /usr/include/bits/endian.h
passfile.o: /usr/include/sys/select.h
passfile.o: /usr/include/bits/select.h
passfile.o: /usr/include/bits/sigset.h
passfile.o: /usr/include/bits/time.h
passfile.o: /usr/include/sys/sysmacros.h
passfile.o: /usr/include/bits/pthreadtypes.h
passfile.o: /usr/include/alloca.h
passfile.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
passfile.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
passfile.o: /usr/include/limits.h
passfile.o: /usr/include/bits/posix1_lim.h
passfile.o: /usr/include/bits/local_lim.h
passfile.o: /usr/include/linux/limits.h
passfile.o: /usr/include/bits/posix2_lim.h
passfile.o: ../../include/ac/ctype.h
passfile.o: /usr/include/ctype.h
passfile.o: ../../include/ac/string.h
passfile.o: /usr/include/string.h
passfile.o: /usr/include/sys/stat.h
passfile.o: /usr/include/bits/stat.h
passfile.o: ../../include/lber.h
passfile.o: ../../include/lber_types.h
passfile.o: ../../include/ldap_cdefs.h
passfile.o: ../../include/lutil.h
md5.o: md5.c
md5.o: ../../include/portable.h
md5.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
md5.o: ../../include/ac/fdset.h
md5.o: /usr/include/bits/types.h
md5.o: /usr/include/features.h
md5.o: /usr/include/sys/cdefs.h
md5.o: /usr/include/bits/wordsize.h
md5.o: /usr/include/gnu/stubs.h
md5.o: /usr/include/gnu/stubs-64.h
md5.o: /usr/include/bits/typesizes.h
md5.o: ../../include/ldap_cdefs.h
md5.o: ../../include/ldap_features.h
md5.o: ../../include/ac/assert.h
md5.o: /usr/include/assert.h
md5.o: ../../include/ac/localize.h
md5.o: ../../include/ac/string.h
md5.o: /usr/include/string.h
md5.o: ../../include/ac/socket.h
md5.o: /usr/include/sys/types.h
md5.o: /usr/include/time.h
md5.o: /usr/include/endian.h
md5.o: /usr/include/bits/endian.h
md5.o: /usr/include/sys/select.h
md5.o: /usr/include/bits/select.h
md5.o: /usr/include/bits/sigset.h
md5.o: /usr/include/bits/time.h
md5.o: /usr/include/sys/sysmacros.h
md5.o: /usr/include/bits/pthreadtypes.h
md5.o: /usr/include/poll.h
md5.o: /usr/include/sys/poll.h
md5.o: /usr/include/bits/poll.h
md5.o: /usr/include/sys/socket.h
md5.o: /usr/include/sys/uio.h
md5.o: /usr/include/bits/uio.h
md5.o: /usr/include/bits/socket.h
md5.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
md5.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
md5.o: /usr/include/limits.h
md5.o: /usr/include/bits/posix1_lim.h
md5.o: /usr/include/bits/local_lim.h
md5.o: /usr/include/linux/limits.h
md5.o: /usr/include/bits/posix2_lim.h
md5.o: /usr/include/bits/sockaddr.h
md5.o: /usr/include/asm/socket.h
md5.o: /usr/include/asm-x86_64/socket.h
md5.o: /usr/include/asm/sockios.h
md5.o: /usr/include/asm-x86_64/sockios.h
md5.o: /usr/include/sys/un.h
md5.o: /usr/include/netinet/in.h
md5.o: /usr/include/stdint.h
md5.o: /usr/include/bits/wchar.h
md5.o: /usr/include/bits/in.h
md5.o: /usr/include/bits/byteswap.h
md5.o: /usr/include/netinet/tcp.h
md5.o: /usr/include/arpa/inet.h
md5.o: /usr/include/arpa/nameser.h
md5.o: /usr/include/sys/param.h
md5.o: /usr/include/linux/param.h
md5.o: /usr/include/asm/param.h
md5.o: /usr/include/asm-x86_64/param.h
md5.o: /usr/include/sys/bitypes.h
md5.o: /usr/include/arpa/nameser_compat.h
md5.o: /usr/include/netdb.h
md5.o: /usr/include/rpc/netdb.h
md5.o: /usr/include/bits/netdb.h
md5.o: /usr/include/resolv.h
md5.o: /usr/include/stdio.h
md5.o: /usr/include/libio.h
md5.o: /usr/include/_G_config.h
md5.o: /usr/include/wchar.h
md5.o: /usr/include/gconv.h
md5.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
md5.o: /usr/include/bits/stdio_lim.h
md5.o: /usr/include/bits/sys_errlist.h
md5.o: ../../include/lutil_md5.h
md5.o: ../../include/lber_types.h
md5.o: ../../include/ldap_cdefs.h
passwd.o: passwd.c
passwd.o: ../../include/portable.h
passwd.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
passwd.o: ../../include/ac/fdset.h
passwd.o: /usr/include/bits/types.h
passwd.o: /usr/include/features.h
passwd.o: /usr/include/sys/cdefs.h
passwd.o: /usr/include/bits/wordsize.h
passwd.o: /usr/include/gnu/stubs.h
passwd.o: /usr/include/gnu/stubs-64.h
passwd.o: /usr/include/bits/typesizes.h
passwd.o: ../../include/ldap_cdefs.h
passwd.o: ../../include/ldap_features.h
passwd.o: ../../include/ac/assert.h
passwd.o: /usr/include/assert.h
passwd.o: ../../include/ac/localize.h
passwd.o: /usr/include/stdio.h
passwd.o: /usr/include/libio.h
passwd.o: /usr/include/_G_config.h
passwd.o: /usr/include/wchar.h
passwd.o: /usr/include/bits/wchar.h
passwd.o: /usr/include/gconv.h
passwd.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
passwd.o: /usr/include/bits/stdio_lim.h
passwd.o: /usr/include/bits/sys_errlist.h
passwd.o: ../../include/ac/stdlib.h
passwd.o: /usr/include/stdlib.h
passwd.o: /usr/include/sys/types.h
passwd.o: /usr/include/time.h
passwd.o: /usr/include/endian.h
passwd.o: /usr/include/bits/endian.h
passwd.o: /usr/include/sys/select.h
passwd.o: /usr/include/bits/select.h
passwd.o: /usr/include/bits/sigset.h
passwd.o: /usr/include/bits/time.h
passwd.o: /usr/include/sys/sysmacros.h
passwd.o: /usr/include/bits/pthreadtypes.h
passwd.o: /usr/include/alloca.h
passwd.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
passwd.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
passwd.o: /usr/include/limits.h
passwd.o: /usr/include/bits/posix1_lim.h
passwd.o: /usr/include/bits/local_lim.h
passwd.o: /usr/include/linux/limits.h
passwd.o: /usr/include/bits/posix2_lim.h
passwd.o: ../../include/ac/string.h
passwd.o: /usr/include/string.h
passwd.o: ../../include/ac/unistd.h
passwd.o: /usr/include/unistd.h
passwd.o: /usr/include/bits/posix_opt.h
passwd.o: /usr/include/bits/confname.h
passwd.o: /usr/include/getopt.h
passwd.o: ../../include/lutil_lockf.h
passwd.o: ../../include/ac/param.h
passwd.o: /usr/include/sys/param.h
passwd.o: /usr/include/linux/param.h
passwd.o: /usr/include/asm/param.h
passwd.o: /usr/include/asm-x86_64/param.h
passwd.o: ../../include/lber.h
passwd.o: ../../include/lber_types.h
passwd.o: ../../include/ldap_cdefs.h
passwd.o: ../../include/ldap_pvt.h
passwd.o: ../../include/lber_pvt.h
passwd.o: ../../include/ldap_pvt_uc.h
passwd.o: ../../include/ac/bytes.h
passwd.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
passwd.o: ../../include/lutil_md5.h
passwd.o: ../../include/lutil_sha1.h
passwd.o: ../../include/lutil.h
sha1.o: sha1.c
sha1.o: ../../include/portable.h
sha1.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
sha1.o: ../../include/ac/fdset.h
sha1.o: /usr/include/bits/types.h
sha1.o: /usr/include/features.h
sha1.o: /usr/include/sys/cdefs.h
sha1.o: /usr/include/bits/wordsize.h
sha1.o: /usr/include/gnu/stubs.h
sha1.o: /usr/include/gnu/stubs-64.h
sha1.o: /usr/include/bits/typesizes.h
sha1.o: ../../include/ldap_cdefs.h
sha1.o: ../../include/ldap_features.h
sha1.o: ../../include/ac/assert.h
sha1.o: /usr/include/assert.h
sha1.o: ../../include/ac/localize.h
sha1.o: ../../include/ac/param.h
sha1.o: /usr/include/sys/param.h
sha1.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
sha1.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
sha1.o: /usr/include/limits.h
sha1.o: /usr/include/bits/posix1_lim.h
sha1.o: /usr/include/bits/local_lim.h
sha1.o: /usr/include/linux/limits.h
sha1.o: /usr/include/bits/posix2_lim.h
sha1.o: /usr/include/linux/param.h
sha1.o: /usr/include/asm/param.h
sha1.o: /usr/include/asm-x86_64/param.h
sha1.o: /usr/include/sys/types.h
sha1.o: /usr/include/time.h
sha1.o: /usr/include/endian.h
sha1.o: /usr/include/bits/endian.h
sha1.o: /usr/include/sys/select.h
sha1.o: /usr/include/bits/select.h
sha1.o: /usr/include/bits/sigset.h
sha1.o: /usr/include/bits/time.h
sha1.o: /usr/include/sys/sysmacros.h
sha1.o: /usr/include/bits/pthreadtypes.h
sha1.o: ../../include/ac/unistd.h
sha1.o: /usr/include/unistd.h
sha1.o: /usr/include/bits/posix_opt.h
sha1.o: /usr/include/bits/confname.h
sha1.o: /usr/include/getopt.h
sha1.o: ../../include/lutil_lockf.h
sha1.o: ../../include/ac/string.h
sha1.o: /usr/include/string.h
sha1.o: ../../include/ac/socket.h
sha1.o: /usr/include/poll.h
sha1.o: /usr/include/sys/poll.h
sha1.o: /usr/include/bits/poll.h
sha1.o: /usr/include/sys/socket.h
sha1.o: /usr/include/sys/uio.h
sha1.o: /usr/include/bits/uio.h
sha1.o: /usr/include/bits/socket.h
sha1.o: /usr/include/bits/sockaddr.h
sha1.o: /usr/include/asm/socket.h
sha1.o: /usr/include/asm-x86_64/socket.h
sha1.o: /usr/include/asm/sockios.h
sha1.o: /usr/include/asm-x86_64/sockios.h
sha1.o: /usr/include/sys/un.h
sha1.o: /usr/include/netinet/in.h
sha1.o: /usr/include/stdint.h
sha1.o: /usr/include/bits/wchar.h
sha1.o: /usr/include/bits/in.h
sha1.o: /usr/include/bits/byteswap.h
sha1.o: /usr/include/netinet/tcp.h
sha1.o: /usr/include/arpa/inet.h
sha1.o: /usr/include/arpa/nameser.h
sha1.o: /usr/include/sys/bitypes.h
sha1.o: /usr/include/arpa/nameser_compat.h
sha1.o: /usr/include/netdb.h
sha1.o: /usr/include/rpc/netdb.h
sha1.o: /usr/include/bits/netdb.h
sha1.o: /usr/include/resolv.h
sha1.o: /usr/include/stdio.h
sha1.o: /usr/include/libio.h
sha1.o: /usr/include/_G_config.h
sha1.o: /usr/include/wchar.h
sha1.o: /usr/include/gconv.h
sha1.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
sha1.o: /usr/include/bits/stdio_lim.h
sha1.o: /usr/include/bits/sys_errlist.h
sha1.o: ../../include/ac/bytes.h
sha1.o: ../../include/lutil_sha1.h
sha1.o: ../../include/ldap_cdefs.h
sha1.o: ../../include/ac/stdlib.h
sha1.o: /usr/include/stdlib.h
sha1.o: /usr/include/alloca.h
sha1.o: ../../include/ac/errno.h
sha1.o: /usr/include/errno.h
sha1.o: /usr/include/bits/errno.h
sha1.o: /usr/include/linux/errno.h
sha1.o: /usr/include/asm/errno.h
sha1.o: /usr/include/asm-x86_64/errno.h
sha1.o: /usr/include/asm-generic/errno.h
sha1.o: /usr/include/asm-generic/errno-base.h
sha1.o: /usr/include/sys/file.h
sha1.o: /usr/include/fcntl.h
sha1.o: /usr/include/bits/fcntl.h
getpass.o: getpass.c
getpass.o: ../../include/portable.h
getpass.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
getpass.o: ../../include/ac/fdset.h
getpass.o: /usr/include/bits/types.h
getpass.o: /usr/include/features.h
getpass.o: /usr/include/sys/cdefs.h
getpass.o: /usr/include/bits/wordsize.h
getpass.o: /usr/include/gnu/stubs.h
getpass.o: /usr/include/gnu/stubs-64.h
getpass.o: /usr/include/bits/typesizes.h
getpass.o: ../../include/ldap_cdefs.h
getpass.o: ../../include/ldap_features.h
getpass.o: ../../include/ac/assert.h
getpass.o: /usr/include/assert.h
getpass.o: ../../include/ac/localize.h
getpass.o: /usr/include/stdio.h
getpass.o: /usr/include/libio.h
getpass.o: /usr/include/_G_config.h
getpass.o: /usr/include/wchar.h
getpass.o: /usr/include/bits/wchar.h
getpass.o: /usr/include/gconv.h
getpass.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
getpass.o: /usr/include/bits/stdio_lim.h
getpass.o: /usr/include/bits/sys_errlist.h
getpass.o: ../../include/ac/stdlib.h
getpass.o: /usr/include/stdlib.h
getpass.o: /usr/include/sys/types.h
getpass.o: /usr/include/time.h
getpass.o: /usr/include/endian.h
getpass.o: /usr/include/bits/endian.h
getpass.o: /usr/include/sys/select.h
getpass.o: /usr/include/bits/select.h
getpass.o: /usr/include/bits/sigset.h
getpass.o: /usr/include/bits/time.h
getpass.o: /usr/include/sys/sysmacros.h
getpass.o: /usr/include/bits/pthreadtypes.h
getpass.o: /usr/include/alloca.h
getpass.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
getpass.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
getpass.o: /usr/include/limits.h
getpass.o: /usr/include/bits/posix1_lim.h
getpass.o: /usr/include/bits/local_lim.h
getpass.o: /usr/include/linux/limits.h
getpass.o: /usr/include/bits/posix2_lim.h
getpass.o: ../../include/ac/ctype.h
getpass.o: /usr/include/ctype.h
getpass.o: ../../include/ac/signal.h
getpass.o: /usr/include/signal.h
getpass.o: /usr/include/bits/signum.h
getpass.o: /usr/include/bits/siginfo.h
getpass.o: /usr/include/bits/sigaction.h
getpass.o: /usr/include/bits/sigcontext.h
getpass.o: /usr/include/bits/sigstack.h
getpass.o: /usr/include/bits/sigthread.h
getpass.o: ../../include/ac/string.h
getpass.o: /usr/include/string.h
getpass.o: ../../include/ac/termios.h
getpass.o: /usr/include/termios.h
getpass.o: /usr/include/bits/termios.h
getpass.o: /usr/include/sys/ttydefaults.h
getpass.o: ../../include/ac/time.h
getpass.o: /usr/include/sys/time.h
getpass.o: ../../include/ac/unistd.h
getpass.o: /usr/include/unistd.h
getpass.o: /usr/include/bits/posix_opt.h
getpass.o: /usr/include/bits/confname.h
getpass.o: /usr/include/getopt.h
getpass.o: ../../include/lutil_lockf.h
getpass.o: /usr/include/fcntl.h
getpass.o: /usr/include/bits/fcntl.h
getpass.o: ../../include/lber.h
getpass.o: ../../include/lber_types.h
getpass.o: ../../include/ldap_cdefs.h
getpass.o: ../../include/ldap.h
getpass.o: ../../include/ldap_features.h
getpass.o: ../../include/ldap_defaults.h
getpass.o: ../../include/ldap_config.h
lockf.o: lockf.c
lockf.o: ../../include/portable.h
lockf.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
lockf.o: ../../include/ac/fdset.h
lockf.o: /usr/include/bits/types.h
lockf.o: /usr/include/features.h
lockf.o: /usr/include/sys/cdefs.h
lockf.o: /usr/include/bits/wordsize.h
lockf.o: /usr/include/gnu/stubs.h
lockf.o: /usr/include/gnu/stubs-64.h
lockf.o: /usr/include/bits/typesizes.h
lockf.o: ../../include/ldap_cdefs.h
lockf.o: ../../include/ldap_features.h
lockf.o: ../../include/ac/assert.h
lockf.o: /usr/include/assert.h
lockf.o: ../../include/ac/localize.h
lockf.o: /usr/include/stdio.h
lockf.o: /usr/include/libio.h
lockf.o: /usr/include/_G_config.h
lockf.o: /usr/include/wchar.h
lockf.o: /usr/include/bits/wchar.h
lockf.o: /usr/include/gconv.h
lockf.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
lockf.o: /usr/include/bits/stdio_lim.h
lockf.o: /usr/include/bits/sys_errlist.h
lockf.o: ../../include/ac/unistd.h
lockf.o: /usr/include/sys/types.h
lockf.o: /usr/include/time.h
lockf.o: /usr/include/endian.h
lockf.o: /usr/include/bits/endian.h
lockf.o: /usr/include/sys/select.h
lockf.o: /usr/include/bits/select.h
lockf.o: /usr/include/bits/sigset.h
lockf.o: /usr/include/bits/time.h
lockf.o: /usr/include/sys/sysmacros.h
lockf.o: /usr/include/bits/pthreadtypes.h
lockf.o: /usr/include/unistd.h
lockf.o: /usr/include/bits/posix_opt.h
lockf.o: /usr/include/bits/confname.h
lockf.o: /usr/include/getopt.h
lockf.o: ../../include/lutil_lockf.h
utils.o: utils.c
utils.o: ../../include/portable.h
utils.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
utils.o: ../../include/ac/fdset.h
utils.o: /usr/include/bits/types.h
utils.o: /usr/include/features.h
utils.o: /usr/include/sys/cdefs.h
utils.o: /usr/include/bits/wordsize.h
utils.o: /usr/include/gnu/stubs.h
utils.o: /usr/include/gnu/stubs-64.h
utils.o: /usr/include/bits/typesizes.h
utils.o: ../../include/ldap_cdefs.h
utils.o: ../../include/ldap_features.h
utils.o: ../../include/ac/assert.h
utils.o: /usr/include/assert.h
utils.o: ../../include/ac/localize.h
utils.o: /usr/include/stdio.h
utils.o: /usr/include/libio.h
utils.o: /usr/include/_G_config.h
utils.o: /usr/include/wchar.h
utils.o: /usr/include/bits/wchar.h
utils.o: /usr/include/gconv.h
utils.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
utils.o: /usr/include/bits/stdio_lim.h
utils.o: /usr/include/bits/sys_errlist.h
utils.o: ../../include/ac/stdlib.h
utils.o: /usr/include/stdlib.h
utils.o: /usr/include/sys/types.h
utils.o: /usr/include/time.h
utils.o: /usr/include/endian.h
utils.o: /usr/include/bits/endian.h
utils.o: /usr/include/sys/select.h
utils.o: /usr/include/bits/select.h
utils.o: /usr/include/bits/sigset.h
utils.o: /usr/include/bits/time.h
utils.o: /usr/include/sys/sysmacros.h
utils.o: /usr/include/bits/pthreadtypes.h
utils.o: /usr/include/alloca.h
utils.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
utils.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
utils.o: /usr/include/limits.h
utils.o: /usr/include/bits/posix1_lim.h
utils.o: /usr/include/bits/local_lim.h
utils.o: /usr/include/linux/limits.h
utils.o: /usr/include/bits/posix2_lim.h
utils.o: ../../include/ac/stdarg.h
utils.o: ../../include/ac/string.h
utils.o: /usr/include/string.h
utils.o: ../../include/ac/ctype.h
utils.o: /usr/include/ctype.h
utils.o: ../../include/ac/unistd.h
utils.o: /usr/include/unistd.h
utils.o: /usr/include/bits/posix_opt.h
utils.o: /usr/include/bits/confname.h
utils.o: /usr/include/getopt.h
utils.o: ../../include/lutil_lockf.h
utils.o: ../../include/ac/time.h
utils.o: /usr/include/sys/time.h
utils.o: ../../include/ac/errno.h
utils.o: /usr/include/errno.h
utils.o: /usr/include/bits/errno.h
utils.o: /usr/include/linux/errno.h
utils.o: /usr/include/asm/errno.h
utils.o: /usr/include/asm-x86_64/errno.h
utils.o: /usr/include/asm-generic/errno.h
utils.o: /usr/include/asm-generic/errno-base.h
utils.o: /usr/include/fcntl.h
utils.o: /usr/include/bits/fcntl.h
utils.o: ../../include/lutil.h
utils.o: ../../include/ldap_cdefs.h
utils.o: ../../include/lber_types.h
utils.o: ../../include/ldap_defaults.h
utils.o: ../../include/ldap_config.h
utils.o: ../../include/ldap_pvt.h
utils.o: ../../include/lber.h
utils.o: ../../include/lber_pvt.h
utils.o: ../../include/ldap_pvt_uc.h
utils.o: ../../include/ac/bytes.h
utils.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
uuid.o: uuid.c
uuid.o: ../../include/portable.h
uuid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
uuid.o: ../../include/ac/fdset.h
uuid.o: /usr/include/bits/types.h
uuid.o: /usr/include/features.h
uuid.o: /usr/include/sys/cdefs.h
uuid.o: /usr/include/bits/wordsize.h
uuid.o: /usr/include/gnu/stubs.h
uuid.o: /usr/include/gnu/stubs-64.h
uuid.o: /usr/include/bits/typesizes.h
uuid.o: ../../include/ldap_cdefs.h
uuid.o: ../../include/ldap_features.h
uuid.o: ../../include/ac/assert.h
uuid.o: /usr/include/assert.h
uuid.o: ../../include/ac/localize.h
uuid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
uuid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
uuid.o: /usr/include/limits.h
uuid.o: /usr/include/bits/posix1_lim.h
uuid.o: /usr/include/bits/local_lim.h
uuid.o: /usr/include/linux/limits.h
uuid.o: /usr/include/bits/posix2_lim.h
uuid.o: /usr/include/stdio.h
uuid.o: /usr/include/libio.h
uuid.o: /usr/include/_G_config.h
uuid.o: /usr/include/wchar.h
uuid.o: /usr/include/bits/wchar.h
uuid.o: /usr/include/gconv.h
uuid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
uuid.o: /usr/include/bits/stdio_lim.h
uuid.o: /usr/include/bits/sys_errlist.h
uuid.o: /usr/include/sys/types.h
uuid.o: /usr/include/time.h
uuid.o: /usr/include/endian.h
uuid.o: /usr/include/bits/endian.h
uuid.o: /usr/include/sys/select.h
uuid.o: /usr/include/bits/select.h
uuid.o: /usr/include/bits/sigset.h
uuid.o: /usr/include/bits/time.h
uuid.o: /usr/include/sys/sysmacros.h
uuid.o: /usr/include/bits/pthreadtypes.h
uuid.o: ../../include/ac/stdlib.h
uuid.o: /usr/include/stdlib.h
uuid.o: /usr/include/alloca.h
uuid.o: ../../include/ac/string.h
uuid.o: /usr/include/string.h
uuid.o: /usr/include/uuid/uuid.h
uuid.o: /usr/include/sys/time.h
uuid.o: ../../include/lutil.h
uuid.o: ../../include/ldap_cdefs.h
uuid.o: ../../include/lber_types.h
sockpair.o: sockpair.c
sockpair.o: ../../include/portable.h
sockpair.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
sockpair.o: ../../include/ac/fdset.h
sockpair.o: /usr/include/bits/types.h
sockpair.o: /usr/include/features.h
sockpair.o: /usr/include/sys/cdefs.h
sockpair.o: /usr/include/bits/wordsize.h
sockpair.o: /usr/include/gnu/stubs.h
sockpair.o: /usr/include/gnu/stubs-64.h
sockpair.o: /usr/include/bits/typesizes.h
sockpair.o: ../../include/ldap_cdefs.h
sockpair.o: ../../include/ldap_features.h
sockpair.o: ../../include/ac/assert.h
sockpair.o: /usr/include/assert.h
sockpair.o: ../../include/ac/localize.h
sockpair.o: ../../include/ac/socket.h
sockpair.o: /usr/include/sys/types.h
sockpair.o: /usr/include/time.h
sockpair.o: /usr/include/endian.h
sockpair.o: /usr/include/bits/endian.h
sockpair.o: /usr/include/sys/select.h
sockpair.o: /usr/include/bits/select.h
sockpair.o: /usr/include/bits/sigset.h
sockpair.o: /usr/include/bits/time.h
sockpair.o: /usr/include/sys/sysmacros.h
sockpair.o: /usr/include/bits/pthreadtypes.h
sockpair.o: /usr/include/poll.h
sockpair.o: /usr/include/sys/poll.h
sockpair.o: /usr/include/bits/poll.h
sockpair.o: /usr/include/sys/socket.h
sockpair.o: /usr/include/sys/uio.h
sockpair.o: /usr/include/bits/uio.h
sockpair.o: /usr/include/bits/socket.h
sockpair.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
sockpair.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
sockpair.o: /usr/include/limits.h
sockpair.o: /usr/include/bits/posix1_lim.h
sockpair.o: /usr/include/bits/local_lim.h
sockpair.o: /usr/include/linux/limits.h
sockpair.o: /usr/include/bits/posix2_lim.h
sockpair.o: /usr/include/bits/sockaddr.h
sockpair.o: /usr/include/asm/socket.h
sockpair.o: /usr/include/asm-x86_64/socket.h
sockpair.o: /usr/include/asm/sockios.h
sockpair.o: /usr/include/asm-x86_64/sockios.h
sockpair.o: /usr/include/sys/un.h
sockpair.o: /usr/include/string.h
sockpair.o: /usr/include/netinet/in.h
sockpair.o: /usr/include/stdint.h
sockpair.o: /usr/include/bits/wchar.h
sockpair.o: /usr/include/bits/in.h
sockpair.o: /usr/include/bits/byteswap.h
sockpair.o: /usr/include/netinet/tcp.h
sockpair.o: /usr/include/arpa/inet.h
sockpair.o: /usr/include/arpa/nameser.h
sockpair.o: /usr/include/sys/param.h
sockpair.o: /usr/include/linux/param.h
sockpair.o: /usr/include/asm/param.h
sockpair.o: /usr/include/asm-x86_64/param.h
sockpair.o: /usr/include/sys/bitypes.h
sockpair.o: /usr/include/arpa/nameser_compat.h
sockpair.o: /usr/include/netdb.h
sockpair.o: /usr/include/rpc/netdb.h
sockpair.o: /usr/include/bits/netdb.h
sockpair.o: /usr/include/resolv.h
sockpair.o: /usr/include/stdio.h
sockpair.o: /usr/include/libio.h
sockpair.o: /usr/include/_G_config.h
sockpair.o: /usr/include/wchar.h
sockpair.o: /usr/include/gconv.h
sockpair.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
sockpair.o: /usr/include/bits/stdio_lim.h
sockpair.o: /usr/include/bits/sys_errlist.h
sockpair.o: ../../include/ac/unistd.h
sockpair.o: /usr/include/unistd.h
sockpair.o: /usr/include/bits/posix_opt.h
sockpair.o: /usr/include/bits/confname.h
sockpair.o: /usr/include/getopt.h
sockpair.o: ../../include/lutil_lockf.h
sockpair.o: ../../include/lutil.h
sockpair.o: ../../include/ldap_cdefs.h
sockpair.o: ../../include/lber_types.h
avl.o: avl.c
avl.o: ../../include/portable.h
avl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
avl.o: ../../include/ac/fdset.h
avl.o: /usr/include/bits/types.h
avl.o: /usr/include/features.h
avl.o: /usr/include/sys/cdefs.h
avl.o: /usr/include/bits/wordsize.h
avl.o: /usr/include/gnu/stubs.h
avl.o: /usr/include/gnu/stubs-64.h
avl.o: /usr/include/bits/typesizes.h
avl.o: ../../include/ldap_cdefs.h
avl.o: ../../include/ldap_features.h
avl.o: ../../include/ac/assert.h
avl.o: /usr/include/assert.h
avl.o: ../../include/ac/localize.h
avl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
avl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
avl.o: /usr/include/limits.h
avl.o: /usr/include/bits/posix1_lim.h
avl.o: /usr/include/bits/local_lim.h
avl.o: /usr/include/linux/limits.h
avl.o: /usr/include/bits/posix2_lim.h
avl.o: /usr/include/stdio.h
avl.o: /usr/include/libio.h
avl.o: /usr/include/_G_config.h
avl.o: /usr/include/wchar.h
avl.o: /usr/include/bits/wchar.h
avl.o: /usr/include/gconv.h
avl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
avl.o: /usr/include/bits/stdio_lim.h
avl.o: /usr/include/bits/sys_errlist.h
avl.o: ../../include/ac/stdlib.h
avl.o: /usr/include/stdlib.h
avl.o: /usr/include/sys/types.h
avl.o: /usr/include/time.h
avl.o: /usr/include/endian.h
avl.o: /usr/include/bits/endian.h
avl.o: /usr/include/sys/select.h
avl.o: /usr/include/bits/select.h
avl.o: /usr/include/bits/sigset.h
avl.o: /usr/include/bits/time.h
avl.o: /usr/include/sys/sysmacros.h
avl.o: /usr/include/bits/pthreadtypes.h
avl.o: /usr/include/alloca.h
avl.o: ../../include/lber.h
avl.o: ../../include/lber_types.h
avl.o: ../../include/ldap_cdefs.h
avl.o: /usr/include/string.h
avl.o: ../../include/avl.h
tavl.o: tavl.c
tavl.o: ../../include/portable.h
tavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
tavl.o: ../../include/ac/fdset.h
tavl.o: /usr/include/bits/types.h
tavl.o: /usr/include/features.h
tavl.o: /usr/include/sys/cdefs.h
tavl.o: /usr/include/bits/wordsize.h
tavl.o: /usr/include/gnu/stubs.h
tavl.o: /usr/include/gnu/stubs-64.h
tavl.o: /usr/include/bits/typesizes.h
tavl.o: ../../include/ldap_cdefs.h
tavl.o: ../../include/ldap_features.h
tavl.o: ../../include/ac/assert.h
tavl.o: /usr/include/assert.h
tavl.o: ../../include/ac/localize.h
tavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
tavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
tavl.o: /usr/include/limits.h
tavl.o: /usr/include/bits/posix1_lim.h
tavl.o: /usr/include/bits/local_lim.h
tavl.o: /usr/include/linux/limits.h
tavl.o: /usr/include/bits/posix2_lim.h
tavl.o: /usr/include/stdio.h
tavl.o: /usr/include/libio.h
tavl.o: /usr/include/_G_config.h
tavl.o: /usr/include/wchar.h
tavl.o: /usr/include/bits/wchar.h
tavl.o: /usr/include/gconv.h
tavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
tavl.o: /usr/include/bits/stdio_lim.h
tavl.o: /usr/include/bits/sys_errlist.h
tavl.o: ../../include/ac/stdlib.h
tavl.o: /usr/include/stdlib.h
tavl.o: /usr/include/sys/types.h
tavl.o: /usr/include/time.h
tavl.o: /usr/include/endian.h
tavl.o: /usr/include/bits/endian.h
tavl.o: /usr/include/sys/select.h
tavl.o: /usr/include/bits/select.h
tavl.o: /usr/include/bits/sigset.h
tavl.o: /usr/include/bits/time.h
tavl.o: /usr/include/sys/sysmacros.h
tavl.o: /usr/include/bits/pthreadtypes.h
tavl.o: /usr/include/alloca.h
tavl.o: ../../include/lber.h
tavl.o: ../../include/lber_types.h
tavl.o: ../../include/ldap_cdefs.h
tavl.o: /usr/include/string.h
tavl.o: ../../include/avl.h
ldif.o: ldif.c
ldif.o: ../../include/portable.h
ldif.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
ldif.o: ../../include/ac/fdset.h
ldif.o: /usr/include/bits/types.h
ldif.o: /usr/include/features.h
ldif.o: /usr/include/sys/cdefs.h
ldif.o: /usr/include/bits/wordsize.h
ldif.o: /usr/include/gnu/stubs.h
ldif.o: /usr/include/gnu/stubs-64.h
ldif.o: /usr/include/bits/typesizes.h
ldif.o: ../../include/ldap_cdefs.h
ldif.o: ../../include/ldap_features.h
ldif.o: ../../include/ac/assert.h
ldif.o: /usr/include/assert.h
ldif.o: ../../include/ac/localize.h
ldif.o: /usr/include/stdio.h
ldif.o: /usr/include/libio.h
ldif.o: /usr/include/_G_config.h
ldif.o: /usr/include/wchar.h
ldif.o: /usr/include/bits/wchar.h
ldif.o: /usr/include/gconv.h
ldif.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
ldif.o: /usr/include/bits/stdio_lim.h
ldif.o: /usr/include/bits/sys_errlist.h
ldif.o: ../../include/ac/stdlib.h
ldif.o: /usr/include/stdlib.h
ldif.o: /usr/include/sys/types.h
ldif.o: /usr/include/time.h
ldif.o: /usr/include/endian.h
ldif.o: /usr/include/bits/endian.h
ldif.o: /usr/include/sys/select.h
ldif.o: /usr/include/bits/select.h
ldif.o: /usr/include/bits/sigset.h
ldif.o: /usr/include/bits/time.h
ldif.o: /usr/include/sys/sysmacros.h
ldif.o: /usr/include/bits/pthreadtypes.h
ldif.o: /usr/include/alloca.h
ldif.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
ldif.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
ldif.o: /usr/include/limits.h
ldif.o: /usr/include/bits/posix1_lim.h
ldif.o: /usr/include/bits/local_lim.h
ldif.o: /usr/include/linux/limits.h
ldif.o: /usr/include/bits/posix2_lim.h
ldif.o: ../../include/ac/ctype.h
ldif.o: /usr/include/ctype.h
ldif.o: ../../include/ac/string.h
ldif.o: /usr/include/string.h
ldif.o: ../../include/ac/socket.h
ldif.o: /usr/include/poll.h
ldif.o: /usr/include/sys/poll.h
ldif.o: /usr/include/bits/poll.h
ldif.o: /usr/include/sys/socket.h
ldif.o: /usr/include/sys/uio.h
ldif.o: /usr/include/bits/uio.h
ldif.o: /usr/include/bits/socket.h
ldif.o: /usr/include/bits/sockaddr.h
ldif.o: /usr/include/asm/socket.h
ldif.o: /usr/include/asm-x86_64/socket.h
ldif.o: /usr/include/asm/sockios.h
ldif.o: /usr/include/asm-x86_64/sockios.h
ldif.o: /usr/include/sys/un.h
ldif.o: /usr/include/netinet/in.h
ldif.o: /usr/include/stdint.h
ldif.o: /usr/include/bits/in.h
ldif.o: /usr/include/bits/byteswap.h
ldif.o: /usr/include/netinet/tcp.h
ldif.o: /usr/include/arpa/inet.h
ldif.o: /usr/include/arpa/nameser.h
ldif.o: /usr/include/sys/param.h
ldif.o: /usr/include/linux/param.h
ldif.o: /usr/include/asm/param.h
ldif.o: /usr/include/asm-x86_64/param.h
ldif.o: /usr/include/sys/bitypes.h
ldif.o: /usr/include/arpa/nameser_compat.h
ldif.o: /usr/include/netdb.h
ldif.o: /usr/include/rpc/netdb.h
ldif.o: /usr/include/bits/netdb.h
ldif.o: /usr/include/resolv.h
ldif.o: ../../include/ac/time.h
ldif.o: /usr/include/sys/time.h
ldif.o: ../../include/ldap_log.h
ldif.o: ../../include/ldap_cdefs.h
ldif.o: ../../include/lber_pvt.h
ldif.o: ../../include/lber.h
ldif.o: ../../include/lber_types.h
ldif.o: ../../include/ldif.h
fetch.o: fetch.c
fetch.o: ../../include/portable.h
fetch.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
fetch.o: ../../include/ac/fdset.h
fetch.o: /usr/include/bits/types.h
fetch.o: /usr/include/features.h
fetch.o: /usr/include/sys/cdefs.h
fetch.o: /usr/include/bits/wordsize.h
fetch.o: /usr/include/gnu/stubs.h
fetch.o: /usr/include/gnu/stubs-64.h
fetch.o: /usr/include/bits/typesizes.h
fetch.o: ../../include/ldap_cdefs.h
fetch.o: ../../include/ldap_features.h
fetch.o: ../../include/ac/assert.h
fetch.o: /usr/include/assert.h
fetch.o: ../../include/ac/localize.h
fetch.o: /usr/include/stdio.h
fetch.o: /usr/include/libio.h
fetch.o: /usr/include/_G_config.h
fetch.o: /usr/include/wchar.h
fetch.o: /usr/include/bits/wchar.h
fetch.o: /usr/include/gconv.h
fetch.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
fetch.o: /usr/include/bits/stdio_lim.h
fetch.o: /usr/include/bits/sys_errlist.h
fetch.o: ../../include/ac/stdlib.h
fetch.o: /usr/include/stdlib.h
fetch.o: /usr/include/sys/types.h
fetch.o: /usr/include/time.h
fetch.o: /usr/include/endian.h
fetch.o: /usr/include/bits/endian.h
fetch.o: /usr/include/sys/select.h
fetch.o: /usr/include/bits/select.h
fetch.o: /usr/include/bits/sigset.h
fetch.o: /usr/include/bits/time.h
fetch.o: /usr/include/sys/sysmacros.h
fetch.o: /usr/include/bits/pthreadtypes.h
fetch.o: /usr/include/alloca.h
fetch.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
fetch.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
fetch.o: /usr/include/limits.h
fetch.o: /usr/include/bits/posix1_lim.h
fetch.o: /usr/include/bits/local_lim.h
fetch.o: /usr/include/linux/limits.h
fetch.o: /usr/include/bits/posix2_lim.h
fetch.o: ../../include/ac/string.h
fetch.o: /usr/include/string.h
fetch.o: ../../include/ac/socket.h
fetch.o: /usr/include/poll.h
fetch.o: /usr/include/sys/poll.h
fetch.o: /usr/include/bits/poll.h
fetch.o: /usr/include/sys/socket.h
fetch.o: /usr/include/sys/uio.h
fetch.o: /usr/include/bits/uio.h
fetch.o: /usr/include/bits/socket.h
fetch.o: /usr/include/bits/sockaddr.h
fetch.o: /usr/include/asm/socket.h
fetch.o: /usr/include/asm-x86_64/socket.h
fetch.o: /usr/include/asm/sockios.h
fetch.o: /usr/include/asm-x86_64/sockios.h
fetch.o: /usr/include/sys/un.h
fetch.o: /usr/include/netinet/in.h
fetch.o: /usr/include/stdint.h
fetch.o: /usr/include/bits/in.h
fetch.o: /usr/include/bits/byteswap.h
fetch.o: /usr/include/netinet/tcp.h
fetch.o: /usr/include/arpa/inet.h
fetch.o: /usr/include/arpa/nameser.h
fetch.o: /usr/include/sys/param.h
fetch.o: /usr/include/linux/param.h
fetch.o: /usr/include/asm/param.h
fetch.o: /usr/include/asm-x86_64/param.h
fetch.o: /usr/include/sys/bitypes.h
fetch.o: /usr/include/arpa/nameser_compat.h
fetch.o: /usr/include/netdb.h
fetch.o: /usr/include/rpc/netdb.h
fetch.o: /usr/include/bits/netdb.h
fetch.o: /usr/include/resolv.h
fetch.o: ../../include/ac/time.h
fetch.o: /usr/include/sys/time.h
fetch.o: ../../include/ldap_log.h
fetch.o: ../../include/ldap_cdefs.h
fetch.o: ../../include/lber_pvt.h
fetch.o: ../../include/lber.h
fetch.o: ../../include/lber_types.h
fetch.o: ../../include/ldap_pvt.h
fetch.o: ../../include/lber_pvt.h
fetch.o: ../../include/ldap_pvt_uc.h
fetch.o: ../../include/ac/bytes.h
fetch.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
fetch.o: ../../include/ldap_config.h
fetch.o: ../../include/ldif.h
testavl.o: testavl.c
testavl.o: ../../include/portable.h
testavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
testavl.o: ../../include/ac/fdset.h
testavl.o: /usr/include/bits/types.h
testavl.o: /usr/include/features.h
testavl.o: /usr/include/sys/cdefs.h
testavl.o: /usr/include/bits/wordsize.h
testavl.o: /usr/include/gnu/stubs.h
testavl.o: /usr/include/gnu/stubs-64.h
testavl.o: /usr/include/bits/typesizes.h
testavl.o: ../../include/ldap_cdefs.h
testavl.o: ../../include/ldap_features.h
testavl.o: ../../include/ac/assert.h
testavl.o: /usr/include/assert.h
testavl.o: ../../include/ac/localize.h
testavl.o: /usr/include/stdio.h
testavl.o: /usr/include/libio.h
testavl.o: /usr/include/_G_config.h
testavl.o: /usr/include/wchar.h
testavl.o: /usr/include/bits/wchar.h
testavl.o: /usr/include/gconv.h
testavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
testavl.o: /usr/include/bits/stdio_lim.h
testavl.o: /usr/include/bits/sys_errlist.h
testavl.o: ../../include/ac/stdlib.h
testavl.o: /usr/include/stdlib.h
testavl.o: /usr/include/sys/types.h
testavl.o: /usr/include/time.h
testavl.o: /usr/include/endian.h
testavl.o: /usr/include/bits/endian.h
testavl.o: /usr/include/sys/select.h
testavl.o: /usr/include/bits/select.h
testavl.o: /usr/include/bits/sigset.h
testavl.o: /usr/include/bits/time.h
testavl.o: /usr/include/sys/sysmacros.h
testavl.o: /usr/include/bits/pthreadtypes.h
testavl.o: /usr/include/alloca.h
testavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
testavl.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
testavl.o: /usr/include/limits.h
testavl.o: /usr/include/bits/posix1_lim.h
testavl.o: /usr/include/bits/local_lim.h
testavl.o: /usr/include/linux/limits.h
testavl.o: /usr/include/bits/posix2_lim.h
testavl.o: ../../include/ac/string.h
testavl.o: /usr/include/string.h
testavl.o: ../../include/avl.h
testavl.o: ../../include/ldap_cdefs.h
meter.o: meter.c
meter.o: ../../include/portable.h
meter.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
meter.o: ../../include/ac/fdset.h
meter.o: /usr/include/bits/types.h
meter.o: /usr/include/features.h
meter.o: /usr/include/sys/cdefs.h
meter.o: /usr/include/bits/wordsize.h
meter.o: /usr/include/gnu/stubs.h
meter.o: /usr/include/gnu/stubs-64.h
meter.o: /usr/include/bits/typesizes.h
meter.o: ../../include/ldap_cdefs.h
meter.o: ../../include/ldap_features.h
meter.o: ../../include/ac/assert.h
meter.o: /usr/include/assert.h
meter.o: ../../include/ac/localize.h
meter.o: ../../include/lutil_meter.h
meter.o: ../../include/portable.h
meter.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
meter.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
meter.o: /usr/include/limits.h
meter.o: /usr/include/bits/posix1_lim.h
meter.o: /usr/include/bits/local_lim.h
meter.o: /usr/include/linux/limits.h
meter.o: /usr/include/bits/posix2_lim.h
meter.o: /usr/include/stdio.h
meter.o: /usr/include/libio.h
meter.o: /usr/include/_G_config.h
meter.o: /usr/include/wchar.h
meter.o: /usr/include/bits/wchar.h
meter.o: /usr/include/gconv.h
meter.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
meter.o: /usr/include/bits/stdio_lim.h
meter.o: /usr/include/bits/sys_errlist.h
meter.o: /usr/include/sys/types.h
meter.o: /usr/include/time.h
meter.o: /usr/include/endian.h
meter.o: /usr/include/bits/endian.h
meter.o: /usr/include/sys/select.h
meter.o: /usr/include/bits/select.h
meter.o: /usr/include/bits/sigset.h
meter.o: /usr/include/bits/time.h
meter.o: /usr/include/sys/sysmacros.h
meter.o: /usr/include/bits/pthreadtypes.h
meter.o: ../../include/ac/stdlib.h
meter.o: /usr/include/stdlib.h
meter.o: /usr/include/alloca.h
meter.o: ../../include/ac/time.h
meter.o: /usr/include/sys/time.h
meter.o: ../../include/ac/assert.h
meter.o: ../../include/ac/string.h
meter.o: /usr/include/string.h
setproctitle.o: setproctitle.c
setproctitle.o: ../../include/portable.h
setproctitle.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
setproctitle.o: ../../include/ac/fdset.h
setproctitle.o: /usr/include/bits/types.h
setproctitle.o: /usr/include/features.h
setproctitle.o: /usr/include/sys/cdefs.h
setproctitle.o: /usr/include/bits/wordsize.h
setproctitle.o: /usr/include/gnu/stubs.h
setproctitle.o: /usr/include/gnu/stubs-64.h
setproctitle.o: /usr/include/bits/typesizes.h
setproctitle.o: ../../include/ldap_cdefs.h
setproctitle.o: ../../include/ldap_features.h
setproctitle.o: ../../include/ac/assert.h
setproctitle.o: /usr/include/assert.h
setproctitle.o: ../../include/ac/localize.h
setproctitle.o: /usr/include/stdio.h
setproctitle.o: /usr/include/libio.h
setproctitle.o: /usr/include/_G_config.h
setproctitle.o: /usr/include/wchar.h
setproctitle.o: /usr/include/bits/wchar.h
setproctitle.o: /usr/include/gconv.h
setproctitle.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
setproctitle.o: /usr/include/bits/stdio_lim.h
setproctitle.o: /usr/include/bits/sys_errlist.h
setproctitle.o: ../../include/ac/stdlib.h
setproctitle.o: /usr/include/stdlib.h
setproctitle.o: /usr/include/sys/types.h
setproctitle.o: /usr/include/time.h
setproctitle.o: /usr/include/endian.h
setproctitle.o: /usr/include/bits/endian.h
setproctitle.o: /usr/include/sys/select.h
setproctitle.o: /usr/include/bits/select.h
setproctitle.o: /usr/include/bits/sigset.h
setproctitle.o: /usr/include/bits/time.h
setproctitle.o: /usr/include/sys/sysmacros.h
setproctitle.o: /usr/include/bits/pthreadtypes.h
setproctitle.o: /usr/include/alloca.h
setproctitle.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
setproctitle.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
setproctitle.o: /usr/include/limits.h
setproctitle.o: /usr/include/bits/posix1_lim.h
setproctitle.o: /usr/include/bits/local_lim.h
setproctitle.o: /usr/include/linux/limits.h
setproctitle.o: /usr/include/bits/posix2_lim.h
setproctitle.o: ../../include/ac/setproctitle.h
setproctitle.o: ../../include/ac/string.h
setproctitle.o: /usr/include/string.h
setproctitle.o: ../../include/ac/stdarg.h
getpeereid.o: getpeereid.c
getpeereid.o: ../../include/portable.h
getpeereid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
getpeereid.o: ../../include/ac/fdset.h
getpeereid.o: /usr/include/bits/types.h
getpeereid.o: /usr/include/features.h
getpeereid.o: /usr/include/sys/cdefs.h
getpeereid.o: /usr/include/bits/wordsize.h
getpeereid.o: /usr/include/gnu/stubs.h
getpeereid.o: /usr/include/gnu/stubs-64.h
getpeereid.o: /usr/include/bits/typesizes.h
getpeereid.o: ../../include/ldap_cdefs.h
getpeereid.o: ../../include/ldap_features.h
getpeereid.o: ../../include/ac/assert.h
getpeereid.o: /usr/include/assert.h
getpeereid.o: ../../include/ac/localize.h
getpeereid.o: /usr/include/sys/types.h
getpeereid.o: /usr/include/time.h
getpeereid.o: /usr/include/endian.h
getpeereid.o: /usr/include/bits/endian.h
getpeereid.o: /usr/include/sys/select.h
getpeereid.o: /usr/include/bits/select.h
getpeereid.o: /usr/include/bits/sigset.h
getpeereid.o: /usr/include/bits/time.h
getpeereid.o: /usr/include/sys/sysmacros.h
getpeereid.o: /usr/include/bits/pthreadtypes.h
getpeereid.o: ../../include/ac/unistd.h
getpeereid.o: /usr/include/unistd.h
getpeereid.o: /usr/include/bits/posix_opt.h
getpeereid.o: /usr/include/bits/environments.h
getpeereid.o: /usr/include/bits/confname.h
getpeereid.o: /usr/include/getopt.h
getpeereid.o: ../../include/lutil_lockf.h
getpeereid.o: ../../include/ac/socket.h
getpeereid.o: /usr/include/poll.h
getpeereid.o: /usr/include/sys/poll.h
getpeereid.o: /usr/include/bits/poll.h
getpeereid.o: /usr/include/sys/socket.h
getpeereid.o: /usr/include/sys/uio.h
getpeereid.o: /usr/include/bits/uio.h
getpeereid.o: /usr/include/bits/socket.h
getpeereid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
getpeereid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
getpeereid.o: /usr/include/limits.h
getpeereid.o: /usr/include/bits/posix1_lim.h
getpeereid.o: /usr/include/bits/local_lim.h
getpeereid.o: /usr/include/linux/limits.h
getpeereid.o: /usr/include/bits/posix2_lim.h
getpeereid.o: /usr/include/bits/xopen_lim.h
getpeereid.o: /usr/include/bits/stdio_lim.h
getpeereid.o: /usr/include/bits/sockaddr.h
getpeereid.o: /usr/include/asm/socket.h
getpeereid.o: /usr/include/asm-x86_64/socket.h
getpeereid.o: /usr/include/asm/sockios.h
getpeereid.o: /usr/include/asm-x86_64/sockios.h
getpeereid.o: /usr/include/sys/un.h
getpeereid.o: /usr/include/string.h
getpeereid.o: /usr/include/xlocale.h
getpeereid.o: /usr/include/netinet/in.h
getpeereid.o: /usr/include/stdint.h
getpeereid.o: /usr/include/bits/wchar.h
getpeereid.o: /usr/include/bits/in.h
getpeereid.o: /usr/include/bits/byteswap.h
getpeereid.o: /usr/include/netinet/tcp.h
getpeereid.o: /usr/include/arpa/inet.h
getpeereid.o: /usr/include/arpa/nameser.h
getpeereid.o: /usr/include/sys/param.h
getpeereid.o: /usr/include/linux/param.h
getpeereid.o: /usr/include/asm/param.h
getpeereid.o: /usr/include/asm-x86_64/param.h
getpeereid.o: /usr/include/sys/bitypes.h
getpeereid.o: /usr/include/arpa/nameser_compat.h
getpeereid.o: /usr/include/netdb.h
getpeereid.o: /usr/include/rpc/netdb.h
getpeereid.o: /usr/include/bits/siginfo.h
getpeereid.o: /usr/include/bits/netdb.h
getpeereid.o: /usr/include/resolv.h
getpeereid.o: /usr/include/stdio.h
getpeereid.o: /usr/include/libio.h
getpeereid.o: /usr/include/_G_config.h
getpeereid.o: /usr/include/wchar.h
getpeereid.o: /usr/include/gconv.h
getpeereid.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
getpeereid.o: /usr/include/bits/sys_errlist.h
getpeereid.o: ../../include/ac/errno.h
getpeereid.o: /usr/include/errno.h
getpeereid.o: /usr/include/bits/errno.h
getpeereid.o: /usr/include/linux/errno.h
getpeereid.o: /usr/include/asm/errno.h
getpeereid.o: /usr/include/asm-x86_64/errno.h
getpeereid.o: /usr/include/asm-generic/errno.h
getpeereid.o: /usr/include/asm-generic/errno-base.h
getpeereid.o: /usr/include/stdlib.h
getpeereid.o: /usr/include/bits/waitflags.h
getpeereid.o: /usr/include/bits/waitstatus.h
getpeereid.o: /usr/include/alloca.h
detach.o: detach.c
detach.o: ../../include/portable.h
detach.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
detach.o: ../../include/ac/fdset.h
detach.o: /usr/include/bits/types.h
detach.o: /usr/include/features.h
detach.o: /usr/include/sys/cdefs.h
detach.o: /usr/include/bits/wordsize.h
detach.o: /usr/include/gnu/stubs.h
detach.o: /usr/include/gnu/stubs-64.h
detach.o: /usr/include/bits/typesizes.h
detach.o: ../../include/ldap_cdefs.h
detach.o: ../../include/ldap_features.h
detach.o: ../../include/ac/assert.h
detach.o: /usr/include/assert.h
detach.o: ../../include/ac/localize.h
detach.o: /usr/include/stdio.h
detach.o: /usr/include/libio.h
detach.o: /usr/include/_G_config.h
detach.o: /usr/include/wchar.h
detach.o: /usr/include/bits/wchar.h
detach.o: /usr/include/gconv.h
detach.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
detach.o: /usr/include/bits/stdio_lim.h
detach.o: /usr/include/bits/sys_errlist.h
detach.o: ../../include/ac/stdlib.h
detach.o: /usr/include/stdlib.h
detach.o: /usr/include/sys/types.h
detach.o: /usr/include/time.h
detach.o: /usr/include/endian.h
detach.o: /usr/include/bits/endian.h
detach.o: /usr/include/sys/select.h
detach.o: /usr/include/bits/select.h
detach.o: /usr/include/bits/sigset.h
detach.o: /usr/include/bits/time.h
detach.o: /usr/include/sys/sysmacros.h
detach.o: /usr/include/bits/pthreadtypes.h
detach.o: /usr/include/alloca.h
detach.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
detach.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
detach.o: /usr/include/limits.h
detach.o: /usr/include/bits/posix1_lim.h
detach.o: /usr/include/bits/local_lim.h
detach.o: /usr/include/linux/limits.h
detach.o: /usr/include/bits/posix2_lim.h
detach.o: ../../include/ac/signal.h
detach.o: /usr/include/signal.h
detach.o: /usr/include/bits/signum.h
detach.o: /usr/include/bits/siginfo.h
detach.o: /usr/include/bits/sigaction.h
detach.o: /usr/include/bits/sigcontext.h
detach.o: /usr/include/bits/sigstack.h
detach.o: /usr/include/bits/sigthread.h
detach.o: ../../include/ac/socket.h
detach.o: /usr/include/poll.h
detach.o: /usr/include/sys/poll.h
detach.o: /usr/include/bits/poll.h
detach.o: /usr/include/sys/socket.h
detach.o: /usr/include/sys/uio.h
detach.o: /usr/include/bits/uio.h
detach.o: /usr/include/bits/socket.h
detach.o: /usr/include/bits/sockaddr.h
detach.o: /usr/include/asm/socket.h
detach.o: /usr/include/asm-x86_64/socket.h
detach.o: /usr/include/asm/sockios.h
detach.o: /usr/include/asm-x86_64/sockios.h
detach.o: /usr/include/sys/un.h
detach.o: /usr/include/string.h
detach.o: /usr/include/netinet/in.h
detach.o: /usr/include/stdint.h
detach.o: /usr/include/bits/in.h
detach.o: /usr/include/bits/byteswap.h
detach.o: /usr/include/netinet/tcp.h
detach.o: /usr/include/arpa/inet.h
detach.o: /usr/include/arpa/nameser.h
detach.o: /usr/include/sys/param.h
detach.o: /usr/include/linux/param.h
detach.o: /usr/include/asm/param.h
detach.o: /usr/include/asm-x86_64/param.h
detach.o: /usr/include/sys/bitypes.h
detach.o: /usr/include/arpa/nameser_compat.h
detach.o: /usr/include/netdb.h
detach.o: /usr/include/rpc/netdb.h
detach.o: /usr/include/bits/netdb.h
detach.o: /usr/include/resolv.h
detach.o: ../../include/ac/unistd.h
detach.o: /usr/include/unistd.h
detach.o: /usr/include/bits/posix_opt.h
detach.o: /usr/include/bits/confname.h
detach.o: /usr/include/getopt.h
detach.o: ../../include/lutil_lockf.h
detach.o: /usr/include/sys/stat.h
detach.o: /usr/include/bits/stat.h
detach.o: /usr/include/fcntl.h
detach.o: /usr/include/bits/fcntl.h
detach.o: /usr/include/sys/file.h
detach.o: /usr/include/sys/ioctl.h
detach.o: /usr/include/bits/ioctls.h
detach.o: /usr/include/asm/ioctls.h
detach.o: /usr/include/asm-x86_64/ioctls.h
detach.o: /usr/include/asm/ioctl.h
detach.o: /usr/include/asm-x86_64/ioctl.h
detach.o: /usr/include/asm-generic/ioctl.h
detach.o: /usr/include/bits/ioctl-types.h
detach.o: /usr/include/sys/ttydefaults.h
detach.o: ../../include/lutil.h
detach.o: ../../include/ldap_cdefs.h
detach.o: ../../include/lber_types.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
