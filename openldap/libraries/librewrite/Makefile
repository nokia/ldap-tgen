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

# LIBREWRITE
# $OpenLDAP: pkg/ldap/libraries/librewrite/Makefile.in,v 1.14.2.5 2010/04/13 20:23:08 kurt Exp $
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
##
## Copyright 2000-2001 Pierangelo Masarati <ando@sys-net.it>
##

SRCS = config.c context.c info.c ldapmap.c map.c params.c rule.c \
	session.c subst.c var.c xmap.c \
	parse.c rewrite.c
XSRCS = version.c
OBJS = config.o context.o info.o ldapmap.o map.o params.o rule.o \
	session.o subst.o var.o xmap.o

LDAP_INCDIR= ../../include       
LDAP_LIBDIR= ../../libraries

LIBRARY = librewrite.a
PROGRAMS	= rewrite
XLIBS = $(LIBRARY) $(LDAP_LIBLUTIL_A) \
	$(LDAP_LIBLDAP_R_LA) $(LDAP_LIBLBER_LA)
XXLIBS  = $(SECURITY_LIBS) $(LUTIL_LIBS)
XXXLIBS = $(LTHREAD_LIBS)

rewrite:	$(XLIBS) rewrite.o parse.o
	$(LTLINK) -o $@ rewrite.o parse.o $(LIBS)
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
# files: -I../../include -I../../include config.c context.c info.c ldapmap.c map.c params.c rule.c session.c subst.c var.c xmap.c parse.c rewrite.c
# command: cc -M -I.  -I../../include -I../../include config.c context.c info.c ldapmap.c map.c params.c rule.c session.c subst.c var.c xmap.c parse.c rewrite.c
#

config.o: config.c
config.o: ../../include/portable.h
config.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
config.o: ../../include/ac/fdset.h
config.o: /usr/include/bits/types.h
config.o: /usr/include/features.h
config.o: /usr/include/sys/cdefs.h
config.o: /usr/include/bits/wordsize.h
config.o: /usr/include/gnu/stubs.h
config.o: /usr/include/gnu/stubs-64.h
config.o: /usr/include/bits/typesizes.h
config.o: ../../include/ldap_cdefs.h
config.o: ../../include/ldap_features.h
config.o: ../../include/ac/assert.h
config.o: /usr/include/assert.h
config.o: ../../include/ac/localize.h
config.o: rewrite-int.h
config.o: ../../include/ac/stdlib.h
config.o: /usr/include/stdlib.h
config.o: /usr/include/sys/types.h
config.o: /usr/include/time.h
config.o: /usr/include/endian.h
config.o: /usr/include/bits/endian.h
config.o: /usr/include/sys/select.h
config.o: /usr/include/bits/select.h
config.o: /usr/include/bits/sigset.h
config.o: /usr/include/bits/time.h
config.o: /usr/include/sys/sysmacros.h
config.o: /usr/include/bits/pthreadtypes.h
config.o: /usr/include/alloca.h
config.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
config.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
config.o: /usr/include/limits.h
config.o: /usr/include/bits/posix1_lim.h
config.o: /usr/include/bits/local_lim.h
config.o: /usr/include/linux/limits.h
config.o: /usr/include/bits/posix2_lim.h
config.o: ../../include/ac/string.h
config.o: /usr/include/string.h
config.o: ../../include/ac/syslog.h
config.o: /usr/include/syslog.h
config.o: /usr/include/sys/syslog.h
config.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
config.o: /usr/include/bits/syslog-path.h
config.o: ../../include/ac/regex.h
config.o: /usr/include/regex.h
config.o: ../../include/ac/socket.h
config.o: /usr/include/poll.h
config.o: /usr/include/sys/poll.h
config.o: /usr/include/bits/poll.h
config.o: /usr/include/sys/socket.h
config.o: /usr/include/sys/uio.h
config.o: /usr/include/bits/uio.h
config.o: /usr/include/bits/socket.h
config.o: /usr/include/bits/sockaddr.h
config.o: /usr/include/asm/socket.h
config.o: /usr/include/asm-x86_64/socket.h
config.o: /usr/include/asm/sockios.h
config.o: /usr/include/asm-x86_64/sockios.h
config.o: /usr/include/sys/un.h
config.o: /usr/include/netinet/in.h
config.o: /usr/include/stdint.h
config.o: /usr/include/bits/wchar.h
config.o: /usr/include/bits/in.h
config.o: /usr/include/bits/byteswap.h
config.o: /usr/include/netinet/tcp.h
config.o: /usr/include/arpa/inet.h
config.o: /usr/include/arpa/nameser.h
config.o: /usr/include/sys/param.h
config.o: /usr/include/linux/param.h
config.o: /usr/include/asm/param.h
config.o: /usr/include/asm-x86_64/param.h
config.o: /usr/include/sys/bitypes.h
config.o: /usr/include/arpa/nameser_compat.h
config.o: /usr/include/netdb.h
config.o: /usr/include/rpc/netdb.h
config.o: /usr/include/bits/netdb.h
config.o: /usr/include/resolv.h
config.o: /usr/include/stdio.h
config.o: /usr/include/libio.h
config.o: /usr/include/_G_config.h
config.o: /usr/include/wchar.h
config.o: /usr/include/gconv.h
config.o: /usr/include/bits/stdio_lim.h
config.o: /usr/include/bits/sys_errlist.h
config.o: ../../include/ac/unistd.h
config.o: /usr/include/unistd.h
config.o: /usr/include/bits/posix_opt.h
config.o: /usr/include/bits/confname.h
config.o: /usr/include/getopt.h
config.o: ../../include/lutil_lockf.h
config.o: ../../include/ac/ctype.h
config.o: /usr/include/ctype.h
config.o: ../../include/lber.h
config.o: ../../include/lber_types.h
config.o: ../../include/ldap_cdefs.h
config.o: ../../include/ldap.h
config.o: ../../include/ldap_features.h
config.o: ../libldap/ldap-int.h
config.o: ../libldap/../liblber/lber-int.h
config.o: ../../include/ldap_log.h
config.o: ../../include/lber_pvt.h
config.o: ../../include/ldap_queue.h
config.o: ../../include/lutil.h
config.o: /usr/include/sasl/sasl.h
config.o: /usr/include/sasl/prop.h
config.o: ../../include/ac/time.h
config.o: /usr/include/sys/time.h
config.o: ../../include/ldap_log.h
config.o: ../../include/ldap_pvt.h
config.o: ../../include/lber_pvt.h
config.o: ../../include/ldap_pvt_uc.h
config.o: ../../include/ac/bytes.h
config.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
config.o: ../../include/lutil.h
config.o: ../../include/avl.h
config.o: ../../include/rewrite.h
config.o: ../../include/ldap_pvt_thread.h
config.o: ../../include/ldap_int_thread.h
config.o: /usr/include/pthread.h
config.o: /usr/include/sched.h
config.o: /usr/include/bits/sched.h
config.o: /usr/include/signal.h
config.o: /usr/include/bits/setjmp.h
config.o: rewrite-map.h
context.o: context.c
context.o: ../../include/portable.h
context.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
context.o: ../../include/ac/fdset.h
context.o: /usr/include/bits/types.h
context.o: /usr/include/features.h
context.o: /usr/include/sys/cdefs.h
context.o: /usr/include/bits/wordsize.h
context.o: /usr/include/gnu/stubs.h
context.o: /usr/include/gnu/stubs-64.h
context.o: /usr/include/bits/typesizes.h
context.o: ../../include/ldap_cdefs.h
context.o: ../../include/ldap_features.h
context.o: ../../include/ac/assert.h
context.o: /usr/include/assert.h
context.o: ../../include/ac/localize.h
context.o: rewrite-int.h
context.o: ../../include/ac/stdlib.h
context.o: /usr/include/stdlib.h
context.o: /usr/include/sys/types.h
context.o: /usr/include/time.h
context.o: /usr/include/endian.h
context.o: /usr/include/bits/endian.h
context.o: /usr/include/sys/select.h
context.o: /usr/include/bits/select.h
context.o: /usr/include/bits/sigset.h
context.o: /usr/include/bits/time.h
context.o: /usr/include/sys/sysmacros.h
context.o: /usr/include/bits/pthreadtypes.h
context.o: /usr/include/alloca.h
context.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
context.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
context.o: /usr/include/limits.h
context.o: /usr/include/bits/posix1_lim.h
context.o: /usr/include/bits/local_lim.h
context.o: /usr/include/linux/limits.h
context.o: /usr/include/bits/posix2_lim.h
context.o: ../../include/ac/string.h
context.o: /usr/include/string.h
context.o: ../../include/ac/syslog.h
context.o: /usr/include/syslog.h
context.o: /usr/include/sys/syslog.h
context.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
context.o: /usr/include/bits/syslog-path.h
context.o: ../../include/ac/regex.h
context.o: /usr/include/regex.h
context.o: ../../include/ac/socket.h
context.o: /usr/include/poll.h
context.o: /usr/include/sys/poll.h
context.o: /usr/include/bits/poll.h
context.o: /usr/include/sys/socket.h
context.o: /usr/include/sys/uio.h
context.o: /usr/include/bits/uio.h
context.o: /usr/include/bits/socket.h
context.o: /usr/include/bits/sockaddr.h
context.o: /usr/include/asm/socket.h
context.o: /usr/include/asm-x86_64/socket.h
context.o: /usr/include/asm/sockios.h
context.o: /usr/include/asm-x86_64/sockios.h
context.o: /usr/include/sys/un.h
context.o: /usr/include/netinet/in.h
context.o: /usr/include/stdint.h
context.o: /usr/include/bits/wchar.h
context.o: /usr/include/bits/in.h
context.o: /usr/include/bits/byteswap.h
context.o: /usr/include/netinet/tcp.h
context.o: /usr/include/arpa/inet.h
context.o: /usr/include/arpa/nameser.h
context.o: /usr/include/sys/param.h
context.o: /usr/include/linux/param.h
context.o: /usr/include/asm/param.h
context.o: /usr/include/asm-x86_64/param.h
context.o: /usr/include/sys/bitypes.h
context.o: /usr/include/arpa/nameser_compat.h
context.o: /usr/include/netdb.h
context.o: /usr/include/rpc/netdb.h
context.o: /usr/include/bits/netdb.h
context.o: /usr/include/resolv.h
context.o: /usr/include/stdio.h
context.o: /usr/include/libio.h
context.o: /usr/include/_G_config.h
context.o: /usr/include/wchar.h
context.o: /usr/include/gconv.h
context.o: /usr/include/bits/stdio_lim.h
context.o: /usr/include/bits/sys_errlist.h
context.o: ../../include/ac/unistd.h
context.o: /usr/include/unistd.h
context.o: /usr/include/bits/posix_opt.h
context.o: /usr/include/bits/confname.h
context.o: /usr/include/getopt.h
context.o: ../../include/lutil_lockf.h
context.o: ../../include/ac/ctype.h
context.o: /usr/include/ctype.h
context.o: ../../include/lber.h
context.o: ../../include/lber_types.h
context.o: ../../include/ldap_cdefs.h
context.o: ../../include/ldap.h
context.o: ../../include/ldap_features.h
context.o: ../libldap/ldap-int.h
context.o: ../libldap/../liblber/lber-int.h
context.o: ../../include/ldap_log.h
context.o: ../../include/lber_pvt.h
context.o: ../../include/ldap_queue.h
context.o: ../../include/lutil.h
context.o: /usr/include/sasl/sasl.h
context.o: /usr/include/sasl/prop.h
context.o: ../../include/ac/time.h
context.o: /usr/include/sys/time.h
context.o: ../../include/ldap_log.h
context.o: ../../include/ldap_pvt.h
context.o: ../../include/lber_pvt.h
context.o: ../../include/ldap_pvt_uc.h
context.o: ../../include/ac/bytes.h
context.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
context.o: ../../include/lutil.h
context.o: ../../include/avl.h
context.o: ../../include/rewrite.h
context.o: ../../include/ldap_pvt_thread.h
context.o: ../../include/ldap_int_thread.h
context.o: /usr/include/pthread.h
context.o: /usr/include/sched.h
context.o: /usr/include/bits/sched.h
context.o: /usr/include/signal.h
context.o: /usr/include/bits/setjmp.h
info.o: info.c
info.o: ../../include/portable.h
info.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
info.o: ../../include/ac/fdset.h
info.o: /usr/include/bits/types.h
info.o: /usr/include/features.h
info.o: /usr/include/sys/cdefs.h
info.o: /usr/include/bits/wordsize.h
info.o: /usr/include/gnu/stubs.h
info.o: /usr/include/gnu/stubs-64.h
info.o: /usr/include/bits/typesizes.h
info.o: ../../include/ldap_cdefs.h
info.o: ../../include/ldap_features.h
info.o: ../../include/ac/assert.h
info.o: /usr/include/assert.h
info.o: ../../include/ac/localize.h
info.o: rewrite-int.h
info.o: ../../include/ac/stdlib.h
info.o: /usr/include/stdlib.h
info.o: /usr/include/sys/types.h
info.o: /usr/include/time.h
info.o: /usr/include/endian.h
info.o: /usr/include/bits/endian.h
info.o: /usr/include/sys/select.h
info.o: /usr/include/bits/select.h
info.o: /usr/include/bits/sigset.h
info.o: /usr/include/bits/time.h
info.o: /usr/include/sys/sysmacros.h
info.o: /usr/include/bits/pthreadtypes.h
info.o: /usr/include/alloca.h
info.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
info.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
info.o: /usr/include/limits.h
info.o: /usr/include/bits/posix1_lim.h
info.o: /usr/include/bits/local_lim.h
info.o: /usr/include/linux/limits.h
info.o: /usr/include/bits/posix2_lim.h
info.o: ../../include/ac/string.h
info.o: /usr/include/string.h
info.o: ../../include/ac/syslog.h
info.o: /usr/include/syslog.h
info.o: /usr/include/sys/syslog.h
info.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
info.o: /usr/include/bits/syslog-path.h
info.o: ../../include/ac/regex.h
info.o: /usr/include/regex.h
info.o: ../../include/ac/socket.h
info.o: /usr/include/poll.h
info.o: /usr/include/sys/poll.h
info.o: /usr/include/bits/poll.h
info.o: /usr/include/sys/socket.h
info.o: /usr/include/sys/uio.h
info.o: /usr/include/bits/uio.h
info.o: /usr/include/bits/socket.h
info.o: /usr/include/bits/sockaddr.h
info.o: /usr/include/asm/socket.h
info.o: /usr/include/asm-x86_64/socket.h
info.o: /usr/include/asm/sockios.h
info.o: /usr/include/asm-x86_64/sockios.h
info.o: /usr/include/sys/un.h
info.o: /usr/include/netinet/in.h
info.o: /usr/include/stdint.h
info.o: /usr/include/bits/wchar.h
info.o: /usr/include/bits/in.h
info.o: /usr/include/bits/byteswap.h
info.o: /usr/include/netinet/tcp.h
info.o: /usr/include/arpa/inet.h
info.o: /usr/include/arpa/nameser.h
info.o: /usr/include/sys/param.h
info.o: /usr/include/linux/param.h
info.o: /usr/include/asm/param.h
info.o: /usr/include/asm-x86_64/param.h
info.o: /usr/include/sys/bitypes.h
info.o: /usr/include/arpa/nameser_compat.h
info.o: /usr/include/netdb.h
info.o: /usr/include/rpc/netdb.h
info.o: /usr/include/bits/netdb.h
info.o: /usr/include/resolv.h
info.o: /usr/include/stdio.h
info.o: /usr/include/libio.h
info.o: /usr/include/_G_config.h
info.o: /usr/include/wchar.h
info.o: /usr/include/gconv.h
info.o: /usr/include/bits/stdio_lim.h
info.o: /usr/include/bits/sys_errlist.h
info.o: ../../include/ac/unistd.h
info.o: /usr/include/unistd.h
info.o: /usr/include/bits/posix_opt.h
info.o: /usr/include/bits/confname.h
info.o: /usr/include/getopt.h
info.o: ../../include/lutil_lockf.h
info.o: ../../include/ac/ctype.h
info.o: /usr/include/ctype.h
info.o: ../../include/lber.h
info.o: ../../include/lber_types.h
info.o: ../../include/ldap_cdefs.h
info.o: ../../include/ldap.h
info.o: ../../include/ldap_features.h
info.o: ../libldap/ldap-int.h
info.o: ../libldap/../liblber/lber-int.h
info.o: ../../include/ldap_log.h
info.o: ../../include/lber_pvt.h
info.o: ../../include/ldap_queue.h
info.o: ../../include/lutil.h
info.o: /usr/include/sasl/sasl.h
info.o: /usr/include/sasl/prop.h
info.o: ../../include/ac/time.h
info.o: /usr/include/sys/time.h
info.o: ../../include/ldap_log.h
info.o: ../../include/ldap_pvt.h
info.o: ../../include/lber_pvt.h
info.o: ../../include/ldap_pvt_uc.h
info.o: ../../include/ac/bytes.h
info.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
info.o: ../../include/lutil.h
info.o: ../../include/avl.h
info.o: ../../include/rewrite.h
info.o: ../../include/ldap_pvt_thread.h
info.o: ../../include/ldap_int_thread.h
info.o: /usr/include/pthread.h
info.o: /usr/include/sched.h
info.o: /usr/include/bits/sched.h
info.o: /usr/include/signal.h
info.o: /usr/include/bits/setjmp.h
ldapmap.o: ldapmap.c
ldapmap.o: ../../include/portable.h
ldapmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
ldapmap.o: ../../include/ac/fdset.h
ldapmap.o: /usr/include/bits/types.h
ldapmap.o: /usr/include/features.h
ldapmap.o: /usr/include/sys/cdefs.h
ldapmap.o: /usr/include/bits/wordsize.h
ldapmap.o: /usr/include/gnu/stubs.h
ldapmap.o: /usr/include/gnu/stubs-64.h
ldapmap.o: /usr/include/bits/typesizes.h
ldapmap.o: ../../include/ldap_cdefs.h
ldapmap.o: ../../include/ldap_features.h
ldapmap.o: ../../include/ac/assert.h
ldapmap.o: /usr/include/assert.h
ldapmap.o: ../../include/ac/localize.h
ldapmap.o: rewrite-int.h
ldapmap.o: ../../include/ac/stdlib.h
ldapmap.o: /usr/include/stdlib.h
ldapmap.o: /usr/include/sys/types.h
ldapmap.o: /usr/include/time.h
ldapmap.o: /usr/include/endian.h
ldapmap.o: /usr/include/bits/endian.h
ldapmap.o: /usr/include/sys/select.h
ldapmap.o: /usr/include/bits/select.h
ldapmap.o: /usr/include/bits/sigset.h
ldapmap.o: /usr/include/bits/time.h
ldapmap.o: /usr/include/sys/sysmacros.h
ldapmap.o: /usr/include/bits/pthreadtypes.h
ldapmap.o: /usr/include/alloca.h
ldapmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
ldapmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
ldapmap.o: /usr/include/limits.h
ldapmap.o: /usr/include/bits/posix1_lim.h
ldapmap.o: /usr/include/bits/local_lim.h
ldapmap.o: /usr/include/linux/limits.h
ldapmap.o: /usr/include/bits/posix2_lim.h
ldapmap.o: ../../include/ac/string.h
ldapmap.o: /usr/include/string.h
ldapmap.o: ../../include/ac/syslog.h
ldapmap.o: /usr/include/syslog.h
ldapmap.o: /usr/include/sys/syslog.h
ldapmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
ldapmap.o: /usr/include/bits/syslog-path.h
ldapmap.o: ../../include/ac/regex.h
ldapmap.o: /usr/include/regex.h
ldapmap.o: ../../include/ac/socket.h
ldapmap.o: /usr/include/poll.h
ldapmap.o: /usr/include/sys/poll.h
ldapmap.o: /usr/include/bits/poll.h
ldapmap.o: /usr/include/sys/socket.h
ldapmap.o: /usr/include/sys/uio.h
ldapmap.o: /usr/include/bits/uio.h
ldapmap.o: /usr/include/bits/socket.h
ldapmap.o: /usr/include/bits/sockaddr.h
ldapmap.o: /usr/include/asm/socket.h
ldapmap.o: /usr/include/asm-x86_64/socket.h
ldapmap.o: /usr/include/asm/sockios.h
ldapmap.o: /usr/include/asm-x86_64/sockios.h
ldapmap.o: /usr/include/sys/un.h
ldapmap.o: /usr/include/netinet/in.h
ldapmap.o: /usr/include/stdint.h
ldapmap.o: /usr/include/bits/wchar.h
ldapmap.o: /usr/include/bits/in.h
ldapmap.o: /usr/include/bits/byteswap.h
ldapmap.o: /usr/include/netinet/tcp.h
ldapmap.o: /usr/include/arpa/inet.h
ldapmap.o: /usr/include/arpa/nameser.h
ldapmap.o: /usr/include/sys/param.h
ldapmap.o: /usr/include/linux/param.h
ldapmap.o: /usr/include/asm/param.h
ldapmap.o: /usr/include/asm-x86_64/param.h
ldapmap.o: /usr/include/sys/bitypes.h
ldapmap.o: /usr/include/arpa/nameser_compat.h
ldapmap.o: /usr/include/netdb.h
ldapmap.o: /usr/include/rpc/netdb.h
ldapmap.o: /usr/include/bits/netdb.h
ldapmap.o: /usr/include/resolv.h
ldapmap.o: /usr/include/stdio.h
ldapmap.o: /usr/include/libio.h
ldapmap.o: /usr/include/_G_config.h
ldapmap.o: /usr/include/wchar.h
ldapmap.o: /usr/include/gconv.h
ldapmap.o: /usr/include/bits/stdio_lim.h
ldapmap.o: /usr/include/bits/sys_errlist.h
ldapmap.o: ../../include/ac/unistd.h
ldapmap.o: /usr/include/unistd.h
ldapmap.o: /usr/include/bits/posix_opt.h
ldapmap.o: /usr/include/bits/confname.h
ldapmap.o: /usr/include/getopt.h
ldapmap.o: ../../include/lutil_lockf.h
ldapmap.o: ../../include/ac/ctype.h
ldapmap.o: /usr/include/ctype.h
ldapmap.o: ../../include/lber.h
ldapmap.o: ../../include/lber_types.h
ldapmap.o: ../../include/ldap_cdefs.h
ldapmap.o: ../../include/ldap.h
ldapmap.o: ../../include/ldap_features.h
ldapmap.o: ../libldap/ldap-int.h
ldapmap.o: ../libldap/../liblber/lber-int.h
ldapmap.o: ../../include/ldap_log.h
ldapmap.o: ../../include/lber_pvt.h
ldapmap.o: ../../include/ldap_queue.h
ldapmap.o: ../../include/lutil.h
ldapmap.o: /usr/include/sasl/sasl.h
ldapmap.o: /usr/include/sasl/prop.h
ldapmap.o: ../../include/ac/time.h
ldapmap.o: /usr/include/sys/time.h
ldapmap.o: ../../include/ldap_log.h
ldapmap.o: ../../include/ldap_pvt.h
ldapmap.o: ../../include/lber_pvt.h
ldapmap.o: ../../include/ldap_pvt_uc.h
ldapmap.o: ../../include/ac/bytes.h
ldapmap.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
ldapmap.o: ../../include/lutil.h
ldapmap.o: ../../include/avl.h
ldapmap.o: ../../include/rewrite.h
ldapmap.o: ../../include/ldap_pvt_thread.h
ldapmap.o: ../../include/ldap_int_thread.h
ldapmap.o: /usr/include/pthread.h
ldapmap.o: /usr/include/sched.h
ldapmap.o: /usr/include/bits/sched.h
ldapmap.o: /usr/include/signal.h
ldapmap.o: /usr/include/bits/setjmp.h
ldapmap.o: rewrite-map.h
map.o: map.c
map.o: ../../include/portable.h
map.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
map.o: ../../include/ac/fdset.h
map.o: /usr/include/bits/types.h
map.o: /usr/include/features.h
map.o: /usr/include/sys/cdefs.h
map.o: /usr/include/bits/wordsize.h
map.o: /usr/include/gnu/stubs.h
map.o: /usr/include/gnu/stubs-64.h
map.o: /usr/include/bits/typesizes.h
map.o: ../../include/ldap_cdefs.h
map.o: ../../include/ldap_features.h
map.o: ../../include/ac/assert.h
map.o: /usr/include/assert.h
map.o: ../../include/ac/localize.h
map.o: /usr/include/stdio.h
map.o: /usr/include/libio.h
map.o: /usr/include/_G_config.h
map.o: /usr/include/wchar.h
map.o: /usr/include/bits/wchar.h
map.o: /usr/include/gconv.h
map.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
map.o: /usr/include/bits/stdio_lim.h
map.o: /usr/include/bits/sys_errlist.h
map.o: /usr/include/pwd.h
map.o: rewrite-int.h
map.o: ../../include/ac/stdlib.h
map.o: /usr/include/stdlib.h
map.o: /usr/include/sys/types.h
map.o: /usr/include/time.h
map.o: /usr/include/endian.h
map.o: /usr/include/bits/endian.h
map.o: /usr/include/sys/select.h
map.o: /usr/include/bits/select.h
map.o: /usr/include/bits/sigset.h
map.o: /usr/include/bits/time.h
map.o: /usr/include/sys/sysmacros.h
map.o: /usr/include/bits/pthreadtypes.h
map.o: /usr/include/alloca.h
map.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
map.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
map.o: /usr/include/limits.h
map.o: /usr/include/bits/posix1_lim.h
map.o: /usr/include/bits/local_lim.h
map.o: /usr/include/linux/limits.h
map.o: /usr/include/bits/posix2_lim.h
map.o: ../../include/ac/string.h
map.o: /usr/include/string.h
map.o: ../../include/ac/syslog.h
map.o: /usr/include/syslog.h
map.o: /usr/include/sys/syslog.h
map.o: /usr/include/bits/syslog-path.h
map.o: ../../include/ac/regex.h
map.o: /usr/include/regex.h
map.o: ../../include/ac/socket.h
map.o: /usr/include/poll.h
map.o: /usr/include/sys/poll.h
map.o: /usr/include/bits/poll.h
map.o: /usr/include/sys/socket.h
map.o: /usr/include/sys/uio.h
map.o: /usr/include/bits/uio.h
map.o: /usr/include/bits/socket.h
map.o: /usr/include/bits/sockaddr.h
map.o: /usr/include/asm/socket.h
map.o: /usr/include/asm-x86_64/socket.h
map.o: /usr/include/asm/sockios.h
map.o: /usr/include/asm-x86_64/sockios.h
map.o: /usr/include/sys/un.h
map.o: /usr/include/netinet/in.h
map.o: /usr/include/stdint.h
map.o: /usr/include/bits/in.h
map.o: /usr/include/bits/byteswap.h
map.o: /usr/include/netinet/tcp.h
map.o: /usr/include/arpa/inet.h
map.o: /usr/include/arpa/nameser.h
map.o: /usr/include/sys/param.h
map.o: /usr/include/linux/param.h
map.o: /usr/include/asm/param.h
map.o: /usr/include/asm-x86_64/param.h
map.o: /usr/include/sys/bitypes.h
map.o: /usr/include/arpa/nameser_compat.h
map.o: /usr/include/netdb.h
map.o: /usr/include/rpc/netdb.h
map.o: /usr/include/bits/netdb.h
map.o: /usr/include/resolv.h
map.o: ../../include/ac/unistd.h
map.o: /usr/include/unistd.h
map.o: /usr/include/bits/posix_opt.h
map.o: /usr/include/bits/confname.h
map.o: /usr/include/getopt.h
map.o: ../../include/lutil_lockf.h
map.o: ../../include/ac/ctype.h
map.o: /usr/include/ctype.h
map.o: ../../include/lber.h
map.o: ../../include/lber_types.h
map.o: ../../include/ldap_cdefs.h
map.o: ../../include/ldap.h
map.o: ../../include/ldap_features.h
map.o: ../libldap/ldap-int.h
map.o: ../libldap/../liblber/lber-int.h
map.o: ../../include/ldap_log.h
map.o: ../../include/lber_pvt.h
map.o: ../../include/ldap_queue.h
map.o: ../../include/lutil.h
map.o: /usr/include/sasl/sasl.h
map.o: /usr/include/sasl/prop.h
map.o: ../../include/ac/time.h
map.o: /usr/include/sys/time.h
map.o: ../../include/ldap_log.h
map.o: ../../include/ldap_pvt.h
map.o: ../../include/lber_pvt.h
map.o: ../../include/ldap_pvt_uc.h
map.o: ../../include/ac/bytes.h
map.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
map.o: ../../include/lutil.h
map.o: ../../include/avl.h
map.o: ../../include/rewrite.h
map.o: ../../include/ldap_pvt_thread.h
map.o: ../../include/ldap_int_thread.h
map.o: /usr/include/pthread.h
map.o: /usr/include/sched.h
map.o: /usr/include/bits/sched.h
map.o: /usr/include/signal.h
map.o: /usr/include/bits/setjmp.h
map.o: rewrite-map.h
params.o: params.c
params.o: ../../include/portable.h
params.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
params.o: ../../include/ac/fdset.h
params.o: /usr/include/bits/types.h
params.o: /usr/include/features.h
params.o: /usr/include/sys/cdefs.h
params.o: /usr/include/bits/wordsize.h
params.o: /usr/include/gnu/stubs.h
params.o: /usr/include/gnu/stubs-64.h
params.o: /usr/include/bits/typesizes.h
params.o: ../../include/ldap_cdefs.h
params.o: ../../include/ldap_features.h
params.o: ../../include/ac/assert.h
params.o: /usr/include/assert.h
params.o: ../../include/ac/localize.h
params.o: rewrite-int.h
params.o: ../../include/ac/stdlib.h
params.o: /usr/include/stdlib.h
params.o: /usr/include/sys/types.h
params.o: /usr/include/time.h
params.o: /usr/include/endian.h
params.o: /usr/include/bits/endian.h
params.o: /usr/include/sys/select.h
params.o: /usr/include/bits/select.h
params.o: /usr/include/bits/sigset.h
params.o: /usr/include/bits/time.h
params.o: /usr/include/sys/sysmacros.h
params.o: /usr/include/bits/pthreadtypes.h
params.o: /usr/include/alloca.h
params.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
params.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
params.o: /usr/include/limits.h
params.o: /usr/include/bits/posix1_lim.h
params.o: /usr/include/bits/local_lim.h
params.o: /usr/include/linux/limits.h
params.o: /usr/include/bits/posix2_lim.h
params.o: ../../include/ac/string.h
params.o: /usr/include/string.h
params.o: ../../include/ac/syslog.h
params.o: /usr/include/syslog.h
params.o: /usr/include/sys/syslog.h
params.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
params.o: /usr/include/bits/syslog-path.h
params.o: ../../include/ac/regex.h
params.o: /usr/include/regex.h
params.o: ../../include/ac/socket.h
params.o: /usr/include/poll.h
params.o: /usr/include/sys/poll.h
params.o: /usr/include/bits/poll.h
params.o: /usr/include/sys/socket.h
params.o: /usr/include/sys/uio.h
params.o: /usr/include/bits/uio.h
params.o: /usr/include/bits/socket.h
params.o: /usr/include/bits/sockaddr.h
params.o: /usr/include/asm/socket.h
params.o: /usr/include/asm-x86_64/socket.h
params.o: /usr/include/asm/sockios.h
params.o: /usr/include/asm-x86_64/sockios.h
params.o: /usr/include/sys/un.h
params.o: /usr/include/netinet/in.h
params.o: /usr/include/stdint.h
params.o: /usr/include/bits/wchar.h
params.o: /usr/include/bits/in.h
params.o: /usr/include/bits/byteswap.h
params.o: /usr/include/netinet/tcp.h
params.o: /usr/include/arpa/inet.h
params.o: /usr/include/arpa/nameser.h
params.o: /usr/include/sys/param.h
params.o: /usr/include/linux/param.h
params.o: /usr/include/asm/param.h
params.o: /usr/include/asm-x86_64/param.h
params.o: /usr/include/sys/bitypes.h
params.o: /usr/include/arpa/nameser_compat.h
params.o: /usr/include/netdb.h
params.o: /usr/include/rpc/netdb.h
params.o: /usr/include/bits/netdb.h
params.o: /usr/include/resolv.h
params.o: /usr/include/stdio.h
params.o: /usr/include/libio.h
params.o: /usr/include/_G_config.h
params.o: /usr/include/wchar.h
params.o: /usr/include/gconv.h
params.o: /usr/include/bits/stdio_lim.h
params.o: /usr/include/bits/sys_errlist.h
params.o: ../../include/ac/unistd.h
params.o: /usr/include/unistd.h
params.o: /usr/include/bits/posix_opt.h
params.o: /usr/include/bits/confname.h
params.o: /usr/include/getopt.h
params.o: ../../include/lutil_lockf.h
params.o: ../../include/ac/ctype.h
params.o: /usr/include/ctype.h
params.o: ../../include/lber.h
params.o: ../../include/lber_types.h
params.o: ../../include/ldap_cdefs.h
params.o: ../../include/ldap.h
params.o: ../../include/ldap_features.h
params.o: ../libldap/ldap-int.h
params.o: ../libldap/../liblber/lber-int.h
params.o: ../../include/ldap_log.h
params.o: ../../include/lber_pvt.h
params.o: ../../include/ldap_queue.h
params.o: ../../include/lutil.h
params.o: /usr/include/sasl/sasl.h
params.o: /usr/include/sasl/prop.h
params.o: ../../include/ac/time.h
params.o: /usr/include/sys/time.h
params.o: ../../include/ldap_log.h
params.o: ../../include/ldap_pvt.h
params.o: ../../include/lber_pvt.h
params.o: ../../include/ldap_pvt_uc.h
params.o: ../../include/ac/bytes.h
params.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
params.o: ../../include/lutil.h
params.o: ../../include/avl.h
params.o: ../../include/rewrite.h
params.o: ../../include/ldap_pvt_thread.h
params.o: ../../include/ldap_int_thread.h
params.o: /usr/include/pthread.h
params.o: /usr/include/sched.h
params.o: /usr/include/bits/sched.h
params.o: /usr/include/signal.h
params.o: /usr/include/bits/setjmp.h
rule.o: rule.c
rule.o: ../../include/portable.h
rule.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
rule.o: ../../include/ac/fdset.h
rule.o: /usr/include/bits/types.h
rule.o: /usr/include/features.h
rule.o: /usr/include/sys/cdefs.h
rule.o: /usr/include/bits/wordsize.h
rule.o: /usr/include/gnu/stubs.h
rule.o: /usr/include/gnu/stubs-64.h
rule.o: /usr/include/bits/typesizes.h
rule.o: ../../include/ldap_cdefs.h
rule.o: ../../include/ldap_features.h
rule.o: ../../include/ac/assert.h
rule.o: /usr/include/assert.h
rule.o: ../../include/ac/localize.h
rule.o: rewrite-int.h
rule.o: ../../include/ac/stdlib.h
rule.o: /usr/include/stdlib.h
rule.o: /usr/include/sys/types.h
rule.o: /usr/include/time.h
rule.o: /usr/include/endian.h
rule.o: /usr/include/bits/endian.h
rule.o: /usr/include/sys/select.h
rule.o: /usr/include/bits/select.h
rule.o: /usr/include/bits/sigset.h
rule.o: /usr/include/bits/time.h
rule.o: /usr/include/sys/sysmacros.h
rule.o: /usr/include/bits/pthreadtypes.h
rule.o: /usr/include/alloca.h
rule.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
rule.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
rule.o: /usr/include/limits.h
rule.o: /usr/include/bits/posix1_lim.h
rule.o: /usr/include/bits/local_lim.h
rule.o: /usr/include/linux/limits.h
rule.o: /usr/include/bits/posix2_lim.h
rule.o: ../../include/ac/string.h
rule.o: /usr/include/string.h
rule.o: ../../include/ac/syslog.h
rule.o: /usr/include/syslog.h
rule.o: /usr/include/sys/syslog.h
rule.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
rule.o: /usr/include/bits/syslog-path.h
rule.o: ../../include/ac/regex.h
rule.o: /usr/include/regex.h
rule.o: ../../include/ac/socket.h
rule.o: /usr/include/poll.h
rule.o: /usr/include/sys/poll.h
rule.o: /usr/include/bits/poll.h
rule.o: /usr/include/sys/socket.h
rule.o: /usr/include/sys/uio.h
rule.o: /usr/include/bits/uio.h
rule.o: /usr/include/bits/socket.h
rule.o: /usr/include/bits/sockaddr.h
rule.o: /usr/include/asm/socket.h
rule.o: /usr/include/asm-x86_64/socket.h
rule.o: /usr/include/asm/sockios.h
rule.o: /usr/include/asm-x86_64/sockios.h
rule.o: /usr/include/sys/un.h
rule.o: /usr/include/netinet/in.h
rule.o: /usr/include/stdint.h
rule.o: /usr/include/bits/wchar.h
rule.o: /usr/include/bits/in.h
rule.o: /usr/include/bits/byteswap.h
rule.o: /usr/include/netinet/tcp.h
rule.o: /usr/include/arpa/inet.h
rule.o: /usr/include/arpa/nameser.h
rule.o: /usr/include/sys/param.h
rule.o: /usr/include/linux/param.h
rule.o: /usr/include/asm/param.h
rule.o: /usr/include/asm-x86_64/param.h
rule.o: /usr/include/sys/bitypes.h
rule.o: /usr/include/arpa/nameser_compat.h
rule.o: /usr/include/netdb.h
rule.o: /usr/include/rpc/netdb.h
rule.o: /usr/include/bits/netdb.h
rule.o: /usr/include/resolv.h
rule.o: /usr/include/stdio.h
rule.o: /usr/include/libio.h
rule.o: /usr/include/_G_config.h
rule.o: /usr/include/wchar.h
rule.o: /usr/include/gconv.h
rule.o: /usr/include/bits/stdio_lim.h
rule.o: /usr/include/bits/sys_errlist.h
rule.o: ../../include/ac/unistd.h
rule.o: /usr/include/unistd.h
rule.o: /usr/include/bits/posix_opt.h
rule.o: /usr/include/bits/confname.h
rule.o: /usr/include/getopt.h
rule.o: ../../include/lutil_lockf.h
rule.o: ../../include/ac/ctype.h
rule.o: /usr/include/ctype.h
rule.o: ../../include/lber.h
rule.o: ../../include/lber_types.h
rule.o: ../../include/ldap_cdefs.h
rule.o: ../../include/ldap.h
rule.o: ../../include/ldap_features.h
rule.o: ../libldap/ldap-int.h
rule.o: ../libldap/../liblber/lber-int.h
rule.o: ../../include/ldap_log.h
rule.o: ../../include/lber_pvt.h
rule.o: ../../include/ldap_queue.h
rule.o: ../../include/lutil.h
rule.o: /usr/include/sasl/sasl.h
rule.o: /usr/include/sasl/prop.h
rule.o: ../../include/ac/time.h
rule.o: /usr/include/sys/time.h
rule.o: ../../include/ldap_log.h
rule.o: ../../include/ldap_pvt.h
rule.o: ../../include/lber_pvt.h
rule.o: ../../include/ldap_pvt_uc.h
rule.o: ../../include/ac/bytes.h
rule.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
rule.o: ../../include/lutil.h
rule.o: ../../include/avl.h
rule.o: ../../include/rewrite.h
rule.o: ../../include/ldap_pvt_thread.h
rule.o: ../../include/ldap_int_thread.h
rule.o: /usr/include/pthread.h
rule.o: /usr/include/sched.h
rule.o: /usr/include/bits/sched.h
rule.o: /usr/include/signal.h
rule.o: /usr/include/bits/setjmp.h
session.o: session.c
session.o: ../../include/portable.h
session.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
session.o: ../../include/ac/fdset.h
session.o: /usr/include/bits/types.h
session.o: /usr/include/features.h
session.o: /usr/include/sys/cdefs.h
session.o: /usr/include/bits/wordsize.h
session.o: /usr/include/gnu/stubs.h
session.o: /usr/include/gnu/stubs-64.h
session.o: /usr/include/bits/typesizes.h
session.o: ../../include/ldap_cdefs.h
session.o: ../../include/ldap_features.h
session.o: ../../include/ac/assert.h
session.o: /usr/include/assert.h
session.o: ../../include/ac/localize.h
session.o: rewrite-int.h
session.o: ../../include/ac/stdlib.h
session.o: /usr/include/stdlib.h
session.o: /usr/include/sys/types.h
session.o: /usr/include/time.h
session.o: /usr/include/endian.h
session.o: /usr/include/bits/endian.h
session.o: /usr/include/sys/select.h
session.o: /usr/include/bits/select.h
session.o: /usr/include/bits/sigset.h
session.o: /usr/include/bits/time.h
session.o: /usr/include/sys/sysmacros.h
session.o: /usr/include/bits/pthreadtypes.h
session.o: /usr/include/alloca.h
session.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
session.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
session.o: /usr/include/limits.h
session.o: /usr/include/bits/posix1_lim.h
session.o: /usr/include/bits/local_lim.h
session.o: /usr/include/linux/limits.h
session.o: /usr/include/bits/posix2_lim.h
session.o: ../../include/ac/string.h
session.o: /usr/include/string.h
session.o: ../../include/ac/syslog.h
session.o: /usr/include/syslog.h
session.o: /usr/include/sys/syslog.h
session.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
session.o: /usr/include/bits/syslog-path.h
session.o: ../../include/ac/regex.h
session.o: /usr/include/regex.h
session.o: ../../include/ac/socket.h
session.o: /usr/include/poll.h
session.o: /usr/include/sys/poll.h
session.o: /usr/include/bits/poll.h
session.o: /usr/include/sys/socket.h
session.o: /usr/include/sys/uio.h
session.o: /usr/include/bits/uio.h
session.o: /usr/include/bits/socket.h
session.o: /usr/include/bits/sockaddr.h
session.o: /usr/include/asm/socket.h
session.o: /usr/include/asm-x86_64/socket.h
session.o: /usr/include/asm/sockios.h
session.o: /usr/include/asm-x86_64/sockios.h
session.o: /usr/include/sys/un.h
session.o: /usr/include/netinet/in.h
session.o: /usr/include/stdint.h
session.o: /usr/include/bits/wchar.h
session.o: /usr/include/bits/in.h
session.o: /usr/include/bits/byteswap.h
session.o: /usr/include/netinet/tcp.h
session.o: /usr/include/arpa/inet.h
session.o: /usr/include/arpa/nameser.h
session.o: /usr/include/sys/param.h
session.o: /usr/include/linux/param.h
session.o: /usr/include/asm/param.h
session.o: /usr/include/asm-x86_64/param.h
session.o: /usr/include/sys/bitypes.h
session.o: /usr/include/arpa/nameser_compat.h
session.o: /usr/include/netdb.h
session.o: /usr/include/rpc/netdb.h
session.o: /usr/include/bits/netdb.h
session.o: /usr/include/resolv.h
session.o: /usr/include/stdio.h
session.o: /usr/include/libio.h
session.o: /usr/include/_G_config.h
session.o: /usr/include/wchar.h
session.o: /usr/include/gconv.h
session.o: /usr/include/bits/stdio_lim.h
session.o: /usr/include/bits/sys_errlist.h
session.o: ../../include/ac/unistd.h
session.o: /usr/include/unistd.h
session.o: /usr/include/bits/posix_opt.h
session.o: /usr/include/bits/confname.h
session.o: /usr/include/getopt.h
session.o: ../../include/lutil_lockf.h
session.o: ../../include/ac/ctype.h
session.o: /usr/include/ctype.h
session.o: ../../include/lber.h
session.o: ../../include/lber_types.h
session.o: ../../include/ldap_cdefs.h
session.o: ../../include/ldap.h
session.o: ../../include/ldap_features.h
session.o: ../libldap/ldap-int.h
session.o: ../libldap/../liblber/lber-int.h
session.o: ../../include/ldap_log.h
session.o: ../../include/lber_pvt.h
session.o: ../../include/ldap_queue.h
session.o: ../../include/lutil.h
session.o: /usr/include/sasl/sasl.h
session.o: /usr/include/sasl/prop.h
session.o: ../../include/ac/time.h
session.o: /usr/include/sys/time.h
session.o: ../../include/ldap_log.h
session.o: ../../include/ldap_pvt.h
session.o: ../../include/lber_pvt.h
session.o: ../../include/ldap_pvt_uc.h
session.o: ../../include/ac/bytes.h
session.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
session.o: ../../include/lutil.h
session.o: ../../include/avl.h
session.o: ../../include/rewrite.h
session.o: ../../include/ldap_pvt_thread.h
session.o: ../../include/ldap_int_thread.h
session.o: /usr/include/pthread.h
session.o: /usr/include/sched.h
session.o: /usr/include/bits/sched.h
session.o: /usr/include/signal.h
session.o: /usr/include/bits/setjmp.h
subst.o: subst.c
subst.o: ../../include/portable.h
subst.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
subst.o: ../../include/ac/fdset.h
subst.o: /usr/include/bits/types.h
subst.o: /usr/include/features.h
subst.o: /usr/include/sys/cdefs.h
subst.o: /usr/include/bits/wordsize.h
subst.o: /usr/include/gnu/stubs.h
subst.o: /usr/include/gnu/stubs-64.h
subst.o: /usr/include/bits/typesizes.h
subst.o: ../../include/ldap_cdefs.h
subst.o: ../../include/ldap_features.h
subst.o: ../../include/ac/assert.h
subst.o: /usr/include/assert.h
subst.o: ../../include/ac/localize.h
subst.o: rewrite-int.h
subst.o: ../../include/ac/stdlib.h
subst.o: /usr/include/stdlib.h
subst.o: /usr/include/sys/types.h
subst.o: /usr/include/time.h
subst.o: /usr/include/endian.h
subst.o: /usr/include/bits/endian.h
subst.o: /usr/include/sys/select.h
subst.o: /usr/include/bits/select.h
subst.o: /usr/include/bits/sigset.h
subst.o: /usr/include/bits/time.h
subst.o: /usr/include/sys/sysmacros.h
subst.o: /usr/include/bits/pthreadtypes.h
subst.o: /usr/include/alloca.h
subst.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
subst.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
subst.o: /usr/include/limits.h
subst.o: /usr/include/bits/posix1_lim.h
subst.o: /usr/include/bits/local_lim.h
subst.o: /usr/include/linux/limits.h
subst.o: /usr/include/bits/posix2_lim.h
subst.o: ../../include/ac/string.h
subst.o: /usr/include/string.h
subst.o: ../../include/ac/syslog.h
subst.o: /usr/include/syslog.h
subst.o: /usr/include/sys/syslog.h
subst.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
subst.o: /usr/include/bits/syslog-path.h
subst.o: ../../include/ac/regex.h
subst.o: /usr/include/regex.h
subst.o: ../../include/ac/socket.h
subst.o: /usr/include/poll.h
subst.o: /usr/include/sys/poll.h
subst.o: /usr/include/bits/poll.h
subst.o: /usr/include/sys/socket.h
subst.o: /usr/include/sys/uio.h
subst.o: /usr/include/bits/uio.h
subst.o: /usr/include/bits/socket.h
subst.o: /usr/include/bits/sockaddr.h
subst.o: /usr/include/asm/socket.h
subst.o: /usr/include/asm-x86_64/socket.h
subst.o: /usr/include/asm/sockios.h
subst.o: /usr/include/asm-x86_64/sockios.h
subst.o: /usr/include/sys/un.h
subst.o: /usr/include/netinet/in.h
subst.o: /usr/include/stdint.h
subst.o: /usr/include/bits/wchar.h
subst.o: /usr/include/bits/in.h
subst.o: /usr/include/bits/byteswap.h
subst.o: /usr/include/netinet/tcp.h
subst.o: /usr/include/arpa/inet.h
subst.o: /usr/include/arpa/nameser.h
subst.o: /usr/include/sys/param.h
subst.o: /usr/include/linux/param.h
subst.o: /usr/include/asm/param.h
subst.o: /usr/include/asm-x86_64/param.h
subst.o: /usr/include/sys/bitypes.h
subst.o: /usr/include/arpa/nameser_compat.h
subst.o: /usr/include/netdb.h
subst.o: /usr/include/rpc/netdb.h
subst.o: /usr/include/bits/netdb.h
subst.o: /usr/include/resolv.h
subst.o: /usr/include/stdio.h
subst.o: /usr/include/libio.h
subst.o: /usr/include/_G_config.h
subst.o: /usr/include/wchar.h
subst.o: /usr/include/gconv.h
subst.o: /usr/include/bits/stdio_lim.h
subst.o: /usr/include/bits/sys_errlist.h
subst.o: ../../include/ac/unistd.h
subst.o: /usr/include/unistd.h
subst.o: /usr/include/bits/posix_opt.h
subst.o: /usr/include/bits/confname.h
subst.o: /usr/include/getopt.h
subst.o: ../../include/lutil_lockf.h
subst.o: ../../include/ac/ctype.h
subst.o: /usr/include/ctype.h
subst.o: ../../include/lber.h
subst.o: ../../include/lber_types.h
subst.o: ../../include/ldap_cdefs.h
subst.o: ../../include/ldap.h
subst.o: ../../include/ldap_features.h
subst.o: ../libldap/ldap-int.h
subst.o: ../libldap/../liblber/lber-int.h
subst.o: ../../include/ldap_log.h
subst.o: ../../include/lber_pvt.h
subst.o: ../../include/ldap_queue.h
subst.o: ../../include/lutil.h
subst.o: /usr/include/sasl/sasl.h
subst.o: /usr/include/sasl/prop.h
subst.o: ../../include/ac/time.h
subst.o: /usr/include/sys/time.h
subst.o: ../../include/ldap_log.h
subst.o: ../../include/ldap_pvt.h
subst.o: ../../include/lber_pvt.h
subst.o: ../../include/ldap_pvt_uc.h
subst.o: ../../include/ac/bytes.h
subst.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
subst.o: ../../include/lutil.h
subst.o: ../../include/avl.h
subst.o: ../../include/rewrite.h
subst.o: ../../include/ldap_pvt_thread.h
subst.o: ../../include/ldap_int_thread.h
subst.o: /usr/include/pthread.h
subst.o: /usr/include/sched.h
subst.o: /usr/include/bits/sched.h
subst.o: /usr/include/signal.h
subst.o: /usr/include/bits/setjmp.h
var.o: var.c
var.o: ../../include/portable.h
var.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
var.o: ../../include/ac/fdset.h
var.o: /usr/include/bits/types.h
var.o: /usr/include/features.h
var.o: /usr/include/sys/cdefs.h
var.o: /usr/include/bits/wordsize.h
var.o: /usr/include/gnu/stubs.h
var.o: /usr/include/gnu/stubs-64.h
var.o: /usr/include/bits/typesizes.h
var.o: ../../include/ldap_cdefs.h
var.o: ../../include/ldap_features.h
var.o: ../../include/ac/assert.h
var.o: /usr/include/assert.h
var.o: ../../include/ac/localize.h
var.o: rewrite-int.h
var.o: ../../include/ac/stdlib.h
var.o: /usr/include/stdlib.h
var.o: /usr/include/sys/types.h
var.o: /usr/include/time.h
var.o: /usr/include/endian.h
var.o: /usr/include/bits/endian.h
var.o: /usr/include/sys/select.h
var.o: /usr/include/bits/select.h
var.o: /usr/include/bits/sigset.h
var.o: /usr/include/bits/time.h
var.o: /usr/include/sys/sysmacros.h
var.o: /usr/include/bits/pthreadtypes.h
var.o: /usr/include/alloca.h
var.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
var.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
var.o: /usr/include/limits.h
var.o: /usr/include/bits/posix1_lim.h
var.o: /usr/include/bits/local_lim.h
var.o: /usr/include/linux/limits.h
var.o: /usr/include/bits/posix2_lim.h
var.o: ../../include/ac/string.h
var.o: /usr/include/string.h
var.o: ../../include/ac/syslog.h
var.o: /usr/include/syslog.h
var.o: /usr/include/sys/syslog.h
var.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
var.o: /usr/include/bits/syslog-path.h
var.o: ../../include/ac/regex.h
var.o: /usr/include/regex.h
var.o: ../../include/ac/socket.h
var.o: /usr/include/poll.h
var.o: /usr/include/sys/poll.h
var.o: /usr/include/bits/poll.h
var.o: /usr/include/sys/socket.h
var.o: /usr/include/sys/uio.h
var.o: /usr/include/bits/uio.h
var.o: /usr/include/bits/socket.h
var.o: /usr/include/bits/sockaddr.h
var.o: /usr/include/asm/socket.h
var.o: /usr/include/asm-x86_64/socket.h
var.o: /usr/include/asm/sockios.h
var.o: /usr/include/asm-x86_64/sockios.h
var.o: /usr/include/sys/un.h
var.o: /usr/include/netinet/in.h
var.o: /usr/include/stdint.h
var.o: /usr/include/bits/wchar.h
var.o: /usr/include/bits/in.h
var.o: /usr/include/bits/byteswap.h
var.o: /usr/include/netinet/tcp.h
var.o: /usr/include/arpa/inet.h
var.o: /usr/include/arpa/nameser.h
var.o: /usr/include/sys/param.h
var.o: /usr/include/linux/param.h
var.o: /usr/include/asm/param.h
var.o: /usr/include/asm-x86_64/param.h
var.o: /usr/include/sys/bitypes.h
var.o: /usr/include/arpa/nameser_compat.h
var.o: /usr/include/netdb.h
var.o: /usr/include/rpc/netdb.h
var.o: /usr/include/bits/netdb.h
var.o: /usr/include/resolv.h
var.o: /usr/include/stdio.h
var.o: /usr/include/libio.h
var.o: /usr/include/_G_config.h
var.o: /usr/include/wchar.h
var.o: /usr/include/gconv.h
var.o: /usr/include/bits/stdio_lim.h
var.o: /usr/include/bits/sys_errlist.h
var.o: ../../include/ac/unistd.h
var.o: /usr/include/unistd.h
var.o: /usr/include/bits/posix_opt.h
var.o: /usr/include/bits/confname.h
var.o: /usr/include/getopt.h
var.o: ../../include/lutil_lockf.h
var.o: ../../include/ac/ctype.h
var.o: /usr/include/ctype.h
var.o: ../../include/lber.h
var.o: ../../include/lber_types.h
var.o: ../../include/ldap_cdefs.h
var.o: ../../include/ldap.h
var.o: ../../include/ldap_features.h
var.o: ../libldap/ldap-int.h
var.o: ../libldap/../liblber/lber-int.h
var.o: ../../include/ldap_log.h
var.o: ../../include/lber_pvt.h
var.o: ../../include/ldap_queue.h
var.o: ../../include/lutil.h
var.o: /usr/include/sasl/sasl.h
var.o: /usr/include/sasl/prop.h
var.o: ../../include/ac/time.h
var.o: /usr/include/sys/time.h
var.o: ../../include/ldap_log.h
var.o: ../../include/ldap_pvt.h
var.o: ../../include/lber_pvt.h
var.o: ../../include/ldap_pvt_uc.h
var.o: ../../include/ac/bytes.h
var.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
var.o: ../../include/lutil.h
var.o: ../../include/avl.h
var.o: ../../include/rewrite.h
var.o: ../../include/ldap_pvt_thread.h
var.o: ../../include/ldap_int_thread.h
var.o: /usr/include/pthread.h
var.o: /usr/include/sched.h
var.o: /usr/include/bits/sched.h
var.o: /usr/include/signal.h
var.o: /usr/include/bits/setjmp.h
xmap.o: xmap.c
xmap.o: ../../include/portable.h
xmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
xmap.o: ../../include/ac/fdset.h
xmap.o: /usr/include/bits/types.h
xmap.o: /usr/include/features.h
xmap.o: /usr/include/sys/cdefs.h
xmap.o: /usr/include/bits/wordsize.h
xmap.o: /usr/include/gnu/stubs.h
xmap.o: /usr/include/gnu/stubs-64.h
xmap.o: /usr/include/bits/typesizes.h
xmap.o: ../../include/ldap_cdefs.h
xmap.o: ../../include/ldap_features.h
xmap.o: ../../include/ac/assert.h
xmap.o: /usr/include/assert.h
xmap.o: ../../include/ac/localize.h
xmap.o: /usr/include/stdio.h
xmap.o: /usr/include/libio.h
xmap.o: /usr/include/_G_config.h
xmap.o: /usr/include/wchar.h
xmap.o: /usr/include/bits/wchar.h
xmap.o: /usr/include/gconv.h
xmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
xmap.o: /usr/include/bits/stdio_lim.h
xmap.o: /usr/include/bits/sys_errlist.h
xmap.o: /usr/include/pwd.h
xmap.o: rewrite-int.h
xmap.o: ../../include/ac/stdlib.h
xmap.o: /usr/include/stdlib.h
xmap.o: /usr/include/sys/types.h
xmap.o: /usr/include/time.h
xmap.o: /usr/include/endian.h
xmap.o: /usr/include/bits/endian.h
xmap.o: /usr/include/sys/select.h
xmap.o: /usr/include/bits/select.h
xmap.o: /usr/include/bits/sigset.h
xmap.o: /usr/include/bits/time.h
xmap.o: /usr/include/sys/sysmacros.h
xmap.o: /usr/include/bits/pthreadtypes.h
xmap.o: /usr/include/alloca.h
xmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
xmap.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
xmap.o: /usr/include/limits.h
xmap.o: /usr/include/bits/posix1_lim.h
xmap.o: /usr/include/bits/local_lim.h
xmap.o: /usr/include/linux/limits.h
xmap.o: /usr/include/bits/posix2_lim.h
xmap.o: ../../include/ac/string.h
xmap.o: /usr/include/string.h
xmap.o: ../../include/ac/syslog.h
xmap.o: /usr/include/syslog.h
xmap.o: /usr/include/sys/syslog.h
xmap.o: /usr/include/bits/syslog-path.h
xmap.o: ../../include/ac/regex.h
xmap.o: /usr/include/regex.h
xmap.o: ../../include/ac/socket.h
xmap.o: /usr/include/poll.h
xmap.o: /usr/include/sys/poll.h
xmap.o: /usr/include/bits/poll.h
xmap.o: /usr/include/sys/socket.h
xmap.o: /usr/include/sys/uio.h
xmap.o: /usr/include/bits/uio.h
xmap.o: /usr/include/bits/socket.h
xmap.o: /usr/include/bits/sockaddr.h
xmap.o: /usr/include/asm/socket.h
xmap.o: /usr/include/asm-x86_64/socket.h
xmap.o: /usr/include/asm/sockios.h
xmap.o: /usr/include/asm-x86_64/sockios.h
xmap.o: /usr/include/sys/un.h
xmap.o: /usr/include/netinet/in.h
xmap.o: /usr/include/stdint.h
xmap.o: /usr/include/bits/in.h
xmap.o: /usr/include/bits/byteswap.h
xmap.o: /usr/include/netinet/tcp.h
xmap.o: /usr/include/arpa/inet.h
xmap.o: /usr/include/arpa/nameser.h
xmap.o: /usr/include/sys/param.h
xmap.o: /usr/include/linux/param.h
xmap.o: /usr/include/asm/param.h
xmap.o: /usr/include/asm-x86_64/param.h
xmap.o: /usr/include/sys/bitypes.h
xmap.o: /usr/include/arpa/nameser_compat.h
xmap.o: /usr/include/netdb.h
xmap.o: /usr/include/rpc/netdb.h
xmap.o: /usr/include/bits/netdb.h
xmap.o: /usr/include/resolv.h
xmap.o: ../../include/ac/unistd.h
xmap.o: /usr/include/unistd.h
xmap.o: /usr/include/bits/posix_opt.h
xmap.o: /usr/include/bits/confname.h
xmap.o: /usr/include/getopt.h
xmap.o: ../../include/lutil_lockf.h
xmap.o: ../../include/ac/ctype.h
xmap.o: /usr/include/ctype.h
xmap.o: ../../include/lber.h
xmap.o: ../../include/lber_types.h
xmap.o: ../../include/ldap_cdefs.h
xmap.o: ../../include/ldap.h
xmap.o: ../../include/ldap_features.h
xmap.o: ../libldap/ldap-int.h
xmap.o: ../libldap/../liblber/lber-int.h
xmap.o: ../../include/ldap_log.h
xmap.o: ../../include/lber_pvt.h
xmap.o: ../../include/ldap_queue.h
xmap.o: ../../include/lutil.h
xmap.o: /usr/include/sasl/sasl.h
xmap.o: /usr/include/sasl/prop.h
xmap.o: ../../include/ac/time.h
xmap.o: /usr/include/sys/time.h
xmap.o: ../../include/ldap_log.h
xmap.o: ../../include/ldap_pvt.h
xmap.o: ../../include/lber_pvt.h
xmap.o: ../../include/ldap_pvt_uc.h
xmap.o: ../../include/ac/bytes.h
xmap.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
xmap.o: ../../include/lutil.h
xmap.o: ../../include/avl.h
xmap.o: ../../include/rewrite.h
xmap.o: ../../include/ldap_pvt_thread.h
xmap.o: ../../include/ldap_int_thread.h
xmap.o: /usr/include/pthread.h
xmap.o: /usr/include/sched.h
xmap.o: /usr/include/bits/sched.h
xmap.o: /usr/include/signal.h
xmap.o: /usr/include/bits/setjmp.h
xmap.o: rewrite-map.h
parse.o: parse.c
parse.o: ../../include/portable.h
parse.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
parse.o: ../../include/ac/fdset.h
parse.o: /usr/include/bits/types.h
parse.o: /usr/include/features.h
parse.o: /usr/include/sys/cdefs.h
parse.o: /usr/include/bits/wordsize.h
parse.o: /usr/include/gnu/stubs.h
parse.o: /usr/include/gnu/stubs-64.h
parse.o: /usr/include/bits/typesizes.h
parse.o: ../../include/ldap_cdefs.h
parse.o: ../../include/ldap_features.h
parse.o: ../../include/ac/assert.h
parse.o: /usr/include/assert.h
parse.o: ../../include/ac/localize.h
parse.o: /usr/include/stdio.h
parse.o: /usr/include/libio.h
parse.o: /usr/include/_G_config.h
parse.o: /usr/include/wchar.h
parse.o: /usr/include/bits/wchar.h
parse.o: /usr/include/gconv.h
parse.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
parse.o: /usr/include/bits/stdio_lim.h
parse.o: /usr/include/bits/sys_errlist.h
parse.o: rewrite-int.h
parse.o: ../../include/ac/stdlib.h
parse.o: /usr/include/stdlib.h
parse.o: /usr/include/sys/types.h
parse.o: /usr/include/time.h
parse.o: /usr/include/endian.h
parse.o: /usr/include/bits/endian.h
parse.o: /usr/include/sys/select.h
parse.o: /usr/include/bits/select.h
parse.o: /usr/include/bits/sigset.h
parse.o: /usr/include/bits/time.h
parse.o: /usr/include/sys/sysmacros.h
parse.o: /usr/include/bits/pthreadtypes.h
parse.o: /usr/include/alloca.h
parse.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
parse.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
parse.o: /usr/include/limits.h
parse.o: /usr/include/bits/posix1_lim.h
parse.o: /usr/include/bits/local_lim.h
parse.o: /usr/include/linux/limits.h
parse.o: /usr/include/bits/posix2_lim.h
parse.o: ../../include/ac/string.h
parse.o: /usr/include/string.h
parse.o: ../../include/ac/syslog.h
parse.o: /usr/include/syslog.h
parse.o: /usr/include/sys/syslog.h
parse.o: /usr/include/bits/syslog-path.h
parse.o: ../../include/ac/regex.h
parse.o: /usr/include/regex.h
parse.o: ../../include/ac/socket.h
parse.o: /usr/include/poll.h
parse.o: /usr/include/sys/poll.h
parse.o: /usr/include/bits/poll.h
parse.o: /usr/include/sys/socket.h
parse.o: /usr/include/sys/uio.h
parse.o: /usr/include/bits/uio.h
parse.o: /usr/include/bits/socket.h
parse.o: /usr/include/bits/sockaddr.h
parse.o: /usr/include/asm/socket.h
parse.o: /usr/include/asm-x86_64/socket.h
parse.o: /usr/include/asm/sockios.h
parse.o: /usr/include/asm-x86_64/sockios.h
parse.o: /usr/include/sys/un.h
parse.o: /usr/include/netinet/in.h
parse.o: /usr/include/stdint.h
parse.o: /usr/include/bits/in.h
parse.o: /usr/include/bits/byteswap.h
parse.o: /usr/include/netinet/tcp.h
parse.o: /usr/include/arpa/inet.h
parse.o: /usr/include/arpa/nameser.h
parse.o: /usr/include/sys/param.h
parse.o: /usr/include/linux/param.h
parse.o: /usr/include/asm/param.h
parse.o: /usr/include/asm-x86_64/param.h
parse.o: /usr/include/sys/bitypes.h
parse.o: /usr/include/arpa/nameser_compat.h
parse.o: /usr/include/netdb.h
parse.o: /usr/include/rpc/netdb.h
parse.o: /usr/include/bits/netdb.h
parse.o: /usr/include/resolv.h
parse.o: ../../include/ac/unistd.h
parse.o: /usr/include/unistd.h
parse.o: /usr/include/bits/posix_opt.h
parse.o: /usr/include/bits/confname.h
parse.o: /usr/include/getopt.h
parse.o: ../../include/lutil_lockf.h
parse.o: ../../include/ac/ctype.h
parse.o: /usr/include/ctype.h
parse.o: ../../include/lber.h
parse.o: ../../include/lber_types.h
parse.o: ../../include/ldap_cdefs.h
parse.o: ../../include/ldap.h
parse.o: ../../include/ldap_features.h
parse.o: ../libldap/ldap-int.h
parse.o: ../libldap/../liblber/lber-int.h
parse.o: ../../include/ldap_log.h
parse.o: ../../include/lber_pvt.h
parse.o: ../../include/ldap_queue.h
parse.o: ../../include/lutil.h
parse.o: /usr/include/sasl/sasl.h
parse.o: /usr/include/sasl/prop.h
parse.o: ../../include/ac/time.h
parse.o: /usr/include/sys/time.h
parse.o: ../../include/ldap_log.h
parse.o: ../../include/ldap_pvt.h
parse.o: ../../include/lber_pvt.h
parse.o: ../../include/ldap_pvt_uc.h
parse.o: ../../include/ac/bytes.h
parse.o: ../../include/../libraries/liblunicode/ucdata/ucdata.h
parse.o: ../../include/lutil.h
parse.o: ../../include/avl.h
parse.o: ../../include/rewrite.h
parse.o: ../../include/ldap_pvt_thread.h
parse.o: ../../include/ldap_int_thread.h
parse.o: /usr/include/pthread.h
parse.o: /usr/include/sched.h
parse.o: /usr/include/bits/sched.h
parse.o: /usr/include/signal.h
parse.o: /usr/include/bits/setjmp.h
rewrite.o: rewrite.c
rewrite.o: ../../include/portable.h
rewrite.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stddef.h
rewrite.o: ../../include/ac/fdset.h
rewrite.o: /usr/include/bits/types.h
rewrite.o: /usr/include/features.h
rewrite.o: /usr/include/sys/cdefs.h
rewrite.o: /usr/include/bits/wordsize.h
rewrite.o: /usr/include/gnu/stubs.h
rewrite.o: /usr/include/gnu/stubs-64.h
rewrite.o: /usr/include/bits/typesizes.h
rewrite.o: ../../include/ldap_cdefs.h
rewrite.o: ../../include/ldap_features.h
rewrite.o: ../../include/ac/assert.h
rewrite.o: /usr/include/assert.h
rewrite.o: ../../include/ac/localize.h
rewrite.o: ../../include/ac/stdlib.h
rewrite.o: /usr/include/stdlib.h
rewrite.o: /usr/include/sys/types.h
rewrite.o: /usr/include/time.h
rewrite.o: /usr/include/endian.h
rewrite.o: /usr/include/bits/endian.h
rewrite.o: /usr/include/sys/select.h
rewrite.o: /usr/include/bits/select.h
rewrite.o: /usr/include/bits/sigset.h
rewrite.o: /usr/include/bits/time.h
rewrite.o: /usr/include/sys/sysmacros.h
rewrite.o: /usr/include/bits/pthreadtypes.h
rewrite.o: /usr/include/alloca.h
rewrite.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/limits.h
rewrite.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/syslimits.h
rewrite.o: /usr/include/limits.h
rewrite.o: /usr/include/bits/posix1_lim.h
rewrite.o: /usr/include/bits/local_lim.h
rewrite.o: /usr/include/linux/limits.h
rewrite.o: /usr/include/bits/posix2_lim.h
rewrite.o: ../../include/ac/string.h
rewrite.o: /usr/include/string.h
rewrite.o: ../../include/ac/syslog.h
rewrite.o: /usr/include/syslog.h
rewrite.o: /usr/include/sys/syslog.h
rewrite.o: /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h
rewrite.o: /usr/include/bits/syslog-path.h
rewrite.o: ../../include/ac/regex.h
rewrite.o: /usr/include/regex.h
rewrite.o: ../../include/ac/socket.h
rewrite.o: /usr/include/poll.h
rewrite.o: /usr/include/sys/poll.h
rewrite.o: /usr/include/bits/poll.h
rewrite.o: /usr/include/sys/socket.h
rewrite.o: /usr/include/sys/uio.h
rewrite.o: /usr/include/bits/uio.h
rewrite.o: /usr/include/bits/socket.h
rewrite.o: /usr/include/bits/sockaddr.h
rewrite.o: /usr/include/asm/socket.h
rewrite.o: /usr/include/asm-x86_64/socket.h
rewrite.o: /usr/include/asm/sockios.h
rewrite.o: /usr/include/asm-x86_64/sockios.h
rewrite.o: /usr/include/sys/un.h
rewrite.o: /usr/include/netinet/in.h
rewrite.o: /usr/include/stdint.h
rewrite.o: /usr/include/bits/wchar.h
rewrite.o: /usr/include/bits/in.h
rewrite.o: /usr/include/bits/byteswap.h
rewrite.o: /usr/include/netinet/tcp.h
rewrite.o: /usr/include/arpa/inet.h
rewrite.o: /usr/include/arpa/nameser.h
rewrite.o: /usr/include/sys/param.h
rewrite.o: /usr/include/linux/param.h
rewrite.o: /usr/include/asm/param.h
rewrite.o: /usr/include/asm-x86_64/param.h
rewrite.o: /usr/include/sys/bitypes.h
rewrite.o: /usr/include/arpa/nameser_compat.h
rewrite.o: /usr/include/netdb.h
rewrite.o: /usr/include/rpc/netdb.h
rewrite.o: /usr/include/bits/netdb.h
rewrite.o: /usr/include/resolv.h
rewrite.o: /usr/include/stdio.h
rewrite.o: /usr/include/libio.h
rewrite.o: /usr/include/_G_config.h
rewrite.o: /usr/include/wchar.h
rewrite.o: /usr/include/gconv.h
rewrite.o: /usr/include/bits/stdio_lim.h
rewrite.o: /usr/include/bits/sys_errlist.h
rewrite.o: ../../include/ac/unistd.h
rewrite.o: /usr/include/unistd.h
rewrite.o: /usr/include/bits/posix_opt.h
rewrite.o: /usr/include/bits/confname.h
rewrite.o: /usr/include/getopt.h
rewrite.o: ../../include/lutil_lockf.h
rewrite.o: ../../include/ac/ctype.h
rewrite.o: /usr/include/ctype.h
rewrite.o: ../../include/rewrite.h
rewrite.o: ../../include/lutil.h
rewrite.o: ../../include/ldap_cdefs.h
rewrite.o: ../../include/lber_types.h
rewrite.o: ../../include/ldap.h
rewrite.o: ../../include/lber.h
rewrite.o: ../../include/ldap_features.h

# IF YOU PUT ANYTHING HERE IT WILL GO AWAY
