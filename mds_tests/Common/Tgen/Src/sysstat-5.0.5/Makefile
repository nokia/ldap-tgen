# Makefile to build sysstat commands
# (C) 1999-2004 Sebastien GODARD (sysstat <at> wanadoo.fr)

# Version
VERSION = 5.0.5

include build/CONFIG

# Compiler to use
CC = gcc
# 'ar' command
AR = ar
# Other commands
SED = sed
CHMOD = chmod
CHOWN = chown
# Full path to prevent from using aliases
CP = /bin/cp

# Directories
ifndef PREFIX
PREFIX = /usr
endif
DESTDIR = $(RPM_BUILD_ROOT)
BIN_DIR = $(PREFIX)/bin
LIB_DIR = $(PREFIX)/lib
ifndef MAN_DIR
MAN_DIR = $(PREFIX)/man
endif
MAN1_DIR = $(MAN_DIR)/man1
MAN8_DIR = $(MAN_DIR)/man8
DOC_DIR = $(PREFIX)/doc/sysstat-$(VERSION)
NLS_DIR = $(PREFIX)/share/locale

# Compiler flags
CFLAGS = -Wall -Wstrict-prototypes -pipe -O2 -fno-strength-reduce
LFLAGS = -L. -lsysstat -s
SAS_DFLAGS += -DSA_DIR=\"$(SA_DIR)\"

# NLS (National Language Support)
# Package name
PACKAGE = sysstat
# The msgfmt command
MSGFMT = msgfmt

ifndef IGNORE_MAN_GROUP
MANGRPARG = -g $(MAN_GROUP)
else
MANGRPARG =
endif

# Run-command directories
ifndef RC_DIR
RC_DIR = /etc/rc.d
endif
RC2_DIR = $(RC_DIR)/rc2.d
RC3_DIR = $(RC_DIR)/rc3.d
RC5_DIR = $(RC_DIR)/rc5.d
ifndef INIT_DIR
INIT_DIR = /etc/rc.d/init.d
endif
ifndef INITD_DIR
INITD_DIR = init.d
endif

all: sadc sa1 sa2 crontab sysstat sar iostat mpstat locales

common.o: common.c common.h
	$(CC) -c -o $@ $(CFLAGS) $(DFLAGS) $<

libsysstat.a: common.o
	$(AR) r $@ $<
	$(AR) s $@

version.h: version.in
	$(SED) s+VERSION_NUMBER+$(VERSION)+g $< > $@

sadc: sadc.c sa.h common.h version.h libsysstat.a
	$(CC) -o $@ $(CFLAGS) $(DFLAGS) $(SAS_DFLAGS) $< $(LFLAGS)

sapath.h: sapath.in
	$(SED) s+ALTLOC+$(PREFIX)+g $< > $@

sa1: sa1.sh
	$(SED) -e s+PREFIX+$(PREFIX)+g -e s+SA_DIR+$(SA_DIR)+g $< > $@
	$(CHMOD) 755 $@

sa2: sa2.sh
	$(SED) -e s+BIN_DIR+$(BIN_DIR)+g -e s+SA_DIR+$(SA_DIR)+g \
		-e s+PREFIX+$(PREFIX)+g -e s+YESTERDAY+$(YESTERDAY)+g \
		-e s+HISTORY+$(HISTORY)+g $< > $@
	$(CHMOD) 755 $@

sysstat: sysstat.sh
ifeq ($(INSTALL_CRON),y)
ifeq ($(CRON_OWNER),root)
	$(SED) -e s+PREFIX/+$(PREFIX)/+g -e 's+ QUOTE++g' $< > sysstat
else
	$(SED) -e 's+PREFIX/+su $(CRON_OWNER) -c "$(PREFIX)/+g' \
		-e 's+ QUOTE+"+g' $< > sysstat
endif
else
	$(SED) -e s+PREFIX/+$(PREFIX)/+g -e 's+ QUOTE++g' $< > sysstat
endif
	$(CHMOD) 755 sysstat
	
crontab: crontab.sample
	$(SED) s+PREFIX/+$(PREFIX)/+g $< > $@

sar: sar.c sa.h common.h version.h sapath.h libsysstat.a
	$(CC) -o $@ $(CFLAGS) $(DFLAGS) $(SAS_DFLAGS) $< $(LFLAGS)

iostat: iostat.c iostat.h common.h version.h libsysstat.a
	$(CC) -o $@ $(CFLAGS) $(DFLAGS) $(IOS_DFLAGS) $< $(LFLAGS)

mpstat: mpstat.c mpstat.h common.h version.h libsysstat.a
	$(CC) -o $@ $(CFLAGS) $(DFLAGS) $< $(LFLAGS)

ifdef REQUIRE_NLS
locales: nls/fr/$(PACKAGE).mo nls/de/$(PACKAGE).mo nls/es/$(PACKAGE).mo nls/pt/$(PACKAGE).mo nls/af/$(PACKAGE).mo nls/nb_NO/$(PACKAGE).mo nls/nn_NO/$(PACKAGE).mo nls/it/$(PACKAGE).mo nls/ru/$(PACKAGE).mo nls/ro/$(PACKAGE).mo nls/pl/$(PACKAGE).mo nls/sk/$(PACKAGE).mo nls/ja/$(PACKAGE).mo
else
locales:
endif

nls/fr/$(PACKAGE).mo: nls/fr/$(PACKAGE).po
	$(MSGFMT) -o nls/fr/$(PACKAGE).mo nls/fr/$(PACKAGE).po

nls/de/$(PACKAGE).mo: nls/de/$(PACKAGE).po
	$(MSGFMT) -o nls/de/$(PACKAGE).mo nls/de/$(PACKAGE).po

nls/es/$(PACKAGE).mo: nls/es/$(PACKAGE).po
	$(MSGFMT) -o nls/es/$(PACKAGE).mo nls/es/$(PACKAGE).po

nls/pt/$(PACKAGE).mo: nls/pt/$(PACKAGE).po
	$(MSGFMT) -o nls/pt/$(PACKAGE).mo nls/pt/$(PACKAGE).po

nls/af/$(PACKAGE).mo: nls/af/$(PACKAGE).po
	$(MSGFMT) -o nls/af/$(PACKAGE).mo nls/af/$(PACKAGE).po

nls/nb_NO/$(PACKAGE).mo: nls/nb_NO/$(PACKAGE).po
	$(MSGFMT) -o nls/nb_NO/$(PACKAGE).mo nls/nb_NO/$(PACKAGE).po

nls/nn_NO/$(PACKAGE).mo: nls/nn_NO/$(PACKAGE).po
	$(MSGFMT) -o nls/nn_NO/$(PACKAGE).mo nls/nn_NO/$(PACKAGE).po

nls/it/$(PACKAGE).mo: nls/it/$(PACKAGE).po
	$(MSGFMT) -o nls/it/$(PACKAGE).mo nls/it/$(PACKAGE).po

nls/ru/$(PACKAGE).mo: nls/ru/$(PACKAGE).po
	$(MSGFMT) -o nls/ru/$(PACKAGE).mo nls/ru/$(PACKAGE).po

nls/ro/$(PACKAGE).mo: nls/ro/$(PACKAGE).po
	$(MSGFMT) -o nls/ro/$(PACKAGE).mo nls/ro/$(PACKAGE).po

nls/pl/$(PACKAGE).mo: nls/pl/$(PACKAGE).po
	$(MSGFMT) -o nls/pl/$(PACKAGE).mo nls/pl/$(PACKAGE).po

nls/sk/$(PACKAGE).mo: nls/sk/$(PACKAGE).po
	$(MSGFMT) -o nls/sk/$(PACKAGE).mo nls/sk/$(PACKAGE).po

nls/ja/$(PACKAGE).mo: nls/ja/$(PACKAGE).po
	$(MSGFMT) -o nls/ja/$(PACKAGE).mo nls/ja/$(PACKAGE).po

# Phony targets
.PHONY: clean distclean config install install_base install_all uninstall uninstall_base uninstall_all dist squeeze

uninstall_base:
	rm -f $(DESTDIR)$(LIB_DIR)/sa/sadc
	rm -f $(DESTDIR)$(MAN8_DIR)/sadc.8
	rm -f $(DESTDIR)$(LIB_DIR)/sa/sa1
	rm -f $(DESTDIR)$(MAN8_DIR)/sa1.8
	rm -f $(DESTDIR)$(LIB_DIR)/sa/sa2
	rm -f $(DESTDIR)$(MAN8_DIR)/sa2.8
	rm -f $(DESTDIR)$(BIN_DIR)/sar
	rm -f $(DESTDIR)$(MAN1_DIR)/sar.1
	rm -f $(DESTDIR)$(BIN_DIR)/iostat
	rm -f $(DESTDIR)$(MAN1_DIR)/iostat.1
	rm -f $(DESTDIR)$(BIN_DIR)/mpstat
	rm -f $(DESTDIR)$(MAN1_DIR)/mpstat.1
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(LIB_DIR)/sa
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(SA_DIR)
	rm -f $(DESTDIR)$(PREFIX)/share/locale/fr/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/de/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/es/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/pt/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/af/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/nb_NO/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/nn_NO/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/it/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/ru/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/ro/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/pl/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/sk/LC_MESSAGES/$(PACKAGE).mo
	rm -f $(DESTDIR)$(PREFIX)/share/locale/ja/LC_MESSAGES/$(PACKAGE).mo
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/fr/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/de/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/es/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/pt/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/af/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/nb_NO/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/nn_NO/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/it/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ru/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ro/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/pl/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/sk/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ja/LC_MESSAGES
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/fr
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/de
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/es
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/pt
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/af
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/nb_NO
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/nn_NO
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/it
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ru
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ro
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/pl
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/sk
	-rmdir --ignore-fail-on-non-empty $(DESTDIR)$(PREFIX)/share/locale/ja
	rm -f $(DESTDIR)$(DOC_DIR)/*
	-rmdir $(DESTDIR)$(DOC_DIR)
	@echo "Please ignore the errors above, if any."

uninstall_all: uninstall_base
	-su $(CRON_OWNER) -c "crontab -l > /tmp/crontab-$(CRON_OWNER).old"
	-$(CP) -a /tmp/crontab-$(CRON_OWNER).old ./crontab-$(CRON_OWNER).`date '+%Y%m%d.%H%M%S'`.old
	@echo "USER CRONTAB SAVED IN CURRENT DIRECTORY (WITH .old SUFFIX)."
	-su $(CRON_OWNER) -c "crontab -r"
	rm -f $(DESTDIR)$(INIT_DIR)/sysstat
	rm -f $(DESTDIR)$(RC2_DIR)/S03sysstat
	rm -f $(DESTDIR)$(RC3_DIR)/S03sysstat
	rm -f $(DESTDIR)$(RC5_DIR)/S03sysstat

install_base: all man/sadc.8 man/sar.1 man/sa1.8 man/sa2.8 man/iostat.1
	mkdir -p $(DESTDIR)$(LIB_DIR)/sa
	mkdir -p $(DESTDIR)$(MAN1_DIR)
	mkdir -p $(DESTDIR)$(MAN8_DIR)
	mkdir -p $(DESTDIR)$(SA_DIR)
ifeq ($(CLEAN_SA_DIR),y)
	rm -f $(DESTDIR)$(SA_DIR)/sa??
endif
	mkdir -p $(DESTDIR)$(BIN_DIR)
	mkdir -p $(DESTDIR)$(DOC_DIR)
	install -m 755 sadc $(DESTDIR)$(LIB_DIR)/sa
	install -m 644 $(MANGRPARG) man/sadc.8 $(DESTDIR)$(MAN8_DIR)
	install -m 755 sa1 $(DESTDIR)$(LIB_DIR)/sa
	install -m 644 $(MANGRPARG) man/sa1.8 $(DESTDIR)$(MAN8_DIR)
	install -m 755 sa2 $(DESTDIR)$(LIB_DIR)/sa
	install -m 644 $(MANGRPARG) man/sa2.8 $(DESTDIR)$(MAN8_DIR)
	install -m 755 sar $(DESTDIR)$(BIN_DIR)
	install -m 644 $(MANGRPARG) man/sar.1 $(DESTDIR)$(MAN1_DIR)
	install -m 755 iostat $(DESTDIR)$(BIN_DIR)
	install -m 644 $(MANGRPARG) man/iostat.1 $(DESTDIR)$(MAN1_DIR)
	install -m 755 mpstat $(DESTDIR)$(BIN_DIR)
	install -m 644 $(MANGRPARG) man/mpstat.1 $(DESTDIR)$(MAN1_DIR)
	install -m 644 CHANGES $(DESTDIR)$(DOC_DIR)
	install -m 644 COPYING $(DESTDIR)$(DOC_DIR)
	install -m 644 CREDITS $(DESTDIR)$(DOC_DIR)
	install -m 644 README  $(DESTDIR)$(DOC_DIR)
	install -m 644 FAQ     $(DESTDIR)$(DOC_DIR)
	install -m 644 *.lsm   $(DESTDIR)$(DOC_DIR)
ifdef REQUIRE_NLS
	mkdir -p $(DESTDIR)$(NLS_DIR)/fr/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/de/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/es/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/pt/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/af/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/nb_NO/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/nn_NO/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/it/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/ru/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/ro/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/pl/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/sk/LC_MESSAGES
	mkdir -p $(DESTDIR)$(NLS_DIR)/ja/LC_MESSAGES
	install -m 644 nls/fr/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/fr/LC_MESSAGES
	install -m 644 nls/de/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/de/LC_MESSAGES
	install -m 644 nls/es/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/es/LC_MESSAGES
	install -m 644 nls/pt/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/pt/LC_MESSAGES
	install -m 644 nls/af/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/af/LC_MESSAGES
	install -m 644 nls/nb_NO/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/nb_NO/LC_MESSAGES
	install -m 644 nls/nn_NO/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/nn_NO/LC_MESSAGES
	install -m 644 nls/it/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/it/LC_MESSAGES
	install -m 644 nls/ru/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/ru/LC_MESSAGES
	install -m 644 nls/ro/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/ro/LC_MESSAGES
	install -m 644 nls/pl/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/pl/LC_MESSAGES
	install -m 644 nls/sk/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/sk/LC_MESSAGES
	install -m 644 nls/ja/$(PACKAGE).mo $(DESTDIR)$(NLS_DIR)/ja/LC_MESSAGES
endif

# NB: Leading minus sign tells make to ignore errors...
install_all: install_base
	$(CHOWN) $(CRON_OWNER) $(DESTDIR)$(SA_DIR)
	-su $(CRON_OWNER) -c "crontab -l > /tmp/crontab-$(CRON_OWNER).save"
	-$(CP) -a /tmp/crontab-$(CRON_OWNER).save ./crontab-$(CRON_OWNER).`date '+%Y%m%d.%H%M%S'`.save
	@echo "USER PREVIOUS CRONTAB SAVED IN CURRENT DIRECTORY (USING .save SUFFIX)."
	-su $(CRON_OWNER) -c "crontab crontab"
	if [ -d $(DESTDIR)$(INIT_DIR) ]; then \
	   install -m 755 sysstat $(DESTDIR)$(INIT_DIR)/sysstat; \
	fi
	cd $(DESTDIR)$(RC2_DIR) && ln -sf ../$(INITD_DIR)/sysstat S03sysstat
	cd $(DESTDIR)$(RC3_DIR) && ln -sf ../$(INITD_DIR)/sysstat S03sysstat
	cd $(DESTDIR)$(RC5_DIR) && ln -sf ../$(INITD_DIR)/sysstat S03sysstat


ifeq ($(INSTALL_CRON),y)
uninstall: uninstall_all
else
uninstall: uninstall_base
endif

ifeq ($(INSTALL_CRON),y)
install: install_all
else
install: install_base
endif

clean:
	rm -f sadc sa1 sa2 sysstat sar iostat mpstat *.o *.a core TAGS crontab
	rm -f sapath.h version.h
	find nls -name "*.mo" -exec rm -f {} \;

distclean: clean
	$(CP) build/CONFIG.def build/CONFIG
	rm -f *.save *.old .*.swp data

dist: distclean
	cd .. && (tar -cvf - sysstat-$(VERSION) | gzip -v9 > sysstat-$(VERSION).tar.gz)

bdist: distclean
	cd .. && (tar -cvf - sysstat-$(VERSION) | bzip2 > sysstat-$(VERSION).tar.bz2)

config: clean
	@sh build/Configure.sh

squeeze:
	sed 's/ *$$//g' sar.c > squeeze-file
	mv squeeze-file sar.c
	sed 's/ *$$//g' sadc.c > squeeze-file
	mv squeeze-file sadc.c
	sed 's/ *$$//g' iostat.c > squeeze-file
	mv squeeze-file iostat.c
	sed 's/ *$$//g' mpstat.c > squeeze-file
	mv squeeze-file mpstat.c
	sed 's/ *$$//g' common.c > squeeze-file
	mv squeeze-file common.c
	sed 's/ *$$//g' common.h > squeeze-file
	mv squeeze-file common.h
	sed 's/ *$$//g' iostat.h > squeeze-file
	mv squeeze-file iostat.h
	sed 's/ *$$//g' mpstat.h > squeeze-file
	mv squeeze-file mpstat.h
	sed 's/ *$$//g' sa.h > squeeze-file
	mv squeeze-file sa.h
	sed 's/ *$$//g' version.in > squeeze-file
	mv squeeze-file version.in
	sed 's/ *$$//g' sapath.in > squeeze-file
	mv squeeze-file sapath.in

tags:
	etags ./*.[hc]

