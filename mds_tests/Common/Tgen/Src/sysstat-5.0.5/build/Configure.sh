#!/bin/sh
# Configuration script for sysstat
# (C) 2000-2004 Sebastien GODARD (sysstat <at> wanadoo.fr)

ASK="sh build/Ask.sh"

echo ; echo
echo You can enter a ? to display a help message at any time...
echo

# Installation directory

PREFIX=`${ASK} 'Installation directory:' "/usr/local" "prefix"`
if [ ! -d ${PREFIX} ]; then
	echo "WARNING: Directory ${PREFIX} not found: Using default (/usr/local)."
	PREFIX=/usr/local
fi

# System Activity directory

SA_DIR=`${ASK} 'System activity directory:' "/var/log/sa" "sa-dir"`
if [ ! -d ${SA_DIR} ]; then
	echo "INFO: Directory ${SA_DIR} will be created during installation stage."
fi

CLEAN_SA_DIR=`${ASK} 'Clean system activity directory?' "n" "clean-sa-dir"`

# National Language Support
NLS=`${ASK} 'Enable National Language Support (NLS)?' "y" "nls"`
which msgfmt > /dev/null 2>&1
WHICH=`echo $?`
if [ "${NLS}" = "y" -a ${WHICH} -eq 1 ]; then
	echo WARNING: msgfmt command not found!
fi

# Linux SMP race workaround

SMPRACE=`${ASK} 'Linux SMP race in serial driver workaround?' "n" "smp-race"`

# sa2 processes data file of the day before

YESTERDAY=`${ASK} 'sa2 uses daily data file of previous day?' "n" "yesterday"`
if [ "${YESTERDAY}" = "y" ];
then
	YDAY="--date=yesterday"
else
	YDAY=""
fi

# Data history to keep by sa2

HISTORY=`${ASK} 'Number of daily data files to keep:' "7" "history"`

# Manual page group

grep ^man: /etc/group >/dev/null 2>&1
if [ $? -eq 1 ];
then
	GRP=root
else
	GRP=man
fi
MAN=`${ASK} 'Group for manual pages:' "${GRP}" "man-group"`
grep ^${MAN}: /etc/group >/dev/null 2>&1
if [ $? -eq 1 ];
then
	echo WARNING: Group ${MAN} not found: Using ${GRP} instead.
	MAN=${GRP}
fi

# Set system directories

if [ -d /etc/init.d ];
then
	if [ -d /etc/init.d/rc2.d ];
	then
		RC_DIR=/etc/init.d
		INITD_DIR=.
	else
		RC_DIR=/etc
		INITD_DIR=init.d
	fi
	INIT_DIR=/etc/init.d
elif [ -d /sbin/init.d ];
then
	RC_DIR=/sbin/init.d
	INIT_DIR=/sbin/init.d
	INITD_DIR=.
else
	RC_DIR=/etc/rc.d
	INIT_DIR=/etc/rc.d/init.d
	INITD_DIR=init.d
fi

# Crontab

grep ^adm: /etc/passwd >/dev/null 2>&1
if [ $? -eq 1 ];
then
	USR=root
else
	USR=adm
fi
CRON_OWNER=${USR}
CRON=`${ASK} 'Set crontab to start sar automatically?' "n" "start-crontab"`
if [ "${CRON}" = "y" ];
then
	CRON_OWNER=`${ASK} 'Crontab owner (his crontab will be saved in current directory):' "${USR}" "crontab-owner"`

	grep ^${CRON_OWNER}: /etc/passwd >/dev/null 2>&1
	if [ $? -eq 1 ];
	then
		echo WARNING: User ${CRON_OWNER} not found: Using ${USR} instead.
		CRON_OWNER=${USR}
	fi
fi

# Man directory

if [ -L ${PREFIX}/man -a -d ${PREFIX}/share/man ];
then
	MANDIR=${PREFIX}/share/man
else
	MANDIR=${PREFIX}/man
fi

echo
echo " man directory is ${MANDIR}"
echo "  rc directory is ${RC_DIR}"
echo "init directory is ${INIT_DIR}"
echo

# Create CONFIG file

echo -n Creating CONFIG file now... 

sed <build/CONFIG.in >build/CONFIG \
	-e "s+^\\(PREFIX =\\)\$+\\1 ${PREFIX}+" \
	-e "s+^\\(SA_DIR =\\)\$+\\1 ${SA_DIR}+" \
	-e "s+^\\(MAN_DIR =\\)\$+\\1 ${MANDIR}+" \
	-e "s+^\\(CLEAN_SA_DIR =\\)\$+\\1 ${CLEAN_SA_DIR}+" \
	-e "s+^\\(ENABLE_NLS =\\)\$+\\1 ${NLS}+" \
	-e "s+^\\(ENABLE_SMP_WRKARD =\\)\$+\\1 ${SMPRACE}+" \
	-e "s+^\\(YESTERDAY =\\)\$+\\1 ${YDAY}+" \
	-e "s+^\\(HISTORY =\\)\$+\\1 ${HISTORY}+" \
	-e "s+^\\(MAN_GROUP =\\)\$+\\1 ${MAN}+" \
	-e "s+^\\(RC_DIR =\\)\$+\\1 ${RC_DIR}+" \
	-e "s+^\\(INIT_DIR =\\)\$+\\1 ${INIT_DIR}+" \
	-e "s+^\\(INITD_DIR =\\)\$+\\1 ${INITD_DIR}+" \
	-e "s+^\\(CRON_OWNER =\\)\$+\\1 ${CRON_OWNER}+" \
	-e "s+^\\(INSTALL_CRON =\\)\$+\\1 ${CRON}+"
echo " Done."

echo
echo 'Now enter "make" to build sysstat commands.'
if [ "${CRON}" = "y" ];
then
	echo 'Then edit the crontab file created in current directory ("vi crontab")'
fi
echo 'The last step is to log in as root and enter "make install"'
echo 'to perform installation process.'

