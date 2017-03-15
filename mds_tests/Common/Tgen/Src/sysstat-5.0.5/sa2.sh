#!/bin/sh
# PREFIX/lib/sa/sa2.sh
# (C) 1999-2004 Sebastien Godard (sysstat <at> wanadoo.fr)
#
S_TIME_FORMAT=ISO ; export S_TIME_FORMAT
umask 0022
DATE=`date YESTERDAY +%d`
RPT=SA_DIR/sar${DATE}
ENDIR=BIN_DIR
DFILE=SA_DIR/sa${DATE}
[ -f "$DFILE" ] || exit 0
cd ${ENDIR}
${ENDIR}/sar $* -f ${DFILE} > ${RPT}
find SA_DIR \( -name 'sar??' -o -name 'sa??' \) -mtime +HISTORY -exec rm -f {} \;

