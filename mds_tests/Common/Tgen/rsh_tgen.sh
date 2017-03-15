#!/bin/tcsh
#
# Launch tgen from remote host
# Can be invoked remotely by:
#	ssh -l root lalx02si3 "/usr/atria/bin/cleartool setview -exec 'tcsh -c /root/bin/rsh_tgen.sh' anthoin1_st_sdm11.01.ln"
#

# view should already been set

# starting neededd Vobs
/usr/atria/bin/cleartool mount /3pp_openssl > /dev/null
/usr/atria/bin/cleartool mount /hss_openldap > /dev/null
/usr/atria/bin/cleartool mount /hss_freeradius > /dev/null
/usr/atria/bin/cleartool mount /mds_tests > /dev/null

# loading clients env
source /mds_tests/mas/Common/PCTomcase/cshrc.tomcase

# execute cmd
echo "Launching tgen..."
setenv COLUMNS '140';
setenv LINES '40';
#echo y | tgen_mas -c ~/TestU/tgen_base.ini -s6 -p300 -r100 -z10 172.25.195.206
