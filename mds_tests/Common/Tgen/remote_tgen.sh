#!/bin/bash
#
# EmA, 27/08/2010
# copyright (c) 2010 Alcatel-Lucent
# All Rights Reserved
#
# Remote launcher of the tgen tool on a given client
# First param is the client to be used
# Other params are the tgen launch params
# 
# ex: remote_tgen.sh lalx02si3 -c ~/TestU/tgen_base.ini -s6 -p300 -r100 -z10 172.25.195.206

cc_location="/mds_tests/Common/Tgen"
launcher="rsh_tgen.sh"
viewtag="anthoin1_st_sdm11.01.ln"



confirm() {
  while : ; do 
      echo -n "$1 [y] "
      read answer
      if strstr $"yY" "$answer" || test -z "$answer" ; then
         return 0
      elif strstr $"nN" "$answer" ; then
         return 1
      fi
  done
}

wait_end() {
	pidtgen="1"
	while [ -n "$pidtgen" ]
	do
		sleep 1
		pidtgen=`ssh -q -o "StrictHostKeyChecking no" -l root $host "ps -ef | grep 'tgen_mas -c $tempdir/$fic' | grep -v grep | sed 's/  */ /g' | cut -d' ' -f2"`
		#echo pidtgen="$pidtgen"
	done
}

kill_pause() {
	echo "Transmit Ctrl Z..."
	pidtgen=`ssh -q -o "StrictHostKeyChecking no" -l root $host "ps -ef | grep 'tgen_mas -c $tempdir/$fic' | grep -v grep | sed 's/  */ /g' | cut -d' ' -f2"`
	#echo pidtgen=$pidtgen
	[ -n "$pidtgen" ] && ssh -q -o "StrictHostKeyChecking no" -l root $host "kill -TSTP $pidtgen"
	
	return 0
}

kill_stop() {
	echo "Transmit Ctrl C..."
	#echo "tgen_mas -c $tempdir/$fic $params"
	pidtgen=`ssh -q -o "StrictHostKeyChecking no" -l root $host "ps -ef | grep 'tgen_mas -c $tempdir/$fic' | grep -v grep | sed 's/  */ /g' | cut -d' ' -f2"`
	#echo pidtgen=$pidtgen
	[ -n "$pidtgen" ] && ssh -q -o "StrictHostKeyChecking no" -l root $host "kill -INT $pidtgen"
	wait_end
	return 0
}

kill_exit() {
	echo "Kill all pending remote process..."
	pidtgen=`ssh -q -o "StrictHostKeyChecking no" -l root $host "ps -ef | grep 'tgen_mas -c $tempdir/$fic' | grep -v grep | sed 's/  */ /g' | cut -d' ' -f2"`
	#echo pidtgen=$pidtgen
	[ -n "$pidtgen" ] && ssh -q -o "StrictHostKeyChecking no" -l root $host "kill $pidtgen"
	wait_end
	return 0
}

###########################################################################################
# MAIN
###########################################################################################

/usr/atria/bin/cleartool mount /mds_tests > /dev/null

if test -z "$1"
then
	echo "No client defined. Quit."
	exit 1
fi
host=$1
echo "Remote client: $host"

# check access to remote client
echo -n "Test remote access..."
ssh -q -o "StrictHostKeyChecking no" -l root $host "echo  OK."
RETVAL=$?
if [ $RETVAL != 0 ]
then
	echo "Can not access client. Check rlogin/ssh configuration first"
	exit 2
fi

shift
params=""
while test -n "$1";
do
	if [ "$1" == "-c" ]
	then
		conf="$2"
		shift
	else
		if [ -z "$params" ]
		then
			params="$1";
		else
			params="$params $1";
		fi
	fi 
	shift
done
echo "Parameters: conf='$conf' params='$params'"


if test -n "$conf"
then
	dir=`dirname $conf`
	fic=`basename $conf`
fi

if test -z "$conf" || [ ! -r "$dir/$fic" ]
then
	echo "WARNING: Use default ini files"
	dir="$cc_location"
	fic="tgen.ini"
fi

tempdir="/var/tmp/tgen_${HOSTNAME}_$$"
echo "Create remote temp directory: $tempdir"
ssh -q -o "StrictHostKeyChecking no" -l root $host "mkdir -p $tempdir"

echo "Export running files..."
for f in "$dir/tgen*.ini"
do
	scp -q -o "StrictHostKeyChecking no" $f root@$host:"$tempdir"
done

echo "Clone env params..."
cp "$cc_location/$launcher" "$launcher_$$"
chmod +wx "$launcher_$$"

[ -n "${HSS_IP_CX}" ] && echo "setenv HSS_IP_CX ${HSS_IP_CX}" >> "$launcher_$$"
[ -n "${LDAPBASE}" ] && echo "setenv LDAPBASE ${LDAPBASE}" >> "$launcher_$$"
[ -n "${LDAPBINDDN}" ] && echo "setenv LDAPBINDDN ${LDAPBINDDN}" >> "$launcher_$$"
[ -n "${LDAP_SECRET}" ] && echo "setenv LDAP_SECRET ${LDAP_SECRET}" >> "$launcher_$$"
[ -n "${RAD_SECRET}" ] && echo "setenv RAD_SECRET ${RAD_SECRET}" >> "$launcher_$$"
#[ -n "${MY_IP_ADDRESS}" ] && echo "setenv MY_IP_ADDRESS ${MY_IP_ADDRESS}" >> "$launcher_$$"
#[ -n "${MY_FQDN}" ] && echo "setenv MY_FQDN ${MY_FQDN}" >> "$launcher_$$"
echo "cd $tempdir; tgen_mas -c $tempdir/$fic $params" >> "$launcher_$$"

scp -p -q -o "StrictHostKeyChecking no" "$launcher_$$" root@$host:"$tempdir/$launcher"
\rm -f "$launcher_$$"

# interception of kill signals
stty susp ^-
trap 'kill_stop' INT
#trap 'kill_pause' TSTP
trap 'kill_exit' EXIT

#ssh -q -o "StrictHostKeyChecking no" -l root $host "resize -s 40 140;/usr/atria/bin/cleartool setview -exec 'tcsh -c $tempdir/$launcher' $viewtag"
#ssh -q -o "StrictHostKeyChecking no" -l root $host "/usr/atria/bin/cleartool setview -exec 'tcsh -c $tempdir/$launcher \|\& tee $tempdir/console' $viewtag" &
ssh -q -o "StrictHostKeyChecking no" -l root $host "/usr/atria/bin/cleartool setview -exec 'tcsh -c $tempdir/$launcher' $viewtag" &
sleep 5
wait_end

echo "Import result files..."
for f in "tgen.[clo]*"
do
	scp -q -o "StrictHostKeyChecking no" root@$host:"$tempdir/$f" .
done

echo "Clean temp remote directory..."
ssh -q -o "StrictHostKeyChecking no" -l root $host "\rm -rf $tempdir"

echo "End."

