#!/bin/bash
#
# EmA, 10/01/2011
# copyright (c) 2010 Alcatel-Lucent
# All Rights Reserved
#
# Launch performance tests set
# 
# ex: launch_perf.sh -g 22 -d essai1 -t 10


#-----------------------------------------------------------------------------------------------------------
usage()
{
  echo "Usage : $0 [-g <servers_group>] [-d <diff>]"
  echo "   -g <servers_group>   : group of servers (in the tgen_servers.ini conf file)"
  echo "   -d <dirname>   		: name of the directory where to store the results (default: .)"
  echo "   -t <timeout>   		: nominal duration of loop traffics (default: 300)"
  echo
}

#-----------------------------------------------------------------------------------------------------------
watchdog()
{
#	echo "Watchdog on pid $1. Wait $2 sec before kill"
	for elapsedsec in `seq $2`
	do
		ps -p $1 > /dev/null 2>&1 
		[ $? == "1" ] && return 0
		sleep 1
	done
	kill -2 $1 > /dev/null 2>&1
	return 1
}

#-----------------------------------------------------------------------------------------------------------
progressbox()
# arg1: label to display permanently in the progress window
# arg2: nb of steps
{
	tick=0
return 1
	label="$1"
	dcopRef=`kdialog -title Tgen --geometry 250x40 --progressbar "$label" $2`
	dcop $dcopRef showCancelButton true
}

#-----------------------------------------------------------------------------------------------------------
tick_progress()
# arg1: additional label to the progress window
# arg2: suffixe of dirname
{
	((tick++))
	mkdir $startdir/$dir/$tick$2; cd $startdir/$dir/$tick$2
return 1
	if test "true" == `dcop $dcopRef wasCancelled`
	then
		echo Script canceled.
		exit 1
	fi
	dcop $dcopRef setProgress $tick
	dcop $dcopRef setLabel "$label$1"
}

#-----------------------------------------------------------------------------------------------------------
close_progress()
{
return 1
	dcop $dcopRef close
}


#-----------------------------------------------------------------------------------------------------------
view_results()
{
grep --with-filename --before-context=1 --after-context=100 "TGEN FINAL REPORT" */tgen.out > report.txt
which nedit
[ $? == "0" ] && nedit report.txt &
echo "Report in file: `pwd`/report.txt"
}


#-----------------------------------------------------------------------------------------------------------
# MAIN
#-----------------------------------------------------------------------------------------------------------

# default parmeter values
timeout=300
threads=50
startdir=`pwd`

# getting cmdline parameter
while getopts g:d:z:t:h option
do	case "$option" in
	g) group=$OPTARG;;
	d) dir=$OPTARG;;
	z) threads=$OPTARG;;
	t) timeout=$OPTARG;;
	h) usage; exit 0;;
	[?]) usage; exit 1;;
	esac
done
echo "Parameters: group=$group dir=$dir timeout=$timeout threads=$threads"

# check parmeters
if test -z "$group"
then
	echo "No server defined. Quit."
	exit 1
fi

if [ -n "$dir" ] && [ -e "$dir" ]
then
	echo "Directory $dir already exists. Exit"
	exit 1
else
	mkdir -p $dir
	cd $dir
fi

common_args="-r100000 -z$threads -g$group -u"
progressbox "Performance test running : " 19

# SEARCH
tick_progress "Basic search" _basic
tgen_mas -s6 -p320 $common_args -U0 -T$timeout
tick_progress "All attributes search" _allAttributes
tgen_mas -s52 -p320 $common_args -U0 -T$timeout
tick_progress "5 attributes search" _5attributes
tgen_mas -s53 -p320 $common_args -U0 -T$timeout
tick_progress "1 attribute search" _1attribute
tgen_mas -s54 -p320 $common_args -U0 -T$timeout
tick_progress "Scone one search" _SOne
#tgen_mas -s6 -p323 $common_args -U0 -T$timeout
#reported later: tick_progress "Scone one search by secondary key" _SOne_seckey
#reported later: tgen_mas -s6 -p324 $common_args -U0 -T$timeout
tick_progress "Scone one search, return 10 entries" _SOne_return10
#tgen_mas -s6 -p325 $common_args -U0 -T$timeout
tick_progress "Scone one search by secondary key, return 10 entries" _SOne_seckey_retrun10
#tgen_mas -s6 -p326 $common_args -U0 -T$timeout
tick_progress "Wrong search" _wrong
tgen_mas -s6 -p322 $common_args -U0 -T$timeout -q

# ADD:
tick_progress "Add one entry" _add
tgen_mas -s90 -p322 $common_args -U1

# SEARCH NEWLY CREATED
tick_progress "Scone one search by secondary key" _SOne_seckey
#tgen_mas -s6 -p324 $common_args -U0 -T$timeout


# MODIFY:
tick_progress "Add one attribute" _addOne
tgen_mas -s753 -p322 $common_args -U1 
tick_progress "Remove one attribute" _removeOne
tgen_mas -s754 -p322 $common_args -U1
tick_progress "Replace one attribute" _replace
tgen_mas -s750 -p322 $common_args -U1
tick_progress "Remove all instances of one attribute" _removeAll
tgen_mas -s753 -p322 $common_args -U1
\rm tgen.*
tgen_mas -s752 -p322 $common_args -U1
tick_progress "4 serial Modifies" _modifyMix4
tgen_mas -s75 -p322 $common_args -U1

# DEL:
tick_progress "Delete one entry" _del
tgen_mas -s10 -p322 $common_args -U1
# ADD (NRG2):
tick_progress "Add one entry in NRG2" _addnrg2
tgen_mas -s902 -p322 $common_args -U1


# MIXTE:
tick_progress "Mixte traffic" _mix8
tgen_mas -s10 -p322 $common_args -U1
\rm tgen.*
tgen_mas -s80 -p322 $common_args -U0 -T$timeout
# MIXTE 80/20:
tick_progress "80% search / 20% modify" _mix8020
tgen_mas -t8 -p320 $common_args -U0 -T$timeout
cd ..


close_progress

view_results
