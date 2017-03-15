#!/bin/bash

check_pf()
{
   echo >> static_perf.txt
   echo +++ Checking PF status before traffic: >> static_perf.txt

   ndb_select_count -d smsc TsmsMDN0301 | grep records >> static_perf.txt
   fw usage -z >> static_perf.txt
   fw lsta >> static_perf.txt
   fw lsndb >> static_perf.txt
   df >> static_perf.txt
   rsh station_a netstat -npl | grep ldap  >> static_perf.txt

   echo +++ Done.
}

next_million ()
{
   echo >> static_perf.txt
   echo `date` - Next million: $1 >> static_perf.txt
   tgen_mas -s90 -p322$1 -r100000 -z130 -u -U1 -g27
   
   check_pf

   /mds_tests/Common/Tgen/launch_perf_smsc_ddm.sh -g27 -d static_ddm_$1.1M -t60 -z130
   mv tgen.* static_ddm_$1.1M/ 
}

echo === Starting at `date` >> static_perf.txt

# clean working range
tgen_mas -s10 -p322 -r100000 -z130 -u -U1 -g27 -q
\rm -rf tgen.* static_ddm*

check_pf

/mds_tests/Common/Tgen/launch_perf_smsc_ddm.sh -g27 -d static_ddm_0.1M -t60 -z130
mv tgen.* static_ddm_0.1M/ 

for m in `seq 1 15`
do
	next_million $m
done

echo === Finished at `date` >> static_perf.txt
