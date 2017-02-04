#!/bin/ksh
# Prints the amount of matching ACLs for the IPs 
# found in the source and destination
# Takes a list of IP's as an argument
# E.g. asasearch.sh 10.0.1.64/28,10.0.1.68
# Combines all similarly named ACLs across directories
IPS=$*
for acl in `ls */*acl | sed -e 's%^.*/%%' | sort -u`
do
	for dir in src dst
	do
#		eval cnt${dir}=`ipaclmatch.py --noany -t --direct --permit --$dir -a $IPS $acl | optimacl.py | wc -l | awk '{print $1}'`
		eval cnt${dir}=`cat */$acl | ipaclmatch.py --noany -t --permit --$dir -a $IPS - | optimacl.py | wc -l | awk '{print $1}'`

	done
	echo $acl $cntsrc $cntdst
done
