#!/bin/ksh
# Prints the amount of matching ACLs for the IPs 
# found in the source and destination
# Takes a list of IP's as an argument
# E.g. asasearch.sh 10.0.1.64/28,10.0.1.68
IPS=$*
for acl in */*.acl
do
	for dir in src dst
	do
		eval cnt${dir}=`ipaclmatch.py --noany --permit --$dir -a $IPS $acl | wc -l | awk '{print $1}'`
#		eval cnt${dir}=`ipaclmatch.py --permit --$dir -a $IPS $acl | wc -l | awk '{print $1}'`
	done
	echo $acl $cntsrc $cntdst
done
