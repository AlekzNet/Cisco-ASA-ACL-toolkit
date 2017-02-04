#!/bin/bash

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
