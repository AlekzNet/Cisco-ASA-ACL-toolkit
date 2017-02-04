#!/bin/bash

IPS=$*
for acl in */*.acl
do
	for dir in src dst
	do
		cnt=`ipaclmatch.py --noany --permit --$dir -a $IPS $acl | wc -l`
#		cnt=`ipaclmatch.py --permit --$dir -a $IPS $acl | wc -l`
		echo $acl $dir $cnt
	done
done
