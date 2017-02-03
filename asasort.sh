#!/bin/bash

for fw in `cat asa.list | awk '{print $2}'`
do
	echo $fw
	for acl in `awk '/^access-group/ {print $2}' $fw/$fw*groups`
	do
		echo "   "$acl
		fgrep $acl $fw/${fw}.out > $fw/${acl}.acl
	done
done
