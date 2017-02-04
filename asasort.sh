#!/bin/bash

for fw in `awk '{print $2}' asa.list`
do
	echo $fw
	for acl in `awk '/^access-group/ {print $2}' $fw/$fw*groups`
	do
		echo "   "$acl
		fgrep $acl $fw/${fw}.out > $fw/${acl}.acl
	done
done
