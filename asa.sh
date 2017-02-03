#!/bin/bash

FWS=edge.list
USERNAME=username
PASSWD=L1passwd
ENABLE=L2passwd

#echo -n "Enter the username: "
#read -e  USERNAME
#echo -n "Enter the SSH password: "
#read -s -e PASSWD
#echo -ne '\n'
#echo -n "Enter the Enable password: "
#read -s -e ENABLE
#echo -ne '\n'

while read fw
do
	set $fw
	mkdir -p $2
	OUTFILE=$2/$2
	./asa.exp $1 $2 $USERNAME $PASSWD $ENABLE $OUTFILE &
done < $FWS
