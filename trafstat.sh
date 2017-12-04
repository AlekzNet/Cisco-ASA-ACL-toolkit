#!/bin/bash

FILES="$*"
DIR=`date +'%Y%m%d_%H%M'`
THOLD=10

for i in $FILES
do
        if [ ! -f $i ]; then
                echo "No such file $i"
                exit 1
        fi 
done

mkdir -p $DIR
echo "Saving in $DIR"

ACLS=`cat $FILES | egrep permitted | egrep access-list | sed -e 's/^.*access-list //' | awk '{acl[$1]++;} END { for ( i in a
cl ) printf("%s %d %d %d %d %d\n",i,acl[i],acl[i]/10000,acl[i]/5000,acl[i]/1000,acl[i]/500);}' | tee ${DIR}/acl.stat | awk '{print $1}'`

echo "ACL    Count  0.01%   0.02%   0.1%   0.2%"
cat  ${DIR}/acl.stat
echo $ACLS

for i in $ACLS
do
        echo $i
        # output format:
        # count source_IP destination_IP protocol:port
        # sorted in the descending order

        cat $FILES | egrep -v icmp |  egrep "access-list $i permitted" | sed -e 's/^.*permitted //' | sed -e 's/ hit-cnt.*$//' | sed -e 's%(.
*/% %' | sed -e 's/^ //' | sed -e 's% .*/% %' | sed -e 's/(\(.*\))/ \1/' | awk '{ if ($4 < 32768) {conn[$0]++;} } END { for ( i in conn ) print conn[i],"",i;}' 
| sort +0nr  | awk '{printf("%d %s %s %s:%d\n",$1,$3,$4,$2,$5);}' >>  ${DIR}/$i

        set `grep $i ${DIR}/acl.stat`
        cat ${DIR}/$i | awk ' {conn[$2] += $1;} END {for ( i in conn ) print conn[i],"",i;}' | sort +0nr > ${DIR}/${i}.tops
        cat ${DIR}/$i | awk ' {conn[$3] += $1;} END {for ( i in conn ) print conn[i],"",i;}' | sort +0nr > ${DIR}/${i}.topd
        cat ${DIR}/$i | awk ' { if ($1 >'$THOLD') {print $0}}' > ${DIR}/${i}.$THOLD
        cat ${DIR}/$i | awk ' { if ($1 >'$3') {print $0}}' > ${DIR}/${i}.$3
done
