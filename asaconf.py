#!/usr/bin/python
# ASA conf converter to sh access-list
import string
import argparse
import re
import sys
import pprint
try:
	import netaddr
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)


def fillobj (obj, key, val):
	obj[key].append(val)

def newobj (obj, key):
	global curobj,curname
	curobj=obj
	curname=key
	curobj[curname]=[]


parser = argparse.ArgumentParser()
parser.add_argument('conf', default="-", nargs='?', help="Cisco ASA conf filename or \"-\" to read from the console (default)")
args = parser.parse_args()

netobj = {}	# network-objects
netgrp = {}	# network-groups
srvgrp = {}	# service-groups
aclmode = False
rulecnt = 0 # ACL rule counter
# global curobj points to the current dict: netobj, netgrp or srvgrp
# global curname points to the current object name
#global curobj,curname

#object network mynet1
re_objnet = re.compile('^\s*object\s+network\s+(?P<obj_name>\S+)', re.IGNORECASE)
# subnet 10.1.2.0 255.255.255.0
re_subnet = re.compile('^\s*subnet\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
# host 10.2.1.41
re_host = re.compile('^\s*host\s+(?P<ip>\S+)', re.IGNORECASE)
#object-group network mynetgrp1
re_netgrp = re.compile('^\s*object-group\s+network\s+(?P<net_grp>\S+)', re.IGNORECASE)
# network-object 10.1.1.1 255.255.255.255
re_netobj = re.compile('^\s*network-object\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
#object-group service mysrvgrp1
re_srvgrp = re.compile('^\s*object-group\s+service\s+(?P<srv_grp>\S+)', re.IGNORECASE)
# group-object net-10.1.0.0-16
re_grpobj = re.compile('^\s*group-object\s+(?P<grp_obj>\S+)', re.IGNORECASE)
# service-object tcp destination eq 123
re_srvobj = re.compile('^\s*service-object\s+(?P<proto>\S+)\s+destination\s+(?P<service>.*$)', re.IGNORECASE)

#access-list name
re_aclname = re.compile('^\s*access-list\s+(?P<acl_name>\S+)\s+', re.IGNORECASE)


f=sys.stdin if "-" == args.conf else open (args.conf,"r")


for line in f:
	line = line.rstrip()
	# Parsing and filling in network and service objects
	if not aclmode:
		if re_objnet.search(line):
			newobj(netobj,re_objnet.search(line).group('obj_name'))
		if re_subnet.search(line):
			curobj[curname]=netaddr.IPNetwork(re_subnet.search(line).group('ip') +
				'/' + re_subnet.search(line).group('mask'))
#			fillobj(curobj, curname, netaddr.IPNetwork(re_subnet.search(line).group('ip') +
#				'/' + re_subnet.search(line).group('mask')))
		if re_host.search(line):
			curobj[curname]=netaddr.IPNetwork(re_host.search(line).group('ip') + '/32')
#			fillobj(curobj, curname, netaddr.IPNetwork(re_host.search(line).group('ip') + '/32'))
		if re_netgrp.search(line):
			newobj(netgrp,re_netgrp.search(line).group('net_grp'))
		if re_netobj.search(line):
			fillobj(curobj, curname, netaddr.IPNetwork(re_netobj.search(line).group('ip') +
				'/' + re_netobj.search(line).group('mask')))
		if re_srvgrp.search(line):
			newobj(srvgrp,re_srvgrp.search(line).group('srv_grp'))
		if re_grpobj.search(line):
			fillobj(curobj, curname, 'object-group ' + re_grpobj.search(line).group('grp_obj'))
		if re_srvobj.search(line):
			fillobj(curobj, curname, re_srvobj.search(line).group('proto') + ':' +
				re_srvobj.search(line).group('service'))
		if re_aclname.search(line): aclmode = True

	else:
		rulecnt += 1

print 'netobj'
pprint.pprint(netobj)
print 'netgrp'
pprint.pprint(netgrp)
print 'srvgrp'
pprint.pprint(srvgrp)
print '\n'
print 'total rules: ', rulecnt
