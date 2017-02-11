#!/usr/bin/python
# ASA conf converter to sh access-list or HTML

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

# If new object is found, add it to the group
# And set the current names
def newobj (obj, key):
	global curobj,curname
	curobj=obj
	curname=key
	curobj[curname]=[]

# Add new services or networks to the object
def fillobj (obj, key, val):
	obj[key].append(val)

# Iterate through all objects in netgrp or srvgrp
def unfold(objarr):
	for obj in objarr:
		unfold_rec(objarr[obj],objarr)


# Unfold all included objects
def unfold_rec(obj, objarr):
	for item in obj:
		# If object-group is found,
		# recurse through the object-groups
		if "object-group" in str(item):
				# Add the content of the object-group
				# item by item
				for i in objarr[item.split()[1]]:
					obj.append(i)
				# Remove the object-group
				obj.remove(item)
				# and dive into the new updated object
				unfold_rec(obj, objarr)

def html_hdr(title):
	print '<html lang=en><head><title>' + title + '</title></head><body>'

def html_tbl_hdr(title):
	print '<table><caption>' + title + '</caption><tr><th>Line #</th><th>Source</th> \
	<th><Destination></th><th>Service</th><th>Action</th></tr>'

def html_tbl_ftr():
	print '</table>'

def html_ftr():
	print '</body></html>'


parser = argparse.ArgumentParser()
parser.add_argument('conf', default="-", nargs='?', help="Cisco ASA conf filename or \"-\" to read from the console (default)")
out = parser.add_mutually_exclusive_group()
out.add_argument('--html', default=True, help="Cisco policy to HTML", action="store_true")
out.add_argument('--acl', default=False, help="Cisco policy to sh access-list", action="store_true")
args = parser.parse_args()
if args.acl: args.html=False

netobj = {}	# network-objects
netgrp = {}	# network-groups
srvgrp = {}	# service-groups
aclmode = False
rulecnt = 0 # ACL rule counter
curacl = '' # current ACL name
# global curobj points to the current dict: netobj, netgrp or srvgrp
# global curname points to the current object name
# curproto points to the current protocol
#global curobj,curname

# hostname fw_name
re_hostname = re.compile('^\s*hostname\s+(?P<hostname>\S+)', re.IGNORECASE)
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
re_srvgrp = re.compile('^\s*object-group\s+service\s+(?P<srv_grp>\S+)\s*$', re.IGNORECASE)
#object-group service srv_tcp tcp
re_srvgrp_proto = re.compile('^\s*object-group\s+service\s+(?P<srv_grp>\S+)\s+(?P<proto>\S+)', re.IGNORECASE)
# port-object eq ldaps
re_portobj = re.compile('^\s*port-object\s+(?P<service>.*$)', re.IGNORECASE)
# group-object net-10.1.0.0-16
re_grpobj = re.compile('^\s*group-object\s+(?P<grp_obj>\S+)', re.IGNORECASE)
# service-object tcp destination eq 123
re_srvobj = re.compile('^\s*service-object\s+(?P<proto>\S+)(\s+destination)?\s+(?P<service>.*$)', re.IGNORECASE)
# service-object 97
re_srvobj_ip = re.compile('^\s*service-object\s+(?P<proto>\d+)', re.IGNORECASE)
# access-list acl_name extended ...
re_isacl = re.compile('^\s*access-list\s+\S+\s+extended', re.IGNORECASE)

#access-list name
re_aclname = re.compile('^\s*access-list\s+(?P<acl_name>\S+)\s+', re.IGNORECASE)


f=sys.stdin if "-" == args.conf else open (args.conf,"r")


for line in f:
	line = line.strip()
	# Parsing and filling in the network and service objects
	if not aclmode:
		if args.html and re_hostname.search(line):
			html_hdr(re_hostname.search(line).group('hostname'))
		elif re_objnet.search(line):
			newobj(netobj,re_objnet.search(line).group('obj_name'))
		elif re_subnet.search(line):
			curobj[curname]=netaddr.IPNetwork(re_subnet.search(line).group('ip') +
				'/' + re_subnet.search(line).group('mask'))
		elif re_host.search(line):
			curobj[curname]=netaddr.IPNetwork(re_host.search(line).group('ip') + '/32')
		elif re_netgrp.search(line):
			newobj(netgrp,re_netgrp.search(line).group('net_grp'))
		elif re_netobj.search(line):
			fillobj(curobj, curname, netaddr.IPNetwork(re_netobj.search(line).group('ip') +
				'/' + re_netobj.search(line).group('mask')))
		elif re_srvgrp.search(line):
			newobj(srvgrp,re_srvgrp.search(line).group('srv_grp'))
		elif re_grpobj.search(line):
			fillobj(curobj, curname, 'object-group ' + re_grpobj.search(line).group('grp_obj'))
		elif re_srvobj.search(line):
			fillobj(curobj, curname, re_srvobj.search(line).group('proto') + ':' +
				re_srvobj.search(line).group('service'))
		elif re_srvgrp_proto.search(line):
			newobj(srvgrp,re_srvgrp_proto.search(line).group('srv_grp'))
			curproto = re_srvgrp_proto.search(line).group('proto')
		elif re_portobj.search(line):
			fillobj(curobj, curname, curproto + ':' + re_portobj.search(line).group('service'))
		elif re_srvobj_ip.search(line):
			fillobj(curobj, curname, re_srvobj_ip.search(line).group('proto'))
		elif re_isacl.search(line):
			aclmode = True
			unfold(netgrp)
			unfold(srvgrp)

	# Parsing access-lists
	if aclmode:
		if re_aclname.search(line):
			newacl = re_aclname.search(line).group('acl_name')
			if not curacl == newacl:
				curacl = newacl
				if args.html:
					if rulecnt: html_tbl_ftr()
					html_tbl_hdr(curacl)
		rulecnt += 1

#print 'netobj'
#pprint.pprint(netobj)
#print 'netgrp'
#pprint.pprint(netgrp)
#print 'srvgrp'
#pprint.pprint(srvgrp)
#print '\n'
#print 'total rules: ', rulecnt
if args.html:
	html_tbl_ftr()
	html_ftr()
