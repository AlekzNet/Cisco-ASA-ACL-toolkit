#!/usr/bin/python
# ASA conf converter to sh access-list or HTML
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_extended.html
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_objects.html
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/ref_ports.html

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
		if not args.noaggr and objarr is netgrp: objarr[obj] = netaddr.cidr_merge(objarr[obj])


# Unfold all included objects
def unfold_rec(obj, objarr,index=0):
	# We are starting with the index from the previous iteration
	for i in range(index, len(obj)):
		item=obj[i]
		# If object-group is found,
		# recurse through the object-groups
		if "object-group" in str(item):
			# Add the content of the object-group
			# item by item
			for j in objarr[item.split()[1]]:
				obj.append(j)
			# Remove the item with object-group
			del obj[i]
			# and dive into the new updated object
			# We are passing the index we are currently on
			unfold_rec(obj,objarr,i)
		elif 'net-object' in str(item):
			# if net-object is in the group
			# get its address from netobj
			obj.append(netobj[item.split()[1]])
			del obj[i]
			unfold_rec(obj,objarr,i)

def html_hdr(title):
	print '<html lang=en><head><title>' + title + '</title></head><body> <style> \
		body {background: #FFF5DD; color: #000080; font-family: sans-serif; padding-left: 20px; } \
		table {color: #000080; font-size: 0.8em; border: solid 1px #000080; border-collapse: collapse; } \
		th { font-size: 1em; padding: 0.8em; }\
		td {padding-left: 15px; padding-top: 5px; padding-bottom: 5px; padding-right: 15px;} \
		a {color: #0000d0; text-decoration: none;} \
		.permit {color: DarkGreen;} \
		.deny {color: DarkRed;} </style> \
		<h1>' + title + ' policy</h1><h4><a href=#content>Content</a></h4>'

def html_tbl_hdr(title):
	print '<table border=1><caption id=' + title + '><h2>' + title + '</h2></caption> \
	<tr><th>Line #</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th></tr>'

def html_tbl_ftr():
	print '</table><br /><br />'

def html_ftr(content):
	print '<div id=content><h2>Content</h2><ul>'
	for i in content:
		print '<li><a href=#' + i + '>' + i + '</a> ' + content[i] + '</i>'
	print '</ul></div></body></html>'


class Rule:
	'Class for an ACL rule'
	#access-list myacl remark My best rule
	re_acl_rem = re.compile('^\s*access-list\s+\S+\s+remark\s+(?P<acl_rem>.*$)', re.IGNORECASE)

	#All subsequent remarks are concatenated in this persistent variable
	remark = ''

	def __init__(self,lnum,line):
		self.lnum = lnum
		self.line=line
		self.name = ''
		self.src = []
		self.dst = []
		self.srv = []
		self.proto = ''
		self.action = ''
		self.rem = ''
		self.cleanup()
		self.parse()

	# Simple clean-up
	def cleanup(self):
		self.line=re.sub(r'\s+log$|\s+log\s+.*$','',self.line)
		self.line=re.sub(r'\bany\b|\bany4\b','0.0.0.0 0.0.0.0',self.line)

	def parse(self):
		if Rule.re_acl_rem.search(self.line):
			# Found Remarked ACL
			# Was the prev rule also remarked? If yes, add <br>
			if Rule.remark: Rule.remark += '<br />'
			Rule.remark += Rule.re_acl_rem.search(line).group('acl_rem')
		else:
			# Clean the remarks
			self.rem = Rule.remark
			Rule.remark = ''
			arr=self.line.split()
			# ACL name
			self.name = arr[1]
			# Permit or deny
			self.action = arr[3]
			del arr[0:4]
			if 'object-group' in arr[0]:
				self.srv = srvgrp[arr[1]]
				del arr[0:2]
			else:
				self.proto = arr[0]
				del arr[0]
			# Source
			if 'object-group' in arr[0]:
				self.src = netgrp[arr[1]]
			elif 'object' in arr[0]:
				self.src = [netobj[arr[1]]]
			elif 'host' in arr[0]:
				self.src = [netaddr.IPNetwork(arr[1] + '/32')]
			else:
				self.src = [netaddr.IPNetwork(arr[0] + '/' + arr[1])]
			del arr[0:2]
			# Source ports are not supported
			if "range" in arr[0]: del arr[0:3]
			if "eq" in arr[0] or "lt" in arr[0] or "gt" in arr[0] or "neq" in arr[0]:
				del arr[0:2]
			# Destination
			if 'object-group' in arr[0]:
				self.dst = netgrp[arr[1]]
			elif 'object' in arr[0]:
				self.dst = [netobj[arr[1]]]
			elif 'host' in arr[0]:
				self.dst = [netaddr.IPNetwork(arr[1] + '/32')]
			else:
				self.dst = [netaddr.IPNetwork(arr[0] + '/' + arr[1])]
			del arr[0:2]
			# Services
			if len(arr) > 0:
				if 'object-group' in arr[0]:
					self.srv = srvgrp[arr[1]]
				else:
					self.srv = [self.proto + ':' + ' '.join(arr[:])]
			elif not self.srv:
				self.srv = [self.proto]

	# Print rule in the sh access-list format
	def rprint(self):
		if not Rule.remark:
			for src in self.src:
				for dst in self.dst:
					for srv in self.srv:
						proto,ports= srv.split(":") if ":" in srv else [srv,'']
						print 'access-list ' + self.name + ' line ' + str(self.lnum) + ' extended ' + \
				' '.join([self.action, proto, str(src.ip), str(src.netmask), str(dst.ip), str(dst.netmask), ports])
			self.rem = ''

	# Print rule as an HTML table row
	def html(self):
		if not Rule.remark:
			# Are there accumulated comments?
			if self.rem:
				print '<tr><td colspan=5>' + self.rem + '</td></tr>'
			print '<tr><td>' + str(self.lnum) + '</td>' + self.html_obj(self.src) + \
				self.html_obj(self.dst) + self.html_obj(self.srv) + '<td>' + self.html_color_action(self.action) + '</td></tr>'

	# Highlight the action in green or red
	def html_color_action(self, act):
		if 'permit' in act: return '<span class=permit>' + act + '</span>'
		else: return '<span class=deny>' + act + '</span>'

	# Print out the content of the object-group with <br /> in between
	def html_obj(self,obj):
		return '<td>' + '<br />'.join(map(lambda x: str(x), obj)) + '</td>'

parser = argparse.ArgumentParser()
parser.add_argument('conf', default="-", nargs='?', help="Cisco ASA conf filename or \"-\" to read from the console (default)")
out = parser.add_mutually_exclusive_group()
out.add_argument('--html', default=True, help="Cisco policy to HTML", action="store_true")
out.add_argument('--acl', default=False, help="Cisco policy to sh access-list", action="store_true")
parser.add_argument('--noaggr', default=False, help="Do not aggregate networks", action="store_true")
args = parser.parse_args()
if args.acl: args.html=False

netobj = {}	# network-objects
netgrp = {}	# network-groups
srvgrp = {}	# service-groups
aclmode = False
rulecnt = 0 # ACL rule counter
curacl = '' # current ACL name
aclnames = {} # ACL names and interfaces
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
#network-object host 10.1.1.1
re_netobj_host = re.compile('^\s*network-object\s+host\s+(?P<ip>\S+)', re.IGNORECASE)
#network-object object mynet1
re_netobj_obj = re.compile('^\s*network-object\s+object\s+(?P<obj_name>\S+)', re.IGNORECASE)
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


#access-group management_acl in interface management
re_aclgrp = re.compile('^\s*access-group\s+(?P<acl_name>\S+)\s+(?P<acl_int>.*$)', re.IGNORECASE)

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
		elif re_netobj_host.search(line):
			fillobj(curobj, curname, netaddr.IPNetwork(re_netobj_host.search(line).group('ip') + '/32'))
		elif re_netobj_obj.search(line):
			fillobj(curobj, curname, 'net-object ' + re_netobj_obj.search(line).group('obj_name'))
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
				aclnames[curacl] = ''
				if args.html:
					if rulecnt: html_tbl_ftr()
					html_tbl_hdr(curacl)
				rulecnt = 1
			r=Rule(rulecnt,line)
			if args.html: r.html()
			else: r.rprint()
			rulecnt += 1
		#Assign interfaces and directions to the corresponfing access-groups
		elif re_aclgrp.search(line):
			aclnames[re_aclgrp.search(line).group('acl_name')] = re_aclgrp.search(line).group('acl_int')

if args.html:
	html_tbl_ftr()
	html_ftr(aclnames)
