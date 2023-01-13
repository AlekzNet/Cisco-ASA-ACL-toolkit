#!/usr/bin/python3
# ASA conf converter to sh access-list or HTML
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_extended.html
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_objects.html
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/ref_ports.html

import argparse
import re
import sys

try:
	import netaddr
except ImportError:
	print('ERROR: netaddr module not found.', file=sys.stderr)
	sys.exit(1)

try:
	import pprint
except ImportError:
	print('ERROR: pprint module not found. Either install pprint with \"pip install pprint\" \n or replace '
		  'pprint.pprint with print (the debug function)', file=sys.stderr)
	sys.exit(1)


def debug(string, level=1):
	if args.verbose >= level:
		pprint.pprint(string, sys.stderr, width=70)


def newobj(obj, key):
	"""
	If new object is found, add it to the group
	And set the current names
	"""
	global curobj, curname
	curobj = obj
	curname = key
	curobj[curname] = []


def fillobj(obj, key, val):
	"""
	Add new services or networks to the object
	:param obj:
	:param key: object name
	:param val: object value
	"""
	obj[key].append(val)


def unfold(objarr):
	"""
	Iterate through all objects in netgrp, srvgrp or prtgrp
	"""
	debug(objarr, 2)
	for obj in objarr:
		debug(obj, 3)
		unfold_rec(objarr[obj], objarr)
		if not args.noaggr and objarr is netgrp:
			objarr[obj] = netaddr.cidr_merge(objarr[obj])


def unfold_rec(obj, objarr, index=0):
	"""
	Unfold all included objects
	objarr{} - netgrp, srvgrp, prtgrp
	obj[] - curent object from objarr{} to unfold
	index - curent index of objects in obj[]
	"""
	# We are starting with the index from the previous iteration
	debug("unfold_rec", 4)
	for i in range(index, len(obj)):
		item = obj[i]
		debug(item, 4)
		# If object-group is found,
		# recurse through the object-groups
		if "object-group" in str(item):
			# Add the content of the object-group
			# item by item
			for j in objarr[item.split()[1]]:
				debug(j, 4)
				obj.append(j)
			# Remove the item with object-group
			del obj[i]
			# and dive into the new updated object
			# We are passing the index we are currently on
			unfold_rec(obj, objarr, i)
		elif 'net-object' in str(item):
			# if net-object is in the group
			# get its address from netobj
			obj.append(netobj[item.split()[1]])
			del obj[i]
			unfold_rec(obj, objarr, i)


def html_hdr(title):
	print('<html lang=en><head><title>' + title + '</title></head><body> <style> \
	body {background: #FFF5DD; color: #000080; font-family: sans-serif; padding-left: 20px; } \
	table {color: #000080; font-size: 0.8em; border: solid 1px #000080; border-collapse: collapse; } \
	th { font-size: 1em; padding: 0.8em; }\
	td {padding-left: 15px; padding-top: 5px; padding-bottom: 5px; padding-right: 15px;} \
	a {color: #0000d0; text-decoration: none;} \
	.permit {color: DarkGreen;} \
	.deny {color: DarkRed;} </style> \
	<h1>' + title + ' policy</h1><h4><a href=#content>Content</a></h4>')


def html_tbl_hdr(title):
	print('<table border=1><caption id=' + title + '><h2>' + title + '</h2></caption> \
	<tr><th>Line #</th><th>Source</th><th>Destination</th><th>Service</th><th>Action</th></tr>')


def html_tbl_ftr():
	print('</table><br /><br />')


def html_ftr(content):
	print('<div id=content><h2>Content</h2><ul>')
	for i in content:
		print('<li><a href=#' + i + '>' + i + '</a> ' + content[i] + '</i>')
	print('</ul></div></body></html>')


class Rule:
	"""Class for an ACL rule"""
	# access-list myacl remark My best rule
	re_acl_rem = re.compile(r'^\s*access-list\s+\S+\s+remark\s+(?P<acl_rem>.*$)', re.IGNORECASE)
	
	# All subsequent remarks are concatenated in this persistent variable
	remark = ''
	
	def __init__(self, lnum, line):
		self.lnum = lnum
		self.line = line
		self.name = ''
		self.src = []
		self.dst = []
		self.srv = []
		self.proto = []
		self.action = ''
		self.rem = ''
		self.isinactive = False
		self.cleanup()
		self.parse()
	
	def cleanup(self):
		"""
		Simple clean-up
		"""
		self.line = re.sub(r'\s+log$|\s+log\s+.*$', '', self.line)
		self.line = re.sub(r'\bany\b|\bany4\b', '0.0.0.0 0.0.0.0', self.line)
	
	def parse(self):
		"""
		access-list line parser
		"""
		if Rule.re_acl_rem.search(self.line):
			# Found Remarked ACL
			# Was the prev rule also remarked? If yes, add <br>
			if Rule.remark:
				Rule.remark += '<br />'
			Rule.remark += Rule.re_acl_rem.search(line).group('acl_rem')
			debug(f"Rule.remark = {Rule.remark}", 3)
		else:
			# Clean the remarks
			self.rem = Rule.remark
			Rule.remark = ''
			arr = self.line.split()
			# ACL name
			self.name = arr[1]
			# Permit or deny
			self.action = arr[3]
			del arr[0:4]
			debug(f'Rule number {self.lnum}', 3)
			debug(arr, 3)
			
			""" Protocol or service """
			
			if 'object-group' in arr[0]:
				if arr[1] in prtgrp:
					self.proto = prtgrp[arr[1]]
				else:
					self.srv = srvgrp[arr[1]]
				debug(f"srv = service object group {arr[1]} {self.srv}", 4)
				del arr[0:2]
			elif 'object' in arr[0]:
				self.srv = srvgrp[arr[1]]
				debug(f"srv = object {arr[1]} {self.srv}", 4)
				del arr[0:2]
			else:
				self.proto.append(arr[0])
				debug(f"proto = {self.proto}", 4)
				del arr[0]
			
			""" Source """
			
			if 'object-group' in arr[0]:
				self.src = netgrp[arr[1]]
			elif 'object' in arr[0]:
				self.src = [netobj[arr[1]]]
			elif 'host' in arr[0]:
				self.src = [netaddr.IPNetwork(arr[1] + '/32')]
			else:
				self.src = [netaddr.IPNetwork(arr[0] + '/' + arr[1])]
			debug("Source: %s" % self.src, 3)
			del arr[0:2]
			# Source ports are not supported
			if "range" in arr[0]:
				del arr[0:3]
			if "eq" in arr[0] or "lt" in arr[0] or "gt" in arr[0] or "neq" in arr[0]:
				del arr[0:2]
			
			""" Destination """
			
			if 'object-group' in arr[0]:
				self.dst = netgrp[arr[1]]
			elif 'object' in arr[0]:
				self.dst = [netobj[arr[1]]]
			elif 'host' in arr[0]:
				self.dst = [netaddr.IPNetwork(arr[1] + '/32')]
			else:
				self.dst = [netaddr.IPNetwork(arr[0] + '/' + arr[1])]
			del arr[0:2]
			
			"""  Services """
			
			if len(arr) > 0:
				if 'object-group' in arr[0]:
					self.srv = srvgrp[arr[1]]
				else:
					self.srv = [','.join(self.proto) + ':' + ' '.join(arr[:])]
			elif not self.srv:
				self.srv = self.proto
	
	def rprint(self):
		"""
		Print rule in the sh access-list format
		"""
		if not Rule.remark:
			for src in self.src:
				for dst in self.dst:
					for srv in self.srv:
						proto, ports = srv.split(":") if ":" in srv else [srv, '']
						print('access-list ' + self.name + ' line ' + str(self.lnum) + ' extended ' +
							  ' '.join(
								  [self.action, proto, str(src.ip), str(src.netmask), str(dst.ip), str(dst.netmask),
								   ports]))
			self.rem = ''
	
	def html(self):
		"""
		Print the rule as an HTML table row
		"""
		if not Rule.remark:
			# Are there accumulated comments?
			if self.rem:
				print('<tr><td colspan=5>' + self.rem + '</td></tr>')
			print(f'<tr>{self.html_lnum()} {self.html_obj(self.src)} {self.html_obj(self.dst)}'
				  f'{self.html_obj(self.proto)} {self.html_obj(self.srv)} {self.html_action(self.action)}</tr>')
	
	def html_action(self, act):
		"""
		Highlight the action in green or red
		"""
		if 'permit' in act:
			return '<td><span class=permit>' + act + '</span></td>'
		else:
			return '<td><span class=deny>' + act + '</span></td>'
	
	def html_obj(self, obj):
		"""
		Print out the content of the object-group with <br /> in between
		"""
		debug(f"html_obj {obj}", 4)
		#debug(obj, 4)
		return '<td>' + '<br />'.join(map(lambda x: str(x), obj)) + '</td>'
	
	def html_lnum(self):
		return f'<td>{self.lnum}</td>'


parser = argparse.ArgumentParser()
parser.add_argument("conf", default="-", nargs="?",
					help='Cisco ASA conf filename or "-" to read from the console (default)')
parser.add_argument("-v", "--verbose", default=0,
					help='Verbose mode. Messages are sent to STDERR.\n To increase the level add "v", e.g. -vvv',
					action="count")
out = parser.add_mutually_exclusive_group()
out.add_argument('--html', default=True, help="Cisco policy to HTML", action="store_true")
out.add_argument('--acl', default=False, help="Cisco policy to sh access-list", action="store_true")
parser.add_argument('--noaggr', default=False, help="Do not aggregate networks", action="store_true")
args = parser.parse_args()
if args.acl:
	args.html = False

netobj = {}  # network-objects
netgrp = {}  # network-groups
srvgrp = {}  # service-groups
prtgrp = {}  # protocol-groups
aclmode = False
rulecnt = 0  # ACL rule counter
curacl = ''  # current ACL name
aclnames = {}  # ACL names and interfaces
# global curobj points to the current dict: netobj, netgrp or srvgrp
# global curname points to the current object name
# curproto points to the current protocol
# global curobj,curname

# hostname fw_name
re_hostname = re.compile(r'^\s*hostname\s+(?P<hostname>\S+)', re.IGNORECASE)

""" Network objects"""

# object network mynet1
re_objnet = re.compile(r'^\s*object\s+network\s+(?P<obj_name>\S+)', re.IGNORECASE)
# subnet 10.1.2.0 255.255.255.0
re_subnet = re.compile(r'^\s*subnet\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
# range 10.1.2.1 10.1.3.2
re_range = re.compile(r'^\s*range\s+(?P<ip1>\S+)\s+(?P<ip2>\S+)', re.IGNORECASE)
# host 10.2.1.41
re_host = re.compile(r'^\s*host\s+(?P<ip>\S+)', re.IGNORECASE)
# object-group network mynetgrp1
re_netgrp = re.compile(r'^\s*object-group\s+network\s+(?P<net_grp>\S+)', re.IGNORECASE)
# network-object 10.1.1.1 255.255.255.255
re_netobj = re.compile(r'^\s*network-object\s+(?P<ip>\S+)\s+(?P<mask>\S+)', re.IGNORECASE)
# network-object host 10.1.1.1
re_netobj_host = re.compile(r'^\s*network-object\s+host\s+(?P<ip>\S+)', re.IGNORECASE)
# network-object object mynet1
re_netobj_obj = re.compile(r'^\s*network-object\s+object\s+(?P<obj_name>\S+)', re.IGNORECASE)
# group-object net-10.1.0.0-16
re_grpobj = re.compile(r'^\s*group-object\s+(?P<grp_obj>\S+)', re.IGNORECASE)

""" Protocol """

# object-group protocol protogrp
re_protogrp = re.compile(r'^\s*object-group\s+protocol\s+(?P<prt_grp>\S+)\s*$', re.IGNORECASE)
# protocol-object udp
re_protobj = re.compile(r'^\s*protocol-object\s+(?P<prt_obj>\S+)\s*$', re.IGNORECASE)

""" Service """

# object-group service mysrvgrp1
re_srvgrp = re.compile(r'^\s*object-group\s+service\s+(?P<srv_grp>\S+)\s*$', re.IGNORECASE)
# object-group service srv_tcp tcp
re_srvgrp_proto = re.compile(r'^\s*object-group\s+service\s+(?P<srv_grp>\S+)\s+(?P<proto>\S+)', re.IGNORECASE)
# port-object eq ldaps
re_portobj = re.compile(r'^\s*port-object\s+(?P<service>.*$)', re.IGNORECASE)
# service-object tcp destination eq 123
re_srvobj = re.compile(r'^\s*service-object\s+(?P<proto>\S+)(\s+destination)?\s+(?P<service>.*$)', re.IGNORECASE)
# service-object 97
re_srvobj_ip = re.compile(r'^\s*service-object\s+(?P<proto>\d+)', re.IGNORECASE)
# service-object object srvname
re_srvobj_obj = re.compile(r'^\s*service-object\s+object\s+(?P<srv_obj>\S+)\s*$', re.IGNORECASE)
# object service srvname
re_objsrv = re.compile(r'^\s*object\s+service\s+(?P<srv_obj>\S+)\s*$', re.IGNORECASE)
# service tcp destination eq 123
re_srvobj_1 = re.compile(r'^\s*service\s+(?P<proto>\S+)(\s+destination)?\s+(?P<service>.*$)', re.IGNORECASE)

""" ACL type """

# access-list ... inactive
re_isinactive = re.compile(r'^\s*access-list\s.*\sinactive\s*$', re.IGNORECASE)
# access-list acl_name extended ...
re_isacl = re.compile(r'^\s*access-list\s+\S+\s+extended', re.IGNORECASE)
# description .....
re_descr = re.compile(r'^\s*description\s+.*', re.IGNORECASE)

# access-list name
re_aclname = re.compile(r'^\s*access-list\s+(?P<acl_name>\S+)\s+', re.IGNORECASE)

# access-group management_acl in interface management
re_aclgrp = re.compile(r'^\s*access-group\s+(?P<acl_name>\S+)\s+(?P<acl_int>.*$)', re.IGNORECASE)

f = sys.stdin if "-" == args.conf else open(args.conf, "r")

for line in f:
	line = line.strip()
	debug(line, 3)
	# Parsing and filling in the network and service objects
	if re_isinactive.match(line) or re_descr.match(line):
		debug(f"{line} -- ignored")
		continue
	if not aclmode:
		if args.html and re_hostname.search(line):
			html_hdr(re_hostname.search(line).group('hostname'))
		elif re_objnet.search(line):
			newobj(netobj, re_objnet.search(line).group('obj_name'))
		elif re_subnet.search(line):
			curobj[curname] = netaddr.IPNetwork(re_subnet.search(line).group('ip') +
												'/' + re_subnet.search(line).group('mask'))
		elif re_range.search(line):
			curobj[curname] = netaddr.IPRange(re_range.search(line).group('ip1'), re_range.search(line).group('ip2'))
		elif re_host.search(line):
			curobj[curname] = netaddr.IPNetwork(re_host.search(line).group('ip') + '/32')
		elif re_netgrp.search(line):
			newobj(netgrp, re_netgrp.search(line).group('net_grp'))
		elif re_netobj_host.search(line):
			fillobj(curobj, curname, netaddr.IPNetwork(re_netobj_host.search(line).group('ip') + '/32'))
		elif re_netobj_obj.search(line):
			fillobj(curobj, curname, 'net-object ' + re_netobj_obj.search(line).group('obj_name'))
		elif re_netobj.search(line):
			fillobj(curobj, curname, netaddr.IPNetwork(re_netobj.search(line).group('ip') +
													   '/' + re_netobj.search(line).group('mask')))
		elif re_protogrp.search(line):
			newobj(prtgrp, re_protogrp.search(line).group('prt_grp'))
		elif re_protobj.search(line):
			fillobj(curobj, curname, re_protobj.search(line).group('prt_obj'))
		elif re_srvgrp.search(line):
			newobj(srvgrp, re_srvgrp.search(line).group('srv_grp'))
		elif re_objsrv.search(line):
			newobj(srvgrp, re_objsrv.search(line).group('srv_obj'))
		elif re_grpobj.search(line):
			fillobj(curobj, curname, 'object-group ' + re_grpobj.search(line).group('grp_obj'))
		elif re_srvobj_obj.search(line):
			fillobj(curobj, curname, re_srvobj_obj.search(line).group('srv_obj'))
		elif re_srvobj.search(line):
			fillobj(curobj, curname, re_srvobj.search(line).group('proto') + ':' +
					re_srvobj.search(line).group('service'))
		elif re_srvobj_1.search(line):
			fillobj(curobj, curname, re_srvobj_1.search(line).group('proto') + ':' +
					re_srvobj_1.search(line).group('service'))
		elif re_srvgrp_proto.search(line):
			newobj(srvgrp, re_srvgrp_proto.search(line).group('srv_grp'))
			curproto = re_srvgrp_proto.search(line).group('proto')
		elif re_portobj.search(line):
			fillobj(curobj, curname, curproto + ':' + re_portobj.search(line).group('service'))
		elif re_srvobj_ip.search(line):
			fillobj(curobj, curname, re_srvobj_ip.search(line).group('proto'))
		elif re_isacl.search(line):
			aclmode = True
			debug("netgrp", 2)
			unfold(netgrp)
			debug("srvgrp", 2)
			unfold(srvgrp)
			debug("prtgrp", 2)
			unfold(prtgrp)
	
	# Parsing access-lists
	if aclmode:
		if re_aclname.search(line):
			newacl = re_aclname.search(line).group('acl_name')
			if not curacl == newacl:
				curacl = newacl
				aclnames[curacl] = ''
				if args.html:
					if rulecnt:
						html_tbl_ftr()
					html_tbl_hdr(curacl)
				rulecnt = 1
			r = Rule(rulecnt, line)
			if args.html:
				r.html()
			else:
				r.rprint()
			rulecnt += 1
		# Assign interfaces and directions to the corresponding access-groups
		elif re_aclgrp.search(line):
			aclnames[re_aclgrp.search(line).group('acl_name')] = re_aclgrp.search(line).group('acl_int')

if args.html:
	html_tbl_ftr()
	html_ftr(aclnames)
