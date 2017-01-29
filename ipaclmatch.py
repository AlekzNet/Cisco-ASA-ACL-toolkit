#!/usr/bin/python

import string
import argparse
import re
import sys
try:
	from netaddr import *
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)

parser = argparse.ArgumentParser()
parser.add_argument('-a','--addr', default='0.0.0.0/0', help="Comma-separated list of addresses/netmasks. \"all\" shows all lines")
parser.add_argument('acl', default="-", nargs='?', help="Cisco ASA ACL filename or \"-\" to read from the console (default)")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s', '--src', help="Search the source", action="store_true")
sd.add_argument('-d', '--dst', help="Search the destination", action="store_true")
sd.add_argument('-b', '--both', help="Search both the source and the destination (default)", action="store_true")
an = parser.add_mutually_exclusive_group()
an.add_argument('--noany', help="Ignore \'any\' in the ACLs", action="store_true")
an.add_argument('--any', help="Show only \'any\' in the ACLs", action="store_true")
dp = parser.add_mutually_exclusive_group()
dp.add_argument('--deny', help="Search \'deny\' rules only" , action="store_true")
dp.add_argument('--permit', help="Search \'permit\' rules only" , action="store_true")
ra = parser.add_mutually_exclusive_group()
ra.add_argument('--range', default=True, help="Replace lt, gt, and neq with ranges (default)", action="store_true")
ra.add_argument('--norange', default=False, help="Replace lt, gt, and neq with \<, \>, and ! symbols", action="store_true")
parser.add_argument('--direct', help="Direct IP match only" , action="store_true")
parser.add_argument('-t','--transform', help='Transform the output. Must be used with either -s or -d and with either --deny or --permit', action="store_true")
parser.add_argument('-p','--policy', help='Print the policy in the form:\n SourceIP SourceMask DestIP DestMask Proto:Port. Must be used with either --deny or --permit', action="store_true")
parser.add_argument('--contain', help='Direct matches and subnets (not direct and uppernets). Assumes --noany', action="store_true")
parser.add_argument('--noline', help='Removes line number from the output', action="store_true")
args = parser.parse_args()

if not args.src and not args.dst and not args.both: args.both = True
if "all" in args.addr: args.addr="0.0.0.0/0"
if "0.0.0.0/0" in args.addr and not args.any: args.contain=True
if args.both and args.transform:
	print >>sys.stderr, "--transform requires either --src or --dst. --transform cannot be used with --both"
	sys.exit(1)
if args.policy: args.transform=True
if args.both and args.direct:
	print >>sys.stderr, "--direct requires either --src or --dst. --both cannot be used with --direct"
	sys.exit(1)

if args.norange: args.range=False



# service name - port mapping from
# http://www.cisco.com/c/en/us/td/docs/security/asa/asa96/configuration/general/asa-96-general-config/ref-ports.html#ID-2120-000002b8
if args.transform:
	s2n={'domain': '53', 'sunrpc': '111', 'citrix-ica': '1494', 'telnet': '23', 'tftp': '69', 'syslog': '514', 'rtsp': '554', 'secureid-udp': '5510', 'gopher': '70', 'h323': '1720', 'echo': '7', 'netbios-ssn': '139', 'snmptrap': '162', 'rpc': '111', 'radius': '1645', 'pcanywhere-data': '5631', 'nameserver': '42', 'rsh': '514', 'sqlnet': '1521', 'uucp': '540', 'ftp': '21', 'sip': '5060', 'whois': '43', 'smtp': '25', 'ctiqbe': '2748', 'hostname': '101', 'snmp': '161', 'mobile-ip': '434', 'daytime': '13', 'ldaps': '636', 'isakmp': '500', 'netbios-dgm': '138', 'finger': '79', 'https': '443', 'ldap': '389', 'kshell': '544', 'irc': '194', 'nntp': '119', 'biff': '512', 'http': '80', 'cifs': '3020', 'exec': '512', 'pptp': '1723', 'ntp': '123', 'aol': '5190', 'talk': '517', 'pcanywhere-status': '5632', 'pop3': '110', 'pop2': '109', 'ftp-data': '20', 'lotusnotes': '1352', 'rip': '520', 'xdmcp': '177', 'pim-auto-rp': '496', 'login': '513', 'dnsix': '195', 'ident': '113', 'netbios-ns': '137', 'kerberos': '750', 'tacacs': '49', 'who': '513', 'cmd': '514', 'bootps': '67', 'bgp': '179', 'nfs': '2049', 'klogin': '543', 'chargen': '19', 'www': '80', 'time': '37', 'discard': '13', 'imap4': '143', 'lpd': '515', 'bootpc': '68', 'radius-acct': '1646', 'ssh': '22'}


# True if the IP belongs to the Source IP
# arr[7] -- source IP-address or host
# arr[8] -- netmask or hostip
def issrc():
	if "host" in arr[7]:
		arr[7] = arr[8]
		arr[8] = "255.255.255.255"

	if args.direct:	return isdir(arr[7],arr[8])
	if arr[7] == "0.0.0.0" and args.noany : return False
	if args.contain: return isnetin(arr[7],arr[8])
	else: return isinnet(arr[7],arr[8])

# True if the IP belongs to the Dest IP
# arr[9] -- dest IP-address or host
# arr[10] -- netmask or hostip
def isdst():
	if "range" in arr[9]: del arr[9:12]
	if "host" in arr[9]:
		arr[9] = arr[10]
		arr[10] = "255.255.255.255"

	if args.direct: return isdir(arr[9],arr[10])
	if arr[9] == "0.0.0.0" and args.noany : return False
	if 	args.contain: return isnetin(arr[9],arr[10])
	else: return isinnet(arr[9],arr[10])

# True if there is a direct match
# Go through all IP's in ips and compare with the ip and mask from the ACL
def isdir(ip,mask):
	result = False
	for i in ips:
		result = result or ( str(IPNetwork(i).ip) == ip and str(IPNetwork(i).netmask) == mask )
	return result

# Does any of the IP-addresses we are searching for belong to the current IP network?
def isinnet(ip,mask):
	result = False
	for i in ips:
		result = result or i in IPNetwork(ip + "/" + mask)
	return result

# Does any of the IP-addresses we are searching for contains the current IP network?
def isnetin(ip,mask):
	result = False
	for i in ips:
		result = result or IPNetwork(ip + "/" + mask) in i
	return result

# Postformat the ACL and print
# arr[6] - protocol (ip, tcp, udp)
# arr[7] - source ip
# arr[8] - source mask
# arr[9] - dest ip
# arr[10]- dest mask
# arr[11]- range, eq, lt, gt - prepsvc changes it to proto:port
# arr[12]- port or port1
# arr[13]- port2 or nothing
# action is either empty or 'deny'
# neq_range contains the second range, if 'neq'
def print_acl():
	global line
	if args.transform:
#		if "icmp" in arr[6]: return
		if args.policy:
			host2num("src")
			host2num("dst")
			neq_range = prepsvc()
			print arr[7],arr[8],arr[9],arr[10],arr[11],action
			if neq_range: print arr[7],arr[8],arr[9],arr[10],neq_range,action
		elif args.src:
			host2num("src")
			neq_range = prepsvc()
			print arr[9],arr[10],arr[11], action
			if neq_range: print arr[9],arr[10],neq_range,action
		elif args.dst:
			host2num("dst")
			neq_range = prepsvc()
			print arr[7],arr[8],arr[11],action
			if neq_range: print arr[7],arr[8],neq_range,action
	elif args.noline:
		line=re.sub(r'\bline\b \d+ ','',line)
		print line.replace('0.0.0.0 0.0.0.0','any')
	else: print line.replace('0.0.0.0 0.0.0.0','any')

# Replace "host" with IP 255.255.255.255
def host2num(where):
	if "src" in where:
		if "host" in arr[9]:
			arr[9] = arr[10]
			arr[10] = "255.255.255.255"
	if "dst" in where:
		if "host" in arr[7]:
			arr[7] = arr[8]
			arr[8] = "255.255.255.255"

# Place the service in arr[11] in the form of tcp:1234, udp:12345=3456, or *
# If --range: replace neq, gt, lt with ranges
# Return True if "neq", False in all other cases
def prepsvc():
	if len(arr)-1 >= 12: serv2num(12)
	if len(arr)-1 >= 13: serv2num(13)
	if "ip" in arr[6]: arr.insert(11,"*")
	elif len(arr) < 12: arr.insert(11, arr[6])
	elif "range" in arr[11]: arr[11] = arr[6]+':'+arr[12]+'-'+arr[13]
	elif "neq" in arr[11]:
		if args.range:
			# the first range goes into arr[11]
			arr[11] = arr[6]+':1-'+str(int(arr[12])-1)
			# the second range is returned
			return arr[6]+':'+str(int(arr[12])+1)+'-65535'
		else:
			arr[11] = arr[6]+'!'+arr[12]
	elif "eq" in arr[11]: arr[11] = arr[6]+':'+arr[12]
	elif "gt" in arr[11]:
		if args.range:
			arr[11] = arr[6]+':'+arr[12]+'-65535'
		else:
			arr[11] = arr[6]+'>'+arr[12]
	elif "lt" in arr[11]:
		if args.range:
			arr[11] = arr[6]+':1-'+arr[12]
		else:
			arr[11] = arr[6]+'>'+arr[12]
	return False

# Replace service name with port number
# f is the position in arr
def serv2num(f):
	if re.match(r'\d+',arr[f]): return  # if number nothing to do
	if arr[f] in s2n: arr[f]=s2n[arr[f]]
	else: quit(arr[f] + " is not a known service")



ips = []
arr = []

# If a list of IP's is given, add them all
if "," in args.addr:
	for i in args.addr.split(","):
		ips.append(IPNetwork(i))
else:
		ips.append(IPNetwork(args.addr))

f=sys.stdin if "-" == args.acl else open (args.acl,"r")

for line in f:

	# Remove leftovers
	if "remark" in line or "object-group" in line or not "extended" in line: continue
	line=re.sub(r'\(hitcnt.*$','',line)		#remove hitcounters
	line=re.sub(r' log .*$','',line)		#remove logging statements
	line=line.replace(r'<--- More --->','')
	line = line.strip()

	# Replace any with 0/0
	line=re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line)

	arr = line.split()

	# We are not interested in permit lines, if --deny is set
	if args.deny and not "deny" in arr[5]: continue

	# We are not interested in deny lines, if --permit is set
	if args.permit and "deny" in arr[5]: continue

	# Explicitly add 'deny' at the end of the policy line
	if not args.permit and not args.deny and "deny" in arr[5]:
		action = 'deny'
	else:
		action = ''

	if args.both and args.noany and "0.0.0.0 0.0.0.0" in line: continue

	if "0.0.0.0/0" in args.addr and not args.any and not args.noany:
		print_acl()
	elif args.src:
		if issrc(): print_acl()

	elif args.dst:
		if isdst(): print_acl()

	elif args.both:
		if issrc() or isdst(): print_acl()

	del arr[:]

f.close()
