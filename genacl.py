#!/usr/bin/python

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


def cidr2str(addr):
	tmp = netaddr.IPNetwork(addr)
	return ' '.join([str(tmp.ip),str(tmp.netmask)])

def str2cidr(addr):
	return str(netaddr.IPNetwork(re.sub(' ','/',addr)))

def net2name(net):
	ip,mask=str2cidr(net).split('/')
	if '32' in mask: return 'h-'+ip
	else: return 'n-'+ip+'_'+mask

class PRule:
	'Class for a rule prototype'

	re_any=re.compile('^any$', re.IGNORECASE)
	re_dig=re.compile('^\d')
	re_nondig=re.compile('^\D')

	def __init__(self,line,):
		self.line=line.strip()
		self.parse()

	def check_arr(self,arr):
		if not len(arr):
			print >>sys.stderr, self.line
			print >>sys.stderr, "Too few fields in the policy."
			sys.exit(1)

	def parse_addr(self,arr):
		if 'any' in  arr[0]:
			addr='any'
			del arr[0]
		elif not ',' in arr[0]:
			if '/' in arr[0]:
				addr = [cidr2str(arr[0])]
				del arr[0]
			else:
				addr = [' '.join(arr[0:2])]
				del arr[0:2]
		else:
			addr = [cidr2str(x) for x in arr[0].split(',')]
			addr.sort()
			del arr[0]
		return addr

	def parse_addr_args(self,addr):
		if '/' in addr:
			return [cidr2str(addr)]
		elif self.re_any.search(addr):
			return ['any']
		elif self.re_nondig.match(addr):
			return ["object-group "+addr]
		elif ' ' in addr:
			return [addr]
		else: return [addr+' 255.255.255.255']

	def parse(self):

		addr1=''
		addr2=''

		arr=line.split()

		# Get the first address
		addr1=self.parse_addr(arr)
		self.check_arr(arr)

		if self.re_dig.match(arr[0]) or 'any' in arr[0] or 'host' in arr[0]:
			addr2=self.parse_addr(arr)
			self.check_arr(arr)

		if not ',' in arr[0]:
#			self.proto = self.protocol(arr[0])
#			self.srv = self.port(arr[0])
			self.srv=[arr[0]]
		else:
			self.proto = ''
			self.srv = [ x for x in arr[0].split(',')]
		del arr[0]

		if len(arr): self.action = arr[0]
		elif not args.deny: self.action = 'permit'
		else: self.action = 'deny'

		if addr2:
			self.src = addr1
			self.dst = addr2
		elif args.src:
			self.src = self.parse_addr_args(args.src)
			self.dst = addr1
		elif args.dst:
			self.src = addr1
			self.dst = self.parse_addr_args(args.dst)
		else:
			print >>sys.stderr, self.line
			print >>sys.stderr, "Either too few fields or define either --src IP or --dst IP"
			sys.exit(1)

class FW():
	'General Firewall Class'
	devtype='' #Device type

	def fw_netobj_print(self,netobj):
		pass

	def fw_srvobj_print(self,srvobj):
		pass

	def netobj_add(self,netobj,rule):
		pass

	def srvobj_add(self,srvobj,rule):
		pass

class FGT(FW):
	'FortiGate specific class'
	devtype='fgt'
	vdom = ''
	srcintf = ''
	dstintf = ''
	rulenum = 0

	re_any = re.compile('any|all|0\.0\.0\.0 0\.0\.0\.0|0\.0\.0\.0/0', re.IGNORECASE)

	predefsvc = {'tcp:540': 'UUCP', 'udp:1-65535': 'ALL_UDP', 'tcp:7000-7009 udp:7000-7009': 'AFS3', 'tcp:70': 'GOPHER', 'IP:89': 'OSPF', 'ip': 'ALL', 'udp:520': 'RIP', 'tcp:1723': 'PPTP', 'udp:67-68': 'DHCP', 'tcp:1720': 'NetMeeting', 'IP:51': 'AH', 'udp:389': 'LDAP_UDP', 'udp:500 udp:4500': 'IKE', 'IP:50': 'ESP', 'udp:517-518': 'TALK', 'tcp:1080 udp:1080': 'SOCKS', 'tcp:465': 'SMTPS', 'IP:47': 'GRE', 'tcp:5631 udp:5632': 'PC-Anywhere', 'tcp:79': 'FINGER', 'tcp:554 tcp:7070 tcp:8554 udp:554': 'RTSP', 'tcp:1433-1434': 'MS-SQL', 'icmp': 'ALL_ICMP', 'tcp:143': 'IMAP', 'tcp:111 tcp:2049 udp:111 udp:2049': 'NFS', 'tcp:995': 'POP3S', 'tcp:993': 'IMAPS', 'udp:2427 udp:2727': 'MGCP', 'tcp:1512 udp:1512': 'WINS', 'tcp:512': 'REXEC', 'udp:546-547': 'DHCP6', 'tcp:5900': 'VNC', 'tcp:3389': 'RDP', 'tcp:6660-6669': 'IRC', 'udp:1645-1646': 'RADIUS-OLD', 'udp:33434-33535': 'TRACEROUTE', 'tcp:80': 'HTTP', 'tcp:2401 udp:2401': 'CVSPSERVER', 'tcp:2000': 'SCCP', 'tcp:1863': 'SIP-MSNmessenger', 'tcp:161-162 udp:161-162': 'SNMP', 'tcp:210': 'WAIS', 'tcp:1720 tcp:1503 udp:1719': 'H323', 'ICMP:8': 'PING', 'tcp:5060 udp:5060': 'SIP', 'tcp:1701 udp:1701': 'L2TP', 'tcp:389': 'LDAP', 'tcp:123 udp:123': 'NTP', 'udp:26000 udp:27000 udp:27910 udp:27960': 'QUAKE', 'tcp:21': 'FTP', 'tcp:5190-5194': 'AOL', 'tcp:23': 'TELNET', 'tcp:53 udp:53': 'DNS', 'tcp:25': 'SMTP', 'tcp:6000-6063': 'X-WINDOWS', 'tcp:7000-7010': 'VDOLIVE', 'tcp:3128': 'SQUID', 'tcp:88 udp:88': 'KERBEROS', 'tcp:0': 'NONE', 'tcp:443': 'HTTPS', 'tcp:445': 'SMB', 'tcp:1-65535': 'ALL_TCP', 'ICMP6:128': 'PING6', 'udp:69': 'TFTP', 'udp:7070': 'RAUDIO', 'tcp:1755 udp:1024-5000': 'MMS', 'udp:1812-1813': 'RADIUS', 'tcp:135 udp:135': 'DCE-RPC', 'tcp:179': 'BGP', 'udp:514': 'SYSLOG', 'tcp:110': 'POP3', 'tcp:119': 'NNTP', 'ICMP:13': 'TIMESTAMP', 'tcp:3306': 'MYSQL', 'tcp:22': 'SSH', 'tcp:111 udp:111': 'ONC-RPC', 'icmp:17': 'INFO_ADDRESS', 'tcp:139': 'SAMBA', 'icmp:15': 'INFO_REQUEST', 'tcp:1494 tcp:2598': 'WINFRAME'}



	def __init__(self,vdom='root',srcintf='any',dstintf='any',rulenum=10000, label=''):
		self.vdom = vdom
		self.srcintf = srcintf
		self.dstintf = dstintf
		self.rulenum=rulenum
		self.label=label

	def upnum(self):
		self.rulenum += 1

	def rprint(self,policy):
		if self.vdom:
			self.fw_header_print()
		self.fw_netobj_print(policy.netobj)
		self.fw_srvobj_print(policy.srvobj)
		self.fw_rules_print(policy)
		self.fw_footer_print()

	def fw_header_print(self):
		if self.vdom:
			print 'config vdom'
			print 'edit ' + self.vdom

	def fw_footer_print(self):
		print 'end'

	def fw_rules_print(self,policy):
		print 'config firewall policy'
		policy.srvobj.update(self.predefsvc)
		for rule in policy.policy:
			print ' edit ' + str(self.rulenum)
			print '  set srcintf ' + self.srcintf
			print '  set dstintf ' + self.dstintf
			print '  set srcaddr ' + ' '.join(map(lambda x: policy.netobj[x], rule.src))
			print '  set dstaddr ' + ' '.join(map(lambda x: policy.netobj[x], rule.dst))
			print '  set service ' + ' '.join(map(lambda x: policy.srvobj[x], rule.srv))
			print '  set schedule always'
			print '  set status enable'
			if 'permit' in rule.action:
				print '  set action accept'
			else:
				print '  set action deny'
			if self.label:
				print '  set global-label "' + self.label + '"'
			self.rulenum += 1
			print ' next'
		print 'end'

	def fw_netobj_print(self,netobj):
		print 'config firewall address'
		for obj in netobj:
			print ' edit '+ netobj[obj]
			print '  set subnet ' + obj
			print ' next\n'
		print 'end'

	def fw_srvobj_print(self,srvobj):
		print 'config firewall service custom'
		for obj in srvobj:
			if not '*' in obj:
				# For some reason the following construction does not work
				# proto,ports = obj.split(':') if ':' in obj else obj,''
				if ':' in obj:	proto,ports = obj.split(':')
				else: proto,ports = obj,''
				print ' edit ' + srvobj[obj]
				if 'udp' in proto or 'tcp' in proto:
					print '  set protocol TCP/UDP/SCTP'
					print '  set ' + proto + '-portrange ' + ports
				elif 'icmp' in proto:
					print '  set protocol ICMP'
					if ports:
						print '  set icmptype ' + ports
				elif 'ip' in proto:
					if ports:
						print '  set protocol IP'
						print '  set protocol-number ' + ports
				else:
					print '  set protocol IP'
					print '  set protocol-number ' + proto
				print ' next'
		print 'end'

	def netobj_add(self,netobj,rule):
		for addrs in rule.src,rule.dst:
			# Convert a single IP-address to a list
#			if not type(addrs) is list: addrs=[addrs]
			for addr in addrs:
				if addr not in netobj:
					if self.re_any.search(addr):
						netobj[addr]  = 'all'
					else: netobj[addr] = net2name(addr)

	def srvobj_add(self,srvobj,rule):
		services = rule.srv
#		if not type(services) is list: services=[services]
		for srv in services:
			if srv not in srvobj and srv not in self.predefsvc:
				if '*' in srv:
					srvobj[srv] = 'ALL'
				else:
					srvobj[srv]=re.sub(':','-',srv)


class ASA(FW):
	'ASA specific class'
	devtype='asa'
	aclname='' #ACL name
	netobj_name='obj_net_' # Template for network object-group
	netobj_cnt=0 # network object-group counter shift
	srvobj_name='obj_srv_' # Template for service object-group
	srvobj_cnt=0 # service object-group counter shift
	action='permit' #default action

	def __init__(self,aclname='Test_ACL'):
		self.aclname=aclname

	def fw_rules_print(self,policy):
		for rule in policy.policy:
			print  ' '.join(["access-list", self.aclname, "extended", self.action, self.rule_proto(rule), \
				self.rule_addr(rule.src), self.rule_addr(rule.dst), self.rule_port(rule)])

	def rule_proto(self,rule):
		if len(rule.srv) > 1:
			return 'object-group ' + policy.srvobj[tuple(rule.srv)]
		else:
			return self.protocol(rule.srv[0])

	def rule_port(self,rule):
		if len(rule.srv) > 1:
			return ''
		else:
			return self.port(rule.srv[0])

	def rule_addr(self,addr):
		if len(addr) > 1:
			return 'object-group ' + policy.netobj[tuple(addr)]
		else:
			return addr[0]

	def rprint(self,policy):
		self.fw_header_print()
		self.fw_netobj_print(policy.netobj)
		self.fw_srvobj_print(policy.srvobj)
		self.fw_rules_print(policy)
		self.fw_footer_print()

	def fw_header_print(self):
		print 'config terminal'

	def fw_footer_print(self):
		print 'wri'
		print 'exit'

	def fw_netobj_print(self,netobj):
		for addrs in netobj:
			print 'object-group network',netobj[tuple(addrs)]
			for addr in addrs:
				print ' network-object',addr

	def fw_srvobj_print(self,srvobj):
		for svcs in srvobj:
			print 'object-group service',srvobj[tuple(svcs)]
			for svc in svcs:
				print ' service-object',self.protocol(svc),'destination',self.port(svc)

	def protocol(self,service):
		if "*" in service:
			return "ip"
		elif ":" in service:
			tmp = service.split(":")
			return tmp[0]
		else:
			return service

	def port(self,service):
		if ":" in service:
			tmp = service.split(":")
			if "-" in tmp[1]:
				low,high = tmp[1].split("-")
				if int(low) == 1:
					return "lt " +high
				elif int(high) == 65535:
					return "gt " +low
				else:
					return "range "+low+" "+high
			elif "icmp" not in tmp[0]:
				return "eq "+tmp[1]
			else:
				return tmp[1]
		else:
			return ''

	def netobj_add(self,netobj,rule):
		for addrs in rule.src,rule.dst:
			if len(addrs) > 1:
				if tuple(addrs) not in netobj:
					objname=self.netobj_name+str(len(netobj)+1+self.netobj_cnt)
					netobj[tuple(addrs)]=objname


	def srvobj_add(self,srvobj,rule):
		if len(rule.srv) > 1:
			if tuple(rule.srv) not in srvobj:
				objname=self.srvobj_name+str(len(srvobj)+1+self.srvobj_cnt)
				srvobj[tuple(rule.srv)]=objname


class Policy(PRule):
	'Class for the whole policy'
	netobj = {} # { '10.0.1.0 255.255.255.0': 'n-10.0.1.0_24' }
	srvobj = {} # { 'tcp:20-23': 'TCP-20-23' }
	netgrp = {}	# { 'net-group1: }network-groups
	srvgrp = {}	# service-groups
	policy = [] # global policy
	device = '' # 'ASA' or 'FGT' class object

	def __init__(self,dev):
		self.device = dev

	def getdev(self):
		return self.device

	def addrule(self,rule):
		self.policy.append(rule)

	def getpol(self):
		return self.policy

	def get_objects(self):
		for rule in self.policy:
			self.device.netobj_add(self.netobj,rule)
			self.device.srvobj_add(self.srvobj,rule)

	def rprint(self):
		self.get_objects()
		self.device.rprint(self)



parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
parser.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name for ASA. Default=Test_ACL")
parser.add_argument('--dev', default="asa", choices=['asa','fgt'], help="Type of device: asa (default) or fgt")
parser.add_argument('--vdom', default="", help="VDOM name for FortiGate. Default - none")
parser.add_argument('--si', default="any", help="Source interface for FortiGate. Default - any")
parser.add_argument('--di', default="any", help="Destination interface for FortiGate. Default - any")
parser.add_argument('--rn', default=10000, help="Starting rule number for Fortigate. Default - 10000")
parser.add_argument('--label', default='', help="Section label, Default - none")
args = parser.parse_args()



f=sys.stdin if "-" == args.pol else open (args.pol,"r")

if 'asa' in args.dev:
	dev=ASA(args.acl)
elif 'fgt' in args.dev:
	dev=FGT(args.vdom, args.si, args.di, args.rn, args.label)
else:
	print >>sys.stderr, dev, "- not supported device. It should be asa (Cisco ASA) or fgt (FortiGate)"
	sys.exit(1)

policy = Policy(dev)

for line in f:
	r=PRule(line)
	policy.addrule(r)

policy.rprint()
