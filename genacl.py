#!/usr/bin/python

import string
import argparse
import re
import sys
#import pprint

try:
	import netaddr
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)


def cidr2str(addr):
	tmp = netaddr.IPNetwork(addr)
	return ' '.join([str(tmp.ip),str(tmp.netmask)])



class PRule:
	'Class for a rule prototype'

	def __init__(self,line,):
		self.line=line.strip()
		self.parse()

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

	def check_arr(self,arr):
		if not len(arr):
			print >>sys.stderr, self.line
			print >>sys.stderr, "Too few fields in the policy."
			sys.exit(1)

	def parse_addr(self,arr):
		if 'any' in  arr[0]:
			addr=arr[0]
			del arr[0]
		elif not ',' in arr[0]:
			if '/' in arr[0]:
				addr = cidr2str(arr[0])
				del arr[0]
			else:
				addr = ' '.join(arr[0:2])
				del arr[0:2]
		return addr

	def parse_addr_args(self,addr):
		if '/' in addr:
			return cidr2str(addr)
		elif re.match(r'^\D',addr):
			return "object-group "+addr
		elif ' ' in addr:
			return addr
		else: return 'host '+addr

	def parse(self):

		addr1=''
		addr2=''

		arr=line.split()

		addr1=self.parse_addr(arr)
		self.check_arr(arr)

		if re.match(r'^\d',arr[0]) or 'any' in arr[0] or 'host' in arr[0]:
			addr2=self.parse_addr(arr)
			self.check_arr(arr)

		if not ',' in arr[0]:
			self.proto = self.protocol(arr[0])
			self.srv = self.port(arr[0])
			del arr[0]

		if len (arr): self.action = arr[0]
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

class FGT():
	'FortiGate specific class'
	type='fgt'
	vdom = ''
	srcintf = ''
	dstintf = ''
	rulenum = 0

	def __init__(self,vdom='root',srcintf='any',dstintf='any',rulenum=10000):
		self.vdom = vdom
		self.srcintf = srcintf
		self.dstintf = dstintf
		self.rulenum=10000

	def upnum(self):
		self.rulenum += 1

	def rprint(self,rule):
		print self.rulenum, self.type
		self.rulenum += 1

class ASA():
	'ASA specific class'
	type='asa'
	aclname='' #ACL name

	def __init__(self,aclname='Test_ACL'):
		self.aclname=aclname

	def rprint(self,rule):
		print  " ".join(["access-list", self.aclname, "extended", rule.proto, rule.src, rule.dst, rule.srv])



class Policy(PRule):
	'Class for the whole policy'
	netobj = {}
	srvobj = {}
	netgrp = {}	# network-groups
	srvgrp = {}	# service-groups
	policy = [] # global policy
	device = '' # 'asa' or 'fgt'

	def __init__(self,dev):
		self.device = dev

	def getdev(self):
		return self.device

	def addrule(self,rule):
		self.policy.append(rule)

	def getpol(self):
		return self.policy

	def rprint(self):
		for rule in self.policy:
			dev.rprint(rule)



parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
parser.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name for ASA. Default=Test_ACL")
parser.add_argument('--dev', default="asa", help="Type of device: asa (default) or fgt")
parser.add_argument('--vdom', default="root", help="VDOM name for FortiGate. Default - root")
parser.add_argument('--si', default="any", help="Source interface for FortiGate. Default - any")
parser.add_argument('--di', default="any", help="Destination interface for FortiGate. Default - any")
parser.add_argument('--rn', default=10000, help="Starting rule number for FOrtigate. Default - 10000")
args = parser.parse_args()

f=sys.stdin if "-" == args.pol else open (args.pol,"r")

if 'asa' in args.dev:
	dev=ASA(args.acl)
elif 'fgt' in args.dev:
	dev=FGT(args.vdom, args.si, args.di, args.rn)
else:
	print >>sys.stderr, dev, "- not supported device. It should be asa (Cisco ASA) or fgt (FortiGate)"
	sys.exit(1)

policy = Policy(dev)

for line in f:
	r=PRule(line)
	policy.addrule(r)

policy.rprint()
