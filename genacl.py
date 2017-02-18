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

class Policy:
	'Class for the whole policy'
	netgrp = {}	# network-groups
	srvgrp = {}	# service-groups
	device = '' # asa or fgt

	def __init__(self,dev):
		Policy.device = dev

	def getdev(self):
		return Policy.device


class PRule(Policy):
	'Class for a rule prototype'

	def __init__(self,line):
		self.line=line.strip()
		self.name = args.acl
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

	def rprint(self):
		if 'asa' in self.getdev(): self.asaout()

	def asaout(self):
		print  " ".join(["access-list", self.name, "extended", self.proto, self.src, self.dst, self.srv])

parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
parser.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name, default=Test_ACL")
parser.add_argument('--dev', default="asa", help="Type of device. Default - asa")
args = parser.parse_args()

f=sys.stdin if "-" == args.pol else open (args.pol,"r")

policy = Policy(args.dev)

for line in f:
	r=PRule(line)
	r.rprint()
