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


def addr_form(addr):
	if "any" in addr or "0.0.0.0 0.0.0.0" in addr or "0.0.0.0/0" in addr:
		return "any"
	elif re.match(r'^\d',addr):
		tmp=netaddr.IPNetwork(addr.replace(" ","/"))
		if '255.255.255.255' in str(tmp.netmask):
			return "host "+str(tmp.ip)
		else:
			return str(tmp.ip) + " " + str(tmp.netmask)
	elif re.match(r'^\w',addr):
		return "object-group "+addr
	else:
		print >>sys.stderr, "Unknown format or the address " +addr
		sys.exit(1)



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
		self.line=self.cleanup(line)
		self.name = args.acl
		self.parse()

	# Simple clean-up
	def cleanup(self,line):
		# Replace any with 0/0
		return re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line.strip())

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


	def parse(self):
		global address

		arr=line.split()
		if len(arr) <= 3 and not (args.src or args.dst):
			print >>sys.stderr, line
			print >>sys.stderr, "Too few fields. Specify either the source or destination IP-address/netmask or object name"
			sys.exit(1)
		elif len(arr) <= 2:
			print >>sys.stderr, line
			print >>sys.stderr, "Too few fields in the policy. There must be 3 or more"
			sys.exit(1)

		if len(arr) >= 5:
			# arr[0] - sourceIP
			# arr[1] - source mask
			# arr[2] - destIP
			# arr[3] - dest mask
			# arr[4] - service
			# arr[5] - action
			self.src = ' '.join(arr[0:2])
			self.dst = ' '.join(arr[2:4])
			self.proto = self.protocol(arr[4])
			self.srv = self.port(arr[4])
			self.action = 'permit' if len(arr) == 5  else arr[5]
		else:
			if args.src:
				# arr[0] - destIP
				# arr[1] - dest mask
				# arr[2] - service
				self.src = address
				self.dst = ' '.join(arr[0:2])
				self.proto = self.protocol(arr[2])
				self.srv = self.port(arr[2])
				self.action = 'permit' if not args.deny else 'deny'
			elif args.dst:
				# arr[0] - sourceIP
				# arr[1] - source mask
				# arr[2] - service
				self.src = ' '.join(arr[0:2])
				self.dst = address
				self.proto = self.protocol(arr[2])
				self.srv = self.port(arr[2])
				self.action = 'permit' if not args.deny else 'deny'

	def rprint(self):
#		pprint.pprint(self.line, self.src, self.dst, self.proto, self.srv, self.action)
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

if args.src:
	address = args.src
elif args.dst:
	address = args.dst
else:
	address = "any"
address = addr_form(address)

policy = Policy(args.dev)

for line in f:
	r=PRule(line)
	r.rprint()
