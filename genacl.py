#!/usr/bin/python

import string
import argparse
import re
import sys
from netaddr import *

def proto(service):
	if "*" in service: 
		return "ip"
	elif ":" in service: 
		tmp = service.split(":")
		return tmp[0]
	else: 
		return service

def port(service):
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
		else: 
			return "eq "+tmp[1]
	else: 
		return ''

def addr_form(addr):
	if "any" in addr or "0.0.0.0 0.0.0.0" in addr or "0.0.0.0/0" in addr:
		return "any"
	elif re.match(r'^\d',addr):
		tmp=IPNetwork(addr.replace(" ","/"))
		if '255.255.255.255' in str(tmp.netmask):
			return "host "+str(tmp.ip)
		else:
			return str(tmp.ip) + " " + str(tmp.netmask)
	elif re.match(r'^\w',addr):
		return "object-group "+addr
	else:
		quit("Unknown format or the address " +addr)


parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
parser.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name, default=Test_ACL")
args = parser.parse_args()

f=sys.stdin if "-" == args.pol else open (args.pol,"r")

if args.src: 
	address = args.src
elif args.dst: 
	address = args.dst
else: 
	address = "any"
address = addr_form(address)

for line in f:
	line.strip()
	# Replace any with 0/0
	line=re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line)	
	arr=line.split()
	if len(arr) <= 3 and not (args.src or args.dst):
		quit("Not enough fields. Specify either the source or destination IP-address/netmask or object name")
	elif len(arr) <= 2:
		quit("Too little fields in the policy. There must be 3 or more")		
	
	if len(arr) == 5:	
# arr[0] - sourceIP
# arr[1] - source mask
# arr[2] - destIP
# arr[3] - dest mask
# arr[4] - service	
# arr[5] - action 
		print "access-list",args.acl,"extended", "permit" if not args.deny else "deny", \
		proto(arr[4]),addr_form(arr[0]+" "+arr[1]),addr_form(arr[2]+" "+arr[3]),port(arr[4])
	elif len(arr) > 5:
		print "access-list",args.acl,"extended", arr[5], \
		proto(arr[4]),addr_form(arr[0]+" "+arr[1]),addr_form(arr[2]+" "+arr[3]),port(arr[4])			
	else:	
		if args.src:		
# arr[0] - destIP
# arr[1] - dest mask		
# arr[2] - service
			print "access-list",args.acl,"extended", "permit" if not args.deny else "deny", \
			proto(arr[2]),address,addr_form(arr[0]+" "+arr[1]),port(arr[2])
		elif args.dst:
# arr[0] - sourceIP
# arr[1] - source mask		
# arr[2] - service
			print "access-list",args.acl,"extended", "permit" if not args.deny else "deny", \
			proto(arr[2]),addr_form(arr[0]+" "+arr[1]),address,port(arr[2])
			

			
