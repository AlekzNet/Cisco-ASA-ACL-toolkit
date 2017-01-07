#!/usr/bin/python

from netaddr import *
import string
import argparse
import re

parser = argparse.ArgumentParser()
parser.add_argument('--addr', default='0.0.0.0/0', help="Comma-separated list of addresses/netmasks")
parser.add_argument('--acl', default='es_nsn-partner.acl', help="Cisco ASA ACL filename")
parser.add_argument('--sd', default='both', help="Where to search: source, dest or both")
parser.add_argument('--noany', help="Ignore \'any\' in the ACLs", action="store_true")
parser.add_argument('--deny', help="Search \'deny\' rules only" , action="store_true")
parser.add_argument('--permit', help="Search \'permit\' rules only" , action="store_true")
args = parser.parse_args()

# True if the IP belongs to the Source IP
def issrc():
	if "host" in arr[7]: 
		ip = arr[8]
		mask = "32"
	else:
		ip = arr[7]	
		mask = arr[8]	
	if ip == "0.0.0.0" and args.noany : return False
	temp_set.add(IPNetwork(ip + "/" + mask))
	return ips.intersection(temp_set)

# True if the IP belongs to the Dest IP	
def isdst():
	if "range" in arr[9]: del arr[9:12]
	if "host" in arr[9]: 
		ip = arr[10]
		mask = "32"
	else:
		ip = arr[9]	
		mask = arr[10]	
	if ip == "0.0.0.0" and args.noany : return False		
	temp_set.add(IPNetwork(ip + "/" + mask))
	return ips.intersection(temp_set) 

# Postformat the ACL and print
def print_acl():
	print re.sub('0.0.0.0 0.0.0.0','any',line)


ips = IPSet()

# If a list of IP's is given, add them all
if "," in args.addr:
	for i in args.addr.split(","):
		ips.add(IPNetwork(i))
else:
	ips.add(IPNetwork(args.addr))	
	
arr = []
temp_set = IPSet()
temp_set.clear()
f = open (args.acl,"r")

for line in f:

	# Remove leftovers
	if " remark " in line or "object-group" in line or not "extended" in line: continue
	line=re.sub(r'\(hitcnt.*$','',line)
	line=re.sub(r'<--- More --->','',line)
	line = line.strip()	
	
	# Replace any with 0/0
	line=re.sub('any','0.0.0.0 0.0.0.0',line)
		
	arr = line.split(" ")
	
	# We are not interested in permit lines, if --deny is set
	if args.deny and not "deny" in arr[5]: continue

	# We are not interested in deny lines, if --permit is set
	if args.permit and "deny" in arr[5]: continue

	if "source" in args.sd:
		if issrc(): print_acl()
	
	elif "dest" in args.sd:	
		if isdst(): print_acl()

	elif "both" in args.sd:
		if issrc() or isdst(): print_acl()

	temp_set.clear()
	del arr[:]		
	
f.close()		

