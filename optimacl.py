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

def check_line():
	global line
	#Sanity check
	line = line.strip()
	if "host" in line:
		print >>sys.stderr, line
		print >>sys.stderr, "\'host\' word not expected."
		sys.exit(1)
	# Replace any with 0/0
	line=re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line)
	if not line.count(" ") == 2:
		print >>sys.stderr, line
		print >>sys.stderr, "Too less or too many parameters. Expected: network mask proto:port"
		sys.exit(1)


parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
args = parser.parse_args()

services={}
policy={}
star_nets=IPSet()

f=sys.stdin if "-" == args.pol else open (args.pol,"r")

for line in f:
	check_line()
	net,mask,service = line.split()
	network=IPNetwork(net+"/"+mask)
	if "*" in service:
# The following two lines can be commented out if memory is not
# an issue
		if not len(policy.get(network,'')) == 0:
			del policy[network]
		star_nets.add(network)
# The following is CPU expensive, but saves RAM
#	elif not network in star_nets:
	else:
		if service not in policy.get(network,''):
			if len(policy.get(network,'')) == 0:
				policy[network] = []
			policy[network].append(service)

# From policy to services
# policy is a dict of IPNetwork: [ port_list]
for net in policy:
	if not net in star_nets:
		for srv in policy[net]:
			if srv in services.keys():
				services[srv].add(net)
			else:
				services[srv] = IPSet(net)


for i in services:
	for j in cidr_merge(services[i]):
#	print i, services[i]
		print j.ip, j.netmask, i


for i in cidr_merge(star_nets):
	print i.ip, i.netmask, "*"
