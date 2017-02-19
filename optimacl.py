#!/usr/bin/python

import string
import argparse
import re
import sys
from operator import itemgetter
from itertools import groupby

try:
	import netaddr
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)

# Check if the line contains 3 fields only
# Remove leading and trailing spaces
# Replace any with 0/0
def check_line():
	global line
	line = line.strip()
	if "host" in line:
		print >>sys.stderr, line
		print >>sys.stderr, "\'host\' word not expected."
		sys.exit(1)
	# Replace any with 0/0
	line=re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line)
	if not line.count(" ") == 2:
		print >>sys.stderr, line
		print >>sys.stderr, "Too few or too many parameters. Expected: network mask proto:port"
		sys.exit(1)

# Range (port1-port2) to range (port1, port+1, ... port2)
# srv is a port list, e.g. ["1000", "2000"]
def rtor(arr,srv):
	for i in range(int(srv[0]),int(srv[1])+1):
		arr.append(i)

# Add ports to the port array
def srvadd(port,arr):
	if "-" in port:
		rtor(arr,port.split("-"))
	else:
		arr.append(int(port))

# Sort all ports, remove duplicates, and group in continuous ranges
# The explanation how it works is here:
# http://stackoverflow.com/questions/2154249/identify-groups-of-continuous-numbers-in-a-list
# https://docs.python.org/2.6/library/itertools.html#examples
def squeeze(arr):
	srvarr = []
	ranges = []
	for port in arr:
		srvadd(port,srvarr)

	for k, g in groupby(enumerate(sorted(set(srvarr))), lambda (x,y):x-y):
		group = map(itemgetter(1), g)
		if group[0] == group[-1]:
			ranges.append(str(group[0]))
		else:
			ranges.append(str(group[0])+"-"+str(group[-1]))
	return ranges

# Print "star" networks
# the CIDR merging is very slow
def print_star():
	for i in star_nets:
		print i.ip, i.netmask, "*"

# Is net a part of any networks in the netlist?
def isnetin(net,netlist):
	for inet in netlist:
		if net in inet: return True
	return False

parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" (default) to read from the console")
parser.add_argument('--group', help='Group services and networks together', action="store_true")
parser.add_argument('--nomerge', help='Do not merge ports', action="store_true")
args = parser.parse_args()

services={}
policy={}
star_nets=[]

f=sys.stdin if "-" == args.pol else open(args.pol,"r")

# First iteration is to create a list of services per network
# If all ports (*) are allowed for a network, then place
# this network in star_nets, and replace the service list with "*"
# policy is a dict of IPNetwork: {proto1:[port_list], proto2:[port_list]}
for line in f:
	check_line()
	net,mask,service = line.split()
	network=netaddr.IPNetwork(net+"/"+mask)
	if "*" in service:
# The following two lines can be commented out if memory is not
# an issue
#		if not len(policy.get(network,'')) == 0:
#			del policy[network]
		star_nets.append(network)
	else:
		proto,port = service.split(":") if ":" in service else [service,""]
		if network not in policy:
			policy[network]={}
		if proto not in policy[network]:
			policy[network][proto]=[]
		if port and port not in policy[network][proto]:
			policy[network][proto].append(port)


star_nets = netaddr.cidr_merge(star_nets)

# Second iteration
# Combine services together and remove overlaps
# Iterating over policy.keys(), because some entries will be removed from policy
for net in policy.keys():
	if isnetin(net,star_nets):
		del policy[net]
	else:
		for proto in policy[net]:
			if len(policy[net][proto]) > 1:
				# First combine all TCP/UDP services
				if ("tcp" in proto or "udp" in proto) and not args.nomerge:
					policy[net][proto] = squeeze(policy[net][proto])
		tmparr = policy[net]
		policy[net] = []
		for proto in tmparr:
			if tmparr[proto]:
				for port in tmparr[proto]:
					policy[net].append(proto+":"+port)
			else:
				policy[net].append(proto)

# Third iteration is to create a list of networks per allowed service
# From policy to services
# policy is a dict of IPNetwork: [ port_list]
# services is a dict of Service: list(IPNetworks)
for net in policy:
	for srv in policy[net]:
		if srv in services.keys():
			services[srv].append(net)
		else:
			services[srv] = [net]


if args.group:
	# Let's reuse policy dict
	policy = {}
	for service in services:
		# services[service] contains a list of IPNetworks
		# 1. CIDR merge the list of IPNetworks
		# 2. Iterate through the list and convert the nets into strings
		# with IP-address/netmask
		# 3. Join them together using "," as a separator
		# The commented out line can be used instead to generate the CIDR /xx notation
		networks=",".join(map(lambda x: str(x),netaddr.cidr_merge(services[service])))
#		networks=",".join(map(lambda x: str(x.ip)+"/"+str(x.netmask),netaddr.cidr_merge(services[service])))
		if service not in policy.get(networks,''):
			if len(policy.get(networks,'')) == 0:
				policy[networks] = []
			policy[networks].append(service)

	services = {}

	# Printing the result
	for net in policy:
		print net,",".join(policy[net])
#	CIDR /xx notation
#	print ",".join(map(lambda x: str(x),star_nets)),"*"
	if len(star_nets):
		print ",".join(map(lambda x: str(x.ip)+"/"+str(x.netmask),star_nets)),"*"

else:
	# CIDR-merging IPNetworks, corresponding to the service
	# And print the result
	for srv in services:
		for net in netaddr.cidr_merge(services[srv]):
			print net.ip, net.netmask, srv


	print_star()
