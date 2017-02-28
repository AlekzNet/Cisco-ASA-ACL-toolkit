#!/usr/bin/python

import string
import argparse
import re
import sys
from operator import itemgetter
from itertools import groupby
import pprint

try:
	import netaddr
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)

# Check if the line contains 3 or 4 fields only
# Remove leading and trailing spaces
# Replace any with 0/0
# True if the line contains addr mask service
# False if the line contains srcaddr src mask dstaddr dstmask service
# Fail if inconsistency is discovered
def check_line():
	global line, mode
	line = line.strip()
	if "host" in line:
		print >>sys.stderr, line
		print >>sys.stderr, "\'host\' word not expected."
		sys.exit(1)
	# Replace any with 0/0
	line=re.sub(r'\bany\b','0.0.0.0 0.0.0.0',line)
	if line.count(" ") == 2: result=True
	elif line.count(" ") == 4: result=False
	else:
		print >>sys.stderr, line
		print >>sys.stderr, "Too few or too many parameters. Expected: \n network mask proto:port \n or \n \
			srcaddr src mask dstaddr dstmask proto:port"
		sys.exit(1)
	if mode == '':
		mode = result
		return result
	else:
		if mode == result: return result
		else:
			print >>sys.stderr, line
			print >>sys.stderr, "Inconsistency discovered. This line contains either less or more parameters than the previous lines"
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
def print_star():
	for i in star_nets:
		print i.ip, i.netmask, "*"

# Is net a part of any networks in the netlist?
def isnetin(net,netlist):
	for inet in netlist:
		if net in inet: return True
	return False

#Check if net1->net2 is netlist
def are_nets_in(net1,net2,netlist):
	for net in netlist:
		if type(netlist[net]) is list:
			for n in netlist[net]:
				if net1 in net and net2 in n: return True
#				print net1," and ", net2, "are not in ", net, " and ", n
		else:
			if net1 in net and net2 in netlist[net]: return True

	return False

# Add networks to the nets dict
# nets := { src: [dst1, dst2, ...], ...}
def add_net_pair(src,dst,nets):
	if src not in nets:
		nets[src] = []
	if dst not in nets[src]:
		nets[src].append(dst)

#Group services by network groups
def add_srv(srv,nets,arr):
	if nets not in arr:
		arr[nets]=[]
	if srv not in arr[nets]:
		arr[nets].append(srv)

def group_nets(nets):
	# nets = { src: [dst1, dst2, ...], ...}
	revnets = {} # nets reversed: { dst: [src1, src2, ...], ... }
	# next iteration
	#print "Grouping nets"
	#pprint.pprint(nets)
	for src in nets:
		nets[src] = netaddr.cidr_merge(nets[src])
		#if len(nets) == 1:
			#print "Only one pair"
			#return {([src]):nets[src]}
#		print "src= ",src
		for dst in nets[src]:
#			print "dst=",dst
			if dst not in revnets:
				revnets[dst] = []
			if src not in revnets[dst]:
				revnets[dst].append(src)
	#print "Result after phase 1"
	#pprint.pprint(revnets)
	# grouping
	nets = {}
	for dst in revnets:
		revnets[dst] = netaddr.cidr_merge(revnets[dst])
		add_net_pair(tuple(revnets[dst]),dst,nets)
	#print "Result after phase 2"
	#pprint.pprint(nets)
	return nets


parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" (default) to read from the console")
parser.add_argument('--group', help='Group services and networks together', action="store_true")
parser.add_argument('--nomerge', help='Do not merge ports', action="store_true")
args = parser.parse_args()

services={} #  { service: { srcnet: [dstnet1, dstnet2, ...] }, ... }
policy={} #
star_nets={} # { [srcnet1, srcnet2, ...]: [dstnet1, dstnet2, ...], ... }
mode = '' # True if addr srv, False if addr1 addr2 srv

f=sys.stdin if "-" == args.pol else open(args.pol,"r")

# First iteration
# Create star_nets
# Create policy { (src1,dst1): {proto1:[port_list], proto2:[port_list]}, ... }
# Fix services, then fix srcnet, and aggregate dstnet
for line in f:
	check_line()
	srcaddr,srcmask,dstaddr,dstmask,service = line.split()
	srcnet=netaddr.IPNetwork(srcaddr+"/"+srcmask)
	dstnet=netaddr.IPNetwork(dstaddr+"/"+dstmask)
	if "*" in service:
		add_net_pair(srcnet, dstnet, star_nets)
	else:
		proto,port = service.split(":") if ":" in service else [service,""]
		pair = (srcnet,dstnet)
		if pair not in policy:
			policy[pair]={}
		if proto not in policy[pair]:
			policy[pair][proto]=[]
		if port and port not in policy[pair][proto]:
			policy[pair][proto].append(port)


# Second iteration
# Combine services together and remove overlaps
# Iterating over policy.keys(), because some entries will be removed from policy
for pair in policy.keys():
	if are_nets_in(pair[0],pair[1],star_nets):
		#print "Deleted: "
		#pprint.pprint(pair)
		#pprint.pprint(policy[pair])
		del policy[pair]
	else:
		for proto in policy[pair]:
			if len(policy[pair][proto]) > 1:
				# First combine all TCP/UDP services
				if ("tcp" in proto or "udp" in proto) and not args.nomerge:
					policy[pair][proto] = squeeze(policy[pair][proto])
		tmparr = policy[pair]
		policy[pair] = []
		for proto in tmparr:
			if tmparr[proto]:
				for port in tmparr[proto]:
					policy[pair].append(proto+":"+port)
			else:
				policy[pair].append(proto)

#print("Policy")
#pprint.pprint(policy)

# Third iteration is to create a list of networks per allowed service
# From policy to services
# policy is a dict of IPNetwork: [ port_list]
# services is a dict of Service: list(IPNetworks)
for pair in policy:
	for srv in policy[pair]:
		if srv not in services.keys():
			services[srv] = {}
		add_net_pair(pair[0],pair[1],services[srv])

policy={}

#print("Services")
#pprint.pprint(services)

# Fourth iteration
# Grouping SRC and DST networks per service
for srv in services:
#	print "Grouping ", services[srv]
	services[srv]=group_nets(services[srv])
#	print "Grouping result"
#	pprint.pprint(services[srv])
	add_srv(srv,tuple([services[srv].keys()[0],tuple(services[srv].values()[0])]),policy)

#print "Finished grouping service nets"


#print("Policy")
#pprint.pprint(policy)

for nets in policy:
#	print "nets=", nets
#	print "nets[0]= ", nets[0]
	src=",".join(map(lambda x: str(x), nets[0]))
#	print "nets[1]= ", nets[1]
	dst=",".join(map(lambda x: str(x), nets[1]))
#	print "srv= ", policy[nets]
	srv=",".join(policy[nets])
	print src,dst,srv

star_nets = group_nets(star_nets)
if len(star_nets):
	for net in star_nets:
		src=",".join(map(lambda x: str(x), net))
		dst=",".join(map(lambda x: str(x), star_nets[net]))
		print src,dst,"*"
