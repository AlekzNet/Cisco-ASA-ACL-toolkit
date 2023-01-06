#!/usr/bin/python3

import string
import argparse
import re
import sys
from operator import itemgetter
from itertools import groupby

try:
	import netaddr
except ImportError:
	print('ERROR: netaddr module not found.', file=sys.stderr)
	sys.exit(1)

try:
	import pprint
except ImportError:
	print(
		'ERROR: pprint module not found. Either install pprint or replace pprint.pprint with print (the debug function)',
		file=sys.stderr)
	sys.exit(1)


def debug(string, level=1):
	if args.verbose >= level:
		pprint.pprint(string, sys.stderr, width=70)


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
		debug(line, 0)
		debug("'host\' word not expected", 0)
		sys.exit(1)
	# Replace any with 0/0
	line = re.sub(r'\bany\b', '0.0.0.0 0.0.0.0', line)
	if line.count(" ") == 2:
		result = True
	elif line.count(" ") == 4:
		result = False
	else:
		debug(line, 0)
		debug("Too few or too many parameters. Expected: \n network mask proto:port \n or \n \
			srcaddr src mask dstaddr dstmask proto:port", 0)
		sys.exit(1)
	if mode == '':
		mode = result
		return result
	else:
		if mode == result:
			return result
		else:
			print(line, file=sys.stderr)
			print("Inconsistency discovered. This line contains either less or more parameters than the previous lines", file=sys.stderr)
			sys.exit(1)


# Range (port1-port2) to range (port1, port+1, ... port2)
# srv is a port list, e.g. ["1000", "2000"]
def rtor(arr, srv):
	for i in range(int(srv[0]), int(srv[1]) + 1):
		arr.append(i)


# Add ports to the port array
def srvadd(port, arr):
	if "-" in port:
		rtor(arr, port.split("-"))
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
		srvadd(port, srvarr)
	# 	for k, g in groupby(enumerate(sorted(set(srvarr))), lambda (x, y): x - y): - original for Python2
	for k, g in groupby(enumerate(sorted(set(srvarr))), lambda x: x[0] - x[1]):
		group = (map(itemgetter(1), g))
		group = list(map(int, group))
		if group[0] == group[-1]:
			ranges.append(str(group[0]))
		else:
			ranges.append(str(group[0]) + "-" + str(group[-1]))
	return ranges


# Check if net1->net2 is netlist
#
def are_nets_in(net1, net2, netlist):
	for net in netlist:
		if type(netlist[net]) is list or type(netlist[net]) is tuple:
			for n in netlist[net]:
				if type(net) is tuple or type(net) is list:
					for m in net:
						if net1 in m and net2 in n:
							debug("are_nets_in -- %s is in %s, %s is in %s" % (str(net1), str(m), str(net2), str(n)), 4)
							return True
				else:
					if net1 in net and net2 in n:
						debug("are_nets_in -- Not list. %s is in %s, %s is in %s" % (
							str(net1), str(net), str(net2), str(n)), 4)
						return True
		else:
			if net1 in net and net2 in netlist[net]:
				debug("are_nets_in -- %s is in %s, %s is in %s" % (str(net1), str(net), str(net2), str(netlist[net])), 4)
				return True
	return False


# Add networks to the nets dict
# nets := { src: [dst1, dst2, ...], ...}
def add_net_pair(src, dst, nets):
	debug("add_net_pair -- Adding new net_pair", 5)
	debug(src, 5)
	debug(dst, 5)
	if src not in nets:
		nets[src] = []
	if dst not in nets[src]:
		nets[src].append(dst)
	debug("add_net_pair -- Current nets", 5)
	debug(nets[src], 5)


# Group services by network groups
def add_srv(srv, nets, arr):
	debug("add_srv -- adding service %s" % srv, 5)
	debug("add_srv -- for the following nets", 5)
	debug(nets, 5)
	if nets not in arr:
		arr[nets] = []
	if srv not in arr[nets]:
		arr[nets].append(srv)
	debug("add_srv -- after adding", 5)
	debug(arr[nets], 5)


def group_nets(nets):
	# nets = { src: [dst1, dst2, ...], ...}
	revnets = {}  # nets reversed: { dst: [src1, src2, ...], ... }
	# next iteration
	debug("group_nets -- Begin ====================", 4)
	debug("group_nets -- Before first phase of grouping (nets)", 4)
	debug(nets, 4)
	
	for src in nets:
		
		debug("group_nets -- The source", 5)
		debug(src, 5)
		debug("group_nets -- 1F The destination", 5)
		debug(nets[src], 5)
		nets[src] = netaddr.cidr_merge(nets[src])
		debug("group_nets -- 1F After CIDR-merge", 5)
		debug(nets[src], 5)
		if len(nets) == 1:
			debug("group_nets -- Only one pair", 4)
			return {(src,): nets[src]}
		for dst in nets[src]:
			debug("group_nets -- For the destination", 5)
			debug(dst, 5)
			
			if dst not in revnets:
				revnets[dst] = []
			if src not in revnets[dst]:
				revnets[dst].append(src)
				debug("group_nets -- Added the following source", 5)
				debug(src, 5)
			debug("group_nets -- Current revnets[dst]", 5)
			debug(revnets[dst], 5)
	# grouping
	debug("group_nets -- The result of the first phase of grouping (revnets)", 4)
	debug(revnets, 4)
	debug("group_nets -- Second phase of grouping", 4)
	
	nets = {}
	for dst in revnets:
		debug("group_nets -- 2F The destination", 5)
		debug(dst, 5)
		debug("group_nets -- The corresponfing sources", 5)
		debug(revnets[dst], 5)
		revnets[dst] = netaddr.cidr_merge(revnets[dst])
		debug("group_nets -- 2F After CIDR-merge", 5)
		debug(revnets[dst], 5)
		add_net_pair(tuple(revnets[dst]), dst, nets)
	debug("group_nets -- The result of grouping (nets)", 4)
	debug(nets, 4)
	
	debug("group_nets -- End ====================", 4)
	return nets


parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" (default) to read from the console")
# parser.add_argument('--group', help='Group services and networks together', action="store_true")
parser.add_argument('-v', '--verbose', default=0,
					help='Verbose mode. Messages are sent to STDERR.\n To increase the level add "v", e.g. -vvv',
					action='count')
parser.add_argument('--nomerge', help='Do not merge ports', action="store_true")
args = parser.parse_args()

services = {}  # { service: { srcnet: [dstnet1, dstnet2, ...] }, ... }
policy = {}  #
star_nets = {}  # { [srcnet1, srcnet2, ...]: [dstnet1, dstnet2, ...], ... }
mode = ''  # True if addr srv, False if addr1 addr2 srv

f = sys.stdin if "-" == args.pol else open(args.pol, "r")
debug("Reading from " + args.pol)

counter = 0
# First iteration
# Create star_nets
# Create policy { (src1,dst1): {proto1:[port_list], proto2:[port_list]}, ... }
# Fix services, then fix srcnet, and aggregate dstnet
for line in f:
	if args.verbose: counter += 1
	check_line()
	srcaddr, srcmask, dstaddr, dstmask, service = line.split()
	srcnet = netaddr.IPNetwork(srcaddr + "/" + srcmask)
	dstnet = netaddr.IPNetwork(dstaddr + "/" + dstmask)
	if "*" in service:
		debug("New star_net pair found", 4)
		debug(srcnet, 4)
		debug(dstnet, 4)
		add_net_pair(srcnet, dstnet, star_nets)
		proto = 'ip'
		port = '*'
	else:
		proto, port = service.split(":") if ":" in service else [service, ""]
	pair = (srcnet, dstnet)
	if pair not in policy:
		policy[pair] = {}
	if proto not in policy[pair]:
		policy[pair][proto] = []
	if port and port not in policy[pair][proto]:
		policy[pair][proto].append(port)

debug("%d rules in the policy file" % counter)
debug("First iteration is completed. %d rules, and %d \"allow all\" rules found" % (len(policy), len(star_nets)))
debug(policy, 3)

star_nets = group_nets(star_nets)
debug("Allow rules are reduced to %d" % len(star_nets))
debug("Second ineration begins")

# Second iteration
# Combine services together and remove overlaps
# Iterating over policy.keys(), because some entries will be removed from policy
# for pair in policy.keys() - was working fir Python2
# For Python3 - explanation  here:
# https://stackoverflow.com/questions/11941817/how-to-avoid-runtimeerror-dictionary-changed-size-during-iteration-error

for pair in list(policy):
	# If the servie is ip * - delete this line
	if 'ip' in policy[pair] and '*' in policy[pair]['ip']:
		debug("Removing *", 4)
		debug(pair, 4)
		debug(policy[pair], 4)
		del policy[pair]
	# Testing src, dst against star_nets
	# is the slowest part of the program
	elif are_nets_in(pair[0], pair[1], star_nets):
		debug("Removing networks matching star_nets", 4)
		debug(pair, 4)
		debug(policy[pair], 4)
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
					policy[pair].append(proto + ":" + port)
			else:
				policy[pair].append(proto)

debug("Second iteration is completed. %d rules left" % len(policy))
debug(policy, 3)

# Third iteration is to create a list of networks per allowed service
# From policy to services
# policy is a dict of IPNetwork: [ port_list]
# services is a dict of Service: list(IPNetworks)
for pair in policy:
	for srv in policy[pair]:
		if srv not in services.keys():
			services[srv] = {}
		add_net_pair(pair[0], pair[1], services[srv])

debug("Third iteration is completed. %d services are in the policy" % len(services))

policy = {}
debug(services, 3)

# Fourth iteration
for srv in services:
	# Grouping SRC and DST networks per service
	services[srv] = group_nets(services[srv])
	# Grouping services together, based on the same src-dst pairs
	# All indexes must be immutable, hence converting to tuples
	# separately, src (keys) and dst (values) per srv
	for src in services[srv]:
		add_srv(srv, (src, tuple(services[srv][src])), policy)

debug("Fourth iteration is completed. %d rules in the policy, plus %d \"allow all\" rules" % (len(policy), len(star_nets)))
debug("Modified services", 3)
debug(services, 3)
debug("Resulting policy")
# print "Finished grouping service nets"
debug(policy, 3)

for nets in policy:
	src = ",".join(map(lambda x: str(x), nets[0]))
	dst = ",".join(map(lambda x: str(x), nets[1]))
	srv = ",".join(policy[nets])
	print(src, dst, srv)

if len(star_nets):
	for net in star_nets:
		src = ",".join(map(lambda x: str(x), net))
		dst = ",".join(map(lambda x: str(x), star_nets[net]))
		print(src, dst, "*")

debug("All done. There are %d rules in the policy." % (len(policy) + len(star_nets)))
