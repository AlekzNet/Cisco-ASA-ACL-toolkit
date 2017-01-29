#!/usr/bin/python

import string
import argparse
import re
import sys
from operator import itemgetter
from itertools import groupby

try:
	from netaddr import *
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
		print >>sys.stderr, "Too less or too many parameters. Expected: network mask proto:port"
		sys.exit(1)

# Range (port1-port2) to range (port1, port+1, ... port2)
# srv is a port list, e.g. ["1000", "2000"]
def rtor(srvarr,srv):
	for i in range(int(srv[0]),int(srv[1])+1):
		srvarr.append(i)

# Add ports to the TCP array
def tcpadd(srv):
	if "-" in srv:
		rtor(tcpsrv,srv.split("-"))
	else:
		tcpsrv.append(int(srv))

# Add ports to the UDP array
def udpadd(srv):
	if "-" in srv:
		rtor(udpsrv,srv.split("-"))
	else:
		udpsrv.append(int(srv))

# Add non UDP or TCP protocol
def ipadd(srv):
	ipsrv.append(srv)

# Functions, corresponding to TCP abd UDP
protoadd = { 'tcp': tcpadd, 'udp': udpadd, 'ip': ipadd}

# Sort all ports, remove duplicates, and group in continuous ranges
# Explanation how it works here:
# http://stackoverflow.com/questions/2154249/identify-groups-of-continuous-numbers-in-a-list
# https://docs.python.org/2.6/library/itertools.html#examples
def squeeze(arr):
#	if len(arr) == 1: return [arr[0],arr[-1]]
	ranges = []
	for k, g in groupby(enumerate(sorted(set(arr))), lambda (x,y):x-y):
		group = map(itemgetter(1), g)
		ranges.append((group[0], group[-1]))
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
args = parser.parse_args()

services={}
policy={}
star_nets=[]

f=sys.stdin if "-" == args.pol else open(args.pol,"r")

# First iteration is to create a list of services per network
# If all ports (*) are allowed for a network, then place
# this network in star_nets, and replace the service list with "*"
# policy is a dict of IPNetwork: [ port_list]
for line in f:
	check_line()
	net,mask,service = line.split()
	network=IPNetwork(net+"/"+mask)
	if "*" in service:
# The following two lines can be commented out if memory is not
# an issue
		if not len(policy.get(network,'')) == 0:
			del policy[network]
		star_nets.append(network)
	else:
		if service not in policy.get(network,''):
			if len(policy.get(network,'')) == 0:
				policy[network] = []
			policy[network].append(service)


star_nets = cidr_merge(star_nets)

# Second iteration
# Combine services together and remove overlaps
# Iterating over policy.keys(), because some entries will be removed from policy
for net in policy.keys():
#	print "policy:", net, policy[net]
	if isnetin(net,star_nets):
#		print "Policy is in star_nets"
		del policy[net]
	elif len(policy[net]) > 1:
		# Filling tcpsrv and udpsrv arrays with ports from the policy
		tcpsrv=[]
		udpsrv=[]
		ipsrv=[]
		for srv in policy[net]:
#			print "srv=",srv
			if ":" in srv:
				proto,ports = srv.split(":")
			else:
				proto = "ip"
				ports = srv
			srvadd = protoadd[proto]
			srvadd(ports)
		# Creating new port list
		policy[net]=[]
		if len(ipsrv) > 0:
			for ports in ipsrv:
				policy[net].append(ports)
		if len(tcpsrv) > 0:
			for ports in squeeze(tcpsrv):
				if ports[0] == ports[1]:
					policy[net].append("tcp:"+str(ports[0]))
				else:
					policy[net].append("tcp:"+str(ports[0])+"-"+str(ports[1]))
		if len(udpsrv) > 0:
			for ports in squeeze(udpsrv):
				if ports[0] == ports[1]:
					policy[net].append("udp:"+str(ports[0]))
				else:
					policy[net].append("udp:"+str(ports[0])+"-"+str(ports[1]))
#		print "new: ",policy[net]


# Third iteration is to create an IPSet of networks per allowed service
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
		# services[service] contains an IPSet
		# 1. CIDR merge the IPSet into a list of IPNetworks
		# 2. Iterate through the list and convert the nets into strings
		# with IP-address/netmask
		# 3. Join them together using "," as a separator
		# The commented out line can be used instead to generate the CIDR /xx notation
#		networks=",".join(map(lambda x: str(x),cidr_merge(services[service])))
		networks=",".join(map(lambda x: str(x.ip)+"/"+str(x.netmask),cidr_merge(services[service])))
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
	print ",".join(map(lambda x: str(x.ip)+"/"+str(x.netmask),star_nets)),"*"

else:
	# CIDR-merging IPNetworks, corresponding to the service
	# And print the result
	for srv in services:
		for net in cidr_merge(services[srv]):
			print net.ip, net.netmask, srv


	print_star()
