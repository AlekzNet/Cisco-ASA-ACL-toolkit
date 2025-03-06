#!/usr/bin/python3

import string
import argparse
import re
import sys

try:
	import netaddr
except ImportError:
	print('ERROR: netaddr module not found, you can install it with \"pip install netaddr\"', file=sys.stderr)
	sys.exit(1)

try:
	import pprint
except ImportError:
	print('ERROR: pprint module not found. Either install pprint with \"pip install pprint\" \n or replace pprint.pprint with print (the debug function)',
		file=sys.stderr)
	sys.exit(1)


def debug(string, level=1):
	if args.verbose >= level:
		pprint.pprint(string, sys.stderr, width=70)


class PRule:
	"""Class for a rule prototype"""
	
	re_any = re.compile(r'^any$', re.IGNORECASE)
	re_dig = re.compile(r'^\d')			# digital
	re_nondig = re.compile(r'^\D')		# non-digital
	re_spaces = re.compile(r'\s+')		# lots of spaces/tabs
	re_comma = re.compile(r'\s*,\s*')	# comma, surrounded by spaces/tabs (or not))
	re_remark = re.compile(r'^\s*#')	# the whole line is a comment/remark
	re_comment = re.compile(r'(?P<line>.*)\s*#(?P<comment>.*)')  # if there is a comment in the line?

	def __init__(self, line, deny=False):
		"""
		line (str) - policy line
		deny (boolean) - by default the action is "allow", unless there is an explicit "deny" in the line
		if deny is set to True, the action will be "deny"
		"""
		
		self.src = []
		self.dst = []
		self.srv = []
		self.num = 0  # rule number
		self.action = "deny" if deny else "permit"
		self.comment = ""
		line = line.strip()
		self.origline = line
		# If the line begins with "#" it's a comment
		if self.re_remark.search(line):
			self.type = "comment"
			self.comment = self.re_remark.sub("", line)
			self.line = None
			return
		else:
			self.type = "rule"
		self.line = self.cleanup(line)
		debug(self.line, 2)
		self.parse()

	def cleanup(self, line):
		debug("cleanup -- before clean-up: %s" % line, 3)
		if self.re_comment.search(line):
			self.comment = self.re_comment.search(line).group('comment')
			line = self.re_comment.search(line).group('line')
		line = self.re_spaces.sub(" ", line)
		line = self.re_comma.sub(",", line)
		debug("After clean-up: %s" % line, 3)
		return line
	
	def cidr2str(self, addr):
		"""
		addr = IP/mask
		return = 1.2.3.4 255.255.255.255
		"""
		# debug("cidr2str -- addr = %s" % addr,4)
		tmp = netaddr.IPNetwork(addr)
		return ' '.join([str(tmp.ip), str(tmp.netmask)])
	
	def check_arr(self, arr):
		if not len(arr):
			debug(self.line, 0)
			debug("Too few fields in the policy.", 0)
			sys.exit(1)

	def parse_addr(self, arr):
		"""
		arr -- takes a list, extracts the next address(es), removes the elements from the list
		returns a list of addresses
		"""
		# debug("parse_addr -- arr", 3)
		# debug(arr,4)
		if 'any' in arr[0]:
			addr = ['any']
			del arr[0]
		elif ',' not in arr[0]:
			if '/' in arr[0]:
				addr = [self.cidr2str(arr[0])]
				del arr[0]
			elif '0.0.0.0' in arr[0] and '0.0.0.0' in arr[1]:
				addr = ['any']
				del arr[0:2]
			else:
				addr = [' '.join(arr[0:2])]
				del arr[0:2]
		else:
			addr = [self.cidr2str(x) for x in arr[0].split(',')]
			addr.sort()
			del arr[0]
		# debug("parse_addr - addr = %s" % addr,3)
		return addr

	def parse_addr_args(self, addr):
		"""
		used when only the source or destination IP-addresses are used in the line
		returns a list of one IP-address
		"""
		
		if '/' in addr:
			return [self.cidr2str(addr)]
		elif self.re_any.search(addr):
			return ['any']
		elif self.re_nondig.match(addr):
			return ["object-group " + addr]
		elif ' ' in addr:
			return [addr]
		else:
			return [addr + ' 255.255.255.255']

	def parse(self):
		addr1 = ''
		addr2 = ''
		arr = self.line.split()

		# Get the first address
		addr1 = self.parse_addr(arr)
		# debug("addr1 is %s" % addr1,3)
		self.check_arr(arr)

		if self.re_dig.match(arr[0]) or 'any' in arr[0] or 'host' in arr[0]:
			addr2 = self.parse_addr(arr)
			# debug("addr2 is %s" % addr2,3)
			self.check_arr(arr)

		if ',' not in arr[0]:
			self.srv = [arr[0]]
		else:
#			self.proto = ''
			self.srv = [x for x in arr[0].split(',')]
			self.srv.sort()
		del arr[0]

		if len(arr):
			self.action = arr[0]

		if addr2:
			self.src = addr1
			self.dst = addr2
		elif args.src:
			self.src = self.parse_addr_args(args.src)
			self.dst = addr1
		elif args.dst:
			self.src = addr1
			self.dst = self.parse_addr_args(args.dst)
		else:
			debug(self.line, 0)
			debug("Either too few fields or define either --src IP or --dst IP",0)
			sys.exit(1)

		debug("Src = %s" % self.src, 3)
		debug("Dst = %s" % self.dst, 3)
		debug("Srv = %s" % self.srv, 3)
		debug("Action = %s" % self.action, 3)
		debug("Comment = %s" % self.comment, 3)


class FW:
	"""
	General Firewall Class
	"""
	
	devtype = ''  # Device type
	anyhost = 'any'  # String for any host
	anyservice = 'any'  # String for any service
	action = {"permit": "permit", "deny": "deny"}  # default actions. Usage:  self.action[rule.action]]
	predefsvc = {}  # Predefined services
	predefsvcgrp = {}  # Predefined service groups
	netgrp_name = 'obj_net_'  # Template for network object-group
	netgrp_cnt = 0  # network object-group counter shift
	srvgrp_name = 'obj_srv_'  # Template for service object-group
	srvgrp_cnt = 0  # service object-group counter shift
	log = ''  # logging
	comment = ''  # comments

	re_any = re.compile(r'any|all|0\.0\.0\.0 0\.0\.0\.0|0\.0\.0\.0/0', re.IGNORECASE)

	def rprint(self, policy):
		self.fw_header_print()
		self.fw_netobj_print(policy.netobj)
		self.fw_srvobj_print(policy.srvobj)
		self.fw_netgrp_print(policy.netgrp)
		self.fw_srvgrp_print(policy.srvgrp)
		self.fw_rules_print(policy)
		self.fw_footer_print()

	def netobj_add(self, netobj, rule):
		for addrs in rule.src, rule.dst:
			# Convert a single IP-address to a list
			# if not type(addrs) is list: addrs=[addrs]
			for addr in addrs:
				if addr not in netobj:
					if self.re_any.search(addr):
						netobj[addr] = self.anyhost
					else:
						netobj[addr] = self.net2name(netaddr.IPNetwork(re.sub(' ', '/', addr)))

	def srvobj_add(self, srvobj, rule):
		services = rule.srv
		# if not type(services) is list: services=[services]
		for srv in services:
			if srv not in srvobj and srv not in self.predefsvc:
				if '*' in srv:
					srvobj[srv] = self.anyservice
				else:
					srvobj[srv] = re.sub(':', '-', srv)

	def netgrp_add(self, netgrp, rule):
		for addrs in rule.src, rule.dst:
			if len(addrs) > 1:
				if tuple(addrs) not in netgrp:
					objname = self.netgrp_name + str(len(netgrp) + 1 + self.netgrp_cnt)
					netgrp[tuple(addrs)] = objname


	def srvgrp_add(self, srvgrp, rule):
		if len(rule.srv) > 1:
			debug("srvgrp_add -- rule.srv", 3)
			debug(rule.srv, 3)
			debug("srvgrp_add -- rule.srv tuple", 3)
			debug(tuple(rule.srv), 3)
			if tuple(rule.srv) not in srvgrp and tuple(rule.srv) not in self.predefsvcgrp:
				objname = self.srvgrp_name + str(len(srvgrp) + 1 + self.srvgrp_cnt)
				srvgrp[tuple(rule.srv)] = objname


	def fw_header_print(self):
		pass

	def fw_netobj_print(self, netobj):
		pass

	def fw_srvobj_print(self, srvobj):
		pass

	def fw_netgrp_print(self, policy):
		pass

	def fw_srvgrp_print(self, policy):
		pass
	
	def fw_rules_print(self, policy):
		pass

	def fw_footer_print(self):
		pass

	def net2name(self, ip):
		"""
		Create object names:
		h-001.020.003.004  -- for hosts
		n-001.020.003.000_24 -- for networks
		net - netaddr.IPNetwork(ip)
		"""
		
		net = str(ip.network)
		mask = str(ip.prefixlen)
		if self.ishost(ip):
			return 'h-' + self.ip2txt(net)
		else:
			return 'n-' + self.ip2txt(net) + '_' + mask

	def ip2txt(self, ip):
		"""
		ip - string IP-address -- 1.2.3.4
		returns - 001.002.003.004
		"""
		return ".".join(map(self.octet2txt, ip.split('.')))

	def octet2txt(self, octet):
		"""
		octet - string of 0...255 (e.g. 12, 1, 123)
		returns 012, 001, 123
		"""
		
		if len(octet) < 3:
			octet = "0" + octet if len(octet) == 2 else "00" + octet
		return octet

	def ishost(self, ip):
		"""
		Returns True if the netmask is 32, and False otherwise
		ip is a netaddr object
		"""
		return True if ip.prefixlen == 32 else False


class FGT(FW):
	"""
	FortiGate specific class
	"""
	
	devtype = 'fgt'
	anyhost = 'all'
	anyservice = 'ALL'
	action = {"permit": "accept", "deny": "deny"}

	predefsvc = {'tcp:540': 'UUCP', 'udp:1-65535': 'ALL_UDP', 'tcp:70': 'GOPHER', 'IP:89': 'OSPF', 'ip': 'ALL', 'udp:520': 'RIP', 'tcp:1723': 'PPTP', 'udp:67-68': 'DHCP', 'tcp:1720': 'NetMeeting', 'IP:51': 'AH', 'udp:389': 'LDAP_UDP', 'IP:50': 'ESP', 'udp:517-518': 'TALK', 'tcp:465': 'SMTPS', 'IP:47': 'GRE',  'tcp:79': 'FINGER', 'tcp:1433-1434': 'MS-SQL', 'icmp': 'ALL_ICMP', 'tcp:143': 'IMAP', 'tcp:995': 'POP3S', 'tcp:993': 'IMAPS', 'tcp:512': 'REXEC', 'udp:546-547': 'DHCP6', 'tcp:5900': 'VNC', 'tcp:3389': 'RDP', 'tcp:6660-6669': 'IRC', 'udp:1645-1646': 'RADIUS-OLD', 'udp:33434-33535': 'TRACEROUTE', 'tcp:80': 'HTTP', 'tcp:2000': 'SCCP', 'tcp:1863': 'SIP-MSNmessenger', 'tcp:210': 'WAIS', 'ICMP:8': 'PING', 'tcp:389': 'LDAP', 'tcp:21': 'FTP', 'tcp:5190-5194': 'AOL', 'tcp:23': 'TELNET', 'tcp:25': 'SMTP', 'tcp:6000-6063': 'X-WINDOWS', 'tcp:7000-7010': 'VDOLIVE', 'tcp:3128': 'SQUID', 'tcp:0': 'NONE', 'tcp:443': 'HTTPS', 'tcp:445': 'SMB', 'tcp:1-65535': 'ALL_TCP', 'ICMP6:128': 'PING6', 'udp:69': 'TFTP', 'udp:7070': 'RAUDIO', 'udp:1812-1813': 'RADIUS',  'tcp:179': 'BGP', 'udp:514': 'SYSLOG', 'tcp:110': 'POP3', 'tcp:119': 'NNTP', 'ICMP:13': 'TIMESTAMP', 'tcp:3306': 'MYSQL', 'tcp:22': 'SSH', 'icmp:17': 'INFO_ADDRESS', 'tcp:139': 'SAMBA', 'icmp:15': 'INFO_REQUEST'}

	predefsvcgrp = {('tcp:7000-7009', 'udp:7000-7009'): 'AFS3', ('udp:500', 'udp:4500'): 'IKE', ('tcp:1080', 'udp:1080'): 'SOCKS', ('tcp:5631', 'udp:5632'): 'PC-Anywhere', ('tcp:554', 'tcp:7070', 'tcp:8554', 'udp:554'): 'RTSP', ('tcp:111', 'tcp:2049', 'udp:111', 'udp:2049'): 'NFS', ('udp:2427', 'udp:2727'): 'MGCP', ('tcp:1512', 'udp:1512'): 'WINS', ('tcp:2401', 'udp:2401'): 'CVSPSERVER', ('tcp:161-162', 'udp:161-162'): 'SNMP', ('tcp:1720', 'tcp:1503', 'udp:1719'): 'H323', ('tcp:5060', 'udp:5060'): 'SIP', ('tcp:1701', 'udp:1701'): 'L2TP', ('tcp:123', 'udp:123'): 'NTP', ('udp:26000', 'udp:27000', 'udp:27910', 'udp:27960'): 'QUAKE', ('tcp:53', 'udp:53'): 'DNS', ('tcp:88', 'udp:88'): 'KERBEROS', ('tcp:1755', 'udp:1024-5000'): 'MMS', ('tcp:135', 'udp:135'): 'DCE-RPC', ('tcp:111', 'udp:111'): 'ONC-RPC', ('tcp:1494', 'tcp:2598'): 'WINFRAME'}

	def __init__(self, vdom='root', srcintf='any', dstintf='any', label='', log=False, comment='', mg=0):
		self.vdom = vdom
		self.srcintf = srcintf
		self.dstintf = dstintf
		self.label = label		# section label
		self.mingrp = mg			# minimum amount of objects to create a group
		self.log = log
		self.comment = comment

	def netgrp_add(self, netgrp, rule):
		pass

	def fw_header_print(self):
		if self.vdom:
			print('config vdom')
			print('edit ' + self.vdom)

	def fw_footer_print(self):
		print('end')

	def fw_rules_print(self, policy):
		print('config firewall policy')
		policy.srvobj.update(self.predefsvc)
		for rule in policy.policy:
			debug("Rule %d Orig line = %s" % (rule.num, rule.origline), 2)
			if "comment" in rule.type:
				self.label = rule.comment
				next
			print(' edit %s' % rule.num)
			print('  set srcintf ' + self.srcintf)
			print('  set dstintf ' + self.dstintf)
			print('  set srcaddr ' + ' '.join(map(lambda x: policy.netobj[x], rule.src)))
			print('  set dstaddr ' + ' '.join(map(lambda x: policy.netobj[x], rule.dst)))
			print('  set service ' + ' '.join(map(lambda x: policy.srvobj[x], rule.srv)))
			print('  set schedule always')
			print('  set status enable')
			print('  set action ' + self.action[rule.action])
			if self.label:
				print('  set global-label "' + self.label + '"')
			if self.log:
				if type(self.log) is string and "disable" in self.log:
					print('  set logtraffic disable')
				else:
					print('  set logtraffic all')
			if self.comment or rule.comment:
				print('  set comments "' + self.comment + ' ' + rule.comment + '"')
			print(' next')
		print('end')

	def fw_netobj_print(self, netobj):
		print('config firewall address')
		for obj in netobj:
			print(' edit ' + netobj[obj])
			print('  set subnet ' + obj)
			print(' next')
		print('end')

	def fw_srvobj_print(self, srvobj):
		print('config firewall service custom')
		for obj in srvobj:
			if '*' not in obj:
				# For some reason the following construction does not work
				# proto,ports = obj.split(':') if ':' in obj else obj,''
				if ':' in obj:
					proto, ports = obj.split(':')
				else:
					proto, ports = obj, ''
				print(' edit ' + srvobj[obj])
				if 'udp' in proto or 'tcp' in proto:
					print('  set protocol TCP/UDP/SCTP')
					print('  set ' + proto + '-portrange ' + ports)
				elif 'icmp' in proto:
					print('  set protocol ICMP')
					if ports:
						print('  set icmptype ' + ports)
				elif 'ip' in proto:
					if ports:
						print('  set protocol IP')
						print('  set protocol-number ' + ports)
				else:
					print('  set protocol IP')
					print('  set protocol-number ' + proto)
				print(' next')
		print('end')


class ASA(FW):
	"""
	ASA specific class
	"""
	
	devtype = 'asa'
	anyhost = 'any'


	def __init__(self, aclname='Test_ACL', log=False, comment=''):
		self.aclname = aclname
		if log:
			self.log = "log"
		self.comment = comment

	def netobj_add(self, netobj, rule):
		pass

	def srvobj_add(self, srvobj, rule):
		pass

	def fw_rules_print(self, policy):
		if self.comment:
			print(' '.join(["access-list", self.aclname, "line %s" % rule.num, "remark", self.comment]))
		for rule in policy.policy:
			debug("Rule %d Orig line = %s" % (rule.num, rule.origline),2)
			if "comment" in rule.type:
				print(' '.join(["access-list", self.aclname, "line %s" % rule.num, "remark", rule.comment]))
			else:
				if rule.comment:
					print(' '.join(["access-list", self.aclname, "line %s" % rule.num, "remark", rule.comment]))
				print(' '.join(["access-list", self.aclname, "line %s" % rule.num, "extended", self.action[rule.action],
								 self.rule_proto(rule), self.rule_addr(rule.src), self.rule_addr(rule.dst), self.rule_port(rule), self.log]))

	def rule_proto(self, rule):
		if len(rule.srv) > 1:
			return 'object-group ' + policy.srvgrp[tuple(rule.srv)]
		else:
			return self.protocol(rule.srv[0])

	def rule_port(self, rule):
		if len(rule.srv) > 1:
			return ''
		else:
			return self.port(rule.srv[0])

	def rule_addr(self, addr):
		if len(addr) > 1:
			return 'object-group ' + policy.netgrp[tuple(addr)]
		else:
			return addr[0]

	def fw_header_print(self):
		print('config terminal')

	def fw_footer_print(self):
		print('wri')
		print('exit')

	def fw_netgrp_print(self, netgrp):
		for addrs in netgrp:
			print('object-group network', netgrp[tuple(addrs)])
			for addr in addrs:
				print(' network-object', addr)

	def fw_srvgrp_print(self, srvgrp):
		for svcs in srvgrp:
			print('object-group service', srvgrp[tuple(svcs)])
			for svc in svcs:
				if 'icmp' in self.protocol(svc):
					print(' service-object', self.protocol(svc), 'icmp_type', self.port(svc))
				else:
					print(' service-object', self.protocol(svc), 'destination', self.port(svc))

	def protocol(self, service):
		if "*" in service:
			return "ip"
		elif ":" in service:
			tmp = service.split(":")
			return tmp[0]
		else:
			return service

	def port(self, service):
		if ":" in service:
			tmp = service.split(":")
			if "-" in tmp[1]:
				low, high = tmp[1].split("-")
				if int(low) == 1:
					return "lt " + high
				elif int(high) == 65535:
					return "gt " + low
				else:
					return "range " + low + " " + high
			elif "icmp" not in tmp[0]:
				return "eq " + tmp[1]
			else:
				return tmp[1]
		else:
			return ''


class R77(FW):
	"""
	CheckPoint R77 specific class
	"""
	
	devtype = 'R77'
	anyhost = "globals:Any"
	anyservice = "globals:Any"
	action = {"permit": "accept_action:accept", "deny": "drop_action:drop"}
	# re_newline=re.compile(r'(\\n$)|(\\n\\$)')
	re_newline = re.compile(r'(\n$)|(\n\$)')
	
	def __init__(self, policy='test', log=False, comment="", nodbedit=False, mg=0):
		self.policy = policy	# policy name
		# self.rulenum=rulenum 	# begin with this rule number: edit rulenum
		# self.label=label		# section label
		self.log = log
		self.comment = comment
		self.nodbedit = nodbedit
		self.mingrp = mg


# Gets a (str) line and wraps it in
# 'echo -e ' line '\nupdate_all\\n-q\\n" | dbedit -local'
	def dbedit(self, line):
		if self.nodbedit: print(self.re_newline.sub("", line))
		else: print('echo -e \"' + line + '\\nupdate_all\\n-q\\n" | dbedit -local')
		
	def fw_netobj_print(self, netobj):
		for obj in netobj:
			debug("fw_netobj_print  -- obj",3)
			debug(obj, 3)
			if not 'any' in obj:
				ip, mask = obj.split()
				if '255.255.255.255' in mask:
					self.dbedit("create host_plain %s" % netobj[obj])
					self.dbedit("modify network_objects {0!s} ipaddr {1!s}".format(netobj[obj],obj.split()[0]))
				else:
					self.dbedit("create network %s" % netobj[obj])
					ip, mask = obj.split()
					self.dbedit("modify network_objects {0!s} ipaddr {1!s}\\nmodify network_objects {0!s} netmask {2!s}".format(netobj[obj],ip,mask))
				

	def fw_srvobj_print(self, srvobj):
		for obj in srvobj:
			debug("fw_srvobj_print  -- obj",3)
			debug(obj, 3)
			if not '*' in obj:
				# For some reason the following construction does not work
				# proto,ports = obj.split(':') if ':' in obj else obj,''
				if ':' in obj:	proto,ports = obj.split(':')
				else: proto,ports = obj,''
				
				if 'udp' in proto or 'tcp' in proto:
					self.dbedit("create {0!s}_service {1!s}".format(proto,srvobj[obj]))
					self.dbedit("modify services {0!s} port {1!s}".format(srvobj[obj],ports))
				elif 'icmp' in proto:
					if ports:
						self.dbedit("create {0!s}_service {1!s}".format(proto,srvobj[obj]))
						self.dbedit("modify services {0!s} icmp_type {1!s}".format(srvobj[obj],ports))					
				elif 'ip' in proto:
					if ports:
						self.dbedit("create other_service {1!s}".format(proto,srvobj[obj]))
						self.dbedit("modify services {0!s} protocol {1!s}".format(srvobj[obj],ports))	
				else:
					print('# %s is not implemented' % proto)

	def fw_rules_print(self, policy):
		policy.srvobj.update(self.predefsvc)
		dbline = ""
		for rule in policy.policy:
			debug("Rule %d Orig line = %s" % (rule.num, rule.origline),2)
			if "comment" in rule.type: 
				self.label = rule.comment
				next
			dbline = "addelement fw_policies ##{0!s} rule security_rule\\n \n".format(self.policy)
			dbline += "addelement fw_policies ##{0!s} rule:{1}:action {2!s}\\n \n".format(self.policy,rule.num,self.action[rule.action])
			dbline += "modify fw_policies ##{0!s} rule:{1}:comments \"{2!s}\"\\n \n".format(self.policy,rule.num,rule.comment)
			dbline += "modify fw_policies ##{0!s} rule:{1}:name \"\"\\n \n".format(self.policy,rule.num)
			for ip in rule.src:
				dbline += "addelement fw_policies ##{0!s} rule:{1}:src:\'\' network_objects:{2!s}\\n \n".format(self.policy,rule.num,policy.netobj[ip])
			for ip in rule.dst:
				dbline += "addelement fw_policies ##{0!s} rule:{1}:dst:\'\' network_objects:{2!s}\\n \n".format(self.policy,rule.num,policy.netobj[ip])		
			for srv in rule.srv:
				dbline += "addelement fw_policies ##{0!s} rule:{1}:services:\'\' services:{2!s}\\n \n".format(self.policy,rule.num,policy.srvobj[srv])	

			if self.log:
				if type(self.log) is string and "disable" in self.log:
					dbline += "modify fw_policies ##{0!s} rule:{1}:track {2!s}\\n \n".format(self.policy,rule.num,"tracks:None")
				else:
					dbline += "modify fw_policies ##{0!s} rule:{1}:track {2!s}\\n \n".format(self.policy,rule.num,"tracks:Log")
			if self.comment or rule.comment:
				dbline += "modify fw_policies ##{0!s} rule:{1}:comments \"{2!s}\"\\n \n".format(self.policy,rule.num,rule.comment)
			self.dbedit(dbline)
			dbline = ""


class Policy():
	"""
	Class for the whole policy
	"""
	
	netobj = {}		# { '10.0.1.0 255.255.255.0': 'n-010.000.001.000_24' }
	srvobj = {}		# { 'tcp:20-23': 'TCP-20-23' }
	netgrp = {}		# { 'net-group1: }network-groups
	srvgrp = {}		# service-groups
	policy = []		# global policy
	device = ''		# 'ASA' or 'FGT' class object


# dev - device class
# rulenum - the number of the first rule
	def __init__(self, dev, rulenum):
		self.device = dev
		self.rulenum = rulenum	#current rule number counter

	def addrule(self, rule):
		self.policy.append(rule)
		rule.num = self.rulenum
		debug("Rule %d Orig line = %s" % (rule.num, rule.origline),2)
		debug("Rule %d Src = %s" % (rule.num, rule.src),2)
		debug("Rule %d Dst = %s" % (rule.num, rule.dst),2)
		debug("Rule %d Srv = %s" % (rule.num, rule.srv),2)
		debug("Rule %d Action = %s" % (rule.num, rule.action),2)
		debug("Rule %d Comment = %s" % (rule.num, rule.comment),2)
		self.rulenum += 1

	def get_objects(self):
		for rule in self.policy:
			self.device.netobj_add(self.netobj,rule)
			self.device.netgrp_add(self.netgrp,rule)
			self.device.srvobj_add(self.srvobj,rule)
			self.device.srvgrp_add(self.srvgrp,rule)
		debug("The %s policy contains:" % self.device.devtype, 1)
		debug("  %d rules " % len(self.policy), 1)
		debug("  %d network objects" % len(self.netobj), 1)
		debug(self.netobj, 2)
		debug("  %d network groups" % len(self.netgrp), 1)
		debug("self.netgrp = %s" % self.netgrp, 2)
		debug(self.netgrp, 2)
		debug("  %d service objects" % len(self.srvobj), 1)
		debug(self.srvobj, 2)
		debug("  %d service groups" % len(self.srvgrp), 1)
		debug(self.srvgrp, 2)

	def rprint(self):
		self.get_objects()
		self.device.rprint(self)


parser = argparse.ArgumentParser(description='Creates Cisco ASA or Fortigate policy')
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console (default)")
parser.add_argument('-v', '--verbose', default=0,
					help='Verbose mode. Messages are sent to STDERR.\n To increase the level add "v", e.g. -vvv',
					action='count')
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
log = parser.add_mutually_exclusive_group()
log.add_argument('--log', default=False, help="Logging. Default: none for ASA and CP, utm for FGT. ", action="store_true")
log.add_argument('--nolog', default=False, help="Logging. Default: none for ASA and CP, utm for FGT. ", action="store_true")
parser.add_argument('--comment', default='', help="Comment, Default - none")
parser.add_argument('--dev', default="asa", choices=['asa','fgt','r77'], help="Type of device: asa (default), fgt or r77")
parser.add_argument('--rn', default=1000, help="Starting rule number. Default - 1000", type=int)

asa = parser.add_argument_group('Cisco ASA')
asa.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name for ASA. Default=Test_ACL")

fgt = parser.add_argument_group('Fortigate')
fgt.add_argument('--vdom', default='', help="VDOM name for FortiGate. Default - none")
fgt.add_argument('--si', default="any", help="Source interface for FortiGate. Default - any")
fgt.add_argument('--di', default="any", help="Destination interface for FortiGate. Default - any")
fgt.add_argument('--label', default='', help="Section label, Default - none")

r77 = parser.add_argument_group('CheckPoint R77')
r77.add_argument('--policy', default='test', help="CheckPoint policy name. 	Default - \"test\" ")
parser.add_argument('--nodbedit', default=False, help="Do not add dbedit decorations", action="store_true")


args = parser.parse_args()

debug("Verbosity level is %d" % args.verbose, 1)

f = sys.stdin if "-" == args.pol else open(args.pol, "r")

if 'asa' in args.dev:
	dev = ASA(args.acl, args.log, args.comment)
elif 'fgt' in args.dev:
	if args.nolog: args.log = "disable"
	dev = FGT(args.vdom, args.si, args.di, args.label, args.log, args.comment)
elif 'r77' in args.dev:
	if args.nolog: args.log = "disable"
	dev = R77(args.policy, args.log, args.comment, args.nodbedit)
else:
	print(args.dev, "is not supported. It should be: asa (Cisco ASA), fgt (FortiGate) or r77 (CheckPOint R77)", file=sys.stderr)
	sys.exit(1)

policy = Policy(dev, args.rn)

for line in f:
	r = PRule(line, args.deny)
	policy.addrule(r)

policy.rprint()
