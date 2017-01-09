# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing and modifying Cisco ASA ACLs. Useful for troubleshooting, migrating a subset of rules to another firewall, removing overlapping rules, rules aggregation, etc.

Install netaddr:

```sh
pip install netaddr
```
## ipaclmatch.py 

ipaclmatch.py finds ACLs matching the given IP-addresses, including networks, the IP_addresses belong to.

Usage:

```txt
usage: ipaclmatch.py [-h] [-a ADDR] [-s | -d | -b] [--noany]
                     [--deny | --permit] [--direct] [-t] [--contain]
                     [--noline]
                     acl

positional arguments:
  acl                   Cisco ASA ACL filename

optional arguments:
  -h, --help            show this help message and exit
  -a ADDR, --addr ADDR  Comma-separated list of addresses/netmasks
  -s, --src             Search the source
  -d, --dst             Search the destination
  -b, --both            Search both the source and the destination (default)
  --noany               Ignore 'any' in the ACLs
  --deny                Search 'deny' rules only
  --permit              Search 'permit' rules only
  --direct              Direct IP match only
  -t, --transform       Transform the output
  --contain             Direct matches and subnets (not direct and uppernets).
                        Assumes --noany
  --noline              Removes line number from the output
```

Examples:

Save the access group using the following command in a file, for example ACL_name.acl:

```txt
sh access-list ACL-name
. . .
access-list FW_ACL_lab line 3 remark 22-01-2016 Alex 13-Feb-2016 test entries
access-list FW_ACL_lab line 4 extended permit tcp object-group group1 object-group group2 object-group group3 0x18972f28 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq ldap (hitcnt=0) 0x6e3a516f 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10389 (hitcnt=0) 0x771e885b 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10391 (hitcnt=0) 0x7055a227 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10393 (hitcnt=0) 0x1fdbe0d8 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10395 (hitcnt=0) 0xbd11fc51 
  access-list FW_ACL_lab line 4 extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10636 (hitcnt=0) 0xc47c2cf2 
. . .
```

Search only the source addresses for 10.0.1.2/32 and 10.2.3.0/24 and networks these addresses belong to (for example, 10/8, 10.2.3.128/25, 10.2.3.4/32, etc):

```txt
python ipaclmatch.py -a 10.0.1.2,10.2.3.0/24 -s ACL_name.acl 
```

Search for 10.2.3.0/24 in both source and destination, but ignore "any":

```txt
python ipaclmatch.py --noany -a 10.2.3.0/24 ACL_name.acl 
```

Search deny rules with 10.2.3.0/24 in the destination and ignore "any" (in the dest):

```txt
python ipaclmatch.py --noany -a 10.2.3.0/24 -d --deny ACL_name.acl
```

List direct only matches (no subnets, supernets, etc, will be looked for) for 10.2.3.0/24 as the source address:

```txt
python ipaclmatch.py --noany -a 10.2.3.0/24 -d --direct ACL_name.acl
```
Search for 10.2.0.1 in the source and remove line numbers:

```txt
python ipaclmatch.py -a 10.2.0.1 -s --noline ACL_name.acl
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq ldap 
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10389 
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10391 
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10393 
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10395 
access-list FW_ACL_lab extended permit tcp 10.2.0.0 255.255.0.0 host 7.2.2.189 eq 10636 
. . .
```

Output only the Dest-IP, Dest-Mask, and service (in the form of `tcp:1224`, `tcp:20000=30000`, `udp:+30000`, or `*`) corresponding to SourceIP=10.2.3.0/24 and all networks it belongs to. This mode replaces service names with the corresponding  port numbers:

```txt
python ipaclmatch.py  -a 10.2.3.0/24 -s -t --permit ACL_name.acl
10.1.20.68 255.255.255.255 tcp:7102
10.15.10.130 255.255.255.255 tcp:80
10.15.10.130 255.255.255.255 tcp:443
10.15.10.130 255.255.255.255 tcp:3389
10.15.10.130 255.255.255.255 tcp:1024=10000
10.15.10.130 255.255.255.255 tcp:7102

```
Mae sure, that no denies prevent you from reordering the rules.

The result can be fed to `sort -u` to get rid of duplicates or to `sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4` (or `sort -u -V` if supported) to sort the output by network numbers:

```sh
python ipaclmatch.py  -a 10.2.3.0/24 -s -t --permit ACL_name.acl | sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4
```
