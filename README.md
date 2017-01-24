# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing, modifying and generating Cisco ASA ACLs. Useful for troubleshooting, migrating a subset of rules to another firewall, removing overlapping rules, rules aggregation, etc.

## Files

* asa.exp - expect script to remotely get the configuration, access-groups and access lists
* ipaclmatch.py - utility to search for rules matching IP-addresses, the networks they belong to, subnetworks, and generate a proto-policy.
* genacl.py - utility to generate ASA ACL's from a proto-policy

Install netaddr:

```sh
pip install netaddr
```
## ipaclmatch.py 

ipaclmatch.py finds ACLs matching the given IP-addresses, including networks, the IP_addresses belong to.

### Usage:

```txt
usage: ipaclmatch.py [-h] [-a ADDR] [-s | -d | -b] [--noany | --any]
                     [--deny | --permit] [--range | --norange] [--direct] [-t]
                     [-p] [--contain] [--noline]
                     [acl]

positional arguments:
  acl                   Cisco ASA ACL filename or "-" to read from the console
                        (default)

optional arguments:
  -h, --help            show this help message and exit
  -a ADDR, --addr ADDR  Comma-separated list of addresses/netmasks. "all"
                        shows all lines
  -s, --src             Search the source
  -d, --dst             Search the destination
  -b, --both            Search both the source and the destination (default)
  --noany               Ignore 'any' in the ACLs
  --any                 Show only 'any' in the ACLs
  --deny                Search 'deny' rules only
  --permit              Search 'permit' rules only
  --range               Replace lt, gt, and neq with ranges (default)
  --norange             Replace lt, gt, and neq with \<, \>, and ! symbols
  --direct              Direct IP match only
  -t, --transform       Transform the output. Must be used with either -s or
                        -d and with either --deny or --permit
  -p, --policy          Print the policy in the form: SourceIP SourceMask
                        DestIP DestMask Proto:Port. Must be used with either
                        --deny or --permit
  --contain             Direct matches and subnets (not direct and uppernets).
                        Assumes --noany
  --noline              Removes line number from the output

```

### Examples

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

Output only the Dest-IP, Dest-Mask, and service (in the form of `tcp:1224`, `tcp:20000-30000`, `udp:30000-65535`, or `*`) corresponding to SourceIP=10.2.3.0/24 and all networks it belongs to. This mode replaces service names with the corresponding  port numbers:

```txt
python ipaclmatch.py  -a 10.2.3.0/24 -s -t --permit ACL_name.acl
10.1.20.68 255.255.255.255 tcp:7102
10.15.10.130 255.255.255.255 tcp:80
10.15.10.130 255.255.255.255 tcp:443
10.15.10.130 255.255.255.255 tcp:3389
10.15.10.130 255.255.255.255 tcp:1024-10000
10.15.10.130 255.255.255.255 tcp:7102

```
Make sure, that no denies prevent you from reordering the rules.

The result can be fed to `sort -u` to get rid of duplicates or to `sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4` (or `sort -u -V` if supported) to sort the output by network numbers:

```sh
python ipaclmatch.py  -a 10.2.3.0/24 -s -t --permit ACL_name.acl | sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4
```
Print the whole "permit" policy in the form:
SourceIP SourceMask DestIP DestMask Proto:Port
```txt
ipaclmatch.py -p --permit test.acl
13.23.9.1 255.255.255.255 38.3.5.4 255.255.255.254 tcp:1-5052,tcp:5054-65535
13.4.2.3 255.255.255.255 38.3.5.4 255.255.255.254 tcp:5053
9.4.2.17 255.255.255.255 38.3.5.4 255.255.255.254 tcp:5053
```

## genacl.py

Generates ASA ACL from a proto-policy written in the following format (e.g. generated by ipaclmatch.py):

```txt
IP-address Netmask Protocol:Port
```
or

```txt
SrcIP SrcMask DstIP DstMask Protocol:Port [Action]
```
IP addresses and netmasks must be in the format `a.b.c.d e.f.g.h` (e.g. 0.0.0.0 0.0.0.0 for "any")

Services can have the following forms (more possible formats to follow :
```txt
tcp:22
icmp
*
udp:1234-3456
```

### Usage:

```txt
genacl.py -h
usage: genacl.py [-h] [-s SRC | -d DST] [--deny] [--acl [ACL]] [pol]

positional arguments:
  pol                Firewall policy or "-" to read from the console

optional arguments:
  -h, --help         show this help message and exit
  -s SRC, --src SRC  Source IP-address/netmask or object name
  -d DST, --dst DST  Destination IP-address/netmasks or object name
  --deny             Use deny by default instead of permit
  --acl [ACL]        ACL name, default=Test_ACL
```


### Examples

Considering the following proto-policy:

```txt
10.228.0.0 255.252.0.0 10.3.0.2 255.255.255.255 tcp:123
13.20.0.0 255.255.0.0 10.3.0.2 255.255.255.255 udp:53
13.20.0.0 255.255.0.0 10.3.0.1 255.255.255.255 udp:53 deny
13.20.0.0 255.255.0.0 10.3.8.4 255.255.255.254 udp:53
10.192.0.0 255.248.0.0 10.3.8.4 255.255.255.254 udp:20000-30000
10.0.0.0 255.0.0.0 10.3.9.4 255.255.255.254 *
0.0.0.0 0.0.0.0 10.3.10.0 255.255.255.0 udp:30000-65535
0.0.0.0 0.0.0.0 0.0.0.0 0.0.0.0 * deny
```

default settings will produce the following output:

```txt
cat test-pol.acl | genacl.py
access-list Test_ACL extended permit tcp 10.228.0.0 255.252.0.0 host 10.3.0.2 eq 123
access-list Test_ACL extended permit udp 13.20.0.0 255.255.0.0 host 10.3.0.2 eq 53
access-list Test_ACL extended deny udp 13.20.0.0 255.255.0.0 host 10.3.0.1 eq 53
access-list Test_ACL extended permit udp 13.20.0.0 255.255.0.0 10.3.8.4 255.255.255.254 eq 53
access-list Test_ACL extended permit udp 10.192.0.0 255.248.0.0 10.3.8.4 255.255.255.254 range 20000 30000
access-list Test_ACL extended permit ip 10.0.0.0 255.0.0.0 10.3.9.4 255.255.255.254 
access-list Test_ACL extended permit udp any 10.3.10.0 255.255.255.0 gt 30000
access-list Test_ACL extended deny ip any any 
```

Another example:

```txt
10.3.0.2 255.255.255.255 tcp:123
10.3.0.1 255.255.255.255 tcp:123
10.3.8.4 255.255.255.254 tcp:123
10.3.0.2 255.255.255.255 tcp:53
10.3.0.1 255.255.255.255 tcp:53
10.3.8.4 255.255.255.254 tcp:53
10.3.0.2 255.255.255.255 udp:53
10.3.0.1 255.255.255.255 udp:53
10.3.8.4 255.255.255.254 udp:20000-30000
10.3.9.4 255.255.255.254 *
10.3.10.0 255.255.255.0 udp:30000-65535
```

Let's use object "MyHosts" as the source and name the ACL "new_acl":

```txt
genacl.py -s MyHosts --acl new_acl test-pol2.acl
access-list new_acl extended permit tcp object-group MyHosts host 10.3.0.2 eq 123
access-list new_acl extended permit tcp object-group MyHosts host 10.3.0.1 eq 123
access-list new_acl extended permit tcp object-group MyHosts 10.3.8.4 255.255.255.254 eq 123
access-list new_acl extended permit tcp object-group MyHosts host 10.3.0.2 eq 53
access-list new_acl extended permit tcp object-group MyHosts host 10.3.0.1 eq 53
access-list new_acl extended permit tcp object-group MyHosts 10.3.8.4 255.255.255.254 eq 53
access-list new_acl extended permit udp object-group MyHosts host 10.3.0.2 eq 53
access-list new_acl extended permit udp object-group MyHosts host 10.3.0.1 eq 53
access-list new_acl extended permit udp object-group MyHosts 10.3.8.4 255.255.255.254 range 20000 30000
access-list new_acl extended permit ip object-group MyHosts 10.3.9.4 255.255.255.254 
access-list new_acl extended permit udp object-group MyHosts 10.3.10.0 255.255.255.0 gt 30000
```

or network 123.123.123.128/25 as the destination:

```txt
genacl.py -d 123.123.123.128/25  --acl new_acl test-pol2.acl
access-list new_acl extended permit tcp host 10.3.0.2 123.123.123.128 255.255.255.128 eq 123
access-list new_acl extended permit tcp host 10.3.0.1 123.123.123.128 255.255.255.128 eq 123
access-list new_acl extended permit tcp 10.3.8.4 255.255.255.254 123.123.123.128 255.255.255.128 eq 123
access-list new_acl extended permit tcp host 10.3.0.2 123.123.123.128 255.255.255.128 eq 53
access-list new_acl extended permit tcp host 10.3.0.1 123.123.123.128 255.255.255.128 eq 53
access-list new_acl extended permit tcp 10.3.8.4 255.255.255.254 123.123.123.128 255.255.255.128 eq 53
access-list new_acl extended permit udp host 10.3.0.2 123.123.123.128 255.255.255.128 eq 53
access-list new_acl extended permit udp host 10.3.0.1 123.123.123.128 255.255.255.128 eq 53
access-list new_acl extended permit udp 10.3.8.4 255.255.255.254 123.123.123.128 255.255.255.128 range 20000 30000
access-list new_acl extended permit ip 10.3.9.4 255.255.255.254 123.123.123.128 255.255.255.128 
access-list new_acl extended permit udp 10.3.10.0 255.255.255.0 123.123.123.128 255.255.255.128 gt 30000
```
