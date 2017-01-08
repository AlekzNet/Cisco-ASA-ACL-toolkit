# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing and modifying Cisco ASA ACLs

Install netaddr:

```sh
pip install netaddr
```
## ipaclmatch.py 

ipaclmatch.py finds ACLs matching the given IP-addresses, including networks, the IP_addresses belong to.

Usage:

```txt
ipaclmatch.py -h
usage: ipaclmatch.py [-h] [-a ADDR] [-s | -d | -b] [--noany]
                     [--deny | --permit] [--direct] [-t]
                     acl

positional arguments:
  acl                   Cisco ASA ACL filename

optional arguments:
  -h, --help            show this help message and exit
  -a ADDR, --addr ADDR  Comma-separated list of addresses/netmasks
  -s, --src             Search the source
  -d, --dst             Search the destination
  -b, --both            Search both the source and the destination
  --noany               Ignore 'any' in the ACLs
  --deny                Search 'deny' rules only
  --permit              Search 'permit' rules only
  --direct              Direct IP match only
  -t, --transform       Transform the output


```

Examples:

Save the access group using the following command in a file, for example ACL_name.acl:

```txt
sh access-list ACL-name
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

Output only the Dest-IP, Dest-Mask, and service (in the form of tcp-1224, udp-20000-30000, or `*`) corresponding to SourceIP=10.2.3.0/24 and all networks it belongs to:

```txt
python ipaclmatch.py  -a 10.2.3.0/24 -s -t ACL_name.acl
```
