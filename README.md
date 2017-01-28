# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing, modifying and generating Cisco ASA ACLs. Useful for troubleshooting, migrating a subset of rules to another firewall, removing overlapping rules, rules aggregation, etc.

## Files

* asa.exp - expect script to remotely get the configuration, access-groups and access lists
* test.acl - test ACL
* [ipaclmatch.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/ipaclmatch.md) - utility to search for rules matching IP-addresses, the networks they belong to, subnetworks, and generate a proto-policy.
* [optimacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/optimacl.md) - optimizes a proto-policy (by aggregating, removing overlapping rules, etc)
* [genacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/genacl.md) - utility to generate ASA ACL's from a proto-policy

Install netaddr:

```sh
pip install netaddr
```
### Issues

* CIDR merging is VERY slow

### Example

For all permitted source addresses in test.acl create an optimized policy

```txt
$ wc -l test.acl
     118 test.acl

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py | genacl.py -s "myObject" --acl new_acl

access-list new_acl extended permit udp object-group myObject 10.3.10.0 255.255.255.0 gt 30000
access-list new_acl extended permit tcp object-group myObject 10.7.8.0 255.255.255.0 range 1200 1351
access-list new_acl extended permit udp object-group myObject host 10.3.0.1 eq 53
access-list new_acl extended permit udp object-group myObject host 10.3.0.2 eq 53
access-list new_acl extended permit tcp object-group myObject host 10.3.0.1 eq 53
access-list new_acl extended permit tcp object-group myObject host 10.3.0.2 eq 53
access-list new_acl extended permit tcp object-group myObject host 10.3.0.1 eq 123
access-list new_acl extended permit tcp object-group myObject host 10.3.0.2 eq 123
access-list new_acl extended permit tcp object-group myObject 10.8.9.4 255.255.255.254 range 22 23
access-list new_acl extended permit tcp object-group myObject 10.3.9.0 255.255.255.252 eq 23
access-list new_acl extended permit ip object-group myObject 10.3.8.4 255.255.255.254 
access-list new_acl extended permit ip object-group myObject 10.3.9.4 255.255.255.254 
access-list new_acl extended permit ip object-group myObject 10.4.0.0 255.254.0.0 

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py | genacl.py -s "myObject" --acl new_acl | wc -l
      13

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py --group      

10.3.10.0/255.255.255.0 udp:30000-65535
10.7.8.0/255.255.255.0 tcp:1200-1351
10.8.9.4/255.255.255.254 tcp:22-23
10.3.0.1/255.255.255.255,10.3.0.2/255.255.255.255 udp:53,tcp:53,tcp:123
10.3.9.0/255.255.255.252 tcp:23
10.3.8.4 255.255.255.254 *
10.3.9.4 255.255.255.254 *
10.4.0.0 255.254.0.0 *

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py --group | wc -l
       8

```
118 -> 13 = 85% rule reduction (in this particular example)


Search test.acl for the destination networks that contain 10.3.8.4, and generate new_acl with 10.3.8.4 as the destination:

```txt
$ ipaclmatch.py -t -d -a 10.3.8.4 --permit test.acl |  optimacl.py | genacl.py -d 10.3.8.4  --acl new_acl
access-list new_acl extended permit tcp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit tcp 172.16.0.0 255.240.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit tcp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 123
access-list new_acl extended permit tcp 172.16.0.0 255.240.0.0 host 10.3.8.4 eq 123
access-list new_acl extended permit udp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit ip 10.0.0.0 255.0.0.0 host 10.3.8.4 

```
