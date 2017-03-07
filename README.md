# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing, modifying and generating Cisco ASA ACLs. Useful for troubleshooting, migrating a subset of rules to another firewall, removing overlapping rules, rules aggregation, converting the rule base to HTML, migrating to FortiGate, etc.

Important! This program set is under active development. Hence expect bugs. Please check the repository frequently, and do test before using in the production environment!

## Files

* asa.sh - Shell script to remotely collect Cisco ASA configs
* asa.exp - Expect script to remotely get and save the configuration, access-groups and access lists
* asa.list - list of Cisco ASA firewall IP's and hostnames 
* asaconf.py - converts ACLs from ASA config file into HTML
* asasort.sh - sort and separate ACLs by name. 
* asasearch.sh - search rules with matching IPaddresses (first in src, then dst) in all ACLs
* combine.sh - same as asasearch.sh, but it combines all similarly named ACLs across directories together
* test.acl - test ACL
* [ipaclmatch.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/ipaclmatch.md) - utility to search for rules matching IP-addresses, the networks they belong to, subnetworks, and generate a proto-policy.
* [optimacl-simple.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/optimacl-simple.md) - optimizes a proto-policy (by aggregating, removing overlapping rules, etc). Works with either the source or destination IP-addresses.
* [optimacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/optimacl.md) - optimizes a proto-policy (by aggregating, removing overlapping rules, etc). Supports full polisy (src dst srv)
* [genacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/genacl.md) - utility to generate ASA ACL's or FortiGate policy from a proto-policy

## Requirements

* Expect (for the data collector)
* Python 2.7
* Netaddr

Install netaddr:

```sh
pip install netaddr
```
## Limitations

The following is not supported:

* IPv6
* NAT
* source ports 
* multiple contexts
* Mixed Permit and Deny rules in optimacl.py

## TODO

* Rewrite ipaclmatch.py. It was written to quickly solve particular tasks. Adding new features created a mess.
* I have one more optimization method in mind, but to implement it optimacl.py should be rewritten.
* Add recursive group generation for all devices in genacl.py


## Data collecting

* Edit asa.list and place a list of the firewall IP-addresses and firewall hostnames (as in the ASA config). No empty lines.
* Enter username/passwords in asa.sh, or uncomment lines that take the info from the keyboard
* Run asa.sh. It will: 
  * create directories with the firewall names
  * log onto the firewalls
  * run the following commands:
    * terminal pager 0 
    * sh run | inc access-group
    * sh run
    * sh access-list
  * save the result in the fwname.group, fwname.conf and fwname.out file in the fwname directories
* Run asasort.sh. It will create ACLname.acl files with corresponding policies in the fwname directories


## Examples

Show the amount of matching ACLs for the IPs found in the source and destination. See asasearch.sh for used parameters. The script processes 4.5mln entries in ~7min (two passes: one for source, one for destination).

```txt
./asasearch.sh 10.1.0.0/16             
fw1/FW_ACL_1.acl 0 0
fw1/FW_ACL_2.acl 0 0
fw2/FW_ACL_1.acl 0 0
fw2/FW_ACL_management.acl 0 0
fw2/FW_ACL_2.acl 4 74
fw2/FW_ACL_3.acl 0 114
fw2/FW_ACL_4.acl 0 1
fw2/FW_ACL_5.acl 4737 16
fw2/FW_ACL_6.acl 0 73
fw2/FW_ACL_7.acl 15 84
fw3/FW_ACL_1.acl 6 16
fw3/FW_ACL_2.acl 0 0

```

Optimize all permitted rules:

```txt
$wc -l test.acl
     126 test.acl

$ ipaclmatch.py -p  --permit test.acl | optimacl.py
10.0.0.0/8 10.8.9.4/31 tcp:22-23
0.0.0.0/0 10.3.10.0/24 udp:30000-65535
13.20.0.0/16 10.7.0.0/16 icmp
10.192.0.0/13 10.7.8.0/24 tcp:1200-1351
0.0.0.0/0 0.0.0.0/0 tcp:66
13.20.0.0/16 10.3.8.4/31 udp:53
10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16 10.3.0.2/32,10.3.0.1/32 udp:53
10.0.0.0/8 10.3.9.0/30 tcp:23
101.10.10.0/24 10.9.9.1/32,10.9.9.2/31,10.9.9.4/32 esp
13.20.0.0/16,172.16.0.0/12 10.3.8.4/31 tcp:53,tcp:123
10.160.0.0/13,10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.208.0.0/12,10.225.0.0/16,10.226.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16,172.16.0.0/12 10.3.0.2/32,10.3.0.1/32 tcp:53,tcp:123
101.10.10.0/24 10.3.8.0/24 icmp:3,icmp:8,icmp:11
10.0.0.0/8 10.3.8.4/31,10.3.9.4/31,10.4.0.0/15 *

ipaclmatch.py -p  --permit test.acl | optimacl.py | wc -l               
      13

```
For all permitted source addresses in test.acl create an optimized Cisco ASA policy

```txt
$ wc -l test.acl
     118 test.acl

$ ipaclmatch.py -t -s --permit test.acl |  optimacl-simple.py | genacl.py -s myObject --acl new_acl

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

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py | genacl.py -s myObject --acl new_acl | wc -l
      13

$ ipaclmatch.py -t -s --permit test.acl |  optimacl-simple.py --group      

10.3.10.0/255.255.255.0 udp:30000-65535
10.7.8.0/255.255.255.0 tcp:1200-1351
10.8.9.4/255.255.255.254 tcp:22-23
10.3.0.1/255.255.255.255,10.3.0.2/255.255.255.255 udp:53,tcp:53,tcp:123
10.3.9.0/255.255.255.252 tcp:23
10.3.8.4/255.255.255.254,10.3.9.4/255.255.255.254,10.4.0.0/255.254.0.0 *

$ ipaclmatch.py -t -s --permit test.acl |  optimacl.py --group | wc -l
       6

```
118 -> 13 = 85% rule reduction (in this particular example)


Search test.acl for the destination networks that contain 10.3.8.4, and generate new_acl with 10.3.8.4 as the destination:

```txt
$ ipaclmatch.py -t -d -a 10.3.8.4 --permit test.acl |  optimacl-simple.py | genacl.py -d 10.3.8.4  --acl new_acl
access-list new_acl extended permit tcp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit tcp 172.16.0.0 255.240.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit tcp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 123
access-list new_acl extended permit tcp 172.16.0.0 255.240.0.0 host 10.3.8.4 eq 123
access-list new_acl extended permit udp 13.20.0.0 255.255.0.0 host 10.3.8.4 eq 53
access-list new_acl extended permit ip 10.0.0.0 255.0.0.0 host 10.3.8.4 

```

Generate a FortiGate policy from all Cisco ASA ACL's that permit traffic from 10.0.0.1:

```txt
$ ipaclmatch.py -p -s -a 10.0.0.1 --permit test.acl | optimacl.py | genacl.py --dev fgt

```
Convert Cisco access-control lists from the saved ASA configuration file into HTML:

```txt
$ asaconf.py --html myfw.conf > myfw.html
```


