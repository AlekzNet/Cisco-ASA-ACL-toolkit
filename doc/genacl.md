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