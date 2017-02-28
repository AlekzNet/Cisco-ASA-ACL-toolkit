## optimacl.py
Optimizes proto-policy created by ipaclmatch.py. As input it takes lines with five fields:

Source_IP Source_Netmask Destination_IP Destination_mask Protocol:Port

```txt
10.232.0.0 255.248.0.0 10.3.0.1 255.255.255.255 tcp:123 
10.232.0.0 255.248.0.0 10.3.8.4 255.255.255.254 tcp:1-122 
10.232.0.0 255.248.0.0 10.3.8.4 255.255.255.254 tcp:124-65535 
10.206.0.0 255.255.0.0 10.3.0.2 255.255.255.255 tcp:123 
10.206.0.0 255.255.0.0 10.3.0.1 255.255.255.255 tcp:123 
10.192.0.0 255.248.0.0 10.7.8.0 255.255.255.0 tcp:1200-1300 
10.192.0.0 255.248.0.0 10.7.8.0 255.255.255.0 tcp:1250-1350 
10.192.0.0 255.248.0.0 10.7.8.0 255.255.255.0 tcp:1351 
10.0.0.0 255.0.0.0 10.8.9.4 255.255.255.254 tcp:22 
10.0.0.0 255.0.0.0 10.8.9.4 255.255.255.254 tcp:23 
101.10.10.0 255.255.255.0 10.9.9.4 255.255.255.255 esp 
101.10.10.0 255.255.255.0 10.9.9.3 255.255.255.255 esp 
101.10.10.0 255.255.255.0 10.3.8.0 255.255.255.0 icmp:8 
101.10.10.0 255.255.255.0 10.3.8.0 255.255.255.0 icmp:3
```

### Usage:

```txt
$ optimacl.py --help
usage: optimacl.py [-h] [--nomerge] [pol]

positional arguments:
  pol         Firewall policy or "-" (default) to read from the console

optional arguments:
  -h, --help  show this help message and exit
  -v, --verbose  Verbose mode. Messages are sent to STDERR
  --nomerge   Do not merge ports
```

### Examples

Optimize all permitted rules:

```txt
$ ipaclmatch.py -p  --permit test.acl | optimacl.py
0.0.0.0/0 10.3.10.0/24 udp:30000-65535
13.20.0.0/16 10.7.0.0/16 icmp
10.192.0.0/13 10.7.8.0/24 tcp:1200-1351
0.0.0.0/0 0.0.0.0/0 tcp:66
10.0.0.0/8 10.8.9.4/31 tcp:22-23
101.10.10.0/24 10.3.8.0/24 icmp:3,icmp:8,icmp:11
10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16 10.3.0.2/32,10.3.0.1/32 udp:53
10.0.0.0/8 10.3.9.0/30 tcp:23
10.160.0.0/13,10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.208.0.0/12,10.225.0.0/16,10.226.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16,172.16.0.0/12 10.3.0.2/32,10.3.0.1/32 tcp:53,tcp:123
101.10.10.0/24 10.9.9.2/31,10.9.9.1/32,10.9.9.4/32 esp
10.0.0.0/8 10.3.8.4/31,10.3.9.4/31,10.4.0.0/15 *
```

Same as above, but do not merge ports:

```txt
$ ipaclmatch.py -p  --permit test.acl | optimacl.py --nomerge            
0.0.0.0/0 10.3.10.0/24 udp:30000-65535,udp:40000
101.10.10.0/24 10.3.8.0/24 icmp:3,icmp:8,icmp:11
0.0.0.0/0 0.0.0.0/0 tcp:66
10.160.0.0/13,10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.208.0.0/12,10.225.0.0/16,10.226.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16,172.16.0.0/12 10.3.0.2/32,10.3.0.1/32 tcp:53,tcp:123
10.0.0.0/8 10.8.9.4/31 tcp:22
10.192.0.0/13,10.205.0.0/16,10.206.0.0/16,10.228.0.0/14,10.232.0.0/13,10.240.0.0/12,13.20.0.0/16 10.3.0.2/32,10.3.0.1/32 udp:53
10.192.0.0/13 10.7.8.0/24 tcp:1250-1350,tcp:1351,tcp:1200-1300
10.0.0.0/8 10.8.9.4/31,10.3.9.0/30 tcp:23
13.20.0.0/16 10.7.0.0/16 icmp
101.10.10.0/24 10.9.9.2/31,10.9.9.1/32,10.9.9.4/32 esp
10.0.0.0/8 10.3.8.4/31,10.3.9.4/31,10.4.0.0/15 *
```

Real world example:

```txt
$ grep CSM_FW_ACL-01 fw01.conf | fgrep -c extende
3034

$ wc -l CSM_FW_ACL-01.acl
  106204 CSM_FW_ACL-01.acl

$ ipaclmatch.py -p  --permit CSM_FW_ACL-01.acl |  optimacl.py | wc -l
     169
```
628x rule reduction (expanded rules), 18x rule reduction (Cisco conf)

Verbosity option:

```txt
ipaclmatch.py -p  --permit test-02.acl |  optimacl.py -v
Reading  -
First iteration is completed.  152 rules, and  9  "allow all" rules found
Second iteration is completed.  152 rules left
Third iteration is completed.  26  services are in the policy
Fourth iteration is completed. 11  rules in the policy, plus  1  "allow all" rules
. . .
All done. There are  12  rules in the policy.
```


