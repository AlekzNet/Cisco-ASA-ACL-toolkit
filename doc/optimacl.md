## optimacl.py
Optimizes proto-policy created by ipaclmatch.py. As input it takes lines with three fields:

IP-address Netmask Protocol:Port

```txt
10.232.0.0 255.248.0.0 tcp:1-122 
10.232.0.0 255.248.0.0 tcp:124-65535 
10.192.0.0 255.248.0.0 udp:20000-30000 
10.0.0.0 255.0.0.0 * 
```

### Usage:

```txt
optimacl.py --help
usage: optimacl.py [-h] [--group] [pol]

positional arguments:
  pol         Firewall policy or "-" to read from the console

optional arguments:
  -h, --help  show this help message and exit
  --group     Group services and networks together
```

### Examples

For all permitted source addresses in test.acl create an optimized policy

```txt
ipaclmatch.py -t -s --permit test.acl |  optimacl.py

10.3.10.0 255.255.255.0 udp:30000-65535
10.7.8.0 255.255.255.0 tcp:1200-1351
10.3.0.1 255.255.255.255 udp:53
10.3.0.2 255.255.255.255 udp:53
10.3.0.1 255.255.255.255 tcp:53
10.3.0.2 255.255.255.255 tcp:53
10.3.0.1 255.255.255.255 tcp:123
10.3.0.2 255.255.255.255 tcp:123
10.8.9.4 255.255.255.254 tcp:22-23
10.3.9.0 255.255.255.252 tcp:23
10.3.8.4 255.255.255.254 *
10.3.9.4 255.255.255.254 *
10.4.0.0 255.254.0.0 *
```

For all permitted source addresses in test.acl create an optimized policy, grouped by addresses and services:

```txt
ipaclmatch.py -t -s --permit test.acl |  optimacl.py --group

10.3.10.0/255.255.255.0 udp:30000-65535
10.7.8.0/255.255.255.0 tcp:1200-1351
10.8.9.4/255.255.255.254 tcp:22-23
10.3.0.1/255.255.255.255,10.3.0.2/255.255.255.255 udp:53,tcp:53,tcp:123
10.3.9.0/255.255.255.252 tcp:23
10.3.8.4/255.255.255.254,10.3.9.4/255.255.255.254,10.4.0.0/255.254.0.0 *
```
