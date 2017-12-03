## trafacl.sh

Checks for the permitted by access control lists traffic in Cisco ASA log and generated the following:

* List of used ACL's
* Total amount of connections per ACL
* List of all connections (with the same SRC-DST-SRV), sorted by amount (per ACL)
* List of all connections, sorted by amount (per ACL), with at least 10 sessions
* List of all connections, sorted by amount (per ACL), with at least 0.01% from the total sessions
* List of source IP-addresses, sorted by amount of initiated connections (per ACL)
* List of destination IP-addresses, sorted by amount of connections (per ACL)

### Usage: 

```txt
trafstat.sh asa.log asa.log.1 asa.log.2
```

