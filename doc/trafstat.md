## trafacl.sh

Analyses Cisco ASA logs and generates allowed traffic statstics (per ACL):

* List of used ACL's
* Total amount of connections
* List of all connections (with the same SRC-DST-SRV), sorted by amount
* List of all connections, sorted by amount, with at least 10 sessions
* List of all connections, sorted by amount, with at least 0.01% from the total sessions
* List of source IP-addresses, sorted by amount of initiated connections
* List of destination IP-addresses, sorted by amount of connections

The script can be used to generate a firewall policy based on the real traffic. 

### Usage: 

#### Configure access-control lists allowing and logging all traffic:

```txt
access-list inside-in extended permit ip any any log
access-list outside-in extended permit ip any any log
access-group inside-in in interface inside
access-group outside-in in interface outside
```

#### On the syslog server run the script with the Cisco ASA log files as the arguments:

```txt
trafstat.sh asa.log asa.log.1 asa.log.2
```


