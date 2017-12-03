## trafacl.sh

Analyses Cisco ASA logs and generates allowed traffic statistics (per ACL):

* List of used ACL's
* Total amount of connections
* List of all connections (with the same SRC-DST-SRV), sorted by amount
* List of all connections, sorted by amount, with at least 10 sessions
* List of all connections, sorted by amount, with at least 0.01% from the total sessions
* List of source IP-addresses, sorted by amount of initiated connections
* List of destination IP-addresses, sorted by amount of connections

The script can be used to generate a firewall policy based on the real traffic.  

#### Performance

* Intel(R) Xeon(R) L5530@2.40GHz
* 10.7GB log file (50M lines)
* ~40 minutes

Other programming languages might "produce" a better result, but in my case only the basic UNIX utilities were available.

### Usage: 

#### 1. Configure access-control lists allowing and logging all traffic:

```txt
access-list inside-in extended permit ip any any log
access-list outside-in extended permit ip any any log
access-group inside-in in interface inside
access-group outside-in in interface outside
```

#### 2. On the syslog server run the script with the Cisco ASA log files as the arguments:

```txt
trafstat.sh asa.log asa.log.1 asa.log.2
```

##### Result:

The script creates a new directory with the name based on the current date and time (e.g. `20171202_2305`) with the following files:

* acl.stat - total amount of connections, and percentages from the total amount

`ACL_name Amount 0.01%   0.02%   0.1%   0.2%`
```txt
inside-in	2302601	230	460	2302	4605
outside-in	1031961	103	206	1031	2063
```
In this case, 0.01% from 2302601 is 230

* inside-in - amount of established connections per session

`Amount Source_IP Destination_IP Protocol:Port`

```txt
10527 10.2.3.12 8.8.8.8 udp:53
9526 10.2.3.14 8.8.8.8 udp:53
9507 10.2.3.11 8.8.8.8 udp:53
9305 10.2.3.12 193.57.16.39 tcp:443
5840 10.2.3.11 193.57.16.38 tcp:443 
. . .
```

* inside-in.10 - same as above but with amount of connection larger, than THOLD (10)

* inside-in.230 - same as above but with amount of connection larger, than 0.01% from the total amount (230 in this case)

* inside-in.topd - destination IP addresses sorted by amount

```txt
66930  8.8.8.8
34597  193.19.80.29
18062  193.57.16.39
17107  193.57.16.38
```

* inside-in.tops - destination IP addresses sorted by amount

* similar files for other ACL's

#### 3. Inspect and edit the generated stat files

#### 4. Remove the first column

#### 5. Use [optimacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/optimacl.md) and [genacl.py](https://github.com/AlekzNet/Cisco-ASA-ACL-toolkit/blob/master/doc/genacl.md) to generate new ACLs without logging

#### 6. Apply the new ACLs on top of the `permit any any log` rule

#### 7. Repeat the procedure above or replace the "allow any" rule with "deny any any log" 
