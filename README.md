# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing and modifuing Cisco ASA ACLs

ipaclmatch.py finds ACLs matching the given IP-addresses, including networks, subnetworks and supernets.

Usage:

Save the access group using the following command in a file, for example ACL_name.acl:

```txt
sh access-list ACL-name
```

Search only the source addresses for 10.0.1.2/32 and 10.2.3.0/24:

```txt
python ipaclmatch.py --addr 10.0.1.2,10.2.3.0/24 --acl ACL_name.acl --sd source
```

Search for 10.2.3.0/24 in both source and destination, but ignore "any":

```txt
python ipaclmatch.py --noany --addr 10.2.3.0/24 --acl ACL_name.acl 
```


