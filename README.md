# Cisco-ASA-ACL-toolkit
Utilities for parsing, analyzing, modifying and generating Cisco ASA ACLs. Useful for troubleshooting, migrating a subset of rules to another firewall, removing overlapping rules, rules aggregation, etc.

## Files

* asa.exp - expect script to remotely get the configuration, access-groups and access lists
* ipaclmatch.py - utility to search for rules matching IP-addresses, the networks they belong to, subnetworks, and generate a proto-policy.
* optimacl.py - optimizes a proto-policy (by aggregating, removing overlapping rules, etc)
* genacl.py - utility to generate ASA ACL's from a proto-policy

Install netaddr:

```sh
pip install netaddr
```


