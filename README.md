# nfs_DR
scripts for nfs DR operations
the following has 2 scripts:
1. nfs_exports_sync - will sync export configuration of replicated filesystems from source InfiniBox to destination InfiniBox.
2. nfs_failover - has a few flags for failover operation \
      disable - will disable all NAS network spaces for a given InfiniBox. \
      enable - will enable all NAS network spaces for a given InfiniBox. \
      failover - will detach replication link and preform change role for all repliocated filesystems.

## Prerequisites
The script uses python 3 \
The script uses infinisdk module \
Prior to running the scripts, please make sure to create an identical user within all relevant InfiniBox systems.

## Authentication and configuration
Please make sure to create a config file for InfiniBox.
File contents should be as follows:
```
[IBOX]
user = user1
password = password1
```
password value should be encrypted using base64.

## Usage
```
usage: nfs_exports_sync.py [-h] -s SOURCE -d DESTINATION -c CREDFILE

usage: nfs_failover.py [-h] -o {disable,enable,failover,reverse} -i IBOX -c CREDFILE

usage: nfs_failback.py [-h] -o {failback,restore} -s SOURCE -d DESTINATION -c CREDFILE
```

