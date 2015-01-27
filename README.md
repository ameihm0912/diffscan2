# diffscan2

## Overview

diffscan2 is a wrapper for nmap intended to automate processing scan results
and generate reports detailing differences (differential reporting).

It has been tested with nmap 6.

## Usage

Update `nmap_scanoptions` in diffscan.py with any additional options that are
required to be sent to nmap.

Typical usage involves execution as follows:

```
	$ ./diffscan.py targets.txt user@host.com GroupName
```

where targets.txt is a list of subnets/hosts, user@host.com is the recipient
address for the report, and GroupName is a string included in the mail
subject to differentiate between different instances of diffscan2.
