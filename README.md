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

A state file (by default ./diffscan.state) is used between executions to
keep state on previous scans. Additionally, the nmap output is saved in an
output directory for future review if required (by default ./diffscan_out)

## Reporting

An example report is shown below.

```
	diffscan2 results output

	New Open Service List
	---------------------
	STATUS HOST PORT PROTO OPREV CPREV DNS
	OPEN 10.0.2.100 22 tcp 0 3 unknown
	OPEN 10.0.2.100 111 tcp 0 3 unknown

	New Closed Service List
	---------------------
	STATUS HOST PORT PROTO OPREV CPREV DNS

	OPREV: number of times service was open in previous scans
	CPREV: number of times service was closed in previous scans
	maximum previous scans stored: 7
	current total services: 7
	previous total services: 5
	up trend: 6,5,5,4
	down trend: 506,507,507,252
```

