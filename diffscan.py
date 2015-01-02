#!/usr/bin/python2

import sys
import os
from string import Template
import getopt
import re
import time
import subprocess
import tempfile
import cPickle
import errno

nmap_scanoptions = '-sS -vv --top-ports 20 -T4'
nmap_logoptions = Template('-oG $tmppath')
nmap_inoptions = Template('-iL $inpath')

class ScanData(object):
    def __init__(self):
        self.scantime = time.gmtime()
        self.hosts = {}
        self.dnsmap = {}

    def get_hosts(self):
        return self.hosts.keys()

    def get_host_ports(self, h):
        return self.hosts[h]

    def open_exists(self, addr, port, proto):
        if addr not in self.hosts:
            return False
        cand = [port, proto]
        if cand not in self.hosts[addr]:
            return False
        return True

    def add_open(self, addr, port, proto, hn):
        if proto != 'tcp' and proto != 'udp':
            raise Exception('unknown protocol %s' % proto)
        if addr not in self.hosts:
            self.hosts[addr] = []
        self.dnsmap[addr] = hn
        self.hosts[addr].append([int(port), proto])

class Alert(object):
    def __init__(self, host, port, proto, dns, open_prev, closed_prev):
        self.host = host
        self.port = port
        self.proto = proto
        self.dns = dns
        self.open_prev = open_prev
        self.closed_prev = closed_prev

    @staticmethod
    def alert_header():
        return '%s%s%s%s%s%s%s' % ('STATUS'.ljust(8), 'HOST'.ljust(16),
            'PORT'.ljust(8), 'PROTO'.ljust(8), 'OPREV'.ljust(6),
            'CPREV'.ljust(6), 'DNS')

    def __str__(self):
        return '%s%s%s%s%s%s' % (self.host.ljust(16),
            str(self.port).ljust(8), self.proto.ljust(8),
            str(self.open_prev).ljust(6), str(self.closed_prev).ljust(6),
            self.dns)

class ScanState(object):
    KEEP_SCANS = 7

    def __init__(self):
        self._lastscan = None
        self._scanlist = []
        self._alerts_open = []
        self._alerts_closed = []

    def clear_alerts(self):
        self._alerts_open = []
        self._alerts_closed = []

    def set_last(self, last):
        self._lastscan = last
        if len(self._scanlist) == self.KEEP_SCANS:
            self._scanlist.pop()
        self._scanlist.insert(0, last)
        self.clear_alerts()

    def calculate(self):
        self.calculate_new_open()
        self.calculate_new_closed()

    def prev_service_status(self, addr, port, proto):
        openprev = 0
        closedprev = 0
        for s in self._scanlist[1:]:
            if s.open_exists(addr, port, proto):
                openprev += 1
            else:
                closedprev += 1
        return (openprev, closedprev)

    def find_closed_prev(self, addr, port, proto):
        pass

    def calculate_new_open(self):
        if len(self._scanlist) <= 1:
            return
        for i in self._lastscan.get_hosts():
            for p in self._lastscan.get_host_ports(i):
                prevscan = self._scanlist[1]
                if not prevscan.open_exists(i, p[0], p[1]):
                    dns = self._lastscan.dnsmap[i]
                    openprev, closedprev = \
                        self.prev_service_status(i, p[0], p[1])
                    self._alerts_open.append(Alert(i, p[0], p[1], dns,
                        openprev, closedprev))

    def calculate_new_closed(self):
        if len(self._scanlist) <= 1:
            return
        prevscan = self._scanlist[1]
        for i in prevscan.get_hosts():
            for p in prevscan.get_host_ports(i):
                if not self._lastscan.open_exists(i, p[0], p[1]):
                    dns = self._lastscan.dnsmap[i]
                    openprev, closedprev = \
                        self.prev_service_status(i, p[0], p[1])
                    self._alerts_closed.append(Alert(i, p[0], p[1], dns,
                        openprev, closedprev))

    def print_open_alerts(self):
        sys.stdout.write('%s\n' % Alert.alert_header())
        for i in self._alerts_open:
            sys.stdout.write('OPEN    %s\n' % str(i))

    def print_closed_alerts(self):
        sys.stdout.write('%s\n' % Alert.alert_header())
        for i in self._alerts_closed:
            sys.stdout.write('CLOSED  %s\n' % str(i))

state = None

statefile = './diffscan.state'

def load_scanstate():
    try:
        f = open(statefile, 'r')
    except IOError as e:
        if e.errno == errno.ENOENT:
            return ScanState()
        else:
            raise
    ret = cPickle.load(f)
    f.close()
    return ret

def write_scanstate():
    f = open(statefile, 'w')
    cPickle.dump(state, f)
    f.close()

def parse_output(path):
    new = ScanData()

    f = open(path, 'r')
    while True:
        buf = f.readline()
        if buf == None:
            break
        if buf == '':
            break
        buf = buf.strip()
        m = re.search('Host: (\S+) \(([^)]*)\).*Ports: (.*)$', buf)
        if m != None:
            addr = m.group(1)
            hn = m.group(2)
            if len(hn) == 0:
                hn = 'unknown'
            p = [x.split('/') for x in m.group(3).split(',')]
            for i in p:
                if i[1] != 'open':
                    continue
                new.add_open(addr.strip(), i[0].strip(), i[2].strip(), hn)
    f.close()

    state.set_last(new)

def diffscan_fail():
    sys.exit(1)

def run_nmap(targets):
    nmap_args = []
    nmap_args += nmap_scanoptions.split()

    tf = tempfile.mkstemp()
    os.close(tf[0])
    nmap_args += nmap_logoptions.substitute(tmppath=tf[1]).split()
    nmap_args += nmap_inoptions.substitute(inpath=targets).split()

    nfd = open('/dev/null', 'w')
    ret = subprocess.call(['nmap',] + nmap_args, stdout=nfd)
    nfd.close()

    if ret != 0:
        sys.stdout.write('nmap failed with return code %d, exiting\n' \
            % ret)
        diffscan_fail()

    parse_output(tf[1])

    os.remove(tf[1])

def usage():
    sys.stdout.write('usage: diffscan.py [-s path] [-h] targets_file\n')
    sys.exit(0)

def domain():
    global statefile
    global state

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'hs:')
    except getopt.GetoptError:
        usage()
    for o, a in opts:
        if o == '-h':
            usage()
        elif o == '-s':
            statefile = a
    if len(args) == 0:
        usage()
    targetfile = args[0]

    state = load_scanstate()

    sys.stdout.write('diffscan2 results output\n\n')

    run_nmap(targetfile)
    state.calculate()
    sys.stdout.write('New Open Service List\n')
    sys.stdout.write('---------------------\n')
    state.print_open_alerts()
    sys.stdout.write('\n')
    sys.stdout.write('New Closed Service List\n')
    sys.stdout.write('-----------------------\n')
    state.print_closed_alerts()

    sys.stdout.write('\n')
    sys.stdout.write('OPREV: number of times service was open in previous ' \
        'scans\n')
    sys.stdout.write('CPREV: number of times service was closed in ' \
        'previous scans\n')
    sys.stdout.write('maximum previous scans stored: %d\n' % state.KEEP_SCANS)

    write_scanstate()

if __name__ == '__main__':
    domain()

sys.exit(0)
