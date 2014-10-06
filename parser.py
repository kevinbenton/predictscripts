# Copyright Kevin Benton
#
# Script to parse output from the argus flows and check
# the IPs against the BGP routing table data to determine
# which ones flows are not present.
#

from collections import defaultdict
# would be much easier with this library, but not present on PREDICT
# import netaddr  # noqa
import json
import socket
import struct
import subprocess
import sys

BGP_TABLE = defaultdict(list)


def build_bgp_table():
    global BGP_TABLE
    with open('l3_gw_1_mapped_interfaces', 'r') as fh:
        for line in fh:
            cidr, interface = line.split(',')
            interface = interface.rstrip()
            # BGP_TABLE[interface].append(netaddr.IPNetwork(cidr))
            BGP_TABLE[interface].append(IntegerRange.from_cidr(cidr))
    print "BGP Table built."
    for interface, table in BGP_TABLE.iteritems():
        print "Interface %s has %s entries" % (interface, len(table))


class IntegerRange(object):
    def __init__(self, begin, end, ident):
        self.begin = int(begin)
        self.end = int(end)
        self.ident = ident

    def contains(self, num):
        res = self.begin < int(num) < self.end
        return res

    def __str__(self):
        return self.ident

    @classmethod
    def from_cidr(cls, cidr):
        ip, mask = cidr.split('/')
        mask = int(mask)
        bitstring = '1' * mask + '0' * (32 - mask)
        inversebitstring = '0' * mask + '1' * (32 - mask)
        binmask = int(bitstring, 2)
        inversebinmask = int(inversebitstring, 2)
        integerip = ip_to_int(ip)
        low = integerip & binmask
        high = low | inversebinmask
        return cls(low, high, cidr)


def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(ip):
    return socket.inet_ntoa(struct.pack("!I", ip))


def is_ip_in_bgp_table(ip):
    """Warning: This will mutate the table to improve performance.

    Checks BGP tables for IP and removes BGP entry if IP in question
    is greater than the max range.
    """
    to_pop = defaultdict(list)
    match_int, match_range = None, None
    for interface, table in BGP_TABLE.iteritems():
        if match_int:
            break
        if not table or ip < table[0].begin:
            # entries are ordered. missing the first means skip the rest
            # in this table
            continue
        for key, range in enumerate(table):
            if ip > range.end:
                # add to removal list
                to_pop[interface].append(key)
            if range.contains(ip):
                match_int, match_range = interface, range
                break
    for interface, keys in to_pop.iteritems():
        msg = ("flushing routes from interface %s\n%s"
               % (interface, ['%s' % str(x) for x in
                              BGP_TABLE[interface][0:keys[-1]+1]]))
        del BGP_TABLE[interface][0:keys[-1]+1]
    return match_int, match_range


IP_TRAFFIC_PROTO = defaultdict(list)
RETURN_LIST = []
def get_all_ip_integers(flowfile):
    global IP_TRAFFIC_PROTO
    global RETURN_LIST
    all_ip_integers = []
    with open(flowfile, 'r') as fh:
        for line in fh:
            try:
                ip, dip, proto = line.split()[0:3]
                all_ip_integers.append(ip_to_int(line.split()[0]))
                if (proto, dip) not in IP_TRAFFIC_PROTO[ip]:
                    IP_TRAFFIC_PROTO[ip] = (proto, dip)
                if dip not in RETURN_LIST:
                    RETURN_LIST.append(dip)
            except:
                continue
    return all_ip_integers


ROUTE_VIEWS_CACHE = {}
def get_route_views_as(ip):
    global ROUTE_VIEWS_CACHE
    intip = ip_to_int(ip)
    if not ROUTE_VIEWS_CACHE:
        with open('additional_data/routeviews-rv2-20140320-1200.pfx2as',
                  'r') as fh:
            for l in fh:
                net, mask, AS = l.split()
                ROUTE_VIEWS_CACHE[
                    IntegerRange.from_cidr('%s/%s' % (net, mask))] = AS
    for r, AS in ROUTE_VIEWS_CACHE.iteritems():
        if r.contains(intip):
            return AS
    return 'NA'


try:
    with open('additional_data/whoiscache.json', 'r') as fh:
        cidr_cache = json.loads(fh.read())
        PREFIX_CACHE = {}
        for cidr, val in cidr_cache.iteritems():
            PREFIX_CACHE[IntegerRange.from_cidr(cidr)] = val
except:
    PREFIX_CACHE = {}


def flush_cache():
    with open('additional_data/whoiscache.json', 'w') as fh:
        cidr_cache = dict((str(r), val) for r, val in PREFIX_CACHE.iteritems())
        fh.write(json.dumps(cidr_cache))


class IPInfo(object):
    def __init__(self, ip_addr):
        AS, IP, PREFIX, CC, REGISTRY, ALLOCATED, NAME = self.get_info(ip_addr)
        self.AS = AS
        self.ip = ip_addr
        self.prefix = PREFIX
        self.cc = CC
        self.registry = REGISTRY
        self.allocated = ALLOCATED
        self.as_name = NAME
        self.traffic_flows = IP_TRAFFIC_PROTO[ip_addr]
        self.present_in_routeviews = get_route_views_as(ip_addr) != 'NA'

    def get_info(self, ip_addr):
        global PREFIX_CACHE
        for range, info in PREFIX_CACHE.iteritems():
            if range.contains(ip_to_int(ip_addr)):
                return info
        command = '/usr/bin/whois -h whois.cymru.com " -v %s"' % ip_addr
        resp, err = subprocess.Popen(command, stdout=subprocess.PIPE,
                                     shell=True).communicate()
        resp = resp.splitlines().pop()
        parts = map(lambda x: x.strip(), resp.split('|')[0:7])
        cidr = parts[2]
        if '/' in cidr:
            PREFIX_CACHE[IntegerRange.from_cidr(cidr)] = parts
        else:
            print "no cidr found in response for %s: %s" %(ip_addr, resp)
            parts[0] = get_route_views_as(ip_addr)
        flush_cache()
        return parts

    def __str__(self):
        return json.dumps(
            dict(AS=self.AS, IP=self.ip, PREFIX=self.prefix, CC=self.cc,
                 REGISTRY=self.registry, ALLOCATED=self.allocated,
                 AS_NAME=self.as_name, TRAFFIC_FLOWS=self.traffic_flows)
        )


if __name__ == '__main__':
    build_bgp_table()
    all_ip_integers = get_all_ip_integers(sys.argv[1])
    print "Number of flows: %s" % len(all_ip_integers)
    print "Sorting by IP"
    all_ip_integers.sort()
    print "Sorting Complete"
    print "Begining iteration through BGP table"
    illegal_ips = []
    good_ips = []
    last = None
    for ip in all_ip_integers:
        if ip == last:
            continue  # de-dup
        else:
           last = ip
        table, route = is_ip_in_bgp_table(ip)
        if not table:
            nice_ip = int_to_ip(ip)
            print "ip did not match BGP entries: %s" % nice_ip
            print "protocols for ip %s: %s" % (nice_ip,
                                               IP_TRAFFIC_PROTO[nice_ip])
            illegal_ips.append(ip)
        else:
            #print "%s in route %s from table %s" % (ip, route, table)
            good_ips.append(ip)
    illegal_info = [IPInfo(int_to_ip(ip)) for ip in illegal_ips]
    #print "Illegal IPs: %s" % map(str, illegal_info)
    print "Illegal IPs: %s" % len(illegal_ips)
    print "Illegal IPs present in routeviews: %s" % len(
        [i for i in illegal_info if i.present_in_routeviews])
    print "Good IPs: %s" % len(good_ips)
    group_by_as = defaultdict(list)
    for info in illegal_info:
        group_by_as[info.AS].append(info)
    for AS, info_list in group_by_as.iteritems():
        print "AS: %s => %s entries" % (AS, len(info_list))
    print "Bad AS count: %s" % len(group_by_as.keys())
