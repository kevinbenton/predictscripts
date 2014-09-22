# Copyright Kevin Benton
#
# Script to parse output from the argus flows and check
# the IPs against the BGP routing table data to determine
# which ones flows are not present.
#

from collections import defaultdict
#import netaddr
import socket
import struct

BGP_TABLE = defaultdict(list)


def build_bgp_table():
    global BGP_TABLE
    with open('l3_gw_1_mapped_interfaces', 'r') as fh:
        for line in fh:
            cidr, interface = line.split(',')
            interface = interface.rstrip()
            #BGP_TABLE[interface].append(netaddr.IPNetwork(cidr))
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
        print ("flushing routes from interface %s\n%s"
               % (interface, ['%s' % str(x) for x in
                              BGP_TABLE[interface][0:keys[-1]+1]]))
        del BGP_TABLE[interface][0:keys[-1]+1]
    return match_int, match_range


def get_all_ip_integers(flowfile):
    all_ip_integers = []
    with open(flowfile, 'r') as fh:
        for line in fh:
            try:
                all_ip_integers.append(ip_to_int(line.split()[0]))
            except:
                continue
    return all_ip_integers


if __name__ == '__main__':
    build_bgp_table()
    all_ip_integers = get_all_ip_integers('last10minutes.txt')
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
            print "ip did not match BGP entries: %s" % ip
            illegal_ips.append(ip)
        else:
            print "%s in route %s from table %s" % (ip, route, table)
            good_ips.append(ip)

    print "Illegal IPs: %s" % len(illegal_ips)
    print "Good IPs: %s" % len(good_ips)
