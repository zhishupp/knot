#!/usr/bin/env python3

''' Check 'stats' query module functionality. '''

import os
import random

from dnstest.libknot import libknot
from dnstest.module import ModStats
from dnstest.test import Test
from dnstest.utils import *

def check_item(server, section, item, value, idx=None, zone=None):
    try:
        ctl = libknot.control.KnotCtl()
        ctl.connect(os.path.join(server.dir, "knot.sock"))

        if zone:
            ctl.send_block(cmd="zone-stats", section=section, item=item, zone=zone.name)
        else:
            ctl.send_block(cmd="stats", section=section, item=item)

        stats = ctl.receive_stats()
    finally:
        ctl.send(libknot.control.KnotCtlType.END)
        ctl.close()

    if zone:
        stats = stats.get("zone").get(zone.name.lower())

    if idx:
        if value == -1:
            isset(idx not in stats.get(section).get(item), idx)
            return
        else:
            data = int(stats.get(section).get(item).get(idx))
    else:
        data = int(stats.get(section).get(item))

    compare(data, value, "%s.%s" % (section, item))

ModStats.check()

proto = random.choice([4, 6])

t = Test(stress=False, tsig=False, address=proto)

knot = t.server("knot")
zones = t.zone_rnd(2)

t.link(zones, knot)

knot.add_module(None,     ModStats())
knot.add_module(zones[0], ModStats())
knot.add_module(zones[1], ModStats())

t.start()
t.sleep(1)

check_item(knot, "server", "zone-count", 2)

resp = knot.dig(zones[0].name, "SOA", tries=1, udp=True)
query_size1 = resp.query_size()
reply_size1 = resp.response_size()

resp = knot.dig(zones[0].name, "NS", tries=1, udp=False)
query_size2 = resp.query_size()
reply_size2 = resp.response_size()

resp = knot.dig(zones[1].name, "TYPE11", tries=1, udp=True)
query_size3 = resp.query_size()
reply_size3 = resp.response_size()

# Sucessfull transfer.
resp = knot.dig(zones[0].name, "AXFR", tries=1)
resp.check_xfr(rcode="NOERROR")
xfr_query_size = resp.query_size()
# Cannot get xfr_resply_size :-/

# Successfull update.
up = knot.update(zones[1])
up.add(zones[1].name, "3600", "AAAA", "::1")
up.send("NOERROR")
ddns_query_size = up.query_size()
# Due to DDNS bulk processing, failed RCODE and response-bytes are not incremented!

# Check IP metrics.
check_item(knot, "mod-stats", "udp%s" % proto, 2)
check_item(knot, "mod-stats", "udp%s" % proto, 1, zone=zones[0])
check_item(knot, "mod-stats", "udp%s" % proto, 1, zone=zones[1])

check_item(knot, "mod-stats", "tcp%s" % proto, 3)
check_item(knot, "mod-stats", "tcp%s" % proto, 1, zone=zones[0])

# Check receive/sent bytes metrics.
check_item(knot, "mod-stats", "query-bytes",    query_size1 + query_size2 + query_size3 +
                                                xfr_query_size)
check_item(knot, "mod-stats", "response-bytes", reply_size1 + reply_size2 + reply_size3)

check_item(knot, "mod-stats", "query-bytes",    query_size1 + query_size2, zone=zones[0])
check_item(knot, "mod-stats", "response-bytes", reply_size1 + reply_size2, zone=zones[0])

check_item(knot, "mod-stats", "query-bytes",    query_size3, zone=zones[1])
check_item(knot, "mod-stats", "response-bytes", reply_size3, zone=zones[1])

# Check ddns-size metrics (just for global module).
check_item(knot, "mod-stats", "ddns-bytes", ddns_query_size)

# Check recv-size metrics (just for global module).
indices = dict()
for size in [query_size1, query_size2, query_size3, xfr_query_size]:
    idx = "%i-%i" % (int(size / 16) * 16, int(size / 16) * 16 + 15)
    if idx not in indices:
        indices[idx] = 1
    else:
        indices[idx] += 1;
for size in indices:
    check_item(knot, "mod-stats", "query-size", indices[size], idx=size)

# Check sent-size metrics (just for global module).
indices = dict()
for size in [reply_size1, reply_size2, reply_size3]:
    idx = "%i-%i" % (int(size / 16) * 16, int(size / 16) * 16 + 15)
    if idx not in indices:
        indices[idx] = 1
    else:
        indices[idx] += 1;
for size in indices:
    check_item(knot, "mod-stats", "response-size", indices[size], idx=size)

# Check qtype metrics.
check_item(knot, "mod-stats", "qtype",  1, idx="SOA")
check_item(knot, "mod-stats", "qtype",  1, idx="NS")
check_item(knot, "mod-stats", "qtype",  1, idx="TYPE11")

check_item(knot, "mod-stats", "qtype",  1, idx="SOA",    zone=zones[0])
check_item(knot, "mod-stats", "qtype",  1, idx="NS",     zone=zones[0])
check_item(knot, "mod-stats", "qtype", -1, idx="TYPE11", zone=zones[0])

check_item(knot, "mod-stats", "qtype", -1, idx="SOA",    zone=zones[1])
check_item(knot, "mod-stats", "qtype", -1, idx="NS",     zone=zones[1])
check_item(knot, "mod-stats", "qtype",  1, idx="TYPE11", zone=zones[1])

# Check opcode metrics.
check_item(knot, "mod-stats", "opcode", 3, idx="QUERY")
check_item(knot, "mod-stats", "opcode", 1, idx="AXFR")
check_item(knot, "mod-stats", "opcode", 1, idx="UPDATE")

# Check rcode metrics (non-QUERY rcodes per zone are not counted!).
check_item(knot, "mod-stats", "rcode",  4, idx="NOERROR")
check_item(knot, "mod-stats", "rcode",  1, idx="NODATA")

check_item(knot, "mod-stats", "rcode",  2, idx="NOERROR", zone=zones[0])
check_item(knot, "mod-stats", "rcode", -1, idx="NODATA",  zone=zones[0])

check_item(knot, "mod-stats", "rcode", -1, idx="NOERROR", zone=zones[1])
check_item(knot, "mod-stats", "rcode",  1, idx="NODATA",  zone=zones[1])

t.end()
