#!/usr/bin/env python3

"""Simple program for exposing statistics from Knot DNS over HTTP/HTTPS."""

import libknot.control
import graphyte
import time

# Configuration.
#libknot.control.load_lib("../src/.libs/libknot.so")
ctl_socket = "/tmp/knot.sock"
ctl_timeout = 2
ctl_flags = "" # set "F" for all supported counters.
host = "127.0.0.1"
port = 8080
# send metrics every x seconds
interval = 10
#metrics naming option
prefix = "Knot"


def send():
# Connect to Knot server.
    ctl = libknot.control.KnotCtl()
    ctl.connect(ctl_socket)
    ctl.set_timeout(ctl_timeout)

    # Get global metrics.
    global_stats = dict()
    try:
        ctl.send_block(cmd="stats", flags=ctl_flags)
        global_stats = ctl.receive_stats()
    except:
        pass

    # Get zone metrics.
    zone_stats = dict()
    try:
        ctl.send_block(cmd="zone-stats", flags=ctl_flags)
        zone_stats = ctl.receive_stats()
    except:
        pass

    # Disconnect from the server.
    ctl.send(libknot.control.KnotCtlType.END)
    ctl.close()

    # Publish the stats.
    stats = {**global_stats, **zone_stats}
    for source in stats:
        for metric in stats[source]:
               graphyte.send(source + "." + metric, int(stats[source][metric]))
    return


graphyte.init(host=host, port=port, prefix=prefix)

print("%s: Graphite sender - Server Start - %s:%s" %
      (time.asctime(), host, port))

try:
    while(True):
        send()
except KeyboardInterrupt:
    pass

httpd.server_close()
