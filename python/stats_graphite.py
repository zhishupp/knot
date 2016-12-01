#!/usr/bin/env python3

"""Simple program for exporting statistics from Knot DNS to influxdb."""

import libknot.control
import graphyte
import time
import json
import io
import os

# Configuration.
libknot.control.load_lib("../src/.libs/libknot.so")
ctl_socket = "/tmp/knot.sock"
ctl_timeout = 2
ctl_flags = "F" # set "F" for all supported counters.
host = "217.31.192.164"
port = "8086"
# send metrics every x seconds
interval = 10
#name of database
DB = "KnotDNS"
#instance - in case of more servers
instance = "Knot1"


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
    output = io.StringIO()

    # Publish the stats.
    stats = {**global_stats, **zone_stats}
    timestamp = str(int(time.time()))
    data = ""
    for metric in stats["server"]:
       if data is not "":
          data = data + ","
       data = data + metric + "=" + stats["server"][metric]
    print("server,instance=" + instance + " " + data + " " + timestamp, file=output)
    data = ""
    '''for zone in stats["zone"]:
        for group in stats["zone"][zone]:
            for metric in stats["zone"][zone][group]:
                if data is not "":
                   data = data + ","
                data = data + metric + "=" + stats["zone"][zone][group][metric]
            print("zone,instance=" + instance + ",zone=" + zone + ",group=" + group + " " + data + " " + timestamp, file=output)'''
    for group in stats["mod-stats"]:
        if type(stats["mod-stats"][group]) is not dict:
            print("module,instance=" + instance + " " + group + "=" + stats["mod-stats"][group] + " " + timestamp, file=output)
        else:
           data = ""
           for metric in stats["mod-stats"][group]:
               if data is not "":
                  data = data + ","
               data = data + metric + "=" + stats["mod-stats"][group][metric]
           print("module,instance=" + instance + ",group=" + group + " " + data + " " + timestamp, file=output)

    bin_data = output.getvalue()
    os.system("curl -i -XPOST 'http://"+host+":"+port+"/write?db="+DB+"&precision=s' --data-binary '" + bin_data + "'")
    
    return

print("%s: Graphite sender - Server Start - %s:%s" %
      (time.asctime(), host, port))

try:
   while(True):
      send()
      time.sleep(interval)
except KeyboardInterrupt:
   pass
