#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
###
# Release Version:  0.3.1
# Revision date: 12/17/19
###
# netsnappy is a more resource friendly version of nethogs,
# constructed with scapy and pandas doing the heavy lifting
###
###
# Todos v.3.3 add destination, add filtering based on my_ips, add total received
# v.4 instead of printing, set them to create a series, and sort by ascending sizes
# v.5 add more recursion. . .
#
from typing import Any, Union

from scapy.all import *
import os
import sys
import time
import numpy as np
import pandas as pd
from subprocess import PIPE, Popen
#
#
#
# Boiler plate
def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]
def Convert(string):
    li = list(string.split("\n"))
    return li
#
# end local functions
#
# begin local variables
# undeclared variables are latent bugs
local_system_ip = cmdline(" ifconfig | grep -i inet | egrep -v \"fe80|::1|127.0.0\" | awk '{  print  $2 }' ").decode('ascii')
localbroadcast = cmdline("ifconfig | grep broadcast | awk ' { print $6 }'").decode('ascii').strip()
packets = sniff(count=100)
#
# end local variables
#


# take the capture
wrpcap("/tmp/filename2.pcap", packets)

scapy_cap = rdpcap("/tmp/filename2.pcap")




for packet in scapy_cap:
    PT = (packet.type)

    if PT == 2048:
        proto = (packet[IP].proto)
        if ( proto == 17) or ( proto == 6 ):
            df = pd.DataFrame({
                "Source": [(packet[IP].src)],
                "Destination": [(packet[IP].dst)],
                "Destport": [(packet[IP].dport)],
                "Sourceport": [(packet[IP].sport)],
                "Size": [(len(packet))],
            })
        elif ( proto == 2 ) or ( proto == 1 ):

            df = pd.DataFrame({
                "Source": [(packet[IP].src)],
                "Destination": [(packet[IP].dst)],
                "Sourceport": ["1"],
                "Destport": ["1"],
                "Size": [(len(packet))],
            })
        else: print("We've got an outlier \n {}").format(packet.summary)

    elif PT == 34525:
        proto = (packet[IPv6].nh)
        if ( proto == 17) or ( proto == 6 ):
            df = pd.DataFrame({
                "Source": [(packet[IPv6].src)],
                "Destination": [(packet[IPv6].dst)],
                "Destport": [(packet[IPv6].dport)],
                "Sourceport": [(packet[IPv6].sport)],
                "Size": [(len(packet))],
            })

    elif ( PT == 2054):
        print("ARP!")
        print(packet.summary)
        df = pd.DataFrame({
            "Source": ["ARP"],
            "Destination": ["ARP"],
            "Destport": ["ARP"],
            "Sourceport": ["ARP"],
            "Size": ["ARP"],
        })

    df.to_csv('/tmp/fullcapture.csv', mode='a',  sep=',', header=False, index=False)

#
#
####add header to fullcapture csv
foobar = pd.read_csv("/tmp/fullcapture.csv", sep=',', names=['Source', 'Destination', 'Destport', 'Sourceport', 'Size'])
###
# Grab unique addresses
###

unique_sources = foobar["Source"]
unique_sources = unique_sources.drop_duplicates()
#print(unique_sources)

unique_destinations = foobar["Destination"]
unique_destinations = unique_destinations.drop_duplicates()
#print(unique_destinations)

###
# define function to extract values


# define function to extract values

for src in unique_sources:

    if src != "ARP":
        mask =  foobar["Source"] == "{}".format(src)
        df = foobar[mask]
        dfsize = df["Size"].astype(int)
        dfsum = pd.DataFrame.sum(dfsize)
        print("Received: {1:10} bytes from {0}".format(src, dfsum))

###


desttable = pd.DataFrame({
    "Destination": [],
    "Bytes_transfered": [],
})

for dst in unique_destinations:
    if dst != "ARP":
        mask = foobar["Destination"] == "{}".format(dst)
        df = foobar[mask]
        dfsize = df["Size"].astype(int)
        dfsum = pd.DataFrame.sum(dfsize)
        currenttable = pd.DataFrame({
            "Destination": [dst],
            "Bytes_transfered": [dfsum],
        })
        desttable = desttable.append(currenttable)

desttable.sort_values(by=['Bytes_transfered'], inplace=True, ascending=False)

####
list_2_remove = ['192.168.0.61', '192.168.0.255', '2601:647:5500:42c1:713d:e934:b8c:730c']

def delineator(list_2_remove, desttable):
    for i in list_2_remove:
        mask = desttable["Destination"] != "{0}".format(i)
        anewone = desttable[mask]
        desttable = anewone

    return desttable

desttable = delineator(list_2_remove, desttable)


print(desttable)















####
#
###
###
# Get list containing our current IP's
###
local_system_ips = (Convert(local_system_ip))
ouriplist = list(filter(None,local_system_ips))

print(ouriplist)

#
#
#
#Tidy up.

cmdline("cp /tmp/*csv /home/greenfan/Desktop/")
cmdline("chmod 777 /home/greenfan/Desktop/*csv")
print("pcap moved to desktop for deubgging")
print("clearing temp files. . . ")
cmdline("rm -rf /tmp/*csv /tmp/*pcap")