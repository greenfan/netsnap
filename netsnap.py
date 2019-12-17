#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
# Release Version:  Aloha Boeing
# Release Date: 12.16.19

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
# local functions
def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]

#convert our output from local system ip into a usable python list
def Convert(string):
    li = list(string.split("\n"))
    return li

# local variables
local_system_ip = cmdline(" ifconfig | grep -i inet | egrep -v \"fe80|::1|127.0.0\" | awk '{  print  $2 }' ").decode('ascii')
localbroadcast = cmdline("ifconfig | grep broadcast | awk ' { print $6 }'").decode('ascii').strip()



# define length
packets = sniff(count=10)

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
        else: print(packet.summary)

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
col_Names=['Source', 'Destination', 'Destport', 'Sourceport', 'Size']
Cov = pd.read_csv("/tmp/fullcapture.csv",  sep=',', names=col_Names)
Cov.to_csv("/tmp/addedheaders.csv")
foobar = pd.read_csv("/tmp/addedheaders.csv", sep=',')


###
# Grab unique addresses
###

unique_sources = foobar["Source"]
unique_sources = unique_sources.drop_duplicates()
print(unique_sources)

unique_destinations = foobar["Destination"]
unique_destinations = unique_destinations.drop_duplicates()
print(unique_destinations)

###
# define function to extract values








####
#
###
###
# Get list containing our current IP's
###
local_system_ips = (Convert(local_system_ip))
ouriplist = list(filter(None,local_system_ips))


#
#
#
#Tidy up.
print("chmoding and moving csvs. . .")
cmdline("cp /tmp/*csv /home/greenfan/Desktop/")
cmdline("chmod 777 /home/greenfan/Desktop/*csv")
#print("clearing temp files. . . ")
#cmdline("rm -rf /tmp/*csv /tmp/*pcap")
