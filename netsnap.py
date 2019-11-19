#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
# Release .11 - - Nov. 2019 - - Russell Dwyer www.russelldwyer.com

from typing import Any, Union

from scapy.all import *
import os
import sys
import time
import pandas as pd


localbroadcast = os.system("ifconfig | grep broadcast | awk '{ print $6 }'")

packets = sniff(count=10)

wrpcap("/tmp/filename.pcap", packets)

scapy_cap = rdpcap("/tmp/filename.pcap")


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
        else: print(proto)

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
