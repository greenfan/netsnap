
#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
# Release .01 - - Nov. 2019 - - Russell Dwyer www.russelldwyer.com

from typing import Any, Union

from scapy.all import *
import os
import time
import pandas as pd
from scapy.plist import PacketList


packets = sniff(count=10)
wrpcap("/tmp/filename.pcap", packets)
count = 1


scapy_cap = rdpcap("/tmp/filename.pcap")


for packet in scapy_cap:
    PT = (packet.type)
    proto = (packet[IP].proto)
    count += 1
    if PT == 2048:
        if ( proto == 17) or ( proto == 6 ):
            df = pd.DataFrame({
                "Column1": [(packet[IP].src)],
                "Column2": [(packet[IP].dst)],
                "Column3": [(packet[IP].dport)],
                "Column4": [(packet[IP].sport)],
                "Column5": [(len(packet))],
                "#": [(count)]
            })
            print(df)

        else: print(packet.summary, proto)
    elif PT == 34525:
        print("ipv6")
    elif PT == 2054:
        print("ARP")

