#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
# Release  Alpha Alpha Beta

from typing import Any, Union

from scapy.all import *
import os
import sys
import time
import pandas as pd
from subprocess import PIPE, Popen


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]







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

    df.to_csv('/tmp/fulldump2.csv', mode='a',  sep='\t', header=False)



col_Names=['Source', 'Destination', 'Destport', 'Sourceport', 'Size']


Cov = pd.read_csv("/tmp/fulldump2.csv",  sep='\t', names=col_Names)


#localbroadcast = os.popen("ifconfig | grep broadcast | awk '{ print $6 }'").read()


localbroadcast = "192.168.0.255"


Cov1 = Cov[Cov.Destination != (localbroadcast) ]

Cov.to_csv('/tmp/headerdump.csv')
Cov1.to_csv('/tmp/withoutbroadcasts.csv')
#print(Cov1)

