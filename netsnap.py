#!/usr/bin/python3
# netsnapshot.py - network monitoring with scapy and python pandas
# Release Version:  Alpha Beta
# Release Date: 11/22/19

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
packets = sniff(count=300)

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

    df.to_csv('/tmp/fullcapture.csv', mode='a',  sep='\t', header=False)

#add header to fullcapture csv
col_Names=['Source', 'Destination', 'Destport', 'Sourceport', 'Size']
Cov = pd.read_csv("/tmp/fullcapture.csv",  sep='\t', names=col_Names)


print(localbroadcast)
local_system_ips = (Convert(local_system_ip))
myarray = np.asarray(local_system_ips)



print("our local system IP's are {}".format(myarray))

#remove packets addressed to broadcast address
# THIS IS not working, so replace it with a for loop 
# This is necessary because we also have to SUM each individual IP
#Cov1 = Cov[Cov.Destination != (localbroadcast) ]
#Cov1.to_csv('/tmp/withoutbroadcasts.csv')

#Cov2 = Cov.loc[Cov['Destination'].isin([(myarray)])]
#Cov2.to_csv('/tmp/cov2.csv')


#inboundtraffic = Cov1.loc[Cov1['Source'].isin(local_system_ips)]
#inboundtraffic.to_csv=('/tmp/inboundwithoutlocal.csv')


#
#
#
#Tiny up our workspace...
#
#
#
print("chmoding and moving csvs. . .")
cmdline("cp /tmp/*csv /home/greenfan/Desktop/")
cmdline("chmod 777 /home/greenfan/Desktop/*csv")
print("clearing temp files. . . ")
cmdline("rm -rf /tmp/*csv /tmp/*pcap")


# Create a Dataframe from CSV
#df1 = pd.read_csv('/tmp/headerdump.csv')

#my_dataframe = my_dataframe[my_dataframe.employee_name != 'chad']

# Create a Dataframe from CSV
#    d1 = pd.read_csv('/tmp/fulldump.csv')

    # Drop via logic: similar to SQL 'WHERE' clause
#    d1 = d1(d1.Destination != '192.168.0.255')

#    d1.to_csv('/tmp/dumpwithoutbroadcasts/csv', mode='a', header=False)
    #print(df.loc[df['Destination'].isin(['192.168.0.255'])])




#    df1.to_csv('/tmp/notbroadcasted.csv', mode='a', header=False)
#



# remove broadcast from Dest column
#fulldump = pd.read_csv('/tmp/fulldump.csv')

#df1 = df[~df['Dest'].str.contains('192.168.0.255')]

#print(df1)
#d1.to_csv('/tmp/d1.csv', mode='a', header=False)


#df[df['Position'].str.contains("PG")]


#ourlocalIP = os.system("ifconfig | grep -v 127 | grep inet\  | awk '{ print $2 }'")
#, filter="not broadcast and not host {0}".format(localbroadcast)


#Removed from middle

#print(localbroadcast)
#Cov1 = Cov[Cov.Destination != (localbroadcast) ]

#Cov1.to_csv('/tmp/withoutbroadcasts.csv')

#inboundsources = (Cov1['Source'])

#outbounddestinations = (Cov1['Destination']et nu
