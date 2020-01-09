
#!/usr/bin/python3
# netsnap.py - version .5
# constructed with scapy and pandas doing the heavy lifting
# TODO: replace scapy with libpcap for accurate wirelen data
from scapy.all import *
import os
import sys
import time
import numpy as np
import pandas as pd
from subprocess import PIPE, Popen

def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]


def Convert(string):
    li = list(string.split("\n"))
    li2 = list(filter(None, li))
    return li2

import signal

def keyboardInterruptHandler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Exiting Immediately.".format(signal))
    exit(0)




# set local variables
local_system_ip = cmdline(" ifconfig | grep -i inet | egrep -v \"fe80|::1|127.0.0\" | awk '{  print  $2 }' ").decode(
    'ascii')
localbroadcast = cmdline("ifconfig | grep broadcast | awk ' { print $6 }'").decode('ascii').strip()
rbc = input('Remove broadcast traffic? (yes/no) ')
rbc = rbc.lower()
if rbc == 'yes':
    list_2_remove = local_system_ip + localbroadcast + '\n239.255.255.250\n' + '224.0.0.251\n' + '224.0.0.255'
else:
    list_2_remove = local_system_ip

list_2_remove = Convert(list_2_remove)
pcapsize = 0
pd.set_option('display.max_rows', 15)

# end local variables


signal.signal(signal.SIGINT, keyboardInterruptHandler)

if __name__ == '__main__':
    while pcapsize < 12000:
        packets = sniff(count=50)

        wrpcap("/tmp/filename2.pcap", packets)

        scapy_cap = rdpcap("/tmp/filename2.pcap")
        raw_wire_length = RawPcapNgReader("/tmp/filename2.pcap")

        for packet in scapy_cap:
            PT = (packet.type)

            if PT == 2048:
                proto = (packet[IP].proto)
                if (proto == 17) or (proto == 6):
                    df = pd.DataFrame({
                        "Source": [(packet[IP].src)],
                        "Destination": [(packet[IP].dst)],
                        "Destport": [(packet[IP].dport)],
                        "Sourceport": [(packet[IP].sport)],
                        "Size": [(len(packet))],
                    })
                elif (proto == 2) or (proto == 1):

                    df = pd.DataFrame({
                        "Source": [(packet[IP].src)],
                        "Destination": [(packet[IP].dst)],
                        "Sourceport": ["1"],
                        "Destport": ["1"],
                        "Size": [(len(packet))],
                    })
                else:
                    print("We've got an outlier \n {}").format(packet.summary)

            elif PT == 34525:
                proto = (packet[IPv6].nh)
                if (proto == 17) or (proto == 6):
                    df = pd.DataFrame({
                        "Source": [(packet[IPv6].src)],
                        "Destination": [(packet[IPv6].dst)],
                        "Destport": [(packet[IPv6].dport)],
                        "Sourceport": [(packet[IPv6].sport)],
                        "Size": [(len(packet))],
                    })

            elif (PT == 2054):
                df = pd.DataFrame({
                    "Source": ["ARP"],
                    "Destination": ["ARP"],
                    "Destport": ["ARP"],
                    "Sourceport": ["ARP"],
                    "Size": ["ARP"],
                })
            df.to_csv('/tmp/fullcapture.csv', mode='a', sep=',', header=False, index=False)

        foobar = pd.read_csv("/tmp/fullcapture.csv", sep=',', names=['Source', 'Destination', 'Destport', 'Sourceport', 'Size'])

        unique_sources = foobar["Source"]
        unique_sources = unique_sources.drop_duplicates()
        # print(unique_sources)

        unique_destinations = foobar["Destination"]
        unique_destinations = unique_destinations.drop_duplicates()
        # print(unique_destinations)

        sourcetable = pd.DataFrame({
            "Source": [],
            "Bytes_received": [],
        })

        for src in unique_sources:
            if src != "ARP":
                mask = foobar["Source"] == "{}".format(src)
                df = foobar[mask]
                dfsize = df["Size"].astype(int)
                dfsum = pd.DataFrame.sum(dfsize)
                currentsrctable = pd.DataFrame({
                    "Source": [src],
                    "Bytes_received": [dfsum],
                })
                sourcetable = sourcetable.append(currentsrctable)

        sourcetable.sort_values(by=['Bytes_received'], inplace=True, ascending=False)

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


        def delineator(list_2_remove, desttable):
            for i in list_2_remove:
                mask = desttable["Destination"] != "{0}".format(i)
                anewone = desttable[mask]
                desttable = anewone

            return desttable

        desttable = delineator(list_2_remove, desttable)


        def sourceverify(list_2_remove, sourcetable):
            for i in list_2_remove:
                mask = sourcetable["Source"] != "{0}".format(i)
                anewone = sourcetable[mask]
                sourcetable = anewone

            return sourcetable


        sourcetable = sourceverify(list_2_remove, sourcetable)
        os.system('clear')
        desttable.set_index('Destination', inplace=True)
        sourcetable.set_index('Source', inplace=True)
        print(desttable)
        print(sourcetable)
        pcapsize = pcapsize + 50

# Tidy up.

cmdline("cp /tmp/*csv /home/greenfan/Desktop/")
cmdline("chmod 777 /home/greenfan/Desktop/*csv")
print("pcap moved to desktop for deubgging")
cmdline("rm -rf /tmp/*csv /tmp/*pcap")
