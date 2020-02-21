#!/usr/bin/python3
# netsnapv3.py
# Rewritten using binary from the wire directly, pulls data from IPv4 and IPv6 headers, then parse with Pandas
# TODO:
#       add DNS resolution
#       add dns query captures
#       enhace CLI output
import socket
import struct
import os
import textwrap
from ipaddress import ip_address
import pandas as pd
from subprocess import PIPE, Popen
import signal

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    psize = 0
    while True:
        while psize < 1000:
            raw_data, addr = conn.recvfrom(65535)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
            if eth_proto == 8:
                #parse the ipv4 packet
                version, header_length, ttl, ipv4_src, ipv4_dest, data = ipv4_packet(data)
                #save to a dataframe
                packetsize = len(data[header_length:])
                df = pd.DataFrame({
                    "Source": [(ipv4_src)],
                    "Destionation": [(ipv4_dest)],
                    "Destionation": [(ipv4_dest)],
                    "Size": [(packetsize)],
                })

            if eth_proto == 56710:
                #parse the ipv6 packet
                ipv6_source, ipv6_destination = ipv6_packet(data[:40])
                packetsize = len(data)
                df = pd.DataFrame({
                    "Source": [(ipv6_source)],
                    "Destionation": [(ipv6_destination)],
                    "Size": [(packetsize)]
                })

            df.to_csv('/tmp/currentcapture.csv', mode='a', sep=',', header=False, index=False)
            psize = os.path.getsize('/tmp/currentcapture.csv')

            # checkpoint to print output
            # combine currentcapture to fullcapture

            #check if fullcapture.csv exists, if not, copy current to full
            exists = os.path.isfile('/tmp/fullcapture.csv')
            if exists:
                # Load configuration file values
                pass
            else:
                cmdline("cp /tmp/currentcapture.csv /tmp/fullcapture.csv")

            csv1 = pd.read_csv(r"/tmp/currentcapture.csv",sep=',',
                             names=['Source', 'Destination', 'Size'])
            csv2 = pd.read_csv(r"/tmp/fullcapture.csv",sep=',',
                             names=['Source', 'Destination', 'Size'])
            finalcsv = pd.concat([csv1, csv2], axis=1, join='inner').sort_index()

            # Write to pandas
            finalcsv.to_csv('/tmp/fullcapture.csv', mode='a', sep=',', header=False, index=False)

        #begin parsing the csv
        foobar = pd.read_csv("/tmp/fullcapture.csv", sep=',',
                             names=['Source', 'Destination', 'Size'])

        unique_sources = foobar["Source"]
        unique_sources = unique_sources.drop_duplicates()

        unique_destinations = foobar["Destination"]
        unique_destinations = unique_destinations.drop_duplicates()

        sourcetable = pd.DataFrame({
            "Source": [],
            "Bytes_received": [],
        })

        for src in unique_sources:
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

        def destdelineator(list_2_remove, desttable):
            for i in list_2_remove:
                mask = desttable["Destination"] != "{0}".format(i)
                boolean_parse = desttable[mask]
                desttable = boolean_parse

            return desttable



        def sourcedelineator(list_2_remove, sourcetable):
            for i in list_2_remove:
                mask = sourcetable["Source"] != "{0}".format(i)
                boolean_parse = sourcetable[mask]
                sourcetable = boolean_parse
            return sourcetable

        sourcetable = sourcedelineator(list_2_remove, sourcetable)
        desttable = destdelineator(list_2_remove, desttable)

        os.system('clear')
        desttable.set_index('Destination', inplace=True)
        sourcetable.set_index('Source', inplace=True)
        print(desttable)
        print(sourcetable)
        cmdline('rm -rf /tmp/currentcapture.csv')
        psize = 0

#unpack IPv4 and IPv6 packet
def ipv4_packet(data):
#ipv4 headers vary in length, so we have to bitshift to the right based on the header length
    v_header_length = data[0]
    version = v_header_length >> 4
    header_length = (v_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, ipv4(src), ipv4(dest), data[header_length:]

#strip ethernet frame header
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4(addr):
    return '.'.join(map(str, addr))

def get_ipv6_addr(ae):
    components = [ae[i:i+4] for i in range(0, len(ae), 4)]
    ipv6_string = ":".join(components)
    ae = ip_address(ipv6_string)
    return ae

def ipv6_packet(data):
    ipv6_hexsrc = data[8:24].hex()
    ipv6_hexdst = data[24:40].hex()
    ipv6_source = get_ipv6_addr(ipv6_hexsrc)
    ipv6_destination = get_ipv6_addr(ipv6_hexdst)
    return ipv6_source, ipv6_destination


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


local_system_ip = cmdline(
    " ifconfig | grep -i inet | egrep -v \"fe80|::1|127.0.0\" | awk '{  print  $2 }' ").decode(
    'ascii')
localbroadcast = cmdline("ifconfig | grep broadcast | awk ' { print $6 }'").decode('ascii').strip()

#Compile list of IP's to remove from output
answer = input('Remove broadcast traffic? (yes/no) ')
answer = answer.lower()
if answer == 'yes':
    list_2_remove = local_system_ip + localbroadcast + '\n239.255.255.250\n' + '224.0.0.251\n' + '224.0.0.255\n' + '255.255.255.255'
else:
    list_2_remove = local_system_ip
list_2_remove = Convert(list_2_remove)

##



def keyboardInterruptHandler(signal, frame):
    print("KeyboardInterrupt (ID: {}) has been caught. Exiting Immediately.".format(signal))
    cmdline("rm -rf /tmp/fullcapture.csv /tmp/currentcapture.csv")
    exit(0)


signal.signal(signal.SIGINT, keyboardInterruptHandler)


main()
