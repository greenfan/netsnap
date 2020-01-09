import socket
import struct
import textwrap

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        eth_proto, data = ethernet_frame(raw_data)
        version, header_length, ttl, ipv4_src, ipv4_dest, data = ipv4_packet(data)
        framesize = len(raw_data)
        print(eth_proto)
        print(ttl)
        print(ipv4_dest)
        print(ipv4_src)
        print(framesize)




#strip ethernet frame header
def ethernet_frame(data):
    framedata, proto = struct.unpack('! 12s H', data[:14])
    return socket.htons(proto), data[14:]

#unpack IPv4 and IPv6 packet
def ipv4_packet(data):
    #need length to determine when to start unpacking
    version_header_length = data[0]
    #bitshift data to the right
    version = version_header_length >> 4
    #compare 2 bytes, get the result when both bytres are 1
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, ipv4(src), ipv4(dest), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

#unpack icmp
#unpack tcp
#unpack udp
#unpack igmp


main()










"""
8 = ipv4
1544 = arp

56710 = weird udp from 192.168.0.24"""