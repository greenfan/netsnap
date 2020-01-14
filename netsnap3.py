import sys  # Python 3.6 NOTE: We need this for the getsizeof method to replace "sizeof" in Py 2 code
if sys.hexversion < 50725360:
    print("ERROR: Please utilize following 3.6.1 version of Python:\r\n\r\n >>>sys.hexversion\r\n50725360\r\n\r\n")
    sys.exit(0)
import socket

import os
import struct
from ctypes import *

# host to listen on
host = "0.0.0.0"  # listen on all interfaces, instead


class IP(Structure):
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte, 8),
        ("len",           c_ushort, 16),
        ("id",            c_ushort, 16),
        ("offset",        c_ushort, 16),
        ("ttl",           c_ubyte, 8),
        ("protocol_num",  c_ubyte, 8),
        ("sum",           c_ushort, 16),
        ("src",           c_uint, 32),
        ("dst",           c_uint, 32),
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):
        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

class ICMP(Structure):
    _fields_ = [
        ("type", c_ubyte, 8),
        ("code", c_ubyte, 8),
        ("checksum", c_ushort, 16),
        ("unused", c_ushort, 16),
        ("next_hop_mtu", c_ushort, 16)
    ]
    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer):
        pass

socket_protocol = socket.IPPROTO_ICMP
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


'''class IP(Structure):
    _fields_ = [
        ("ihl",           c_ubyte, 4),
        ("version",       c_ubyte, 4),
        ("tos",           c_ubyte, 8),
        ("len",           c_ushort, 16),
        ("id",            c_ushort, 16),
        ("offset",        c_ushort, 16),
        ("ttl",           c_ubyte, 8),
        ("protocol_num",  c_ubyte, 8),
        ("sum",           c_ushort, 16),
        ("src",           c_uint, 32),
        ("dst",           c_uint, 32),
    ]'''
while True:
    raw_data, addr = conn.recvfrom(65535)
    ii = IP(raw_data[0:32])
    ip_header = IP(raw_data)
    print(ii.ihl,ii.version,ii.tos,ii.len,ii.id,ii.id,ii.offset,ii.ttl,ii.protocol_num,ii.sum,ii.src,ii.dst)
    print("Protocol: %s %s %s -> %s" % (ip_header.ihl, ip_header.protocol, ip_header.src_address,
                                 ip_header.dst_address))  # Python 3.6 NOTE: Print statement replacement per Python 3.

