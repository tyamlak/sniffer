#!/bin/python3.7

import socket
import os 
import struct
from ctypes import sizeof

from header_struct import Ether, IP, TCP
from util import dump


iface = 'eth0'
ETH_P_ALL = 3
p_filter = None

sniffer = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(ETH_P_ALL))
sniffer.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,0)

sniffer.bind((iface,ETH_P_ALL)) # bind for raw sockets ==> bind(iface,proto)

try:
    while True:
        packet = sniffer.recvfrom(65565)[0]

        ether_header = Ether(packet[0:Ether.HDR_LEN])

        # check type of header 
        # and decode with corresponding struct
        if socket.ntohs(ether_header.type) == 2048: # IP header
            offset = Ether.HDR_LEN
            ip_header = IP(packet[offset:offset + sizeof(IP)])
        else: continue


        if not ip_header.type == 6: continue

        pkt_size = socket.ntohs(ip_header.length) + Ether.HDR_LEN

        if ip_header.type == 6:
            offset = Ether.HDR_LEN + sizeof(IP)
            tcp_buffer = packet[offset:offset + sizeof(TCP)]

            tcp_header = TCP(tcp_buffer)

            if not socket.htons(80) in (tcp_header.src_port,tcp_header.dst_port):
                continue
            print('##########################################################')
            
            ether_header.dump()
            ip_header.dump()
            tcp_header.dump()


            total_header_len = Ether.HDR_LEN + sizeof(IP) + tcp_header.get_header_size() # tcp_header have variable size  

            data_size = pkt_size - total_header_len
            print(f'{data_size} bytes of data.')
            data = packet[total_header_len:]
            dump(data)

except KeyboardInterrupt:
    pass
