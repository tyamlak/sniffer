import struct
from ctypes import *
from socket import inet_ntoa, ntohl, ntohs


class Ether(Structure):
    ADDR_LEN = 6
    HDR_LEN = 14
    _fields_ = [
        ('dest_addr',c_ubyte * ADDR_LEN), # array of u_char
        ('src_addr',c_ubyte * ADDR_LEN),
        ('type',c_ushort),
    ]

    def __new__(self,pkt_buffer):
        return self.from_buffer_copy(pkt_buffer)

    def __init__(self,pkt_buffer):
        pass

    def get_mac(self,option=None):
        src_mac = ':'.join(['%02x'%x for x in self.src_addr])
        dst_mac = ':'.join(['%02x'%x for x in self.dest_addr])
        return (src_mac,dst_mac)

    def dump(self):
        print('  ***************************')
        print('  Ether Header')
        print(f'\tType: {self.type}')
        src, dst = self.get_mac()
        print(f'\tSource MAC: {src}')
        print(f'\tDesination MAC: {dst}')


class IP(Structure):
    _fields_ = [
        ('ihl',c_ubyte,4),
        ('version',c_ubyte,4),
        ('tos',c_ubyte),
        ('length',c_ushort),
        ('id',c_ushort),
        ('offset',c_ushort),
        ('ttl',c_ubyte),
        ('type',c_ubyte),
        ('checksum',c_ushort),
        ('src',c_uint),
        ('dst',c_uint),
    ]

    def __new__(self,pkt_buffer):
        return self.from_buffer_copy(pkt_buffer)

    def __init__(self,pkt_buffer):

        self.protocol_map = {0:'HOPOPT', 1:'ICMP', 6:'TCP', 17:'UDP',27:'RDP'}

    def dump(self):
        print('  ***************************')
        print('  IP Header')
        print(f'\tSource: {inet_ntoa(struct.pack("<L",self.src))}')
        print(f'\tDestination: {inet_ntoa(struct.pack("<L",self.dst))}')
        print(f'\tLength: {ntohs(self.length)}')
        print(f'\tType: {self.type}  ID: {ntohs(self.id)}')
        print(f'\tChecksum {self.checksum}')


class TCP(Structure):
    flag_map = {'FIN':0X01,'SYN':0X02,'RST':0X04,
            'PSH':0X08,'ACK':0X10,'URG':0X20
            }
    _fields_ = [
        ('src_port',c_ushort),
        ('dst_port',c_ushort),
        ('seq_no',c_uint),
        ('ack_no',c_uint),
        ('res',c_ubyte,4),
        ('offset',c_ubyte,4),
        ('flags',c_ubyte),
        ('window',c_ushort),
        ('checksum',c_ushort),
        ('urgent',c_ushort),
    ]

    def __new__(self,pkt_buffer):
        return self.from_buffer_copy(pkt_buffer)

    def __init__(self,pkt_buffer):
        pass

    def get_header_size(self):
        return 4 * self.offset

    def get_flags(self):
        on_flags = []
        for f in self.flag_map:
            if self.flags & self.flag_map[f]:
                on_flags.append(f)
        return on_flags

    def dump(self):
        print('  ***************************')
        print('  TCP Header')
        print(f'\tSource Port: {ntohs(self.src_port)}  ',end='')
        print(f'\tDestination Port: {ntohs(self.dst_port)} ')
        print(f'\tSequence No: {ntohl(self.seq_no)}   ',end='')
        print(f'\tAcknowledgment No: {ntohl(self.ack_no)} ')
        print(f'\tOffset: {self.offset}')
        print(f'\tFlags: ',end='')
        for f in self.get_flags():
            print(f'{f}',end='  ')
        print('')


class UDP(Structure):
    pass


__all__ = [
    'Ether','IP','TCP'
]
