import socket
import struct
from ctypes import *
import time

#IPv4=================================================
class IP(Structure):
    _fields_ = [
        ("version", c_ubyte, 4),
        ("ihl", c_ubyte, 4 ),
        ("tos", c_ubyte),
        ("tl", c_ushort),
        ("id", c_ushort),
        ("offset", c_ushort),
        ("ttl", c_ubyte),
        ("p_num", c_ubyte),
        ("chsum", c_ushort),
        ("src", c_uint32),
        ("des", c_uint32)

    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}

        self.src_addr = socket.inet_ntoa(struct.pack("@I", self.src))
        self.dst_addr = socket.inet_ntoa(struct.pack("@I", self.des))
        try:
            self.protocol = self.protocol_map[self.p_num]
        except:
            self.protocol = str(self.p_num)
        

#TCP====================================================
class TCP(Structure):
    _fields_=[
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("seq_num", c_uint32),
        ("ack", c_uint32),
        ("len", c_ubyte, 4),
        ("rev", c_ubyte, 6),
        ("flg", c_ubyte, 6),
        ("win_size", c_ushort),
        ("tcp_chsum", c_ushort),
        ("up", c_ushort)

    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src_port = socket.htons(self.src_port)
        self.dst_port = socket.htons(self.dst_port)
        pass

#UDP========================================================
class UDP(Structure):
    _fields_=[
        ("src_port", c_ushort),
        ("dst_port", c_ushort),
        ("len", c_ushort),
        ('udp_chsum', c_ushort)
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src_port = socket.htons(self.src_port)
        self.dst_port = socket.htons(self.dst_port)
        self.len = socket.htons(self.len)
        pass

#ICMP===========================================================
class ICMP(Structure):
    _fields_=[
        ("type", c_ubyte),
        ("code", c_ubyte),
        ("chsum", c_ushort),
        ("id", c_ushort)
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        pass

#ipv6=============================================================
class IPv6(Structure):
    _fields_=[
        ("version", c_uint32, 4),
        ("tc", c_uint32, 8),
        ("fl", c_uint32, 20),
        ("pl", c_uint16),
        ("n_head", c_uint8),
        ("h_limit", c_uint8),
        ("src_addr", c_ubyte * 16),
        ("dst_addr", c_ubyte * 16)
    ]

    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.src = socket.inet_ntop(socket.AF_INET6, self.src_addr)
        self.dst = socket.inet_ntop(socket.AF_INET6, self.dst_addr)

        self.protocol_map = {58:"ICMPv6", 6:"TCP", 17:"UDP"}

        try:
            self.protocol = self.protocol_map[self.n_head]
        except:
            self.protocol = str(self.n_head)
        


#Ethernet==========================================================
class ETH(Structure):
    _fields_=[
        ("dst_mac", c_ubyte * 6),
        ("src_mac", c_ubyte * 6),
        ("proto", c_ushort)
  
    ]
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        self.protocol_map = {8:"IPv4", 56710:"IPv6"}
    
        try:
            self.protocol = self.protocol_map[self.proto]
        except:
            self.protocol = str(self.proto)




sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('ens33', 0))

while True:
    try:
        cr_time = time.localtime()
        curent_time = time.strftime("%H:%M.%S", cr_time)
        data, addr = sock.recvfrom(65536)
        eth = ETH(data[:14])
        
        #ipv4==============================================================================================================
        if eth.protocol == "IPv4":
            ip = IP(data[14:])
            if ip.protocol == "TCP":
                tcp = TCP(data[34:])
                print(curent_time, end=" ")
                print(f" {ip.src_addr} >> {ip.dst_addr}   TCP  {tcp.src_port} >> {tcp.dst_port}  ")

            elif ip.protocol == "UDP":
                udp = UDP(data[34:])
                print(curent_time, end=" ")
                print(f" {ip.src_addr} >> {ip.dst_addr}   UDP  {udp.src_port} >> {udp.dst_port}  len: {udp.len} ")

            elif ip.protocol == "ICMP":
                icmp = ICMP(data[34:])
                print(curent_time, end=" ")
                print(f" {ip.src_addr} >> {ip.dst_addr}   ICMP   type: {icmp.type}")

            
        #ipv6===============================================================================================================  
        elif eth.protocol == "IPv6":
            ipv6 = IPv6(data[14:]) 
            if ipv6.protocol == "TCP":
                tcp = TCP(data[54:])
                print(curent_time, end=" ")
                print(f" {ipv6.src}  >>  {ipv6.dst}  TCP  {tcp.src_port} >> {tcp.dst_port} ")
            elif ipv6.protocol == "UDP":
                udp = UDP(data[54:])
                print(curent_time, end=" ")
                print(f" {ipv6.src}  >>  {ipv6.dst}  UDP  {udp.src_port} >> {udp.dst_port}  len: {udp.len}")
            
      

    except ValueError:
        pass
    except KeyboardInterrupt:
        sock.close()
        print("   exiting....")
        break
