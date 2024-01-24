#!/usr/bin/env python3
import struct
from struct import *
import sys
import socket
import textwrap 
from prettytable import PrettyTable
from colorama import Fore
from colorama import Style
import time 
TAB_1 = "\t - "
TAB_2 = "\t\t - "
TAB_3 = "\t\t\t - "
TAB_4 = "\t\t\t\t - "

DATA_TAB_1 = "\t "
DATA_TAB_2 = "\t\t "
DATA_TAB_3 = "\t\t\t "
DATA_TAB_4 = "\t\t\t\t "


#Returns MAC address in form ( AA:BB:CC:DD:EE:FF)
def get_mac_addr(mac_bytes):
    # Convert mac_bytes in the MAC address to its hexadecimal representation
    bytes_addr = map('{:02x}'.format, mac_bytes) 
    # Format the MAC address with colons
    mac_addr = ':'.join(bytes_addr).upper() 
    return mac_addr

#parse the Ethernet header
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    eth_proto = socket.htons(prototype)
    payload = raw_data[14:] #return the actual payload
    return dest_mac, src_mac, eth_proto, payload
#parse the ipv4 header
def ipv4_head(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    ipv4_data = data[header_length:]
    src = get_ip(src)
    target = get_ip(target)
    return version, header_length, ttl, proto, src, target, ipv4_data
#format the IP adresses to a readable format
def get_ip(addr):
    return '.'.join(map(str, addr))

#unpack the TCP packets
def tcp_head(data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    tcp_data = data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, tcp_data
#unpack ICMP head
def icmp_head( data):

    # Unpack the ICMP header using the struct module
    icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', data[:4])
    icmp_data= data[4:]
    return icmp_type, icmp_code, icmp_checksum, icmp_data

#unpack  UDP head 
def udp_head( data):
   
    # Unpack the UDP header using the struct module
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    # Extract UDP data
    udp_data = data[8:]
    return src_port, dest_port, length, udp_data


def format_multi_line(prefix, data, size=16):
    if isinstance(data, bytes):
        lines = []

        for i in range(0, len(data), size):
            chunk = data[i:i + size]
            hex_part = ' '.join(f'{byte:02X}' for byte in chunk)
            text_part = ''.join(chr(byte) if 32 <= byte <= 126 else '.' for byte in chunk)
            
            hex_padding = (size - len(chunk)) * 3  # Adjust padding for hex_part
            lines.append(f"{prefix} {hex_part.ljust(size * 3 + hex_padding)}  {text_part}")

        return '\n'.join(lines)
    

def salpackets():
    print("[*] Start Sniffing .... ")
    #sniffing
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    i = 1
    while True:
        raw_data, addr = s.recvfrom(65535)
        #unpacking the internet layer
        dest_mac, src_mac, eth_proto, payload = ethernet_head(raw_data)
        local_time = time.strftime('%H:%M:%S', time.localtime())
        print('\n \n    Ethernet Frame Number : {} at {}'.format(str(i),local_time))
        t=PrettyTable([f'{Fore.GREEN}Destination', 'Source', f'Protocol{Style.RESET_ALL}'])
        t.add_row([dest_mac, src_mac, eth_proto])
        # Print the table
        print(t)
        i+=1
        #8 for IPV4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, ipv4_data) = ipv4_head(payload) 
            print( '\t - ' + 'IPv4 Packet:')
            print('\t\t - ' + 'Version: {}, Header Length: {}, TTL:{},'.format(version, header_length, ttl))
            print('\t\t - ' + 'Protocol: {}, Source: {}, Target:{}'.format(proto, src, target))    
        #unpacking the transport layer
        #unpacking the TCP header
            if proto == 6:
                src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack,flag_psh, flag_rst, flag_syn, flag_fin, tcp_data = tcp_head(ipv4_data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH:{}'.format(flag_urg, flag_ack, flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))
                if len(tcp_data) > 0:
                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp_data)
                            http_info = str(http[10]).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp_data))
                        else:
                            print(TAB_2 + 'TCP Data:')
                            print(format_multi_line(DATA_TAB_3, tcp_data))
        #unpacking the ICMP header
            elif proto == 1:
                icmp_type, icmp_code, icmp_checksum, icmp_data = icmp_head( ipv4_data)
                print('\t -' + 'ICMP Packet:')
                print('\t\t -' + 'Type: {}, Code: {}, Checksum:{},'.format(icmp_type, icmp_code,icmp_checksum))
                print('\t\t -' + 'ICMP Data:')
                print(format_multi_line('\t\t\t', icmp_data))              
        #unpacking the UDP header    
            elif proto == 17:
                src_port, dest_port, length, udp_data= udp_head(ipv4_data)
                print('\t -' + ' UDP Segment:')
                print('\t\t -' + 'Source Port: {}, Destination Port: {}, Length:{}'.format(src_port,dest_port, length))                  
            # Other
            else :    
                print(TAB_1 + 'Data :')
                print(format_multi_line( DATA_TAB_2 , ipv4_data))
        else :
            print( 'Data:' )
            print( format_multi_line(DATA_TAB_1 , payload))    
