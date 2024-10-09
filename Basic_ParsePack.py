"""Ethernet Frame: First 6 bytes are Destination MAC address, 
next 6 are Source Mac address, last 2 are Ether type,
then data and CRC checksums

IP Header: Protocol Version (4 bits), Header Length (4 bits,represented 
in 32 bit words. Max length: 60 bytes (Usually 5 32-bit words so 20 bytes)),
Type of Service (8 bits), Total Length (16 bits, max 65,535 bytes), 
Flags (3 bits), Time to Live (8 bits), Protocol (8 bits), 
Header Checksum (16 bits), Source and Destination IP (32 bits each).
"""

#import modules required
import socket
import sys
import struct

#convert byte string MAC address into readable format
def get_mac_addr(bytes_addr):
    return ':'.join(format(x, '02x') for x in bytes_addr)

#Extracts destination/source MAC addresses and protocol from raw Ethernet data
def ethernet_head(raw_data):
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    #6s is 6byte string for mac addresses, H is unsigned short for the protocol type, ! is byte order 
    dest_mac = get_mac_addr(dest) # converts mac addresses into readable forms
    src_mac = get_mac_addr(src)
    proto = socket.htons(prototype) #converts protocol type from network byte order to host byet order using htons
    data = raw_data[14:] #extracts remaining data starting at 14
    return dest_mac, src_mac, proto, data

#parse the IP headers (ipv4) from raw data
def ipv4_head(raw_data):
    version_header_length = raw_data[0]
    version = version_header_length >> 4 # get version (first 4 bits)
    header_length = (version_header_length & 15) * 4 # get header length (last 4 bits)
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20]) #unpack headers using struct
    data = raw_data[header_length:]    #extracts remaining data after header
    return version, header_length, ttl, proto, socket.inet_ntoa(src), socket.inet_ntoa(target), data # converts IPs to string

# Parse TCP Headers from raw data
def tcp_head(raw_data):
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4 # Get the data offset
    flag_urg = (offset_reserved_flags & 32) >> 5 # URG flag
    flag_ack = (offset_reserved_flags & 16) >> 4 # ACK flag
    flag_psh = (offset_reserved_flags & 8) >> 3 # PSH flag
    flag_rst = (offset_reserved_flags & 4) >> 2 # RST flag
    flag_syn = (offset_reserved_flags & 2) >> 1 # SYN flag
    flag_fin = offset_reserved_flags & 1 # FIN flag
    data = raw_data[offset:] # Extract TCP payload
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

#placeholder for ICMP parse func
def icmp_head(raw_data):
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    return icmp_type, code, checksum, raw_data[4:]

#placeholder for UDP parse func
def upd_head(raw_data):
    src_port, dest_port, length = struct.unpack('! H H H', raw_data[:8])
    return src_port, dest_port, length 

def main(): #parse the ethernet function to get the details
    # create a raw socket to capture packets
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
        
        # If the protocol is IP (0x0800), parse the IPv4 header
        if eth[2] == 8: # Check for IP protocol (0x0800)
            ipv4_info = ipv4_head(eth[3]) #pass data part to ipv4_head 
            print('IP Version: {}, Header Length: {}, TTL: {}, Protocol: {}, Source: {}, Target: {}'.format(
                ipv4_info[0], ipv4_info[1], ipv4_info[2], ipv4_info[3], ipv4_info[4], ipv4_info[5]))

            # check if the protocol is TCP (protocol #6)
            if ipv4_info[3] == 6:
                tcp = tcp_head(ipv4_info[6]) #pass tcp segment to tcp_head
                print('TCP Segment:')
                print('Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
                print('Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH:{}'.format(tcp[4], tcp[5], tcp[6]))
                print('RST: {}, SYN: {}, FIN:{}'.format(tcp[7], tcp[8], tcp[9])) 

                if len(tcp[10]) > 0:
                    # HTTP
                
                    if tcp[0] == 80 or tcp[1] == 80: # Check for HTTP traffic
                        print('HTTP Data:')
                        try:
                            # Assume HTTP is a func or class defined somewhere else
                            http = HTTP(tcp[10])
                            http_info = str(http[10]).split('\n')
                            for line in http_info:
                                print('    ' + str(line))
                        except Exception as e:
                            print('Error processing HTTP data:', str(e))
                            print('TCP Data:')
                            print(tcp[10]) # Print raw TCP data
                    else:
                        print('TCP Data:')
                        print(tcp[10]) # Print raw TCP data

                #check for ICMP (protocol #1)
                elif ipv4_info[3] == 1:
                    icmp = icmp_head(ipv4_info[6]) #icmp parsing
                    print('\t -' + 'ICMP Packet:')
                    print('\t\t -' + 'Type: {}, Code: {}, Checksum: {},'.format(icmp[0], icmp[1], icmp[2]))
                    print('\t\t -' + 'ICMP Data:')
                    print('\t\t\t', icmp[3])

                #check for UDP (protocol #17)
                elif ipv4_info[3] == 17:
                    upd = upd_head(ipv4_info[6]) #UDP Parsing
                    print('UDP Segment:')
                    print('Source Port: {}, Destination Port: {}, Length: {}'.format(upd[0], upd[1], upd[2]))


if __name__ == '__main__':
    main()
#sudo python3 Basic_ParsePack.py
