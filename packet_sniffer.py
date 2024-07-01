import socket
import struct
import textwrap
import argparse
import sys

TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATA1 = '\t '
DATA2 = '\t\t '
DATA3 = '\t\t\t '
DATA4 = '\t\t\t\t '

def main(interface, protocol_filter, num_packets, verbose):
    print("=" * 60)
    print("\033[1;36m" + r"""
                       _        _               _  __  __           
  _ __   __ _  ___| | _____| |_   ___ _ __ (_)/ _|/ _| ___ _ __ 
 | '_ \ / _` |/ __| |/ / _ \ __| / __| '_ \| | |_| |_ / _ \ '__|
 | |_) | (_| | (__|   <  __/ |_  \__ \ | | | |  _|  _|  __/ |   
 | .__/ \__,_|\___|_|\_\___|\__| |___/_| |_|_|_| |_|  \___|_|   
 |_|                                                            """ + "\033[0m".center(60))
    print("\033[1;33m" + "** Created by Sabari **".center(60) + "\033[0m")
    print("\033[1;33m" + "** Version: 0.1 **".center(60) + "\033[0m	")
    print("=" * 60)

    # Open a socket to listen for packets on the specified interface
    if interface:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        conn.bind((interface, 0))
    else:
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    packet_count = 0

    while True:
        raw_data, addr = conn.recvfrom(65536)
        packet_count += 1
        destination_mac, source_mac, eth_protocol, data = EF(raw_data)
        print('\nEthernet Frame:')
        print(TAB1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, eth_protocol))

        if eth_protocol == 8:  # IPv4
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print(TAB1 + 'IPv4 Packet:')
            print(TAB2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if protocol_filter and proto != protocol_filter:
                continue

            if proto == 1:  # ICMP
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB1 + 'ICMP Packet:')
                print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(TAB2 + 'Data:')
                print(format_multi_line(DATA3, data))

            elif proto == 6:  # TCP
                src_port, dest_port, sequence, acknowledgment, flags, data = tcp_packet(data)
                print(TAB1 + 'TCP Segment:')
                print(TAB2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print(TAB2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print(TAB2 + 'Flags:')
                print(TAB3 + 'URG: {}, ACK: {}, PSH: {}'.format(flags['urg'], flags['ack'], flags['psh']))
                print(TAB3 + 'RST: {}, SYN: {}, FIN: {}'.format(flags['rst'], flags['syn'], flags['fin']))

                if len(data) > 0:
                    # HTTP
                    if src_port == 80 or dest_port == 80:
                        print(TAB2 + 'HTTP Data:')
                        try:
                            http_info = data.decode('utf-8').split('\n')
                            for line in http_info:
                                print(DATA3 + str(line))
                        except UnicodeDecodeError:
                            print(format_multi_line(DATA3, data))
                    else:
                        print(TAB2 + 'TCP Data:')
                        print(format_multi_line(DATA3, data))

            elif proto == 17:  # UDP
                src_port, dest_port, length, data = udp_packet(data)
                print(TAB1 + 'UDP Segment:')
                print(TAB2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:  # Other IPv4
                print(TAB1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA2, data))

        else:
            print('Data:')
            print(format_multi_line(DATA1, data))

        if num_packets and packet_count >= num_packets:
            break

def EF(data):
    destination_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_add(destination_mac), get_mac_add(source_mac), socket.htons(protocol), data[14:]

def get_mac_add(bytes_add):
    bytes_str = map('{:02x}'.format, bytes_add)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'urg': (offset_reserved_flags & 32) >> 5,
        'ack': (offset_reserved_flags & 16) >> 4,
        'psh': (offset_reserved_flags & 8) >> 3,
        'rst': (offset_reserved_flags & 4) >> 2,
        'syn': (offset_reserved_flags & 2) >> 1,
        'fin': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

def udp_packet(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def format_multi_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A simple packet sniffer")
    parser.add_argument('-i', '--interface', type=str, help="Network interface to sniff on")
    parser.add_argument('-p', '--protocol', type=int, choices=[1, 6, 17], help="Protocol filter: 1 (ICMP), 6 (TCP), 17 (UDP)")
    parser.add_argument('-n', '--num-packets', type=int, help="Number of packets to capture")
    parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")

    args = parser.parse_args()

    main(args.interface, args.protocol, args.num_packets, args.verbose)

