import socket
import struct
import textwrap
import argparse
import sys
import logging
from datetime import datetime
from termcolor import colored

# Tab spacing for formatting output
TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATA1 = '\t '
DATA2 = '\t\t '
DATA3 = '\t\t\t '
DATA4 = '\t\t\t\t '

# Setup logging
logging.basicConfig(filename='packet_sniffer.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Protocol mapping
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Summary statistics
packet_summary = {
    'total': 0,
    'TCP': 0,
    'UDP': 0,
    'ICMP': 0,
    'Others': 0
}

def main(interface, protocol_filter, num_packets, verbose, duration):
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
    start_time = datetime.now()

    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            packet_count += 1
            packet_summary['total'] += 1
            destination_mac, source_mac, eth_protocol, data = EF(raw_data)
            print(colored('\nEthernet Frame:', 'blue'))
            print(TAB1 + 'Destination: {}, Source: {}, Protocol: {}'.format(destination_mac, source_mac, eth_protocol))

            if eth_protocol == 8:  # IPv4
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                proto_name = PROTOCOLS.get(proto, "Others")
                packet_summary[proto_name] += 1
                print(colored(TAB1 + 'IPv4 Packet:', 'blue'))
                print(TAB2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto_name, src, target))

                if protocol_filter and proto != protocol_filter:
                    continue

                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(colored(TAB1 + 'ICMP Packet:', 'magenta'))
                    print(TAB2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB2 + 'Data:')
                    print(format_multi_line(DATA3, data))

                elif proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_packet(data)
                    print(colored(TAB1 + 'TCP Segment:', 'green'))
                    print(TAB2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB2 + 'Flags:')
                    print(TAB3 + 'URG: {}, ACK: {}, PSH: {}'.format(flags['urg'], flags['ack'], flags['psh']))
                    print(TAB3 + 'RST: {}, SYN: {}, FIN: {}, ECE: {}, CWR: {}, NS: {}'.format(flags['rst'], flags['syn'], flags['fin'], flags['ece'], flags['cwr'], flags['ns']))

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
                    print(colored(TAB1 + 'UDP Segment:', 'yellow'))
                    print(TAB2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

                    # Example of parsing DNS if the destination port is 53 (DNS)
                    if src_port == 53 or dest_port == 53:
                        print(TAB2 + 'DNS Data:')
                        print(format_multi_line(DATA3, data))
                    else:
                        print(TAB2 + 'UDP Data:')
                        print(format_multi_line(DATA3, data))

                else:  # Other IPv4
                    print(colored(TAB1 + 'Other IPv4 Data:', 'red'))
                    print(format_multi_line(DATA2, data))

            else:
                print(colored('Data:', 'red'))
                print(format_multi_line(DATA1, data))

            # Log packet details
            logging.info('Packet #{}, Src: {}, Dst: {}, Protocol: {}'.format(packet_count, src, target, proto_name))

            # Check if the specified duration has passed
            if duration and (datetime.now() - start_time).seconds >= duration:
                print("\nCapture duration reached. Stopping the sniffer...")
                break

            if num_packets and packet_count >= num_packets:
                print("\nPacket limit reached. Stopping the sniffer...")
                break
    except KeyboardInterrupt:
        print("\nSniffer interrupted. Exiting...")
    except Exception as e:
        print(f"Error: {e}. Exiting...")

    print_summary()

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
        'ns': (offset_reserved_flags & 256) >> 8,  # New ECN-nonce concealment protection flag
        'cwr': (offset_reserved_flags & 128) >> 7,  # Congestion Window Reduced
        'ece': (offset_reserved_flags & 64) >> 6,  # ECN-Echo flag
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

def print_summary():
    print("\n" + "=" * 40)
    print(colored("Summary Statistics", 'cyan'))
    print("=" * 40)
    print("Total Packets Captured: ", packet_summary['total'])
    for protocol, count in packet_summary.items():
        if protocol != 'total':
            print(f"{protocol}: {count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets on")
    parser.add_argument("-p", "--protocol", type=int, help="Protocol filter (e.g., 1 for ICMP, 6 for TCP, 17 for UDP)")
    parser.add_argument("-n", "--num_packets", type=int, help="Number of packets to capture")
    parser.add_argument("-d", "--duration", type=int, help="Duration of capture in seconds")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity level")
    args = parser.parse_args()

    main(args.interface, args.protocol, args.num_packets, args.verbose, args.duration)
