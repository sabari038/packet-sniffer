# Packet Sniffer

This is a Python script for a simple packet sniffer that captures and displays Ethernet, IPv4, TCP, UDP, and ICMP packets.

## Features

- Captures Ethernet frames and parses them to extract Ethernet, IPv4, TCP, UDP, and ICMP packet information.
- Supports filtering by protocol (ICMP, TCP, UDP) and capturing a specified number of packets.
- Provides verbose output option for detailed packet inspection.

## Prerequisites

- Python 3.8
- Libraries: socket, struct, textwrap, argparse

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sabari038/packet-sniffer.git
   mkdir packet-sniffer
   cd packet-sniffer
2. Install dependencies using pip:
   ```bash
   pip install -r requirements.txt

## Usage
Run the packet sniffer script with the following command-line options:
   ```bash
   python packet_sniffer.py -i <interface> [-p {1, 6, 17}] [-n <num_packets>] [-v]
   ```
1.   -i, --interface: Specify the network interface to sniff on.
2.   -p, --protocol: Filter packets by protocol (1 for ICMP, 6 for TCP, 17 for UDP).
3.   -n, --num-packets: Capture a specific number of packets and then stop.
4.   -v, --verbose: Enable verbose output for detailed packet inspection.

## Example
   ```bash
      python packet_sniffer.py -i wlan0 -p 6 -n 10 -v

```

## License
This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.
