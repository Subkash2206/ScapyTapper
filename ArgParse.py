import argparse
from core import PacketSniffer

BPF_FILTERS = [
    "arp",
    "ip",
    "ip6",
    "tcp",
    "udp",
    "icmp",
    "icmp6",
    "port 53",
    "tcp port 80",
    "udp port 53",
    "tcp port 443",
    "tcp port 22",
    "tcp port 25",
    "tcp port 110",
    "tcp port 995",
    "tcp port 143",
    "tcp port 993",
    "tcp port 3306",
    "host 192.168.1.1",
    "net 192.168.1.0/24",
    "broadcast",
    "multicast"
]

def parse_args():
    parser = argparse.ArgumentParser(description="ScapyTapper - A Packet Sniffer based on scapy")

    parser.add_argument("-i", "--interface",
                        help="Interface to sniff(eth0, ens33, enps03, wlan0, etc",
                        default=None)

    parser.add_argument("-f", "--filter",
                        type  = str,
                        default = None,
                        help = "Use standard BPF filters to filter for specific type of traffic. "
                               "Note -> Commonly used BPF Filters are given, for more, refer the README.md. "
                               "Choices: " + ",   ".join(BPF_FILTERS)
                        )

    parser.add_argument("-c", "--count",
                        type = int,
                        help = "Number of packets to sniff",
                        default = 20)

    return parser.parse_args()






