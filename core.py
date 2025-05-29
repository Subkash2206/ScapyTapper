from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_RS
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS, DNSQR
from scapy.packet import Raw

class PacketSniffer():
    def __init__(self, whichFilter = None, interface = None, count = None, timeout = None):
        self.interface = interface or conf.iface
        self.count = count
        self.timeout = timeout
        self.whichFilter = whichFilter
        self.packets = None
        self.proto_dict = {
            6: 'TCP', 17: 'UDP', 58: 'ICMPv6', 1: 'ICMP', 'ARP': 'ARP'
        }

        self.port_dict = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            69: "TFTP", 80: "HTTP", 110: "POP3", 123: "NTP",
            143: "IMAP", 161: "SNMP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT", None: " "
        }

    def sniff_packets(self):
        print(f"Sniffing on interface: {self.interface}")
        if not self.count and not self.timeout:
            print("Press Ctrl+C to stop sniffing...")

        self.packets = sniff(
            iface=self.interface,
            count=self.count if self.count is not None else 0,
            timeout = self.timeout,
            prn=lambda packet: packet.summary(),
            filter=self.whichFilter
        )
        print(f"packets = {self.packets}")
        print(f"Interface = {self.interface}")

    def print_packets(self):

        print(f"\n{'Time':19} {'Source':40} {'->':2} {'Destination':40} {'Protocol':10} {'Port Info':45} {'Extra Info'}")

        for pkt in self.packets:

            timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S')
            src = dst = proto_name = srcPort = dstPort = "-"
            details = ""

            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                proto_name = self.proto_dict.get(proto, str(proto))

            elif IPv6 in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
                proto = pkt[IPv6].nh
                proto_name = self.proto_dict.get(proto, str(proto))

            elif ARP in pkt:
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
                proto_name = self.proto_dict['ARP']
                srcPort = pkt[ARP].hwsrc
                dstPort = pkt[ARP].hwdst
                details = "ARP Packet"
                print(f"{timestamp:19} {src:40} -> {dst:40} {proto_name:10} {srcPort:17} -> {dstPort:25} {details}")
                continue

            elif Ether in pkt:
                src = pkt[Ether].src
                dst = pkt[Ether].dst
                proto_name = "Ethernet"
                srcPort = dstPort = "-"
                details = "No IP/ARP Layer"
                print(f"{timestamp:19} {src:40} -> {dst:40} {proto_name:10} {srcPort:17} -> {dstPort:25} {details}")
                continue

            if TCP in pkt:
                sPort = pkt[TCP].sport
                dPort = pkt[TCP].dport
                srcPort = self.port_dict.get(sPort, str(sPort))
                dstPort = self.port_dict.get(dPort, str(dPort))

                flagsdata = pkt[TCP].flags
                details += f"TCP Flags: {flagsdata} "

                seq_num = pkt[TCP].seq
                ack_num = pkt[TCP].ack
                details += f"(Seq={seq_num}, Ack={ack_num}) "

                if flagsdata == 'S':
                    details += "(SYN -> connection start) "
                elif flagsdata == 'SA':
                    details += "(SYN-ACK -> handshake response) "
                elif flagsdata == 'FA':
                    details += "(FIN-ACK -> connection close) "
                elif flagsdata == 'F':
                    details += "(FIN -> connection termination request) "
                elif flagsdata == 'A':
                    details += "(ACK -> acknowledgment) "
                elif flagsdata == 'R':
                    details += "(RST -> reset connection) "
                elif flagsdata == 'PA':
                    details += "(PSH-ACK -> data packet with push) "
                elif flagsdata == 'P':
                    details += "(PSH -> push function) "
                elif flagsdata == 'RA':
                    details += "(RST-ACK -> reset with acknowledgment) "
                elif flagsdata == 'SAF':
                    details += "(SYN-ACK-FIN combination) "
                else:
                    details += f"(Flags: {flagsdata}) "

                if pkt.haslayer(Raw):
                    raw = pkt[Raw].load
                    if b"HTTP" in raw or b"GET" in raw or b"POST" in raw:
                        try:
                            http = raw.decode(errors="ignore")
                            details += f"HTTP: {http[:50]}  "
                        except:
                            pass

                if dstPort == "HTTPS":
                    details += "Encrypted (TLS) "

            elif UDP in pkt:
                sPort = pkt[UDP].sport
                dPort = pkt[UDP].dport
                srcPort = self.port_dict.get(sPort, str(sPort))
                dstPort = self.port_dict.get(dPort, str(dPort))
                if DNS in pkt and pkt[DNS].qd:
                    try:
                        query = pkt[DNSQR].qname.decode(errors="ignore")
                        details += f"DNS Query: {query}  "
                    except:
                        pass

            elif (ICMP in pkt or ICMPv6EchoRequest in pkt or ICMPv6EchoReply in pkt or
                  ICMPv6ND_RS in pkt or ICMPv6ND_RA in pkt or ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt):
                proto_name = "ICMPv6" if IPv6 in pkt and pkt[IPv6].nh == 58 else "ICMP"
                srcPort = dstPort = "-"
                details = "ICMP Packet"

            print(f"{timestamp:19} {src:40} -> {dst:40} {proto_name:10} {srcPort:17} -> {dstPort:25} {details.strip()}")
            print()



