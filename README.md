
# ScapyTapper
ScapyTapper is a simple network analysis tool which analyses ipv4, ipv6, and arp packets. It can display relevant information such as the source and destination IP, protocol involved, port info, TCP flags, DNS queries, and HTTP methods. Arguments can be passed on the command line to allow users to filter based on protocol, interface, or the number of packets to be captured, etc. 

Requirements

1. Python 3.12.3
2. Dedicated Virtual Env(recommended)
3. pip 25.0.1
4. scapy 2.6.1


## Installation of Python
   
On Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3
```

On MacOS
```bash
brew install python
```

## Creating a dedicated virtual env
```bash
cd path\\to\\your\\project
python -m venv venv
```

a) On Linux/MacOS

```bash
source venv/bin/activate
```

b) On Windows(cmd)

```bash
venv\\Scripts\\activate
```

## Installation of pip(in case it's not present already)

On Ubuntu/Debian
```bash
sudo apt update
sudo apt install python3-pip
```

On Windows
```bash
python get-pip.py
```

## Installation of scapy
```bash
pip install scapy
```

## Getting Started

Ensure root privileges are enabled(On Linux/MacOS/WSL)

```bash
sudo bash
```

Running the program
```bash
git clone git@github.com:yourusername/ScapyTapper.git
cd ScapyTapper
python3 ScapyTapper.py
```

## Usage

```bash
python3 ScapyTapper.py --help
#or
python3 ScapyTapper.py -h
```

## 1. Run with required interface argument:
   
```bash
python3 ScapyTapper.py --interface <your-interface-name>
#or
python3 ScapyTapper.py -i <your-interface-name>

```

Example:

```
python3 ScapyTapper.py --interface ens33

```

## 2. Run with required filter(Berkeley Packet Filter)

```bash
python3 ScapyTapper.py --filter "<bpf_filter>"
#or
python3 ScapyTapper.py -f "<bpf_filter>"

```

Example:

```
python3 ScapyTapper.py --filter "tcp"

```
AND/OR/NOT can be used as long as it is present within " "

List of common BPF Filters:

| Purpose | Filter Expression |
| --- | --- |
| Capture only TCP packets | `tcp` |
| Capture only UDP packets | `udp` |
| Capture only ICMP packets | `icmp` |
| Capture packets on port 80 | `port 80` |
| Capture TCP packets on port 443 | `tcp port 443` |
| Capture traffic to a specific IP | `host 192.168.1.1` |
| Capture traffic from an IP | `src host 10.0.0.5` |
| Capture traffic to an IP | `dst host 10.0.0.10` |
| Capture packets between 2 IPs | `host 192.168.1.1 and 192.168.1.2` |
| Capture packets from a subnet | `net 192.168.1.0/24` |
| Capture packets to/from a MAC addr | `ether host aa:bb:cc:dd:ee:ff` |
| Capture ARP traffic only | `arp` |
| Capture DNS (UDP port 53) | `udp port 53` |
| Capture HTTPS (TCP port 443) | `tcp port 443` |
| Exclude traffic to a port | `not port 22` |
| Combine filters | `tcp and port 80 and not src host 10.0.0.1` |


## 3. Run with required count(Stops capturing after n packets)
```bash
python3 ScapyTapper.py --count <n>
#or
python3 ScapyTapper.py -c <n>

```

Example:

```bash
python3 ScapyTapper.py --count 10

```

## 4. Run with required timeout(Stops capturing after n seconds)

```bash
python3 ScapyTapper.py --timeout <sec>
#or
python3 ScapyTapper.py -t <sec>

```

Example:

```bash
python3 ScapyTapper.py --timeout 10

```

What if both --count and --timeout arguments are passed?  
Both conditions will be respected and sniffing will stop when the first condition is met.

## 5. Save captured packets to a .pcap file
```bash
python3 ScapyTapper.py --save <file_name.pcap>
#or
python3 ScapyTapper.py -s <file_name.pcap>
```
.pcap file is saved in the '../../ScapyTapper/' directory by deafult 

Example:
```bash
python3 ScapyTapper.py --save Test.pcap
```

## Final Example:

```bash
python3 ScapyTapper.py --interface ens33 --filter "tcp or udp" --timeout 10 --count 10 --save Example.pcap
#or
python3 ScapyTapper.py -i ens33 -f "tcp or udp" -t 10 -c 10 -s Example.pcap
```

If no arguments are passed, the packet sniffing will continue endlessly until CTRL + C is pressed to interrupt the program.

## Sample Output

![sample_output](https://github.com/user-attachments/assets/8184f0d4-d81a-4057-aca6-b4cdbb60a477)

## Current Features:
```markdown
## Features

- Captures packets using Scapy
- Supports IPv4, IPv6, TCP, UDP, ICMP, ICMP6, ARP
- Parses and highlights:
  - DNS Queries
  - HTTP traffic
  - TCP Handshake and flags
- Displays protocol and port name resolution
- Protocol filter support (using BPF syntax)
- Captured packets can be saved to a .pcap file
```


  


