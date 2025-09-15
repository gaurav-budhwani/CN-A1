# Computer Networks Assignment 1

This repository contains the implementation and documentation for **Computer Networks Assignment 1**.

## Overview
The assignment consists of two main tasks:
1. **DNS Resolver with Custom Header (Task A)**
2. **Traceroute Protocol Behavior (Task B)**

## Repository Structure
```
.
├── pcaps/                 # Provided pcap files
├── src/
│   ├── client.py          # Client implementation for DNS Resolver
│   └── server.py          # Server implementation
├── report.pdf             # LaTeX report
├── report_morning.csv     # results during morning
├── report_afternoon.csv   # results during afternoon
├── report_night.csv       # results during night
└── README.md # This file
```

## Task A: DNS Resolver

### Objective
To parse DNS query packets from a provided PCAP file, prepend a custom 8-byte header (`HHMMSSID`), and send the packet payload to a server using TCP.

### PCAP Selection
The PCAP file was chosen based on the sum of the last three digits of each team member's roll number:
- Gaurav Budhwani: Roll No. `085` → Sum = 0+8+5 = **13**
- Kaveri Visavadiya: Roll No. `114` → Sum = 1+1+4 = **6**
- Total = **19** → `9.pcap` was selected as per assignment rules.

### Custom Header
The 8-byte header follows the format:
```
HHMMSSID
```
- `HHMMSS`: Current time in hours, minutes, and seconds.
- `ID`: 2-digit zero-padded sequence number of the packet.

### Transport Protocol
We used **TCP** because:
- Reliable delivery.
- Server expects a persistent connection to receive DNS queries with the custom header.

### Implementation Highlights
- PCAP parsed using `scapy` to filter DNS query packets.
- Each DNS query payload is prefixed with the custom header and sent via TCP.
- Results stored in a CSV file (`report_timeframe.csv`) containing:
  - `custom_header`
  - `domain`
  - `resolved_ip`

### Running the Server
``` bash
python3 src/server.py --host 127.0.0.1 --port 53535 --rules src/rules.json
```

### Running the Client
```bash
python3 src/client.py --pcap pcaps/9.pcap --server 127.0.0.1:53535 --out report.csv
```

### Results
Experiments were conducted during three time frames (Morning, Afternoon, Night).  
The server resolved queries to IPs based on time-based routing rules.

---

## Task B: Traceroute Protocol Behavior

### Objective
To analyze how traceroute works on different operating systems (Windows, Linux/Mac).

### Steps
1. Ran traceroute commands to websites like `www.google.com`.
2. Captured packets using `tcpdump`.
3. Analyzed differences in protocols:
   - **Windows** uses ICMP Echo Requests by default.
   - **Linux/Mac** uses UDP probes by default.

### Observations
- Some hops may display `* * *` due to firewall filtering or ICMP rate limiting.
- Linux traceroute increments the UDP destination port for each probe.
- Final hop sends a different type of response (ICMP Echo Reply vs ICMP Port Unreachable).

---

## Dependencies
- Python 3.x
- scapy
- tcpdump (for traceroute capture)

Install dependencies:
```bash
pip install scapy
```
## For more details, please see Report.pdf
---

