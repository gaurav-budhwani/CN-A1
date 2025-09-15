# Computer Networks Assignment 1

This repository contains the implementation and documentation for **Computer Networks Assignment 1**.

## Overview
The assignment consists of two main tasks:
1. **DNS Resolver with Custom Header (Task A)**
2. **Traceroute Protocol Behavior (Task B)**

## Repository Structure
```
.
├── Assignment-1-CN.pdf    # Assignment Document
├── pcaps/                 # Provided pcap files
├── src/
│   ├── client.py          # Client implementation for DNS Resolver
│   ├── utils.py           # parsing the custom header and applying the rule selection logic.
│   └── server.py          # Server implementation
├── report.pdf             # LaTeX report
├── report_morning.csv     # results during morning
├── report_afternoon.csv   # results during afternoon
├── report_night.csv       # results during night
├── requirements.txt      
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
### utils.py

The file `src/utils.py` contains helper functions used by both `client.py` and `server.py`. Below is a summary of the most important helpers, their purpose, and example usage.

#### `parse_custom_header(header_bytes: bytes) -> dict`
- **Purpose:** Validate and parse an 8-byte ASCII header (HHMMSSID).
- **Input:** `header_bytes` — the first 8 bytes from the payload (type `bytes`).
- **Output:** dictionary, e.g.:
```
{
  "header_str": "12040605",   # full 8-char header as string
  "hour": 12,                 # int
  "minute": 4,                # int
  "second": 6,                # int
  "id": 5                     # int
}
```
- **Raises:** `ValueError` for invalid length or non-ASCII data.

#### `find_time_period(hour: int, rules: dict) -> str`
- **Purpose:** Map an hour (0--23) to a time bucket name defined in `rules['timestamp_rules']['time_based_routing']` (e.g. `"morning"`, `"afternoon"`, `"night"`).
- **Input:** `hour` (int), `rules` (dict parsed from `rules.json`).
- **Output:** the period name (string).
- **Behavior:** Handles wrap-around intervals such as night `20:00-03:59` correctly.

#### `select_ip_for_header(header_str: str, rules: dict) -> str`
- **Purpose:** Given an 8-character header string and the rules config, compute the resolved IP.
- **Steps performed internally:**
  1. Extract hour and id from `header_str`.
  2. Determine time bucket using `find_time_period()`.
  3. Read `hash_mod` and `ip_pool_start` from the bucket config.
  4. Compute offset = `id % hash_mod`, final index = `ip_pool_start + offset`.
  5. Return `rules['ip_pool'][final_index]`.
- **Example usage:**
```py
from src.utils import select_ip_for_header
import json

with open('src/rules.json') as f:
    rules = json.load(f)

ip = select_ip_for_header("12040605", rules)
# ip -> "192.168.1.6" (afternoon block, id 05 -> offset 0 -> pool start 5)
```

#### `validate_rules(rules: dict)`
- **Purpose:** Perform basic sanity checks on `rules.json`:
  - `ip_pool` length is at least `sum of buckets' ranges` (here 15).
  - Each time bucket contains `hash_mod` and `ip_pool_start` keys.
  - Time-range strings are in `HH:MM-HH:MM` format.
- **Returns:** `True` if valid else raises descriptive `ValueError`.

### Example: reading header from payload and selecting IP
```py
from src.utils import parse_custom_header, select_ip_for_header
import json

with open('src/rules.json') as f:
    rules = json.load(f)

payload = b"12040605" + b"...dns bytes..."  # first 8 bytes are header
header_info = parse_custom_header(payload[:8])
ip = select_ip_for_header(header_info['header_str'], rules)
print(ip)  # e.g., "192.168.1.6"
```

### Rules Configuration
`src/rules.json` used for selection (example):
```json
{
  "ip_pool": [
    "192.168.1.1","192.168.1.2","192.168.1.3","192.168.1.4","192.168.1.5",
    "192.168.1.6","192.168.1.7","192.168.1.8","192.168.1.9","192.168.1.10",
    "192.168.1.11","192.168.1.12","192.168.1.13","192.168.1.14","192.168.1.15"
  ],
  "timestamp_rules": {
    "time_based_routing": {
      "morning": {
        "time_range": "04:00-11:59",
        "hash_mod": 5,
        "ip_pool_start": 0,
        "description": "Morning traffic routed to first 5 IPs"
      },
      "afternoon": {
        "time_range": "12:00-19:59",
        "hash_mod": 5,
        "ip_pool_start": 5,
        "description": "Afternoon traffic routed to middle 5 IPs"
      },
      "night": {
        "time_range": "20:00-03:59",
        "hash_mod": 5,
        "ip_pool_start": 10,
        "description": "Night traffic routed to last 5 IPs"
      }
    }
  }
}
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

