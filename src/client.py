#!/usr/bin/env python3
"""
PCAP parser and custom header sender
- Reads pcap file (scapy's rdpcap).
- Filters DNS query packets (DNS layer and qr == 0).
- For each DNS query packet:
   a. Build header HHMMSSID (HHMMSS from current local time by default).
   b. Prepend header (8 ASCII bytes) to the raw DNS layer bytes.
   c. Open a TCP connection to server, send payload (header + DNS bytes) and then shut down the write side (sock.shutdown).
   d. Read server reply until EOF and parse resolved IP.
- Log each mapping to CSV (report_timeframe.csv) and print a summary table.
"""
import argparse
import socket
import csv
from datetime import datetime
from scapy.all import rdpcap, DNS


def build_header(seq_num: int, use_packet_time=None) -> bytes:
    """
    create HHMMSSID header (8 ASCII bytes).
    - If use_packet_time is a datetime, use that time; otherwise, use now().
    - seq_num: integer sequence number, will be formatted 2-digit zero padded.
    """
    if use_packet_time is None:
        t = datetime.now()
    else:
        t = use_packet_time
    s = t.strftime("%H%M%S") + f"{seq_num:02d}"
    return s.encode('ascii')


def send_payload_and_get_response(server_host: str, server_port: int, payload: bytes, timeout: float = 5.0) -> str:
    """
    connect to server and send payload WITHOUT a length-prefix:
      - open TCP connection
      - sock.sendall(payload)
      - sock.shutdown(socket.SHUT_WR) to indicate EOF to server
      - read until recv() returns b'' (server closed) or timeout
    returns the ASCII response (decoded). If non-ASCII, returns hex.
    """
    with socket.create_connection((server_host, server_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        # send the payload (no 4-byte prefix)
        sock.sendall(payload)
        # signal EOF to server (important so server knows we're done sending)
        try:
            sock.shutdown(socket.SHUT_WR)
        except Exception:
            # some platforms may raise; ignore and proceed to read
            pass

        # read until EOF (server closes) or timeout
        data_parts = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data_parts.append(chunk)
        except socket.timeout:
            # treat whatever we've got as the full response
            pass

        data = b"".join(data_parts)
        try:
            return data.decode('ascii')
        except Exception:
            return data.hex()


def extract_dns_layer_bytes(pkt):
    """
    given a scapy packet, return the raw bytes of the DNS layer.
    assumes packet has DNS layer.
    """
    dns_layer = pkt.getlayer(DNS)
    return bytes(dns_layer)


def main(pcap_path, server_host, server_port, out_csv='report.csv', use_packet_time=True, timeout=5.0):
    packets = rdpcap(pcap_path)
    dns_queries = []
    # Collect DNS query packets
    for pkt in packets:
        if pkt.haslayer(DNS):
            dns = pkt.getlayer(DNS)
            # dns.qr == 0 => query (scapy uses 0 for queries, 1 for responses)
            if getattr(dns, 'qr', 0) == 0:
                dns_queries.append(pkt)
    print(f"[INFO] Found {len(dns_queries)} DNS query packets in {pcap_path}")

    results = []
    seq = 0
    for pkt in dns_queries:
        # determine header time: packet timestamp or now
        if use_packet_time:
            pkt_ts = getattr(pkt, "time", None)
            if pkt_ts is None:
                pkt_dt = datetime.now()
            else:
                try:
                    pkt_dt = datetime.fromtimestamp(float(pkt_ts))
                except Exception:
                    pkt_dt = datetime.now()
        else:
            pkt_dt = None

        # construct header
        header = build_header(seq, use_packet_time=pkt_dt)
        dns_bytes = extract_dns_layer_bytes(pkt)
        payload = header + dns_bytes  # custom header + original DNS bytes

        try:
            resolved_ip = send_payload_and_get_response(server_host, server_port, payload, timeout=timeout)
        except Exception as e:
            resolved_ip = f"ERROR: {e}"

        # extract domain name for logging (first DNS question)
        dns = pkt.getlayer(DNS)
        qname = dns.qd.qname.decode('ascii') if dns.qd is not None else "<unknown>"
        results.append((header.decode('ascii'), qname.rstrip('.'), resolved_ip))
        seq += 1

    # CSV report
    with open(out_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['custom_header(HHMMSSID)', 'domain', 'resolved_ip'])
        for row in results:
            writer.writerow(row)
    print(f"[INFO] Wrote report to {out_csv}")

    # pretty-print
    for h, d, ip in results:
        print(f"{h}  {d}  -> {ip}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP-based DNS client (no length-prefix)')
    parser.add_argument('--pcap', required=True, help='path to pcap (e.g., pcaps/9.pcap)')
    parser.add_argument('--server', default='127.0.0.1:53535',
                        help='server host:port (default 127.0.0.1:53535)')
    parser.add_argument('--out', default='report.csv')
    parser.add_argument('--no-packet-time', action='store_true', help='Use current system time instead of packet timestamps')
    parser.add_argument('--timeout', type=float, default=5.0, help='Socket timeout in seconds')
    parser.add_argument('--verbose', action='store_true', help='Enable debug prints')
    args = parser.parse_args()
    host, port = args.server.split(':')
    main(args.pcap, host, int(port), args.out, use_packet_time=False, timeout=args.timeout)
