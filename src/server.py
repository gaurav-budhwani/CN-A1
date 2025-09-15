#!/usr/bin/env python3
"""
TCP resolver server WITHOUT length-prefix framing.
- client opens TCP connection and sends one payload:
    [8-byte ASCII header 'HHMMSSID'] + [original DNS packet bytes]
- client then shuts down the write side (sock.shutdown(SHUT_WR)) to indicate EOF.
- server reads until recv() returns b'' (client closed write), then processes:
    * first 8 bytes -> header
    * remaining bytes -> original DNS packet (not further parsed here)
- server selects IP using rules.json and sends back an ASCII response (e.g. "192.168.1.6")
  then closes the connection.

Note:
- This server is multi-threaded: each connection is handled in a separate thread.
- Timeout values are used to avoid hung connections.
"""
import argparse
import socket
import threading
import json
import traceback
from typing import Optional
from utils import select_ip_for_header


def recv_until_close(conn: socket.socket, timeout: float = 5.0) -> bytes:
    """
    read from TCP socket until the peer closes the write side (recv returns b'').
    uses a per-recv timeout to avoid hanging forever.
    """
    conn.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:  # peer closed write -> EOF
                break
            buf.extend(chunk)
    except socket.timeout:
        # timeout reading more data: treat whatever we have as the full payload
        pass
    except Exception:
        raise
    return bytes(buf)


def handle_client(conn: socket.socket, addr, rules):
    try:
        data = recv_until_close(conn, timeout=5.0)
        if len(data) < 8:
            # invalid: must contain at least the 8-byte header
            err = "ERROR: payload too short (expect >=8 bytes for header)\n"
            try:
                conn.sendall(err.encode("ascii"))
            except Exception:
                pass
            return

        header_bytes = data[:8]
        try:
            header_str = header_bytes.decode("ascii")
        except Exception:
            header_str = repr(header_bytes)

        # select IP based on header and the rules (utils.select_ip_for_header)
        try:
            resolved_ip = select_ip_for_header(header_str, rules)
        except Exception as e:
            resolved_ip = f"ERROR: {e}"
        # log
        print(f"[{addr}] Header={header_str} -> Resolved={resolved_ip}")

        # send response (ASCII) and close
        resp = str(resolved_ip).encode("ascii")
        try:
            conn.sendall(resp)
        except Exception:
            pass

    except Exception as e:
        print(f"Exception handling client {addr}: {e}")
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except Exception:
            pass


def serve(host: str, port: int, rules_path: str):
    with open(rules_path) as f:
        rules = json.load(f)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(8)
    print(f"Server listening on {host}:{port}")
    try:
        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, rules), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Resolver server (TCP, no length-prefix)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=53535, type=int)
    parser.add_argument("--rules", default="src/rules.json")
    args = parser.parse_args()
    serve(args.host, args.port, args.rules)
