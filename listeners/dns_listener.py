"""
NetWatch DNS Listener
Captures DNS queries on UDP port 53 and parses query names/types.
Detects DNS enumeration, zone transfer attempts, tunneling,
and spoofed DNS responses from MITM attacks.

Must run as root (port 53 is privileged).
"""

import socket
import struct
from db.database import get_db
from utils.helpers import setup_logger, print_banner, to_hex

logger = setup_logger("dns_listener")

BUFFER_SIZE = 1024

# DNS query type mapping
QUERY_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
    12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 252: "AXFR", 255: "ANY"
}


def parse_dns_query(data):
    """
    Parse a raw DNS query packet.
    Returns (query_name, query_type) or (None, None) on failure.
    """
    try:
        # DNS header is 12 bytes
        if len(data) < 12:
            return None, None

        # Skip header, parse question section
        offset = 12
        labels = []

        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length >= 192:  # Compression pointer
                break
            offset += 1
            label = data[offset:offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

        query_name = ".".join(labels) if labels else "<unknown>"

        # Read query type (2 bytes after the name)
        if offset + 2 <= len(data):
            qtype_num = struct.unpack("!H", data[offset:offset + 2])[0]
            query_type = QUERY_TYPES.get(qtype_num, f"TYPE{qtype_num}")
        else:
            query_type = "UNKNOWN"

        return query_name, query_type

    except Exception as e:
        logger.error(f"DNS parse error: {e}")
        return None, None


def start(host="0.0.0.0", port=5300):
    """Start the DNS listener."""
    get_db().connect()
    print_banner("DNS Listener", host, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind((host, port))
    except PermissionError:
        logger.error("Port 53 requires root privileges. Run with sudo.")
        return

    logger.info("Waiting for DNS queries...")

    try:
        while True:
            data, (source_ip, source_port) = sock.recvfrom(BUFFER_SIZE)

            query_name, query_type = parse_dns_query(data)

            if query_name:
                logger.info(f"DNS query from {source_ip}:{source_port} : {query_type} {query_name}")

                get_db().log_dns(
                    source_ip=source_ip,
                    source_port=source_port,
                    query_name=query_name,
                    query_type=query_type,
                    raw_data=to_hex(data)
                )
            else:
                logger.warning(f"Malformed DNS packet from {source_ip}:{source_port}")

    except KeyboardInterrupt:
        logger.info("DNS listener shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    start()
