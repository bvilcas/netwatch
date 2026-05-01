"""
NetWatch UDP Listener
Captures incoming UDP datagrams and logs payloads.
Detects UDP port scans, DNS queries, and crafted packets from tools
like Nmap (-sU), hping3 (--udp), and custom scapy scripts.
"""

import socket
from db.database import get_db
from utils.helpers import setup_logger, print_banner, safe_decode, to_hex

logger = setup_logger("udp_listener")

BUFFER_SIZE = 4096


def start(host="0.0.0.0", port=9002):
    """Start the UDP listener."""
    get_db().connect()
    print_banner("UDP Listener", host, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))

    logger.info("Waiting for UDP datagrams...")

    try:
        while True:
            data, (source_ip, source_port) = sock.recvfrom(BUFFER_SIZE)

            payload_hex = to_hex(data) if data else None
            payload_ascii = safe_decode(data) if data else None
            payload_size = len(data)

            logger.info(f"Datagram from {source_ip}:{source_port} : {payload_size} bytes")

            if data:
                logger.debug(f"  ASCII: {payload_ascii[:200]}")

            # Log to database
            get_db().log_udp(
                source_ip=source_ip,
                source_port=source_port,
                dest_port=port,
                payload_hex=payload_hex,
                payload_ascii=payload_ascii,
                payload_size=payload_size
            )

    except KeyboardInterrupt:
        logger.info("UDP listener shutting down.")
    finally:
        sock.close()


if __name__ == "__main__":
    start()
