"""
NetWatch TCP Listener
Raw socket listener that captures incoming TCP connections and logs payloads.
Detects port scans (Nmap SYN/connect), Metasploit exploit payloads,
banner grabbing attempts, and custom crafted packets (hping3, scapy).
"""

import socket
import threading
from db.database import get_db
from utils.helpers import setup_logger, print_banner, safe_decode, to_hex

logger = setup_logger("tcp_listener")

BUFFER_SIZE = 4096
MAX_CONNECTIONS = 50


def handle_connection(client_socket, client_addr, listen_port):
    """Handle a single TCP connection : receive data and log it."""
    source_ip, source_port = client_addr
    logger.info(f"Connection from {source_ip}:{source_port} → port {listen_port}")

    try:
        client_socket.settimeout(5.0)
        data = b""

        # Read until timeout or connection close
        try:
            while True:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                data += chunk
                if len(data) >= BUFFER_SIZE:
                    break
        except socket.timeout:
            pass

        payload_hex = to_hex(data) if data else None
        payload_ascii = safe_decode(data) if data else None
        payload_size = len(data)

        if data:
            logger.info(f"  Received {payload_size} bytes from {source_ip}:{source_port}")
            logger.debug(f"  ASCII: {payload_ascii[:200]}")
        else:
            logger.info(f"  Empty connection from {source_ip}:{source_port} (probe/scan)")

        # Log to database
        get_db().log_tcp(
            source_ip=source_ip,
            source_port=source_port,
            dest_port=listen_port,
            payload_hex=payload_hex,
            payload_ascii=payload_ascii,
            payload_size=payload_size,
        )

    except Exception as e:
        logger.error(f"Error handling connection from {source_ip}: {e}")
    finally:
        client_socket.close()


def start(host="0.0.0.0", port=9001):
    """Start the TCP listener on the specified port."""
    get_db().connect()
    print_banner("TCP Listener", host, port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(MAX_CONNECTIONS)

    logger.info(f"Waiting for TCP connections (max {MAX_CONNECTIONS} queued)...")

    try:
        while True:
            client_socket, client_addr = server.accept()
            handler = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_addr, port),
                daemon=True
            )
            handler.start()
    except KeyboardInterrupt:
        logger.info("TCP listener shutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    start()
