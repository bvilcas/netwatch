"""
Database connection manager for NetWatch.
Handles PostgreSQL connections via psycopg2 with connection pooling.
"""

import os
import threading
import psycopg2
from psycopg2 import pool, extras
from datetime import datetime

_instance = None
_lock = threading.Lock()


def get_db():
    """Return the process-wide DatabaseManager singleton."""
    global _instance
    with _lock:
        if _instance is None:
            _instance = DatabaseManager()
    return _instance


class DatabaseManager:
    """Manages PostgreSQL connections and provides insert methods for each log type."""

    def __init__(self):
        self.db_config = {
            "host": os.getenv("NW_DB_HOST", "localhost"),
            "port": int(os.getenv("NW_DB_PORT", 5432)),
            "database": os.getenv("NW_DB_NAME", "netwatch"),
            "user": os.getenv("NW_DB_USER", "netwatch"),
            "password": os.getenv("NW_DB_PASS", "netwatch"),
        }
        self._pool = None

    def connect(self):
        """Initialize the connection pool (no-op if already connected)."""
        if self._pool is not None:
            return
        try:
            self._pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                **self.db_config
            )
            print(f"[DB] Connected to PostgreSQL at {self.db_config['host']}:{self.db_config['port']}")
        except psycopg2.OperationalError as e:
            print(f"[DB] Connection failed: {e}")
            raise

    def _get_conn(self):
        """Get a connection from the pool."""
        if not self._pool:
            self.connect()
        return self._pool.getconn()

    def _put_conn(self, conn):
        """Return a connection to the pool."""
        self._pool.putconn(conn)

    def log_http(self, source_ip, source_port, method, path, headers, body, user_agent, content_length):
        """Insert an HTTP request log."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO http_logs 
                       (source_ip, source_port, method, path, headers, body, user_agent, content_length)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (source_ip, source_port, method, path,
                     extras.Json(dict(headers)) if headers else None,
                     body, user_agent, content_length)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB] HTTP log insert failed: {e}")
        finally:
            self._put_conn(conn)

    def log_tcp(self, source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size, tcp_flags=None):
        """Insert a TCP connection log."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO tcp_logs 
                       (source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size, tcp_flags)
                       VALUES (%s, %s, %s, %s, %s, %s, %s)""",
                    (source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size, tcp_flags)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB] TCP log insert failed: {e}")
        finally:
            self._put_conn(conn)

    def log_udp(self, source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size):
        """Insert a UDP datagram log."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO udp_logs 
                       (source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size)
                       VALUES (%s, %s, %s, %s, %s, %s)""",
                    (source_ip, source_port, dest_port, payload_hex, payload_ascii, payload_size)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB] UDP log insert failed: {e}")
        finally:
            self._put_conn(conn)

    def log_dns(self, source_ip, source_port, query_name, query_type, raw_data):
        """Insert a DNS query log."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO dns_logs 
                       (source_ip, source_port, query_name, query_type, raw_data)
                       VALUES (%s, %s, %s, %s, %s)""",
                    (source_ip, source_port, query_name, query_type, raw_data)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB] DNS log insert failed: {e}")
        finally:
            self._put_conn(conn)

    def log_arp(self, ip_address, mac_address, interface, event_type):
        """Insert an ARP event log."""
        conn = self._get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """INSERT INTO arp_logs 
                       (ip_address, mac_address, interface, event_type)
                       VALUES (%s, %s, %s, %s)""",
                    (ip_address, mac_address, interface, event_type)
                )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print(f"[DB] ARP log insert failed: {e}")
        finally:
            self._put_conn(conn)

    def close(self):
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            print("[DB] Connection pool closed.")
