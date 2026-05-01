"""
Shared utilities for NetWatch listeners.
"""

import logging
import sys
from datetime import datetime


def setup_logger(name, level=logging.INFO):
    """Create a configured logger for a listener module."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "[%(asctime)s] [%(name)s] %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def print_banner(listener_name, host, port):
    """Print a startup banner for a listener."""
    addr = f"{host}:{port}"
    print(f"""
╔══════════════════════════════════════════════╗
║  NetWatch: {listener_name:<32} ║
║  Listening on {addr:<31} ║
║  Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<32} ║
╚══════════════════════════════════════════════╝
    """)


def safe_decode(data, max_length=4096):
    """Safely decode bytes to ASCII, replacing non-printable characters."""
    try:
        decoded = data[:max_length].decode("ascii", errors="replace")
        return "".join(c if c.isprintable() or c in "\r\n\t" else "." for c in decoded)
    except Exception:
        return "<decode error>"


def to_hex(data, max_length=4096):
    """Convert bytes to hex string."""
    return data[:max_length].hex()
