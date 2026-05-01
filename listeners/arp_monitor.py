"""
NetWatch ARP Monitor
Monitors the local ARP table for changes and detects spoofing.
Flags duplicate MAC addresses (indicator of ARP poisoning/MITM attacks).

Runs as a polling daemon : checks the ARP table at regular intervals.
Must run on Linux (reads /proc/net/arp).
"""

import time
import re
from db.database import get_db
from utils.helpers import setup_logger

logger = setup_logger("arp_monitor")

ARP_TABLE_PATH = "/proc/net/arp"
POLL_INTERVAL = 5  # seconds


def read_arp_table():
    """
    Parse the Linux ARP table from /proc/net/arp.
    Returns a list of (ip, mac, interface) tuples.
    """
    entries = []
    try:
        with open(ARP_TABLE_PATH, "r") as f:
            lines = f.readlines()[1:]  # Skip header row

        for line in lines:
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3]
                interface = parts[5]

                # Skip incomplete entries
                if mac == "00:00:00:00:00:00":
                    continue

                entries.append((ip, mac, interface))

    except FileNotFoundError:
        logger.error(f"{ARP_TABLE_PATH} not found : are you running on Linux?")
    except PermissionError:
        logger.error(f"Cannot read {ARP_TABLE_PATH} : check permissions.")

    return entries


def detect_spoofing(current_table, previous_table):
    """
    Compare current and previous ARP tables.
    Detect:
      - New entries (NEW)
      - Changed MAC for same IP (CHANGED : possible spoofing)
      - Duplicate MACs for different IPs (DUPLICATE_MAC : ARP poisoning)
    """
    events = []

    # Build lookup from previous table
    prev_by_ip = {ip: mac for ip, mac, _ in previous_table}
    curr_by_mac = {}

    for ip, mac, iface in current_table:
        # Check for new entries
        if ip not in prev_by_ip:
            events.append((ip, mac, iface, "NEW"))
            logger.info(f"[NEW] {ip} → {mac} on {iface}")

        # Check for MAC changes (strong spoofing indicator)
        elif prev_by_ip[ip] != mac:
            events.append((ip, mac, iface, "CHANGED"))
            logger.warning(
                f"[CHANGED] {ip} MAC changed: {prev_by_ip[ip]} → {mac} "
                f"⚠ POSSIBLE ARP SPOOFING"
            )

        # Track MACs to find duplicates
        if mac not in curr_by_mac:
            curr_by_mac[mac] = []
        curr_by_mac[mac].append(ip)

    # Check for duplicate MACs (multiple IPs sharing one MAC)
    for mac, ips in curr_by_mac.items():
        if len(ips) > 1:
            for ip in ips:
                iface = next(
                    (i for _ip, _mac, i in current_table if _ip == ip),
                    "unknown"
                )
                events.append((ip, mac, iface, "DUPLICATE_MAC"))
            logger.warning(
                f"[DUPLICATE_MAC] {mac} maps to multiple IPs: {ips} "
                f"⚠ POSSIBLE ARP POISONING"
            )

    return events


def start(poll_interval=POLL_INTERVAL):
    """Start the ARP monitoring loop."""
    get_db().connect()

    print(f"""
╔══════════════════════════════════════════════╗
║  NetWatch : ARP Spoofing Monitor             ║
║  Polling /proc/net/arp every {poll_interval}s              ║
╚══════════════════════════════════════════════╝
    """)

    previous_table = []

    try:
        while True:
            current_table = read_arp_table()

            if previous_table:
                events = detect_spoofing(current_table, previous_table)

                for ip, mac, iface, event_type in events:
                    get_db().log_arp(
                        ip_address=ip,
                        mac_address=mac,
                        interface=iface,
                        event_type=event_type
                    )
            else:
                logger.info(f"Initial ARP table: {len(current_table)} entries")
                for ip, mac, iface in current_table:
                    logger.info(f"  {ip} → {mac} ({iface})")

            previous_table = current_table
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        logger.info("ARP monitor shutting down.")


if __name__ == "__main__":
    start()
