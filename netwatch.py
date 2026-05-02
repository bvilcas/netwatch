#!/usr/bin/env python3
"""
NetWatch : Network Traffic Analysis Toolkit
CLI entry point for running listeners.

Usage:
    python netwatch.py http [--port 8080]
    python netwatch.py tcp  [--port 9001]
    python netwatch.py udp  [--port 9002]
    python netwatch.py dns  [--port 53]
    python netwatch.py arp  [--interval 5]
    python netwatch.py all
"""

import argparse
import sys
import threading


def run_http(args):
    from listeners.http_listener import start
    start(host=args.host, port=args.port or 8080)


def run_tcp(args):
    from listeners.tcp_listener import start
    start(host=args.host, port=args.port or 9001)


def run_udp(args):
    from listeners.udp_listener import start
    start(host=args.host, port=args.port or 9002)


def run_dns(args):
    from listeners.dns_listener import start
    start(host=args.host, port=args.port or 5300)


def run_arp(args):
    from listeners.arp_monitor import start
    start(poll_interval=args.interval or 5)


def run_all(args):
    """Start all listeners concurrently in separate threads."""
    print("""
╔══════════════════════════════════════════════════╗
║         NetWatch : Starting All Listeners        ║
╚══════════════════════════════════════════════════╝
    """)

    threads = [
        threading.Thread(target=run_http, args=(args,), daemon=True, name="http"),
        threading.Thread(target=run_tcp, args=(args,), daemon=True, name="tcp"),
        threading.Thread(target=run_udp, args=(args,), daemon=True, name="udp"),
        threading.Thread(target=run_arp, args=(args,), daemon=True, name="arp"),
    ]

    # DNS requires root : start it only if we have privileges
    import os
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        threads.append(
            threading.Thread(target=run_dns, args=(args,), daemon=True, name="dns")
        )
    else:
        print("[!] Skipping DNS listener (requires root). Run with sudo for full coverage.")

    for t in threads:
        t.start()
        print(f"  ✓ {t.name} listener started")

    print("\nAll listeners running. Press Ctrl+C to stop.\n")

    try:
        while True:
            for t in threads:
                t.join(timeout=1.0)
    except KeyboardInterrupt:
        print("\nShutting down all listeners...")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="NetWatch : Network Traffic Analysis Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python netwatch.py http                  # HTTP listener on port 8080
  python netwatch.py tcp --port 666        # TCP listener on custom port
  python netwatch.py all                   # Start all listeners
  sudo python netwatch.py dns              # DNS listener (needs root)

Environment variables for database:
  NW_DB_HOST  (default: localhost)
  NW_DB_PORT  (default: 5432)
  NW_DB_NAME  (default: netwatch)
  NW_DB_USER  (default: netwatch)
  NW_DB_PASS  (default: netwatch)
        """
    )

    subparsers = parser.add_subparsers(dest="listener", help="Listener to run")
    subparsers.required = True

    # Common args
    for name, func in [("http", run_http), ("tcp", run_tcp),
                        ("udp", run_udp), ("dns", run_dns)]:
        sub = subparsers.add_parser(name, help=f"{name.upper()} listener")
        sub.add_argument("--host", default="0.0.0.0", help="Bind address")
        sub.add_argument("--port", type=int, help="Port number")
        sub.set_defaults(func=func)

    # ARP has interval instead of port
    arp_parser = subparsers.add_parser("arp", help="ARP spoofing monitor")
    arp_parser.add_argument("--interval", type=int, default=5, help="Poll interval in seconds")
    arp_parser.add_argument("--host", default="0.0.0.0")
    arp_parser.add_argument("--port", type=int, default=None)
    arp_parser.set_defaults(func=run_arp)

    # All listeners
    all_parser = subparsers.add_parser("all", help="Start all listeners")
    all_parser.add_argument("--host", default="0.0.0.0")
    all_parser.add_argument("--port", type=int, default=None)
    all_parser.add_argument("--interval", type=int, default=5)
    all_parser.set_defaults(func=run_all)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
