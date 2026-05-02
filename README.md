# NetWatch — Network Traffic Analysis Toolkit

[![Demo](https://asciinema.org/a/tZuVPcPt7KkD7cZo.svg)](https://asciinema.org/a/tZuVPcPt7KkD7cZo)

Python-based network listeners for capturing, logging, and analyzing incoming traffic. Built during the **DoD Cybersecurity Workforce Development Program** at Virginia Tech's Senior Military College Cyber Institute (SMCCI).

## Overview

NetWatch is a defensive monitoring toolkit that deploys listeners across multiple protocols to capture and log attack traffic to PostgreSQL for analysis. It was built on the Virginia Cyber Range during the DoD Cybersecurity Fellowship — running offensive tools (Metasploit, Nmap, arpspoof) against the listeners, then verifying what was captured by cross-referencing against Wireshark and tcpdump packet captures. Attack patterns studied include port scanning, ARP spoofing, MITM attacks, DNS enumeration, and exploit delivery.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Attacker Machine                │
│  (Nmap, Metasploit, hping3, arpspoof)       │
└─────────────┬───────────────────────────────┘
              │  attack traffic
              ▼
┌─────────────────────────────────────────────┐
│            NetWatch Listeners                │
│                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐    │
│  │  HTTP    │ │   TCP    │ │   UDP    │    │
│  │ (Flask)  │ │ (socket) │ │ (socket) │    │
│  │ :8080   │ │ :9001   │ │ :9002   │    │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘    │
│       │            │            │           │
│  ┌────┴─────┐ ┌────┴─────┐                 │
│  │   DNS    │ │   ARP    │                 │
│  │ (socket) │ │ (poll)   │                 │
│  │ :53     │ │ /proc    │                 │
│  └────┬─────┘ └────┬─────┘                 │
│       │            │                        │
│       ▼            ▼                        │
│  ┌─────────────────────────────────────┐    │
│  │        PostgreSQL Database          │    │
│  │  http_logs │ tcp_logs │ udp_logs   │    │
│  │  dns_logs  │ arp_logs              │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
              │
              ▼  analysis
┌─────────────────────────────────────────────┐
│     tcpdump / Wireshark / SQL queries        │
└─────────────────────────────────────────────┘
```

## Listeners

| Listener | Protocol | Default Port | What It Catches |
|----------|----------|-------------|-----------------|
| HTTP | Flask (TCP) | 8080 | Web recon, scanning, exploit attempts |
| TCP | Raw socket | 9001 | Port scans, Metasploit payloads, banner grabs |
| UDP | Raw socket | 9002 | UDP scans, crafted datagrams |
| DNS | UDP parser | 5300 | DNS enumeration, zone transfers, tunneling |
| ARP | /proc/net/arp | — | ARP spoofing, cache poisoning, MITM |

## Quick Start

### Prerequisites
- Python 3.8+
- Docker (for PostgreSQL)
- Linux (required for ARP monitor and DNS listener)

### Setup

```bash
# Clone and install
git clone https://github.com/bvilcas/netwatch.git
cd netwatch
pip install -r requirements.txt

# Start PostgreSQL (schema loads automatically on first run)
docker compose up -d

# Configure connection (or export env vars directly)
cp .env.example .env
```

### Usage

```bash
# Start everything at once
chmod +x start.sh && ./start.sh
```

Or run individually:

```bash
# Run individual listeners
python netwatch.py http                  # HTTP on port 8080
python netwatch.py tcp --port 666        # TCP on custom port
python netwatch.py udp                   # UDP on port 9002
python netwatch.py dns                   # DNS on port 5353
python netwatch.py arp --interval 3      # ARP monitor, 3s polling

# Run all listeners at once
sudo python netwatch.py all
```

### Generating Test Traffic

From a separate machine (or Kali VM):

```bash
# Port scan
nmap -sS -p 8080,9001,9002 <listener-ip>

# HTTP probing
curl http://<listener-ip>:8080/admin
curl -X POST http://<listener-ip>:8080/login -d "user=admin&pass=test"

# TCP payload
echo "HELLO" | nc <listener-ip> 9001

# DNS enumeration
dig @<listener-ip> -p 5300 +notcp example.com A
dig @<listener-ip> -p 5300 +notcp example.com AXFR
```

## Analyzing Captured Data

Query the PostgreSQL database directly to investigate captured traffic:

```sql
-- Top scanners by connection count
SELECT source_ip, COUNT(*) as hits
FROM tcp_logs
WHERE payload_size = 0
GROUP BY source_ip
ORDER BY hits DESC;

-- HTTP paths targeted (find recon patterns)
SELECT path, method, COUNT(*) as attempts
FROM http_logs
GROUP BY path, method
ORDER BY attempts DESC;

-- Detect ARP spoofing events
SELECT * FROM arp_logs
WHERE event_type IN ('CHANGED', 'DUPLICATE_MAC')
ORDER BY timestamp DESC;

-- DNS enumeration patterns
SELECT source_ip, query_type, COUNT(*) as queries
FROM dns_logs
GROUP BY source_ip, query_type
ORDER BY queries DESC;
```

## Permissions

| Feature | without sudo | sudo |
|---|---|---|
| HTTP listener (8080) | ✅ | ✅ |
| TCP listener (9001) | ✅ | ✅ |
| UDP listener (9002) | ✅ | ✅ |
| ARP monitor | ✅ | ✅ |
| DNS listener (port 5353) | ✅ | ✅ |

## Exporting Captured Data

Export any table to CSV for offline analysis or sharing:

```bash
# Export HTTP logs
psql -h localhost -U netwatch -d netwatch -c "\copy http_logs TO 'http_logs.csv' CSV HEADER"

# Export TCP logs
psql -h localhost -U netwatch -d netwatch -c "\copy tcp_logs TO 'tcp_logs.csv' CSV HEADER"

# Export ARP events only
psql -h localhost -U netwatch -d netwatch -c "\copy (SELECT * FROM arp_logs WHERE event_type IN ('CHANGED','DUPLICATE_MAC')) TO 'arp_events.csv' CSV HEADER"
```

## Why Not Just Use Wireshark?

Wireshark shows everything raw in real time — you're just watching. The moment you close it, the data is gone.

NetWatch captures specific attack traffic, parses what matters, and stores it permanently in PostgreSQL. A week later you can still query which IPs scanned you, what paths they probed, and whether any MAC addresses changed on the network.

## Tech Stack

- **Python 3** — Flask, socket, threading, struct
- **PostgreSQL** — psycopg2 for connection pooling and structured logging
- **Linux** — /proc/net/arp for ARP table monitoring
- **Analysis** — tcpdump, Wireshark, SQL

## Lab Documentation

See [`docs/lab_notes.md`](docs/lab_notes.md) for sanitized analysis notes covering:
- Network sniffing and protocol analysis
- Port scanning detection and classification
- ARP spoofing and MITM attack detection
- DNS enumeration and spoofing
- Metasploit exploit traffic analysis

## Fellowship Context

Built as part of the DoD Cybersecurity Workforce Development Program at Virginia Tech's Senior Military College Cyber Institute. Labs ran on the Virginia Cyber Range — a sandboxed cloud environment used by Virginia universities for cybersecurity training.

The approach was purple team: I ran attacks using Metasploit, Nmap, and arpspoof against my own listeners, then verified what was captured by cross-referencing listener output against Wireshark and tcpdump packet captures. Each of the five listeners maps to a dedicated lab focused on a different protocol and attack class.

## License

MIT
