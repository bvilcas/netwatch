# Lab Analysis Notes

Sanitized summaries of traffic analysis conducted during the DoD Cybersecurity Fellowship on the Virginia Cyber Range.
All IP addresses are redacted or replaced with RFC 5737 documentation ranges.

---

## Lab 1: Network Sniffing & Protocol Analysis

**Tools used:** tcpdump, Wireshark, HTTP listener  
**Objective:** Capture and analyze cleartext traffic across protocols.

**Findings:**
- Captured HTTP GET/POST requests in cleartext using tcpdump (`tcpdump -i eth0 -w capture.pcap`)
- Identified unencrypted credentials in HTTP POST bodies via Wireshark filter: `http.request.method == POST`
- Logged 200+ HTTP requests through the Flask listener over a 30-minute capture window
- Observed User-Agent strings revealing scanner fingerprints (Nmap scripting engine, curl, Python-requests)

**Key takeaway:** Cleartext protocols expose everything — credentials, session tokens, API keys. 
This is why TLS matters.

---

## Lab 2: Port Scanning Detection

**Tools used:** Nmap (attacker), TCP/UDP listeners (defender), Wireshark  
**Objective:** Detect and classify port scan types from listener logs.

**Findings:**
- **SYN scan** (`nmap -sS`): TCP listener saw connection attempts with no payload — logged as 0-byte connections
- **Connect scan** (`nmap -sT`): Full TCP handshake completed, listener received empty connections
- **UDP scan** (`nmap -sU`): UDP listener received empty datagrams on target port
- Distinguished scan types by analyzing payload size and connection patterns in PostgreSQL:
  ```sql
  SELECT source_ip, COUNT(*), AVG(payload_size) 
  FROM tcp_logs 
  WHERE payload_size = 0 
  GROUP BY source_ip 
  ORDER BY COUNT(*) DESC;
  ```

**Key takeaway:** Port scans leave distinct signatures — zero-payload, high-frequency, sequential port targeting.

---

## Lab 3: ARP Spoofing & MITM Detection

**Tools used:** arpspoof (attacker), ARP monitor (defender), Wireshark  
**Objective:** Detect ARP cache poisoning in real-time.

**Findings:**
- Attacker used `arpspoof -i eth0 -t <victim> <gateway>` to poison the victim's ARP cache
- ARP monitor detected MAC address changes for the gateway IP within one polling cycle (5s)
- Identified DUPLICATE_MAC events — attacker's MAC appeared mapped to both attacker IP and spoofed gateway IP
- Wireshark confirmation: filtered `arp.duplicate-address-detected` to verify gratuitous ARP frames

**Key takeaway:** ARP has no authentication. Any host can claim any IP-to-MAC mapping.
Monitoring for MAC changes and duplicates catches most poisoning attacks.

---

## Lab 4: DNS Enumeration & Spoofing

**Tools used:** dig/nslookup (attacker), DNS listener (defender)  
**Objective:** Log and analyze DNS reconnaissance activity.

**Findings:**
- DNS listener captured zone transfer attempts (`AXFR` queries) from attacker
- Logged high-frequency `A` record queries indicating subdomain brute-forcing
- Identified `ANY` queries used for DNS amplification reconnaissance
- Query patterns revealed sequential enumeration: `mail.`, `www.`, `ftp.`, `admin.`, etc.

**Key takeaway:** DNS enumeration is often the first recon step. Logging query patterns 
reveals attacker intent before they ever touch application-layer services.

---

## Lab 5: Metasploit Exploit Traffic Analysis

**Tools used:** Metasploit Framework (attacker), TCP listener + Wireshark (defender)  
**Objective:** Capture and identify exploit payloads in network traffic.

**Findings:**
- TCP listener on port 666 captured Meterpreter reverse shell payload bytes
- Identified characteristic Metasploit payload patterns in hex dumps
- Wireshark TCP stream reassembly showed the full exploit chain: 
  initial scan → exploit delivery → payload staging
- Logged exploit attempts against multiple service ports, correlating with Nmap scan data

**Key takeaway:** Exploit payloads have identifiable signatures in raw traffic. 
Logging at the network layer catches attacks that application-layer defenses might miss.
