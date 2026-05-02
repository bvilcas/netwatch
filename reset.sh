#!/bin/bash
deactivate 2>/dev/null
sudo pkill -f netwatch.py
sudo fuser -k 8080/tcp
sudo fuser -k 9001/tcp
sudo fuser -k 9002/tcp
sudo fuser -k 5300/udp
sudo docker compose down
sleep 2
sudo docker compose up -d
sleep 3
export PGPASSWORD=netwatch
psql -h localhost -U netwatch -d netwatch -c "TRUNCATE http_logs, tcp_logs, udp_logs, dns_logs, arp_logs;"
echo "Ready."
