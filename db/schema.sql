-- NetWatch Database Schema
-- PostgreSQL schema for network traffic analysis
--
-- Setup:
--   createdb netwatch          (or: psql -c "CREATE DATABASE netwatch;")
--   psql -d netwatch -f schema.sql

-- HTTP request logs from Flask listener
CREATE TABLE IF NOT EXISTS http_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER,
    method VARCHAR(10) NOT NULL,
    path TEXT NOT NULL,
    headers JSONB,
    body TEXT,
    user_agent TEXT,
    content_length INTEGER
);

-- Raw TCP connection logs
CREATE TABLE IF NOT EXISTS tcp_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER NOT NULL,
    dest_port INTEGER NOT NULL,
    payload_hex TEXT,
    payload_ascii TEXT,
    payload_size INTEGER,
    tcp_flags VARCHAR(20)
);

-- UDP datagram logs
CREATE TABLE IF NOT EXISTS udp_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER NOT NULL,
    dest_port INTEGER NOT NULL,
    payload_hex TEXT,
    payload_ascii TEXT,
    payload_size INTEGER
);

-- DNS query logs
CREATE TABLE IF NOT EXISTS dns_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    source_ip VARCHAR(45) NOT NULL,
    source_port INTEGER NOT NULL,
    query_name TEXT NOT NULL,
    query_type VARCHAR(10),
    raw_data TEXT
);

-- ARP table snapshots for spoofing detection
CREATE TABLE IF NOT EXISTS arp_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    ip_address VARCHAR(45) NOT NULL,
    mac_address VARCHAR(17) NOT NULL,
    interface VARCHAR(20),
    event_type VARCHAR(20) NOT NULL  -- 'NEW', 'CHANGED', 'DUPLICATE_MAC'
);

-- Indexes for common queries
CREATE INDEX idx_http_source_ip ON http_logs(source_ip);
CREATE INDEX idx_http_timestamp ON http_logs(timestamp);
CREATE INDEX idx_tcp_source_ip ON tcp_logs(source_ip);
CREATE INDEX idx_tcp_dest_port ON tcp_logs(dest_port);
CREATE INDEX idx_udp_source_ip ON udp_logs(source_ip);
CREATE INDEX idx_dns_query_name ON dns_logs(query_name);
CREATE INDEX idx_arp_event_type ON arp_logs(event_type);
