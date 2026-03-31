#!/usr/bin/env python3
"""
DNS Threat Hunt Playbook Sample Data Generator
================================================
Generates realistic DNS logs containing indicators for all 10 hunt types.
Creates a single mixed dataset with benign traffic + all threat patterns.

This provides a realistic "find the threats" scenario for testing and training.

Output: sample_data/sample_hunt_data.log (TSV format, compatible with Zeek dns.log)

Author: Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import base64
import os
import random
import string
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NORMAL_DOMAINS = [
    "google.com", "facebook.com", "twitter.com", "github.com", "stackoverflow.com",
    "wikipedia.org", "amazon.com", "microsoft.com", "apple.com", "netflix.com",
    "reddit.com", "linkedin.com", "youtube.com", "cloudflare.com", "akamai.com",
]

NORMAL_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "api", "cdn", "static",
    "assets", "images", "files", "download", "upload", "admin", "vpn",
]

INTERNAL_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5", "10.0.0.10"]
ATTACKER_IPS = ["192.168.100.50", "192.168.100.75", "192.168.200.100"]
ATTACKER_DOMAINS = [
    "evil.cc", "malware-c2.net", "badactor.xyz", "data-exfil.cc", "botnet-control.ru"
]


# ---------------------------------------------------------------------------
# Generators for each hunt type
# ---------------------------------------------------------------------------
def generate_normal_traffic(start_time: float, count: int) -> list[dict]:
    """Generate benign DNS queries."""
    queries = []
    for i in range(count):
        timestamp = start_time + i
        src_ip = random.choice(INTERNAL_IPS)
        domain = random.choice(NORMAL_DOMAINS)
        subdomain = random.choice(NORMAL_SUBDOMAINS)
        query_name = f"{subdomain}.{domain}"

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "A",
            "response_code": "NOERROR",
            "answer": f"1.2.3.{random.randint(1, 254)}",
            "server_ip": "8.8.8.8",
        })
    return queries


def generate_dns_tunneling(start_time: float) -> list[dict]:
    """Generate DNS tunneling traffic (H001)."""
    queries = []
    src_ip = random.choice(ATTACKER_IPS)
    domain = random.choice(ATTACKER_DOMAINS)
    base_time = start_time

    # Generate 30 queries with high-entropy subdomains
    for i in range(30):
        timestamp = base_time + i * 2
        # Base32-like encoding
        encoded_label = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", k=48))
        query_name = f"{encoded_label}.{domain}"

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "A",
            "response_code": "NXDOMAIN",
            "answer": "",
            "server_ip": "8.8.8.8",
            "entropy": 4.2,  # High entropy
        })

    return queries


def generate_c2_beacon(start_time: float) -> list[dict]:
    """Generate C2 beacon traffic (H002)."""
    queries = []
    src_ip = random.choice(ATTACKER_IPS)
    domain = random.choice(ATTACKER_DOMAINS)
    base_time = start_time
    interval = 60  # 60-second beacon interval
    jitter = 3  # 3 second jitter

    # Generate 50 beacons over ~50 minutes
    for i in range(50):
        timestamp = base_time + (i * interval) + random.randint(-jitter, jitter)
        encoded = base64.b32encode(f"cmd_{i:04d}".encode()).decode().rstrip("=")
        query_name = f"{encoded}.{domain}"

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "A",
            "response_code": "NOERROR",
            "answer": "10.0.0.99",
            "server_ip": "8.8.8.8",
            "entropy": 3.8,
        })

    # Add some TXT queries (for command responses)
    for i in range(10):
        timestamp = base_time + (i * 300) + random.randint(-5, 5)
        query_name = f"cmd.{domain}"
        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "TXT",
            "response_code": "NOERROR",
            "answer": "execute_payload",
            "server_ip": "8.8.8.8",
        })

    return queries


def generate_dga(start_time: float) -> list[dict]:
    """Generate DGA traffic (H003)."""
    queries = []
    src_ip = random.choice(ATTACKER_IPS)
    base_time = start_time

    # Generate 200 random domains with high NXDOMAIN rate
    for i in range(200):
        timestamp = base_time + i * 0.5
        # Generate random domain
        random_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        random_tld = random.choice(["com", "net", "org", "ru", "cc"])
        query_name = f"{random_label}.{random_tld}"

        # 90% will be NXDOMAIN
        response_code = "NXDOMAIN" if random.random() < 0.9 else "NOERROR"
        answer = "" if response_code == "NXDOMAIN" else "10.0.0.99"

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "A",
            "response_code": response_code,
            "answer": answer,
            "server_ip": "8.8.8.8",
        })

    return queries


def generate_cache_poisoning(start_time: float) -> list[dict]:
    """Generate DNS cache poisoning attempts (H004)."""
    queries = []
    domain = "legitimate-bank.com"  # Mimic legitimate domain
    base_time = start_time

    # Generate responses with multiple A records (contradiction)
    for i in range(20):
        timestamp = base_time + i * 5
        legitimate_ip = "203.0.113.1"  # Real bank IP
        attacker_ip = f"192.0.2.{i % 250}"  # Attacker IP

        # Interleave legitimate and poisoned responses
        answer = attacker_ip if i % 2 == 0 else legitimate_ip

        queries.append({
            "timestamp": timestamp,
            "src_ip": random.choice(INTERNAL_IPS),
            "query_name": domain,
            "query_type": "A",
            "response_code": "NOERROR",
            "answer": answer,
            "server_ip": "8.8.8.8",
        })

    return queries


def generate_zone_transfer(start_time: float) -> list[dict]:
    """Generate zone transfer attempts (H005)."""
    queries = []
    attacker_ip = "203.0.113.50"  # External attacker
    domain = "internal.company.local"
    base_time = start_time

    # AXFR attempt
    queries.append({
        "timestamp": base_time,
        "src_ip": attacker_ip,
        "query_name": domain,
        "query_type": "AXFR",
        "response_code": "REFUSED",  # Should be refused
        "answer": "",
        "server_ip": "10.0.0.1",
    })

    # Zone enumeration attempts (SOA, NS queries)
    for i in range(10):
        timestamp = base_time + 1 + i
        qtype = random.choice(["SOA", "NS"])
        queries.append({
            "timestamp": timestamp,
            "src_ip": attacker_ip,
            "query_name": domain,
            "query_type": qtype,
            "response_code": "NOERROR",
            "answer": "10.0.0.1",
            "server_ip": "8.8.8.8",
        })

    return queries


def generate_dnssec_failure(start_time: float) -> list[dict]:
    """Generate DNSSEC validation failures (H006)."""
    queries = []
    domain = "dnssec-zone.com"
    base_time = start_time

    # Generate SERVFAIL responses
    for i in range(15):
        timestamp = base_time + i * 10
        queries.append({
            "timestamp": timestamp,
            "src_ip": random.choice(INTERNAL_IPS),
            "query_name": domain,
            "query_type": "A",
            "response_code": "SERVFAIL",
            "answer": "",
            "server_ip": "8.8.8.8",
            "ad_flag": False,  # Authenticated data = false
        })

    return queries


def generate_dns_amplification(start_time: float) -> list[dict]:
    """Generate DNS amplification attack vectors (H007)."""
    queries = []
    spoofed_victim_ip = "203.0.113.100"
    attacker_ip = random.choice(ATTACKER_IPS)
    base_time = start_time

    # Large TXT records (amplification)
    for i in range(100):
        timestamp = base_time + i * 0.1
        domain = random.choice(NORMAL_DOMAINS)

        queries.append({
            "timestamp": timestamp,
            "src_ip": attacker_ip,  # Spoofed as victim IP in real attack
            "query_name": domain,
            "query_type": "TXT",
            "response_code": "NOERROR",
            "answer": "v=spf1 include:_spf.example.com ~all " * 20,  # Large response
            "server_ip": "8.8.8.8",
            "response_bytes": 700,  # Large response
            "query_bytes": 40,  # Small query
        })

    return queries


def generate_doh_bypass(start_time: float) -> list[dict]:
    """Generate DoH (DNS over HTTPS) bypass (H008)."""
    queries = []
    src_ip = random.choice(ATTACKER_IPS)
    base_time = start_time

    # Simulate HTTPS connections to DoH providers
    # Note: These would actually be logged as network/firewall events
    # but included here for completeness
    for i in range(30):
        timestamp = base_time + i * 2
        doh_provider = random.choice(["8.8.8.8", "1.1.1.1", "45.33.32.156"])

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": "",  # DoH hides query names in HTTPS
            "query_type": "HTTPS",
            "response_code": "NOERROR",
            "answer": doh_provider,
            "server_ip": doh_provider,
            "protocol": "https",
            "port": 443,
            "bytes_in": 200,
            "bytes_out": 150,
        })

    return queries


def generate_fast_flux(start_time: float) -> list[dict]:
    """Generate fast-flux domain (H009)."""
    queries = []
    domain = random.choice(ATTACKER_DOMAINS)
    base_time = start_time

    # Same domain returning different IPs
    for i in range(40):
        timestamp = base_time + i * 1.5
        ip = f"192.0.2.{i % 20}"  # Rotating IPs

        queries.append({
            "timestamp": timestamp,
            "src_ip": random.choice(INTERNAL_IPS),
            "query_name": domain,
            "query_type": "A",
            "response_code": "NOERROR",
            "answer": ip,
            "server_ip": "8.8.8.8",
        })

    return queries


def generate_data_exfiltration(start_time: float) -> list[dict]:
    """Generate DNS data exfiltration (H010)."""
    queries = []
    src_ip = random.choice(ATTACKER_IPS)
    exfil_domain = random.choice(ATTACKER_DOMAINS)
    base_time = start_time

    # Generate long subdomains encoding data
    for i in range(50):
        timestamp = base_time + i * 0.5
        # Encode fake data as base64 in subdomain
        data_chunk = f"secretdata_{i:04d}".ljust(50, "x")
        encoded = base64.b64encode(data_chunk.encode()).decode().rstrip("=")
        query_name = f"{encoded}.{exfil_domain}"

        queries.append({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "query_name": query_name,
            "query_type": "A",
            "response_code": "NXDOMAIN",
            "answer": "",
            "server_ip": "8.8.8.8",
            "entropy": 4.1,
        })

    return queries


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
def generate_all_hunt_data(output_file: str = "sample_hunt_data.log") -> None:
    """Generate complete sample data with all hunt types."""
    # Start time: 1 hour ago
    start_time = time.time() - 3600
    current_time = start_time

    all_queries = []

    print("Generating sample hunt data...", file=sys.stderr)

    # Generate normal traffic baseline (500 queries over the hour)
    print("  - Generating normal traffic baseline...", file=sys.stderr)
    all_queries.extend(generate_normal_traffic(current_time, 500))
    current_time += 60

    # H001: DNS Tunneling
    print("  - Generating H001 (DNS Tunneling)...", file=sys.stderr)
    all_queries.extend(generate_dns_tunneling(current_time))
    current_time += 120

    # H002: C2 Beacon
    print("  - Generating H002 (C2 Beacon)...", file=sys.stderr)
    all_queries.extend(generate_c2_beacon(current_time))
    current_time += 120

    # H003: DGA
    print("  - Generating H003 (DGA)...", file=sys.stderr)
    all_queries.extend(generate_dga(current_time))
    current_time += 120

    # H004: Cache Poisoning
    print("  - Generating H004 (Cache Poisoning)...", file=sys.stderr)
    all_queries.extend(generate_cache_poisoning(current_time))
    current_time += 120

    # H005: Zone Transfer
    print("  - Generating H005 (Zone Transfer)...", file=sys.stderr)
    all_queries.extend(generate_zone_transfer(current_time))
    current_time += 60

    # H006: DNSSEC Failure
    print("  - Generating H006 (DNSSEC Failure)...", file=sys.stderr)
    all_queries.extend(generate_dnssec_failure(current_time))
    current_time += 120

    # H007: DNS Amplification
    print("  - Generating H007 (DNS Amplification)...", file=sys.stderr)
    all_queries.extend(generate_dns_amplification(current_time))
    current_time += 120

    # H008: DoH Bypass
    print("  - Generating H008 (DoH Bypass)...", file=sys.stderr)
    all_queries.extend(generate_doh_bypass(current_time))
    current_time += 120

    # H009: Fast-Flux
    print("  - Generating H009 (Fast-Flux)...", file=sys.stderr)
    all_queries.extend(generate_fast_flux(current_time))
    current_time += 120

    # H010: Data Exfiltration
    print("  - Generating H010 (Data Exfiltration)...", file=sys.stderr)
    all_queries.extend(generate_data_exfiltration(current_time))

    # Shuffle to mix threat patterns with normal traffic
    random.shuffle(all_queries)

    # Write to file (TSV format, Zeek-compatible)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Writing {len(all_queries)} queries to {output_file}...", file=sys.stderr)

    with open(output_path, "w") as f:
        # Write header
        f.write("#fields\ttimestamp\tsrc_ip\tquery_name\tquery_type\tresponse_code\tanswer\tserver_ip\n")

        # Write queries
        for query in all_queries:
            f.write(
                f"{query['timestamp']:.0f}\t"
                f"{query['src_ip']}\t"
                f"{query.get('query_name', '')}\t"
                f"{query.get('query_type', 'A')}\t"
                f"{query.get('response_code', 'NOERROR')}\t"
                f"{query.get('answer', '')}\t"
                f"{query.get('server_ip', '8.8.8.8')}\n"
            )

    print(f"Generated {len(all_queries)} DNS queries in {output_path}", file=sys.stderr)
    print(f"Hunts represented: H001-H010 (all 10 threat types)", file=sys.stderr)


if __name__ == "__main__":
    output = "sample_hunt_data.log"
    if len(sys.argv) > 1:
        output = sys.argv[1]

    generate_all_hunt_data(output)
