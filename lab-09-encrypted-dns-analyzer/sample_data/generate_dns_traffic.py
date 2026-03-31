#!/usr/bin/env python3
"""
Generate realistic sample DNS traffic logs with various encryption protocols.

Generates JSON-formatted connection logs simulating:
  - Plaintext DNS (UDP port 53)
  - DoT (DNS over TLS, port 853)
  - DoH (DNS over HTTPS, port 443)
  - DoQ (DNS over QUIC, port 853)
  - DoH bypass attempts (clients using external providers)
  - Mixed enterprise and personal DNS usage

Output: sample_dns_traffic.json
"""

import json
import random
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network


def generate_sample_traffic(
    num_events: int = 500,
    seed: int = 42
) -> list:
    """
    Generate realistic DNS traffic logs.

    Args:
        num_events: Number of connection records to generate
        seed: Random seed for reproducibility

    Returns:
        List of connection record dictionaries
    """
    random.seed(seed)

    # Enterprise infrastructure
    enterprise_clients = [
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "192.168.1.103",
        "192.168.1.104",
        "10.0.0.50",
        "10.0.0.51",
        "10.0.0.52",
    ]

    enterprise_resolver_ips = [
        "10.0.0.1",
        "10.0.0.2",
        "192.168.1.1",
    ]

    # Public DoH providers
    doh_providers = {
        "Google": {
            "ips": ["8.8.8.8", "8.8.4.4"],
            "domains": ["dns.google", "dns.google.com"],
        },
        "Cloudflare": {
            "ips": ["1.1.1.1", "1.0.0.1"],
            "domains": ["one.one.one.one"],
        },
        "Quad9": {
            "ips": ["9.9.9.9", "149.112.112.112"],
            "domains": ["dns.quad9.net"],
        },
        "OpenDNS": {
            "ips": ["208.67.222.222", "208.67.220.220"],
            "domains": ["dns.opendns.com"],
        },
    }

    # DoT servers
    dot_servers = [
        {"ip": "8.8.8.8", "domain": "dns.google"},
        {"ip": "1.1.1.1", "domain": "one.one.one.one"},
        {"ip": "9.9.9.9", "domain": "dns.quad9.net"},
    ]

    # DoQ servers
    doq_servers = [
        {"ip": "2606:4700:4700::1111", "domain": "one.one.one.one"},
        {"ip": "8.8.8.8", "domain": "dns.google"},
    ]

    # DNS queries (sample domains being looked up)
    query_domains = [
        "google.com",
        "github.com",
        "stackoverflow.com",
        "internal-app.local",
        "mail.example.com",
        "api.service.local",
        "cdn.company.net",
        "backup.internal",
    ]

    records = []
    base_time = datetime(2024, 1, 1, 0, 0, 0)

    # Distribution: 20% plaintext, 30% DoT, 25% DoH (enterprise), 15% DoQ, 10% DoH (bypass)
    distribution = {
        "plaintext": int(num_events * 0.20),
        "dot": int(num_events * 0.30),
        "doh_enterprise": int(num_events * 0.25),
        "doq": int(num_events * 0.15),
        "doh_bypass": int(num_events * 0.10),
    }

    event_id = 0

    # =========================================================================
    # Plaintext DNS (UDP port 53) - to enterprise resolver
    # =========================================================================
    for _ in range(distribution["plaintext"]):
        client_ip = random.choice(enterprise_clients)
        server_ip = random.choice(enterprise_resolver_ips)
        timestamp = base_time + timedelta(seconds=event_id)

        records.append({
            "timestamp": timestamp.isoformat() + "Z",
            "client_ip": client_ip,
            "server_ip": server_ip,
            "server_port": 53,
            "protocol": random.choice(["UDP", "TCP"]),
            "domain": random.choice(query_domains),
            "path": "",
            "tls_version": "",
        })
        event_id += 1

    # =========================================================================
    # DoT (DNS over TLS, port 853)
    # =========================================================================
    for _ in range(distribution["dot"]):
        client_ip = random.choice(enterprise_clients)
        server_info = random.choice(dot_servers)
        timestamp = base_time + timedelta(seconds=event_id)

        records.append({
            "timestamp": timestamp.isoformat() + "Z",
            "client_ip": client_ip,
            "server_ip": server_info["ip"],
            "server_port": 853,
            "protocol": "TLS",
            "domain": server_info["domain"],
            "path": "",
            "tls_version": random.choice(["TLS 1.2", "TLS 1.3"]),
        })
        event_id += 1

    # =========================================================================
    # DoH Enterprise (HTTPS port 443 to internal/proxy resolver)
    # =========================================================================
    for _ in range(distribution["doh_enterprise"]):
        client_ip = random.choice(enterprise_clients)
        server_ip = random.choice(enterprise_resolver_ips)
        timestamp = base_time + timedelta(seconds=event_id)

        records.append({
            "timestamp": timestamp.isoformat() + "Z",
            "client_ip": client_ip,
            "server_ip": server_ip,
            "server_port": 443,
            "protocol": "HTTPS",
            "domain": "internal-resolver.local",
            "path": "/dns-query",
            "tls_version": "TLS 1.3",
        })
        event_id += 1

    # =========================================================================
    # DoQ (DNS over QUIC, port 853)
    # =========================================================================
    for _ in range(distribution["doq"]):
        client_ip = random.choice(enterprise_clients)
        server_info = random.choice(doq_servers)
        timestamp = base_time + timedelta(seconds=event_id)

        records.append({
            "timestamp": timestamp.isoformat() + "Z",
            "client_ip": client_ip,
            "server_ip": server_info["ip"],
            "server_port": 853,
            "protocol": "QUIC",
            "domain": server_info["domain"],
            "path": "",
            "tls_version": "QUIC/TLS 1.3",
        })
        event_id += 1

    # =========================================================================
    # DoH Bypass (external provider usage) - SECURITY ALERT
    # =========================================================================
    # Some clients bypass enterprise DNS and use external providers directly
    for _ in range(distribution["doh_bypass"]):
        # Pick a client that might be attempting bypass
        client_ip = random.choice(enterprise_clients)
        provider_name = random.choice(list(doh_providers.keys()))
        provider = doh_providers[provider_name]
        timestamp = base_time + timedelta(seconds=event_id)

        records.append({
            "timestamp": timestamp.isoformat() + "Z",
            "client_ip": client_ip,
            "server_ip": random.choice(provider["ips"]),
            "server_port": 443,
            "protocol": "HTTPS",
            "domain": random.choice(provider["domains"]),
            "path": "/dns-query",
            "tls_version": "TLS 1.3",
        })
        event_id += 1

    # Shuffle for realistic ordering
    random.shuffle(records)

    return records


def main():
    """Generate and save sample DNS traffic."""
    import sys
    from pathlib import Path

    output_file = Path(__file__).parent / "sample_dns_traffic.json"

    print("Generating sample DNS traffic logs...", file=sys.stderr)

    # Generate 500 events
    traffic = generate_sample_traffic(num_events=500, seed=42)

    # Save to JSON
    with open(output_file, "w") as f:
        json.dump(traffic, f, indent=2)

    print(f"Generated {len(traffic)} connection records", file=sys.stderr)
    print(f"Saved to: {output_file}", file=sys.stderr)

    # Print summary
    protocols = {}
    for record in traffic:
        proto = record["protocol"]
        protocols[proto] = protocols.get(proto, 0) + 1

    print("\nProtocol Distribution:", file=sys.stderr)
    for proto, count in sorted(protocols.items()):
        pct = count / len(traffic) * 100
        print(f"  {proto:15} {count:4} ({pct:5.1f}%)", file=sys.stderr)

    # Port distribution
    ports = {}
    for record in traffic:
        port = record["server_port"]
        ports[port] = ports.get(port, 0) + 1

    print("\nPort Distribution:", file=sys.stderr)
    for port, count in sorted(ports.items()):
        pct = count / len(traffic) * 100
        print(f"  Port {port:5} {count:4} ({pct:5.1f}%)", file=sys.stderr)


if __name__ == "__main__":
    main()
