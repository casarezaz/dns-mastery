#!/usr/bin/env python3
"""
Encrypted DNS Analyzer — Lab 09 of the DNS Mastery Study Plan
==============================================================
A comprehensive analyzer for DNS encryption protocols (DoH, DoT, DoQ) that detects
which protocol is used, identifies bypass attempts, validates encryption configuration,
and generates protocol comparison matrices. Works with simulated network metadata
(JSON/CSV logs of connection data).

DNS Encryption Protocols Analyzed:
  - DoH (DNS over HTTPS):  HTTPS (443) with /dns-query path or known provider IPs
  - DoT (DNS over TLS):    TCP/TLS port 853
  - DoQ (DNS over QUIC):   QUIC/UDP port 853
  - Plaintext:             UDP/TCP port 53

Bypass Detection:
  Flags clients connecting to external DoH providers instead of enterprise resolver.
  Known DoH providers: Google, Cloudflare, Quad9, NextDNS, OpenDNS, etc.

MITRE ATT&CK Mapping:
    T1071.004 — Application Layer Protocol: DNS
    T1573.002 — Encrypted Channel: Asymmetric Cryptography
    T1572   — Protocol Tunneling (DoH as tunnel)

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from pathlib import Path
from typing import Optional, Union

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants & Enumerations
# ---------------------------------------------------------------------------

class ProtocolType(Enum):
    """DNS encryption protocol types."""
    PLAINTEXT = "plaintext"
    DOT = "DoT"
    DOH = "DoH"
    DOQ = "DoQ"
    UNKNOWN = "unknown"


class BypassSeverity(Enum):
    """DoH bypass severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Known DoH provider database: (domain, IPs, name)
DOH_PROVIDERS = {
    "google": {
        "domains": ["dns.google", "dns.google.com"],
        "ips": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
        "name": "Google DNS",
    },
    "cloudflare": {
        "domains": ["1.1.1.1", "one.one.one.one"],
        "ips": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        "name": "Cloudflare DNS",
    },
    "quad9": {
        "domains": ["dns.quad9.net"],
        "ips": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        "name": "Quad9 DNS",
    },
    "nextdns": {
        "domains": ["dns.nextdns.io"],
        "ips": [],  # NextDNS uses Anycast, varies by geography
        "name": "NextDNS",
    },
    "opendns": {
        "domains": ["dns.opendns.com"],
        "ips": ["208.67.222.222", "208.67.220.220", "2620:119:35::35", "2620:119:53::53"],
        "name": "OpenDNS",
    },
    "adguard": {
        "domains": ["dns.adguard.com"],
        "ips": ["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        "name": "AdGuard DNS",
    },
}

# Common enterprise resolver ports and patterns
ENTERPRISE_RESOLVERS = {
    "internal": re.compile(
        r"\b(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.)",
        re.IGNORECASE,
    ),
    "rfc1918": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
}

# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass
class ConnectionRecord:
    """A single network connection record from logs."""

    timestamp: str  # ISO 8601 or arbitrary timestamp
    client_ip: str
    server_ip: str
    server_port: int
    protocol: str  # TCP, UDP, TLS, QUIC, HTTPS
    domain: str = ""  # For HTTPS connections: Host header or SNI
    path: str = ""  # For HTTPS connections: URL path
    tls_version: str = ""  # For encrypted: TLS 1.2, TLS 1.3, etc.
    host_resolved: bool = False


@dataclass
class ProtocolDetection:
    """Result of protocol detection on a connection."""

    connection: ConnectionRecord
    detected_protocol: ProtocolType
    confidence: float  # 0.0 to 1.0
    reasoning: str
    is_doh_provider: bool = False
    provider_name: str = ""
    is_bypass: bool = False


@dataclass
class BypassAlert:
    """Alert for detected DoH bypass attempt."""

    client_ip: str
    provider_name: str
    severity: BypassSeverity
    reason: str
    connection_details: ConnectionRecord = None
    timestamp: str = ""
    count: int = 1  # Number of bypass attempts


@dataclass
class EncryptionReport:
    """Overall encryption coverage and statistics."""

    total_connections: int = 0
    plaintext_count: int = 0
    dot_count: int = 0
    doh_count: int = 0
    doq_count: int = 0
    unknown_count: int = 0
    encryption_coverage: float = 0.0
    plaintext_percentage: float = 0.0
    clients_per_protocol: dict = field(default_factory=dict)
    protocol_distribution: dict = field(default_factory=dict)
    bypass_alerts: list = field(default_factory=list)
    top_providers: list = field(default_factory=list)
    unencrypted_clients: list = field(default_factory=list)
    analysis_timestamp: str = ""


# ---------------------------------------------------------------------------
# Protocol Detection Functions
# ---------------------------------------------------------------------------


def _is_internal_ip(ip_str: str) -> bool:
    """Check if IP is private/internal (RFC 1918)."""
    try:
        addr = ip_address(ip_str)
        for net_str in ENTERPRISE_RESOLVERS["rfc1918"]:
            net = ip_network(net_str)
            if addr in net:
                return True
        return False
    except ValueError:
        return False


def _is_doh_provider(domain: str, ip: str) -> tuple[bool, str]:
    """Check if domain/IP matches known DoH provider."""
    for provider_key, provider_info in DOH_PROVIDERS.items():
        # Check domain match
        for provider_domain in provider_info["domains"]:
            if provider_domain in domain.lower():
                return True, provider_info["name"]

        # Check IP match
        if ip in provider_info["ips"]:
            return True, provider_info["name"]

    return False, ""


def detect_protocol(conn: ConnectionRecord) -> ProtocolDetection:
    """
    Detect DNS encryption protocol from connection metadata.

    Detection rules:
    - DoT: TCP port 853 with TLS
    - DoQ: QUIC/UDP port 853
    - DoH: HTTPS to port 443 with /dns-query path or known provider
    - Plaintext: UDP/TCP port 53
    """
    reasoning = ""
    protocol = ProtocolType.UNKNOWN
    confidence = 0.0
    is_provider = False
    provider_name = ""

    # Check for DoT (DNS over TLS)
    if conn.server_port == 853 and conn.protocol.upper() in ["TCP", "TLS"]:
        protocol = ProtocolType.DOT
        confidence = 0.95
        reasoning = f"TCP/TLS connection to port 853 (DoT standard port)"

    # Check for DoQ (DNS over QUIC)
    elif conn.server_port == 853 and conn.protocol.upper() in ["QUIC", "UDP"]:
        protocol = ProtocolType.DOQ
        confidence = 0.95
        reasoning = f"QUIC/UDP connection to port 853 (DoQ standard port)"

    # Check for DoH (DNS over HTTPS)
    elif conn.server_port == 443 and conn.protocol.upper() in ["HTTPS", "TLS", "TCP"]:
        # Check for /dns-query path (highest confidence)
        if "/dns-query" in conn.path.lower():
            protocol = ProtocolType.DOH
            confidence = 0.99
            reasoning = f"HTTPS to port 443 with /dns-query path (RFC 8484)"
            # Also check if it's a known provider for tracking
            is_provider, provider_name = _is_doh_provider(conn.domain, conn.server_ip)
        # Check for known DoH provider
        else:
            is_provider, provider_name = _is_doh_provider(conn.domain, conn.server_ip)
            if is_provider:
                protocol = ProtocolType.DOH
                confidence = 0.90
                reasoning = (
                    f"HTTPS connection to known DoH provider: {provider_name}"
                )

    # Check for plaintext DNS
    elif conn.server_port == 53 and conn.protocol.upper() in ["UDP", "TCP"]:
        protocol = ProtocolType.PLAINTEXT
        confidence = 0.99
        reasoning = "Unencrypted DNS on standard port 53"

    # Fallback to domain/port heuristics
    elif conn.domain:
        is_provider, provider_name = _is_doh_provider(conn.domain, conn.server_ip)
        if is_provider:
            protocol = ProtocolType.DOH
            confidence = 0.85
            reasoning = f"Known DoH provider domain detected: {provider_name}"

    if protocol == ProtocolType.UNKNOWN:
        reasoning = (
            f"Could not determine: port={conn.server_port}, "
            f"protocol={conn.protocol}, domain={conn.domain}"
        )

    return ProtocolDetection(
        connection=conn,
        detected_protocol=protocol,
        confidence=confidence,
        reasoning=reasoning,
        is_doh_provider=is_provider,
        provider_name=provider_name,
    )


# ---------------------------------------------------------------------------
# Bypass Detection Functions
# ---------------------------------------------------------------------------


def detect_bypass(
    detections: list[ProtocolDetection], enterprise_resolver_ips: list[str] = None
) -> list[BypassAlert]:
    """
    Detect DoH bypass attempts: clients connecting to external DoH providers
    instead of enterprise resolver.

    Args:
        detections: List of ProtocolDetection results
        enterprise_resolver_ips: Expected internal resolver IPs (default: auto-detect)

    Returns:
        List of BypassAlert objects
    """
    if enterprise_resolver_ips is None:
        enterprise_resolver_ips = []

    alerts = []
    client_providers = defaultdict(Counter)

    # Group detections by protocol and provider
    for det in detections:
        if (
            det.detected_protocol == ProtocolType.DOH
            and det.is_doh_provider
            and not _is_internal_ip(det.connection.server_ip)
        ):
            client_ip = det.connection.client_ip
            provider = det.provider_name
            client_providers[client_ip][provider] += 1

    # Generate alerts for external DoH usage
    for client_ip, providers in client_providers.items():
        for provider, count in providers.items():
            severity = BypassSeverity.HIGH if count > 5 else BypassSeverity.MEDIUM

            alert = BypassAlert(
                client_ip=client_ip,
                provider_name=provider,
                severity=severity,
                reason=f"Client using external DoH provider ({provider}) "
                f"instead of enterprise resolver",
                count=count,
            )
            alerts.append(alert)

    return alerts


# ---------------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------------


def analyze_connections(
    connections: list[ConnectionRecord],
) -> tuple[list[ProtocolDetection], EncryptionReport]:
    """
    Analyze a batch of connections and generate encryption report.

    Returns:
        (list of ProtocolDetection results, EncryptionReport with statistics)
    """
    detections = []
    for conn in connections:
        det = detect_protocol(conn)
        detections.append(det)

    # Generate bypass alerts
    bypass_alerts = detect_bypass(detections)

    # Build report
    report = EncryptionReport()
    report.total_connections = len(detections)
    report.analysis_timestamp = datetime.now(timezone.utc).isoformat()

    # Count protocols
    protocol_counts = Counter()
    client_protocols = defaultdict(Counter)
    provider_usage = Counter()

    for det in detections:
        protocol_counts[det.detected_protocol] += 1
        client_protocols[det.connection.client_ip][det.detected_protocol] += 1

        if det.is_doh_provider:
            provider_usage[det.provider_name] += 1

    # Set counts
    report.plaintext_count = protocol_counts.get(ProtocolType.PLAINTEXT, 0)
    report.dot_count = protocol_counts.get(ProtocolType.DOT, 0)
    report.doh_count = protocol_counts.get(ProtocolType.DOH, 0)
    report.doq_count = protocol_counts.get(ProtocolType.DOQ, 0)
    report.unknown_count = protocol_counts.get(ProtocolType.UNKNOWN, 0)

    # Calculate coverage
    encrypted = report.doh_count + report.dot_count + report.doq_count
    if report.total_connections > 0:
        report.encryption_coverage = encrypted / report.total_connections
        report.plaintext_percentage = report.plaintext_count / report.total_connections

    # Per-client protocol distribution
    for client_ip, protocols in client_protocols.items():
        report.clients_per_protocol[client_ip] = dict(protocols)

    # Protocol distribution summary
    report.protocol_distribution = {
        "plaintext": report.plaintext_count,
        "DoT": report.dot_count,
        "DoH": report.doh_count,
        "DoQ": report.doq_count,
        "unknown": report.unknown_count,
    }

    # Top providers
    report.top_providers = [
        (name, count) for name, count in provider_usage.most_common(5)
    ]

    # Clients using plaintext DNS
    report.unencrypted_clients = [
        client_ip
        for client_ip, protocols in client_protocols.items()
        if ProtocolType.PLAINTEXT in protocols
    ]

    report.bypass_alerts = bypass_alerts

    return detections, report


# ---------------------------------------------------------------------------
# Comparison & Reporting Functions
# ---------------------------------------------------------------------------


def generate_protocol_comparison_matrix() -> dict:
    """
    Generate comprehensive DoH/DoT/DoQ feature comparison matrix.

    Returns:
        Dictionary with comparison metrics
    """
    comparison = {
        "protocols": {
            "DoH": {
                "name": "DNS over HTTPS",
                "rfc": "RFC 8484",
                "port": 443,
                "transport": "HTTPS/TLS",
                "encryption": "TLS 1.2+",
                "authentication": "Certificate-based (HTTPS PKI)",
                "performance": "Good (HTTP/2 multiplexing)",
                "firewall_friendly": True,
                "caching": "HTTP caching possible",
                "privacy": "Mixed (HTTPS SNI leaks destination)",
                "deployability": "High (uses standard HTTPS infrastructure)",
                "client_support": "Widespread (browsers, resolvers, OS)",
                "proxy_bypass": "Difficult (indistinguishable from HTTPS)",
                "advantages": [
                    "Uses standard HTTPS (port 443)",
                    "Multiplexing via HTTP/2",
                    "Works through most firewalls",
                    "Wide browser/OS support",
                    "Reuses TLS infrastructure",
                ],
                "disadvantages": [
                    "Server IP visible in TLS handshake",
                    "HTTP/2 header compression side-channel",
                    "Higher latency than DoT",
                    "Connection overhead",
                ],
            },
            "DoT": {
                "name": "DNS over TLS",
                "rfc": "RFC 7858",
                "port": 853,
                "transport": "TLS",
                "encryption": "TLS 1.2+",
                "authentication": "Certificate-based (DNS PKI)",
                "performance": "Excellent (minimal overhead)",
                "firewall_friendly": False,
                "caching": "Standard DNS caching",
                "privacy": "Excellent (dedicated encrypted channel)",
                "deployability": "Medium (port 853 often blocked)",
                "client_support": "Growing (mobile OS, resolvers)",
                "proxy_bypass": "Impossible (dedicated port)",
                "advantages": [
                    "Dedicated encrypted channel",
                    "Low latency",
                    "Minimal overhead vs DNS",
                    "Strong privacy guarantees",
                    "Connection multiplexing possible",
                ],
                "disadvantages": [
                    "Port 853 often blocked by firewalls",
                    "Requires custom port 853 support",
                    "Less compatible than DoH",
                    "Still has TLS handshake overhead",
                ],
            },
            "DoQ": {
                "name": "DNS over QUIC",
                "rfc": "RFC 9250",
                "port": 853,
                "transport": "QUIC/UDP",
                "encryption": "QUIC (TLS 1.3 embedded)",
                "authentication": "Certificate-based (QUIC PKI)",
                "performance": "Excellent (0-RTT, connection migration)",
                "firewall_friendly": True,
                "caching": "Standard DNS caching",
                "privacy": "Excellent (encrypted UDP)",
                "deployability": "Growing (newer standard)",
                "client_support": "Limited (emerging)",
                "proxy_bypass": "Difficult (UDP 853 less common)",
                "advantages": [
                    "0-RTT connection establishment",
                    "Connection migration (mobile)",
                    "Better mobile experience",
                    "Minimal latency",
                    "UDP port 853 less blocked than TCP",
                ],
                "disadvantages": [
                    "Emerging standard, limited support",
                    "Complex QUIC implementation",
                    "Client support still growing",
                    "May be blocked by UDP 853 filters",
                ],
            },
            "Plaintext": {
                "name": "Unencrypted DNS",
                "rfc": "RFC 1035",
                "port": 53,
                "transport": "UDP/TCP",
                "encryption": "None",
                "authentication": "None",
                "performance": "Excellent (minimal overhead)",
                "firewall_friendly": True,
                "caching": "Standard DNS caching",
                "privacy": "Terrible (all traffic visible)",
                "deployability": "Universal",
                "client_support": "Universal",
                "proxy_bypass": "N/A",
                "advantages": ["Minimal overhead", "Universal support"],
                "disadvantages": [
                    "No encryption",
                    "No authentication",
                    "Vulnerable to spoofing",
                    "Privacy risk",
                    "Can be MITM attacked",
                ],
            },
        },
        "feature_comparison": {
            "Encryption": {"DoH": "Yes", "DoT": "Yes", "DoQ": "Yes", "Plaintext": "No"},
            "Authentication": {
                "DoH": "HTTPS PKI",
                "DoT": "DNS PKI",
                "DoQ": "QUIC PKI",
                "Plaintext": "None",
            },
            "Standard Port": {
                "DoH": "443",
                "DoT": "853",
                "DoQ": "853",
                "Plaintext": "53",
            },
            "Firewall Friendly": {
                "DoH": "Yes",
                "DoT": "No",
                "DoQ": "Somewhat",
                "Plaintext": "Yes",
            },
            "Privacy": {
                "DoH": "Good",
                "DoT": "Excellent",
                "DoQ": "Excellent",
                "Plaintext": "None",
            },
            "Performance": {
                "DoH": "Good",
                "DoT": "Excellent",
                "DoQ": "Excellent",
                "Plaintext": "Excellent",
            },
            "Client Support": {
                "DoH": "Widespread",
                "DoT": "Growing",
                "DoQ": "Limited",
                "Plaintext": "Universal",
            },
            "Recommended For": {
                "DoH": "Enterprise (port 443)",
                "DoT": "Privacy-conscious users",
                "DoQ": "Mobile/modern infrastructure",
                "Plaintext": "Legacy/compatibility only",
            },
        },
    }

    return comparison


def format_text_report(
    detections: list[ProtocolDetection], report: EncryptionReport, verbose: bool = False
) -> str:
    """Format analysis as human-readable text."""
    lines = []
    lines.append("=" * 80)
    lines.append("ENCRYPTED DNS ANALYZER - ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"Analysis Timestamp: {report.analysis_timestamp}")
    lines.append("")

    # Summary statistics
    lines.append("ENCRYPTION COVERAGE SUMMARY")
    lines.append("-" * 80)
    lines.append(f"Total Connections Analyzed: {report.total_connections}")
    lines.append(f"Encrypted Connections:      {report.doh_count + report.dot_count + report.doq_count}")
    lines.append(f"  - DoH (HTTPS):            {report.doh_count}")
    lines.append(f"  - DoT (TLS 853):          {report.dot_count}")
    lines.append(f"  - DoQ (QUIC 853):         {report.doq_count}")
    lines.append(f"Plaintext DNS (port 53):    {report.plaintext_count}")
    lines.append(f"Unknown Protocol:           {report.unknown_count}")
    lines.append(f"\nEncryption Coverage:        {report.encryption_coverage:.1%}")
    lines.append(f"Plaintext Risk:             {report.plaintext_percentage:.1%}")
    lines.append("")

    # Protocol distribution
    if report.protocol_distribution:
        lines.append("PROTOCOL DISTRIBUTION")
        lines.append("-" * 80)
        for protocol, count in sorted(
            report.protocol_distribution.items(),
            key=lambda x: x[1],
            reverse=True,
        ):
            pct = (count / report.total_connections * 100) if report.total_connections else 0
            lines.append(f"  {protocol:15} {count:6} ({pct:5.1f}%)")
        lines.append("")

    # Top providers
    if report.top_providers:
        lines.append("TOP DoH PROVIDERS")
        lines.append("-" * 80)
        for provider, count in report.top_providers:
            pct = (count / report.doh_count * 100) if report.doh_count else 0
            lines.append(f"  {provider:20} {count:6} ({pct:5.1f}%)")
        lines.append("")

    # Bypass alerts
    if report.bypass_alerts:
        lines.append("DoH BYPASS ALERTS")
        lines.append("-" * 80)
        for alert in sorted(report.bypass_alerts, key=lambda x: x.severity.value):
            lines.append(
                f"  [{alert.severity.value}] {alert.client_ip:15} -> {alert.provider_name}"
            )
            lines.append(f"      Count: {alert.count}, Reason: {alert.reason}")
        lines.append("")

    # Unencrypted clients
    if report.unencrypted_clients:
        lines.append("CLIENTS USING PLAINTEXT DNS")
        lines.append("-" * 80)
        for client_ip in sorted(report.unencrypted_clients):
            lines.append(f"  {client_ip}")
        lines.append("")

    # Per-client distribution
    if verbose and report.clients_per_protocol:
        lines.append("PER-CLIENT PROTOCOL USAGE")
        lines.append("-" * 80)
        for client_ip in sorted(report.clients_per_protocol.keys()):
            protocols = report.clients_per_protocol[client_ip]
            lines.append(f"  {client_ip}:")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"    {proto.value:12} {count:6}")
        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def format_json_report(
    detections: list[ProtocolDetection], report: EncryptionReport
) -> str:
    """Format analysis as JSON."""
    output = {
        "analysis_timestamp": report.analysis_timestamp,
        "summary": {
            "total_connections": report.total_connections,
            "encryption_coverage": report.encryption_coverage,
            "plaintext_percentage": report.plaintext_percentage,
            "protocol_distribution": report.protocol_distribution,
        },
        "protocol_counts": {
            "DoH": report.doh_count,
            "DoT": report.dot_count,
            "DoQ": report.doq_count,
            "plaintext": report.plaintext_count,
            "unknown": report.unknown_count,
        },
        "top_providers": [
            {"provider": name, "count": count} for name, count in report.top_providers
        ],
        "bypass_alerts": [
            {
                "client_ip": alert.client_ip,
                "provider": alert.provider_name,
                "severity": alert.severity.value,
                "count": alert.count,
                "reason": alert.reason,
            }
            for alert in report.bypass_alerts
        ],
        "unencrypted_clients": report.unencrypted_clients,
        "detections": [
            {
                "timestamp": det.connection.timestamp,
                "client_ip": det.connection.client_ip,
                "server_ip": det.connection.server_ip,
                "server_port": det.connection.server_port,
                "detected_protocol": det.detected_protocol.value,
                "confidence": det.confidence,
                "is_doh_provider": det.is_doh_provider,
                "provider_name": det.provider_name,
            }
            for det in detections
        ],
    }

    return json.dumps(output, indent=2)


def format_csv_report(detections: list[ProtocolDetection]) -> str:
    """Format detections as CSV."""
    output = []
    output.append(
        "timestamp,client_ip,server_ip,server_port,protocol,domain,"
        "detected_protocol,confidence,is_doh_provider,provider_name"
    )

    for det in detections:
        row = [
            det.connection.timestamp,
            det.connection.client_ip,
            det.connection.server_ip,
            str(det.connection.server_port),
            det.connection.protocol,
            det.connection.domain,
            det.detected_protocol.value,
            f"{det.confidence:.2f}",
            str(det.is_doh_provider),
            det.provider_name,
        ]
        output.append(",".join(row))

    return "\n".join(output)


# ---------------------------------------------------------------------------
# I/O Functions
# ---------------------------------------------------------------------------


def load_connections_from_json(file_path: str) -> list[ConnectionRecord]:
    """Load connection records from JSON file."""
    with open(file_path, "r") as f:
        data = json.load(f)

    connections = []
    records = data if isinstance(data, list) else data.get("connections", [])

    for record in records:
        conn = ConnectionRecord(
            timestamp=record.get("timestamp", ""),
            client_ip=record.get("client_ip", ""),
            server_ip=record.get("server_ip", ""),
            server_port=record.get("server_port", 0),
            protocol=record.get("protocol", ""),
            domain=record.get("domain", ""),
            path=record.get("path", ""),
            tls_version=record.get("tls_version", ""),
        )
        connections.append(conn)

    return connections


def load_connections_from_csv(file_path: str) -> list[ConnectionRecord]:
    """Load connection records from CSV file."""
    connections = []
    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            conn = ConnectionRecord(
                timestamp=row.get("timestamp", ""),
                client_ip=row.get("client_ip", ""),
                server_ip=row.get("server_ip", ""),
                server_port=int(row.get("server_port", 0)),
                protocol=row.get("protocol", ""),
                domain=row.get("domain", ""),
                path=row.get("path", ""),
                tls_version=row.get("tls_version", ""),
            )
            connections.append(conn)

    return connections


def load_connections(file_path: str) -> list[ConnectionRecord]:
    """Auto-detect format and load connections."""
    ext = Path(file_path).suffix.lower()
    if ext == ".json":
        return load_connections_from_json(file_path)
    elif ext == ".csv":
        return load_connections_from_csv(file_path)
    else:
        raise ValueError(f"Unsupported file format: {ext}")


# ---------------------------------------------------------------------------
# CLI & Main
# ---------------------------------------------------------------------------


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Encrypted DNS Analyzer — Detect DNS encryption protocols & DoH bypasses",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """
            Examples:
              # Analyze connection log
              python3 encrypted_dns_analyzer.py connections.json

              # Generate protocol comparison matrix
              python3 encrypted_dns_analyzer.py --comparison-matrix

              # JSON output
              python3 encrypted_dns_analyzer.py connections.json --format json -o report.json

              # CSV export
              python3 encrypted_dns_analyzer.py connections.json --export-csv detections.csv
            """
        ),
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="Input file (JSON or CSV with connection records)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "--export-csv",
        help="Export detections to CSV file",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose output (per-client details)",
    )
    parser.add_argument(
        "--comparison-matrix",
        action="store_true",
        help="Generate DoH/DoT/DoQ comparison matrix",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    # Handle comparison matrix request
    if args.comparison_matrix:
        matrix = generate_protocol_comparison_matrix()
        output = json.dumps(matrix, indent=2)
        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Comparison matrix written to {args.output}")
        else:
            print(output)
        return

    # Require input file for analysis
    if not args.input_file:
        parser.error("input_file required unless using --comparison-matrix")

    # Load and analyze
    try:
        connections = load_connections(args.input_file)
    except Exception as e:
        print(f"Error loading {args.input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    detections, report = analyze_connections(connections)

    # Format output
    if args.format == "text":
        output = format_text_report(detections, report, args.verbose)
    elif args.format == "json":
        output = format_json_report(detections, report)
    else:  # csv
        output = format_csv_report(detections)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Export CSV if requested
    if args.export_csv:
        csv_output = format_csv_report(detections)
        with open(args.export_csv, "w") as f:
            f.write(csv_output)
        print(f"Detections exported to {args.export_csv}", file=sys.stderr)


if __name__ == "__main__":
    main()
