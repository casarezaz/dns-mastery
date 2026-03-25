#!/usr/bin/env python3
"""
Zone Transfer Auditor — Lab 02 of the DNS Mastery Study Plan
=============================================================
A security auditing tool that tests DNS servers for unauthorized AXFR zone
transfers, analyzes leaked zone data for sensitive records, and produces
actionable audit reports with MITRE ATT&CK mapping.

MITRE ATT&CK Mapping:
    T1590.002 — Gather Victim Network Information: DNS
    T1018     — Remote System Discovery (via leaked A/AAAA records)
    T1526     — Cloud Service Discovery (via leaked SRV/CNAME records)

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import socket
import struct
import sys
import textwrap
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from typing import Optional

# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------
__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DNS_PORT = 53
AXFR_QTYPE = 252
DEFAULT_TIMEOUT = 10
SENSITIVE_TXT_PATTERNS = [
    (re.compile(r"v=spf1", re.IGNORECASE), "SPF record"),
    (re.compile(r"v=DKIM1", re.IGNORECASE), "DKIM key"),
    (re.compile(r"v=DMARC1", re.IGNORECASE), "DMARC policy"),
    (re.compile(r"_?api[_-]?key", re.IGNORECASE), "Potential API key"),
    (re.compile(r"token", re.IGNORECASE), "Potential token/secret"),
    (re.compile(r"password", re.IGNORECASE), "Potential credential"),
]
INTERNAL_HOSTNAME_PATTERNS = [
    re.compile(r"\b(dev|stage|staging|internal|priv|test|uat|qa|preprod)\b", re.IGNORECASE),
    re.compile(r"\b(admin|mgmt|management|vpn|db|database|backup)\b", re.IGNORECASE),
    re.compile(r"\b(jenkins|gitlab|jira|confluence|grafana|kibana|prometheus)\b", re.IGNORECASE),
    re.compile(r"\b(k8s|kube|docker|swarm|consul|vault|ansible|puppet)\b", re.IGNORECASE),
]
RFC1918_NETWORKS = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
]

# RDTYPE number → name mapping (common types)
RDTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 99: "SPF",
    256: "URI", 257: "CAA",
}


# ---------------------------------------------------------------------------
# Low-level DNS wire protocol helpers (zero external dependencies)
# ---------------------------------------------------------------------------
def _encode_name(name: str) -> bytes:
    """Encode a domain name into DNS wire format."""
    parts = name.rstrip(".").split(".")
    result = b""
    for part in parts:
        encoded = part.encode("ascii")
        result += struct.pack("B", len(encoded)) + encoded
    result += b"\x00"
    return result


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS wire-format name, handling compression pointers."""
    labels = []
    jumped = False
    original_offset = offset
    max_jumps = 50
    jumps = 0

    while True:
        if offset >= len(data):
            break
        length = data[offset]

        if (length & 0xC0) == 0xC0:
            # Compression pointer
            if not jumped:
                original_offset = offset + 2
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            offset = pointer
            jumped = True
            jumps += 1
            if jumps > max_jumps:
                break
            continue

        if length == 0:
            offset += 1
            break

        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    name = ".".join(labels)
    return name, original_offset if jumped else offset


def _decode_rdata_simple(rdtype: int, rdata: bytes, msg: bytes, rdata_offset: int) -> str:
    """Decode common RDATA types into human-readable strings."""
    if rdtype == 1 and len(rdata) == 4:  # A
        return socket.inet_ntoa(rdata)
    elif rdtype == 28 and len(rdata) == 16:  # AAAA
        return socket.inet_ntop(socket.AF_INET6, rdata)
    elif rdtype in (2, 5, 12):  # NS, CNAME, PTR
        name, _ = _decode_name(msg, rdata_offset)
        return name
    elif rdtype == 15:  # MX
        pref = struct.unpack("!H", rdata[:2])[0]
        exchange, _ = _decode_name(msg, rdata_offset + 2)
        return f"{pref} {exchange}"
    elif rdtype == 16:  # TXT
        texts = []
        i = 0
        while i < len(rdata):
            tlen = rdata[i]
            i += 1
            texts.append(rdata[i:i + tlen].decode("utf-8", errors="replace"))
            i += tlen
        return " ".join(texts)
    elif rdtype == 6:  # SOA
        mname, off = _decode_name(msg, rdata_offset)
        rname, off = _decode_name(msg, off)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[off:off + 20])
        return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
    elif rdtype == 33:  # SRV
        priority, weight, port = struct.unpack("!HHH", rdata[:6])
        target, _ = _decode_name(msg, rdata_offset + 6)
        return f"{priority} {weight} {port} {target}"
    elif rdtype == 257:  # CAA
        flags = rdata[0]
        tag_len = rdata[1]
        tag = rdata[2:2 + tag_len].decode("ascii", errors="replace")
        value = rdata[2 + tag_len:].decode("utf-8", errors="replace")
        return f'{flags} {tag} "{value}"'
    else:
        return rdata.hex()


# ---------------------------------------------------------------------------
# DNS Query and AXFR Implementation
# ---------------------------------------------------------------------------
def _build_axfr_query(domain: str, txn_id: int = None) -> bytes:
    """Build an AXFR query packet."""
    if txn_id is None:
        import random
        txn_id = random.randint(0, 0xFFFF)

    # Header: ID, flags=0x0000 (standard query), QDCOUNT=1
    header = struct.pack("!HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = _encode_name(domain) + struct.pack("!HH", AXFR_QTYPE, 1)  # QTYPE=AXFR, QCLASS=IN
    return header + question


def _build_ns_query(domain: str, txn_id: int = None) -> bytes:
    """Build an NS query packet."""
    if txn_id is None:
        import random
        txn_id = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)  # RD=1
    question = _encode_name(domain) + struct.pack("!HH", 2, 1)  # QTYPE=NS, QCLASS=IN
    return header + question


def _send_udp_query(query: bytes, server: str, timeout: int) -> bytes:
    """Send a DNS query over UDP and return the response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, DNS_PORT))
        data, _ = sock.recvfrom(65535)
        return data
    finally:
        sock.close()


def _recv_tcp_message(sock: socket.socket) -> Optional[bytes]:
    """Receive a length-prefixed TCP DNS message."""
    length_data = b""
    while len(length_data) < 2:
        chunk = sock.recv(2 - len(length_data))
        if not chunk:
            return None
        length_data += chunk

    msg_len = struct.unpack("!H", length_data)[0]
    msg_data = b""
    while len(msg_data) < msg_len:
        chunk = sock.recv(msg_len - len(msg_data))
        if not chunk:
            return None
        msg_data += chunk
    return msg_data


def _parse_response_records(data: bytes) -> list[dict]:
    """Parse all answer records from a DNS response message."""
    records = []
    if len(data) < 12:
        return records

    txn_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    offset = 12

    # Skip question section
    for _ in range(qdcount):
        _, offset = _decode_name(data, offset)
        offset += 4  # QTYPE + QCLASS

    # Parse answer + authority + additional
    total_rr = ancount + nscount + arcount
    for _ in range(total_rr):
        if offset >= len(data):
            break
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rdtype, rdclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata_offset = offset
        rdata = data[offset:offset + rdlength]
        offset += rdlength

        rdata_str = _decode_rdata_simple(rdtype, rdata, data, rdata_offset)
        type_name = RDTYPE_NAMES.get(rdtype, f"TYPE{rdtype}")
        records.append({
            "name": name,
            "type": type_name,
            "rdtype": rdtype,
            "ttl": ttl,
            "rdata": rdata_str,
        })

    return records


def resolve_nameservers(domain: str, timeout: int = DEFAULT_TIMEOUT) -> list[str]:
    """Resolve the authoritative nameservers for a domain."""
    nameservers = []

    # Try system resolver first
    try:
        answers = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror:
        pass

    # Query well-known public resolvers for NS records
    resolvers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    for resolver in resolvers:
        try:
            query = _build_ns_query(domain)
            resp = _send_udp_query(query, resolver, timeout)
            rcode = resp[3] & 0x0F if len(resp) > 3 else 15

            if rcode != 0:
                continue

            records = _parse_response_records(resp)
            for rec in records:
                if rec["type"] == "NS":
                    ns_name = rec["rdata"].rstrip(".")
                    nameservers.append(ns_name)

            if nameservers:
                break
        except (socket.timeout, socket.error, OSError):
            continue

    # Resolve NS hostnames to IPs
    ns_ips = {}
    for ns in set(nameservers):
        try:
            info = socket.getaddrinfo(ns, DNS_PORT, socket.AF_INET)
            if info:
                ns_ips[ns] = info[0][4][0]
        except socket.gaierror:
            pass

    return list(ns_ips.items())  # [(hostname, ip), ...]


def attempt_zone_transfer(domain: str, server_ip: str, server_name: str,
                          timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Attempt an AXFR zone transfer against a single server.
    Returns a result dict with status, records, timing, and error info.
    """
    result = {
        "server_name": server_name,
        "server_ip": server_ip,
        "domain": domain,
        "transfer_allowed": False,
        "records": [],
        "record_count": 0,
        "soa_count": 0,
        "elapsed_ms": 0,
        "error": None,
        "rcode": None,
    }

    start = time.monotonic()
    query = _build_axfr_query(domain)
    # TCP length prefix
    tcp_msg = struct.pack("!H", len(query)) + query

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server_ip, DNS_PORT))
        sock.sendall(tcp_msg)

        all_records = []
        soa_count = 0

        while True:
            msg = _recv_tcp_message(sock)
            if msg is None:
                break

            # Check RCODE in first message
            if not all_records:
                if len(msg) >= 4:
                    rcode = msg[3] & 0x0F
                    result["rcode"] = rcode
                    if rcode == 5:  # REFUSED
                        result["error"] = "Transfer refused (RCODE=REFUSED)"
                        break
                    elif rcode == 9:  # NOTAUTH
                        result["error"] = "Not authoritative (RCODE=NOTAUTH)"
                        break
                    elif rcode != 0:
                        result["error"] = f"Server returned RCODE={rcode}"
                        break

            records = _parse_response_records(msg)
            if not records and not all_records:
                result["error"] = "Empty response — transfer likely refused"
                break

            for rec in records:
                all_records.append(rec)
                if rec["type"] == "SOA":
                    soa_count += 1

            # AXFR ends with second SOA
            if soa_count >= 2:
                break

        sock.close()

        elapsed = (time.monotonic() - start) * 1000
        result["elapsed_ms"] = round(elapsed, 1)

        if all_records and soa_count >= 2:
            result["transfer_allowed"] = True
            result["records"] = all_records
            result["record_count"] = len(all_records)
            result["soa_count"] = soa_count
        elif all_records and not result["error"]:
            # Got some records but transfer may be incomplete
            result["transfer_allowed"] = True
            result["records"] = all_records
            result["record_count"] = len(all_records)
            result["soa_count"] = soa_count
            result["error"] = "Partial transfer (missing closing SOA)"

    except socket.timeout:
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error"] = "Connection refused"
    except OSError as e:
        result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        result["error"] = f"Network error: {e}"

    return result


# ---------------------------------------------------------------------------
# Data classes for audit findings
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str          # e.g., "Zone Transfer", "Sensitive Record", "Internal Exposure"
    title: str
    detail: str
    record: Optional[dict] = None
    mitre_technique: Optional[str] = None


@dataclass
class AuditReport:
    domain: str
    timestamp: str
    servers_tested: list = field(default_factory=list)
    transfer_results: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    record_type_distribution: dict = field(default_factory=dict)
    unique_hostnames: list = field(default_factory=list)
    unique_ips: list = field(default_factory=list)
    sensitive_records: list = field(default_factory=list)
    internal_records: list = field(default_factory=list)
    risk_score: int = 0
    risk_rating: str = "UNKNOWN"


# ---------------------------------------------------------------------------
# Zone Data Analyzer
# ---------------------------------------------------------------------------
class ZoneAnalyzer:
    """Analyzes zone transfer data for security-relevant findings."""

    def __init__(self, domain: str, records: list[dict]):
        self.domain = domain
        self.records = records
        self.findings: list[Finding] = []

    def analyze_all(self) -> list[Finding]:
        """Run all analysis modules and return findings."""
        self.findings = []
        self._analyze_record_distribution()
        self._analyze_sensitive_txt()
        self._analyze_internal_hostnames()
        self._analyze_private_ips()
        self._analyze_srv_records()
        self._analyze_mx_records()
        self._analyze_wildcard_records()
        self._analyze_low_ttls()
        self._analyze_caa_records()
        return self.findings

    def get_record_type_counts(self) -> dict[str, int]:
        counter = Counter(r["type"] for r in self.records)
        return dict(counter.most_common())

    def get_unique_hostnames(self) -> list[str]:
        names = set()
        for r in self.records:
            names.add(r["name"])
            if r["type"] in ("CNAME", "NS", "MX", "SRV"):
                # Extract target hostname from rdata
                parts = r["rdata"].split()
                if r["type"] == "MX" and len(parts) >= 2:
                    names.add(parts[1].rstrip("."))
                elif r["type"] == "SRV" and len(parts) >= 4:
                    names.add(parts[3].rstrip("."))
                elif r["type"] in ("CNAME", "NS"):
                    names.add(r["rdata"].rstrip("."))
        return sorted(names)

    def get_unique_ips(self) -> list[str]:
        ips = set()
        for r in self.records:
            if r["type"] in ("A", "AAAA"):
                ips.add(r["rdata"])
        return sorted(ips)

    def _analyze_record_distribution(self):
        counts = self.get_record_type_counts()
        total = sum(counts.values())
        self.findings.append(Finding(
            severity="INFO",
            category="Zone Summary",
            title=f"Zone contains {total} records across {len(counts)} types",
            detail=", ".join(f"{k}={v}" for k, v in counts.items()),
            mitre_technique="T1590.002",
        ))

    def _analyze_sensitive_txt(self):
        for r in self.records:
            if r["type"] != "TXT":
                continue
            for pattern, label in SENSITIVE_TXT_PATTERNS:
                if pattern.search(r["rdata"]):
                    sev = "LOW" if label.startswith("SPF") or label.startswith("DKIM") or label.startswith("DMARC") else "HIGH"
                    self.findings.append(Finding(
                        severity=sev,
                        category="Sensitive Record",
                        title=f"{label} exposed via zone transfer",
                        detail=f"{r['name']} TXT → {r['rdata'][:120]}",
                        record=r,
                        mitre_technique="T1590.002",
                    ))

    def _analyze_internal_hostnames(self):
        for r in self.records:
            name = r["name"]
            for pattern in INTERNAL_HOSTNAME_PATTERNS:
                if pattern.search(name):
                    self.findings.append(Finding(
                        severity="MEDIUM",
                        category="Internal Exposure",
                        title=f"Internal hostname pattern detected: {name}",
                        detail=f"{name} {r['type']} {r['rdata']}",
                        record=r,
                        mitre_technique="T1018",
                    ))
                    break  # One finding per record

    def _analyze_private_ips(self):
        for r in self.records:
            if r["type"] not in ("A",):
                continue
            try:
                addr = ip_address(r["rdata"])
                if isinstance(addr, IPv4Address):
                    for net in RFC1918_NETWORKS:
                        if addr in net:
                            self.findings.append(Finding(
                                severity="HIGH",
                                category="Internal Exposure",
                                title=f"RFC 1918 private IP leaked: {r['rdata']}",
                                detail=f"{r['name']} A {r['rdata']} (in {net})",
                                record=r,
                                mitre_technique="T1018",
                            ))
                            break
            except ValueError:
                pass

    def _analyze_srv_records(self):
        srv_records = [r for r in self.records if r["type"] == "SRV"]
        if srv_records:
            services = set()
            for r in srv_records:
                # SRV names are like _service._proto.domain
                name = r["name"]
                match = re.match(r"_([^.]+)\._([^.]+)\.", name)
                if match:
                    services.add(f"{match.group(1)}/{match.group(2)}")
            self.findings.append(Finding(
                severity="MEDIUM",
                category="Service Enumeration",
                title=f"{len(srv_records)} SRV records expose {len(services)} services",
                detail=f"Services: {', '.join(sorted(services))}",
                mitre_technique="T1526",
            ))

    def _analyze_mx_records(self):
        mx_records = [r for r in self.records if r["type"] == "MX"]
        if mx_records:
            exchanges = [r["rdata"].split()[-1].rstrip(".") for r in mx_records]
            self.findings.append(Finding(
                severity="LOW",
                category="Mail Infrastructure",
                title=f"{len(mx_records)} MX records expose mail infrastructure",
                detail=f"Mail servers: {', '.join(exchanges)}",
                mitre_technique="T1590.002",
            ))

    def _analyze_wildcard_records(self):
        wildcards = [r for r in self.records if r["name"].startswith("*")]
        if wildcards:
            self.findings.append(Finding(
                severity="LOW",
                category="Zone Configuration",
                title=f"{len(wildcards)} wildcard record(s) detected",
                detail=", ".join(f"{r['name']} {r['type']}" for r in wildcards),
            ))

    def _analyze_low_ttls(self):
        low_ttl = [r for r in self.records if r["ttl"] < 300 and r["type"] not in ("SOA",)]
        if len(low_ttl) > 5:
            self.findings.append(Finding(
                severity="INFO",
                category="Zone Configuration",
                title=f"{len(low_ttl)} records have TTL < 300s",
                detail="Low TTLs may indicate dynamic infrastructure or fast-flux behavior",
            ))

    def _analyze_caa_records(self):
        caa = [r for r in self.records if r["type"] == "CAA"]
        if not caa and any(r["type"] in ("A", "AAAA") for r in self.records):
            self.findings.append(Finding(
                severity="LOW",
                category="Zone Configuration",
                title="No CAA records found",
                detail="CAA records restrict which CAs can issue certificates for this domain",
            ))


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------
SEVERITY_SCORES = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 3, "INFO": 0}

def compute_risk_score(findings: list[Finding], transfer_results: list[dict]) -> tuple[int, str]:
    """Compute an overall risk score (0–100) and rating."""
    score = 0

    # Servers allowing transfers
    allowed = sum(1 for r in transfer_results if r["transfer_allowed"])
    total = len(transfer_results)
    if allowed > 0:
        score += 30  # Base penalty for any allowed transfer
        if total > 0 and allowed == total:
            score += 15  # All servers vulnerable

    # Findings
    for f in findings:
        score += SEVERITY_SCORES.get(f.severity, 0)

    score = min(score, 100)

    if score >= 70:
        rating = "CRITICAL"
    elif score >= 50:
        rating = "HIGH"
    elif score >= 30:
        rating = "MEDIUM"
    elif score >= 10:
        rating = "LOW"
    else:
        rating = "PASS"

    return score, rating


# ---------------------------------------------------------------------------
# Output Formatters
# ---------------------------------------------------------------------------
SEVERITY_SYMBOLS = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[i]"}


def format_text_report(report: AuditReport) -> str:
    """Generate a human-readable text audit report."""
    lines = []
    w = 72

    lines.append("=" * w)
    lines.append("  ZONE TRANSFER AUDIT REPORT")
    lines.append("=" * w)
    lines.append(f"  Domain     : {report.domain}")
    lines.append(f"  Timestamp  : {report.timestamp}")
    lines.append(f"  Risk Score : {report.risk_score}/100 ({report.risk_rating})")
    lines.append("=" * w)

    # --- Transfer Results ---
    lines.append("")
    lines.append("[ SERVER RESULTS ]")
    lines.append("-" * w)
    for tr in report.transfer_results:
        status = "ALLOWED" if tr["transfer_allowed"] else "DENIED"
        icon = "[!!]" if tr["transfer_allowed"] else "[OK]"
        lines.append(f"  {icon} {tr['server_name']} ({tr['server_ip']})")
        lines.append(f"       Transfer: {status}  |  Records: {tr['record_count']}  |  Time: {tr['elapsed_ms']}ms")
        if tr["error"]:
            lines.append(f"       Note: {tr['error']}")
    lines.append("")

    # --- Zone Statistics (only if we got records) ---
    if report.record_type_distribution:
        lines.append("[ ZONE STATISTICS ]")
        lines.append("-" * w)
        for rtype, count in report.record_type_distribution.items():
            bar = "#" * min(count, 40)
            lines.append(f"  {rtype:>8s} : {count:>5d}  {bar}")
        lines.append(f"  {'TOTAL':>8s} : {sum(report.record_type_distribution.values()):>5d}")
        lines.append(f"  Unique hostnames : {len(report.unique_hostnames)}")
        lines.append(f"  Unique IPs       : {len(report.unique_ips)}")
        lines.append("")

    # --- Findings ---
    lines.append("[ FINDINGS ]")
    lines.append("-" * w)

    # Group by severity
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in report.findings if f.severity == sev]
        if not sev_findings:
            continue
        for f in sev_findings:
            sym = SEVERITY_SYMBOLS.get(f.severity, "[?]")
            lines.append(f"  {sym} [{f.severity}] {f.title}")
            lines.append(f"       Category: {f.category}")
            if f.mitre_technique:
                lines.append(f"       MITRE: {f.mitre_technique}")
            # Wrap long detail lines
            for dl in textwrap.wrap(f.detail, width=w - 10):
                lines.append(f"       {dl}")
            lines.append("")

    if not report.findings:
        lines.append("  No findings (zone transfer was denied).")
        lines.append("")

    # --- MITRE ATT&CK Summary ---
    mitre_set = set()
    for f in report.findings:
        if f.mitre_technique:
            mitre_set.add(f.mitre_technique)
    if mitre_set:
        lines.append("[ MITRE ATT&CK MAPPING ]")
        lines.append("-" * w)
        technique_info = {
            "T1590.002": "Gather Victim Network Information: DNS",
            "T1018": "Remote System Discovery",
            "T1526": "Cloud Service Discovery",
        }
        for t in sorted(mitre_set):
            desc = technique_info.get(t, "")
            lines.append(f"  {t} — {desc}")
        lines.append("")

    # --- Remediation ---
    allowed_servers = [tr for tr in report.transfer_results if tr["transfer_allowed"]]
    if allowed_servers:
        lines.append("[ REMEDIATION ]")
        lines.append("-" * w)
        lines.append("  1. Restrict zone transfers to authorized secondary nameservers only.")
        lines.append("     BIND example:")
        lines.append('       options { allow-transfer { <secondary-ip>; }; };')
        lines.append("     Windows DNS: Zone Properties → Zone Transfers → uncheck")
        lines.append('       "Allow zone transfers" or restrict to listed servers.')
        lines.append("  2. Implement TSIG (Transaction Signatures) for transfer authentication.")
        lines.append("  3. Monitor DNS TCP traffic on port 53 for AXFR query types (see")
        lines.append("     detection queries below).")
        lines.append("  4. Audit all nameservers periodically with this tool.")
        lines.append("")

    lines.append("=" * w)
    lines.append("  End of Report")
    lines.append("=" * w)
    return "\n".join(lines)


def format_json_report(report: AuditReport) -> str:
    """Generate a JSON audit report."""
    data = {
        "domain": report.domain,
        "timestamp": report.timestamp,
        "risk_score": report.risk_score,
        "risk_rating": report.risk_rating,
        "servers_tested": report.servers_tested,
        "transfer_results": [],
        "record_type_distribution": report.record_type_distribution,
        "unique_hostnames": report.unique_hostnames,
        "unique_ips": report.unique_ips,
        "findings": [],
    }

    for tr in report.transfer_results:
        entry = {k: v for k, v in tr.items() if k != "records"}
        data["transfer_results"].append(entry)

    for f in report.findings:
        data["findings"].append({
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "mitre_technique": f.mitre_technique,
        })

    return json.dumps(data, indent=2)


def format_csv_records(records: list[dict]) -> str:
    """Export all transferred records as CSV."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["name", "type", "ttl", "rdata"])
    writer.writeheader()
    for r in records:
        writer.writerow({"name": r["name"], "type": r["type"], "ttl": r["ttl"], "rdata": r["rdata"]})
    return output.getvalue()


# ---------------------------------------------------------------------------
# Main Audit Orchestrator
# ---------------------------------------------------------------------------
def run_audit(domain: str, servers: list[tuple[str, str]] = None,
              timeout: int = DEFAULT_TIMEOUT, verbose: bool = False) -> AuditReport:
    """
    Orchestrate a full zone transfer audit for a domain.

    Parameters:
        domain:  Target domain (e.g., 'example.com')
        servers: Optional list of (hostname, ip) tuples. Auto-resolved if None.
        timeout: TCP connection timeout in seconds.
        verbose: Print progress to stderr.
    """
    report = AuditReport(
        domain=domain,
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )

    # Resolve nameservers if not provided
    if not servers:
        if verbose:
            print(f"[*] Resolving nameservers for {domain}...", file=sys.stderr)
        servers = resolve_nameservers(domain, timeout)
        if not servers:
            if verbose:
                print(f"[!] No nameservers found for {domain}", file=sys.stderr)
            report.findings.append(Finding(
                severity="HIGH",
                category="Resolution",
                title="No nameservers could be resolved",
                detail=f"Failed to find NS records for {domain}",
            ))
            return report

    report.servers_tested = [{"name": ns, "ip": ip} for ns, ip in servers]
    if verbose:
        print(f"[*] Found {len(servers)} nameserver(s)", file=sys.stderr)

    # Attempt zone transfers
    all_records = []
    for ns_name, ns_ip in servers:
        if verbose:
            print(f"[*] Testing AXFR against {ns_name} ({ns_ip})...", file=sys.stderr)

        result = attempt_zone_transfer(domain, ns_ip, ns_name, timeout)
        report.transfer_results.append(result)

        if result["transfer_allowed"]:
            if verbose:
                print(f"    [!!] Transfer ALLOWED — {result['record_count']} records", file=sys.stderr)
            all_records.extend(result["records"])
        else:
            if verbose:
                reason = result["error"] or "denied"
                print(f"    [OK] Transfer denied ({reason})", file=sys.stderr)

    # Analyze zone data if we got any
    if all_records:
        # Deduplicate records
        seen = set()
        unique_records = []
        for r in all_records:
            key = (r["name"], r["type"], r["rdata"])
            if key not in seen:
                seen.add(key)
                unique_records.append(r)

        analyzer = ZoneAnalyzer(domain, unique_records)
        report.findings = analyzer.analyze_all()
        report.record_type_distribution = analyzer.get_record_type_counts()
        report.unique_hostnames = analyzer.get_unique_hostnames()
        report.unique_ips = analyzer.get_unique_ips()
        report.sensitive_records = [
            f.record for f in report.findings
            if f.record and f.category == "Sensitive Record"
        ]
        report.internal_records = [
            f.record for f in report.findings
            if f.record and f.category == "Internal Exposure"
        ]
    else:
        report.findings.append(Finding(
            severity="INFO",
            category="Zone Transfer",
            title="All tested servers denied zone transfers",
            detail="No zone data was obtained — transfer controls are in place",
        ))

    # Compute risk
    report.risk_score, report.risk_rating = compute_risk_score(
        report.findings, report.transfer_results
    )

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zone_transfer_auditor",
        description=textwrap.dedent("""\
            Zone Transfer Auditor — test DNS servers for unauthorized AXFR
            zone transfers, analyze leaked zone data, and produce security
            audit reports with MITRE ATT&CK mapping.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s example.com
              %(prog)s example.com --format json --output report.json
              %(prog)s example.com --server ns1.example.com:1.2.3.4
              %(prog)s example.com --export-records records.csv
              %(prog)s zonetransfer.me --verbose

            MITRE ATT&CK Coverage:
              T1590.002 — Gather Victim Network Information: DNS
              T1018     — Remote System Discovery
              T1526     — Cloud Service Discovery
        """),
    )

    parser.add_argument(
        "domain",
        help="Target domain to audit (e.g., example.com)",
    )
    parser.add_argument(
        "--server", "-s",
        action="append",
        metavar="HOST:IP",
        help="Specify nameserver(s) manually as hostname:ip (repeatable). "
             "If omitted, NS records are auto-resolved.",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Write report to FILE instead of stdout",
    )
    parser.add_argument(
        "--export-records",
        metavar="FILE",
        help="Export all transferred records to a CSV file",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"TCP connection timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print progress to stderr",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Parse manual server specifications
    servers = None
    if args.server:
        servers = []
        for spec in args.server:
            if ":" in spec:
                host, ip = spec.rsplit(":", 1)
                servers.append((host, ip))
            else:
                # Try to resolve
                try:
                    info = socket.getaddrinfo(spec, DNS_PORT, socket.AF_INET)
                    if info:
                        servers.append((spec, info[0][4][0]))
                except socket.gaierror:
                    print(f"[!] Cannot resolve server: {spec}", file=sys.stderr)
                    sys.exit(1)

    # Run the audit
    report = run_audit(
        domain=args.domain,
        servers=servers,
        timeout=args.timeout,
        verbose=args.verbose,
    )

    # Format output
    if args.format == "json":
        output = format_json_report(report)
    else:
        output = format_text_report(report)

    # Write report
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Export records CSV
    if args.export_records:
        all_records = []
        for tr in report.transfer_results:
            all_records.extend(tr.get("records", []))
        if all_records:
            csv_data = format_csv_records(all_records)
            with open(args.export_records, "w") as f:
                f.write(csv_data)
            if args.verbose:
                print(f"[*] Records exported to {args.export_records}", file=sys.stderr)
        else:
            print("[!] No records to export (transfers were denied)", file=sys.stderr)

    # Exit code: non-zero if transfers were allowed
    allowed = any(tr["transfer_allowed"] for tr in report.transfer_results)
    sys.exit(1 if allowed else 0)


if __name__ == "__main__":
    main()
