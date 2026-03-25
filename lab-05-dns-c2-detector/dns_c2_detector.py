#!/usr/bin/env python3
"""
DNS C2 Detector — Lab 05 of the DNS Mastery Study Plan
=======================================================
A detection engine that identifies DNS-based command-and-control (C2)
communication patterns in DNS log data. Analyzes query timing for beacon
intervals, measures subdomain entropy to detect encoded payloads, flags
anomalous query volumes, and identifies base32/base64 encoding in labels.

Supports Zeek dns.log (TSV and JSON), generic CSV, and JSON line formats.

MITRE ATT&CK Mapping:
    T1071.004 — Application Layer Protocol: DNS
    T1568.002 — Dynamic Resolution: Domain Generation Algorithms
    T1572     — Protocol Tunneling
    T1041     — Exfiltration Over C2 Channel

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
import textwrap
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants & Thresholds (tunable)
# ---------------------------------------------------------------------------
DEFAULT_THRESHOLDS = {
    "entropy_high": 3.5,           # Shannon entropy above this = suspicious
    "entropy_critical": 4.0,       # Shannon entropy above this = very suspicious
    "beacon_jitter_max": 0.20,     # Max coefficient of variation for beacon detection
    "beacon_min_queries": 10,      # Minimum queries to evaluate beaconing
    "beacon_interval_min": 1.0,    # Minimum interval (seconds) to consider
    "beacon_interval_max": 3600.0, # Maximum interval (seconds) to consider
    "label_length_suspicious": 24, # Subdomain label length above this = suspicious
    "label_length_critical": 40,   # Subdomain label length above this = very suspicious
    "volume_zscore": 3.0,          # Z-score threshold for volume anomaly
    "txt_response_suspicious": 5,  # TXT query count above this per domain = suspicious
    "min_domain_queries": 5,       # Minimum queries to a domain before analysis
}

# Base32 uses A-Z and 2-7, often with = padding
BASE32_PATTERN = re.compile(r'^[A-Z2-7]{16,}={0,6}$')
# Base64 uses A-Za-z0-9+/ with = padding
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]{16,}={0,2}$')
# Hex encoding
HEX_PATTERN = re.compile(r'^[0-9a-fA-F]{16,}$')

# Known benign high-entropy patterns (CDNs, anti-spam, DKIM, etc.)
BENIGN_PREFIXES = [
    "_dmarc.", "_domainkey.", "_spf.", "_acme-challenge.",
    "_mta-sts.", "_srv.", "_tcp.", "_udp.", "_tls.",
]
BENIGN_DOMAINS = {
    "googleapis.com", "gstatic.com", "cloudfront.net", "akamaiedge.net",
    "akadns.net", "cloudflare.com", "amazonaws.com", "azurewebsites.net",
    "trafficmanager.net", "msedge.net", "office365.com", "office.com",
    "microsoftonline.com", "windows.net",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class DNSQuery:
    """A single DNS query parsed from log data."""
    timestamp: float           # Unix epoch
    src_ip: str
    query_name: str            # Full FQDN
    query_type: str            # A, AAAA, TXT, MX, etc.
    response_code: str = ""    # NOERROR, NXDOMAIN, etc.
    answer: str = ""           # Response data if available
    server_ip: str = ""


@dataclass
class DomainProfile:
    """Aggregated analysis profile for a single base domain."""
    domain: str
    queries: list = field(default_factory=list)
    src_ips: set = field(default_factory=set)
    query_types: Counter = field(default_factory=Counter)
    subdomains: list = field(default_factory=list)
    subdomain_entropies: list = field(default_factory=list)
    intervals: list = field(default_factory=list)
    nxdomain_count: int = 0
    total_queries: int = 0


@dataclass
class Detection:
    """A single detection finding."""
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    technique: str         # Detection technique name
    domain: str
    indicator: str         # What was detected
    detail: str            # Human-readable detail
    confidence: float      # 0.0 - 1.0
    mitre_technique: str = ""
    evidence: dict = field(default_factory=dict)
    src_ips: list = field(default_factory=list)
    sample_queries: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Entropy calculation
# ---------------------------------------------------------------------------
def shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    freq = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def label_entropy(fqdn: str, base_domain: str) -> tuple[float, str]:
    """
    Calculate entropy of the subdomain portion only (stripping the base domain).
    Returns (entropy, subdomain_part).
    """
    subdomain = fqdn
    if fqdn.endswith("." + base_domain):
        subdomain = fqdn[:-(len(base_domain) + 1)]
    elif fqdn == base_domain:
        return 0.0, ""

    # Remove dots for entropy calculation (dots are structural, not data)
    flat = subdomain.replace(".", "")
    if not flat:
        return 0.0, ""

    return shannon_entropy(flat), subdomain


# ---------------------------------------------------------------------------
# Base domain extraction
# ---------------------------------------------------------------------------
def extract_base_domain(fqdn: str) -> str:
    """
    Extract the registrable base domain from an FQDN.
    Simple heuristic: takes the last two labels (or three for co.uk-style TLDs).
    """
    fqdn = fqdn.rstrip(".")
    parts = fqdn.split(".")
    if len(parts) <= 2:
        return fqdn

    # Handle common two-part TLDs
    two_part_tlds = {"co.uk", "co.jp", "com.au", "co.nz", "co.za", "com.br",
                     "co.kr", "co.in", "or.jp", "ne.jp", "ac.uk", "gov.uk"}
    if len(parts) >= 3:
        potential_tld = f"{parts[-2]}.{parts[-1]}"
        if potential_tld in two_part_tlds:
            return ".".join(parts[-3:])

    return ".".join(parts[-2:])


# ---------------------------------------------------------------------------
# Log parsers
# ---------------------------------------------------------------------------
def parse_zeek_tsv(filepath: str) -> list[DNSQuery]:
    """Parse Zeek dns.log in TSV format."""
    queries = []
    with open(filepath, "r") as f:
        headers = None
        for line in f:
            line = line.strip()
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line:
                continue
            if headers is None:
                # Try default Zeek field order
                headers = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h",
                           "id.resp_p", "proto", "trans_id", "rtt", "query",
                           "qclass", "qclass_name", "qtype", "qtype_name",
                           "rcode", "rcode_name", "AA", "TC", "RD", "RA",
                           "Z", "answers", "TTLs", "rejected"]

            fields = line.split("\t")
            record = {}
            for i, h in enumerate(headers):
                if i < len(fields):
                    record[h] = fields[i]

            ts = record.get("ts", "0")
            try:
                timestamp = float(ts)
            except ValueError:
                continue

            query_name = record.get("query", "")
            if not query_name or query_name == "-":
                continue

            queries.append(DNSQuery(
                timestamp=timestamp,
                src_ip=record.get("id.orig_h", ""),
                query_name=query_name.lower(),
                query_type=record.get("qtype_name", record.get("qtype", "")),
                response_code=record.get("rcode_name", record.get("rcode", "")),
                answer=record.get("answers", ""),
                server_ip=record.get("id.resp_h", ""),
            ))
    return queries


def parse_zeek_json(filepath: str) -> list[DNSQuery]:
    """Parse Zeek dns.log in JSON-line format."""
    queries = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            query_name = record.get("query", "")
            if not query_name:
                continue

            ts = record.get("ts", 0)
            if isinstance(ts, str):
                try:
                    ts = float(ts)
                except ValueError:
                    continue

            queries.append(DNSQuery(
                timestamp=float(ts),
                src_ip=record.get("id.orig_h", record.get("src_ip", "")),
                query_name=query_name.lower(),
                query_type=record.get("qtype_name", str(record.get("qtype", ""))),
                response_code=record.get("rcode_name", str(record.get("rcode", ""))),
                answer=str(record.get("answers", "")),
                server_ip=record.get("id.resp_h", record.get("dest_ip", "")),
            ))
    return queries


def parse_csv(filepath: str) -> list[DNSQuery]:
    """Parse generic CSV DNS log (flexible column names)."""
    queries = []
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Flexible column name mapping
            ts_str = (row.get("timestamp") or row.get("ts") or
                      row.get("time") or row.get("date") or "0")
            try:
                timestamp = float(ts_str)
            except ValueError:
                # Try ISO format
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamp = dt.timestamp()
                except (ValueError, TypeError):
                    continue

            query_name = (row.get("query") or row.get("query_name") or
                          row.get("domain") or row.get("qname") or "")
            if not query_name:
                continue

            queries.append(DNSQuery(
                timestamp=timestamp,
                src_ip=row.get("src_ip", row.get("id.orig_h", row.get("source", ""))),
                query_name=query_name.lower().rstrip("."),
                query_type=row.get("query_type", row.get("qtype", row.get("type", ""))),
                response_code=row.get("response_code", row.get("rcode", row.get("status", ""))),
                answer=row.get("answer", row.get("answers", "")),
                server_ip=row.get("server_ip", row.get("id.resp_h", row.get("dest", ""))),
            ))
    return queries


def auto_parse(filepath: str) -> list[DNSQuery]:
    """Auto-detect log format and parse."""
    path = Path(filepath)
    # Read first non-empty line to detect format
    with open(filepath, "r") as f:
        first_line = ""
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                first_line = line
                break
            elif line.startswith("#fields"):
                return parse_zeek_tsv(filepath)

    if not first_line:
        return []

    # JSON line format
    if first_line.startswith("{"):
        return parse_zeek_json(filepath)

    # CSV (has header with commas)
    if "," in first_line and any(kw in first_line.lower()
                                 for kw in ["timestamp", "query", "domain", "src_ip", "qname"]):
        return parse_csv(filepath)

    # Zeek TSV (tab-separated, numeric first field)
    if "\t" in first_line:
        return parse_zeek_tsv(filepath)

    # Default: try CSV
    return parse_csv(filepath)


# ---------------------------------------------------------------------------
# Detection modules
# ---------------------------------------------------------------------------
def build_domain_profiles(queries: list[DNSQuery],
                          min_queries: int = 5) -> dict[str, DomainProfile]:
    """Group queries by base domain and build analysis profiles."""
    domain_queries: dict[str, list[DNSQuery]] = defaultdict(list)

    for q in queries:
        base = extract_base_domain(q.query_name)
        domain_queries[base].append(q)

    profiles = {}
    for domain, dq_list in domain_queries.items():
        if len(dq_list) < min_queries:
            continue

        # Skip known benign
        if domain in BENIGN_DOMAINS:
            continue

        profile = DomainProfile(domain=domain, total_queries=len(dq_list))
        dq_list.sort(key=lambda q: q.timestamp)
        profile.queries = dq_list

        for q in dq_list:
            profile.src_ips.add(q.src_ip)
            profile.query_types[q.query_type] += 1
            if q.response_code in ("NXDOMAIN", "3"):
                profile.nxdomain_count += 1

            ent, sub = label_entropy(q.query_name, domain)
            if sub:
                profile.subdomains.append(sub)
                profile.subdomain_entropies.append(ent)

        # Calculate inter-query intervals
        timestamps = [q.timestamp for q in dq_list]
        if len(timestamps) >= 2:
            intervals = [timestamps[i + 1] - timestamps[i]
                         for i in range(len(timestamps) - 1)]
            profile.intervals = [iv for iv in intervals if iv > 0]

        profiles[domain] = profile

    return profiles


def detect_beaconing(profile: DomainProfile,
                     thresholds: dict) -> Optional[Detection]:
    """
    Detect periodic beaconing by analyzing inter-query intervals.
    C2 beacons have regular timing with low jitter.
    """
    intervals = profile.intervals
    min_count = thresholds["beacon_min_queries"]

    if len(intervals) < min_count:
        return None

    # Filter to plausible beacon intervals
    filtered = [iv for iv in intervals
                if thresholds["beacon_interval_min"] <= iv <= thresholds["beacon_interval_max"]]

    if len(filtered) < min_count:
        return None

    mean_iv = statistics.mean(filtered)
    if mean_iv == 0:
        return None

    stdev_iv = statistics.stdev(filtered) if len(filtered) > 1 else 0
    cv = stdev_iv / mean_iv  # Coefficient of variation

    if cv > thresholds["beacon_jitter_max"]:
        return None

    # Calculate confidence based on regularity and sample size
    regularity_score = max(0, 1.0 - (cv / thresholds["beacon_jitter_max"]))
    sample_score = min(1.0, len(filtered) / 50)
    confidence = (regularity_score * 0.7) + (sample_score * 0.3)

    if confidence < 0.3:
        return None

    severity = "CRITICAL" if confidence > 0.8 else "HIGH" if confidence > 0.5 else "MEDIUM"

    return Detection(
        severity=severity,
        technique="Beacon Interval Analysis",
        domain=profile.domain,
        indicator=f"Mean interval: {mean_iv:.1f}s (CV: {cv:.3f})",
        detail=(f"Detected periodic beaconing to {profile.domain}. "
                f"Mean interval {mean_iv:.1f}s with {cv:.1%} jitter across "
                f"{len(filtered)} queries. Consistent with DNS C2 beacon."),
        confidence=round(confidence, 3),
        mitre_technique="T1071.004",
        evidence={
            "mean_interval_sec": round(mean_iv, 2),
            "stdev_sec": round(stdev_iv, 2),
            "coefficient_of_variation": round(cv, 4),
            "sample_count": len(filtered),
            "median_interval_sec": round(statistics.median(filtered), 2),
        },
        src_ips=sorted(profile.src_ips),
        sample_queries=[q.query_name for q in profile.queries[:5]],
    )


def detect_high_entropy(profile: DomainProfile,
                        thresholds: dict) -> Optional[Detection]:
    """
    Detect high-entropy subdomains indicating encoded C2 data.
    """
    if not profile.subdomain_entropies:
        return None

    # Skip if all subdomains are benign patterns
    benign_count = sum(1 for sub in profile.subdomains
                       if any(sub.startswith(p.rstrip(".")) for p in BENIGN_PREFIXES))
    if benign_count == len(profile.subdomains):
        return None

    avg_entropy = statistics.mean(profile.subdomain_entropies)
    max_entropy = max(profile.subdomain_entropies)
    high_entropy_count = sum(1 for e in profile.subdomain_entropies
                             if e >= thresholds["entropy_high"])
    high_entropy_ratio = high_entropy_count / len(profile.subdomain_entropies)

    if avg_entropy < thresholds["entropy_high"] and high_entropy_ratio < 0.5:
        return None

    # Confidence based on consistency and magnitude
    if avg_entropy >= thresholds["entropy_critical"]:
        confidence = min(0.95, 0.6 + (high_entropy_ratio * 0.35))
    elif avg_entropy >= thresholds["entropy_high"]:
        confidence = min(0.8, 0.3 + (high_entropy_ratio * 0.5))
    else:
        confidence = 0.3

    severity = "CRITICAL" if confidence > 0.8 else "HIGH" if confidence > 0.5 else "MEDIUM"

    # Get example high-entropy subdomains
    examples = [(sub, ent) for sub, ent in
                zip(profile.subdomains, profile.subdomain_entropies)
                if ent >= thresholds["entropy_high"]][:5]

    return Detection(
        severity=severity,
        technique="Subdomain Entropy Analysis",
        domain=profile.domain,
        indicator=f"Avg entropy: {avg_entropy:.2f} bits ({high_entropy_ratio:.0%} above threshold)",
        detail=(f"High-entropy subdomains detected for {profile.domain}. "
                f"Average entropy {avg_entropy:.2f} bits across "
                f"{len(profile.subdomain_entropies)} unique subdomains. "
                f"{high_entropy_count} queries ({high_entropy_ratio:.0%}) exceed "
                f"the {thresholds['entropy_high']} bit threshold."),
        confidence=round(confidence, 3),
        mitre_technique="T1071.004",
        evidence={
            "avg_entropy": round(avg_entropy, 3),
            "max_entropy": round(max_entropy, 3),
            "high_entropy_count": high_entropy_count,
            "high_entropy_ratio": round(high_entropy_ratio, 3),
            "total_subdomains": len(profile.subdomain_entropies),
            "examples": [{"subdomain": s, "entropy": round(e, 2)} for s, e in examples],
        },
        src_ips=sorted(profile.src_ips),
        sample_queries=[q.query_name for q in profile.queries[:5]],
    )


def detect_encoded_labels(profile: DomainProfile,
                          thresholds: dict) -> Optional[Detection]:
    """
    Detect base32/base64/hex encoding patterns in subdomain labels.
    """
    encoded_count = 0
    encoding_types = Counter()
    examples = []

    for sub in profile.subdomains:
        labels = sub.split(".")
        for label in labels:
            if len(label) < 16:
                continue

            # Check hex BEFORE base64 (hex chars are a subset of base64)
            if HEX_PATTERN.match(label):
                encoded_count += 1
                encoding_types["hex"] += 1
                if len(examples) < 5:
                    examples.append(("hex", label))
            elif BASE32_PATTERN.match(label.upper()):
                encoded_count += 1
                encoding_types["base32"] += 1
                if len(examples) < 5:
                    examples.append(("base32", label))
            elif BASE64_PATTERN.match(label):
                encoded_count += 1
                encoding_types["base64"] += 1
                if len(examples) < 5:
                    examples.append(("base64", label))

    if encoded_count == 0:
        return None

    ratio = encoded_count / max(len(profile.subdomains), 1)
    if ratio < 0.1:
        return None

    confidence = min(0.95, 0.3 + (ratio * 0.6) + (min(encoded_count, 20) / 40))
    severity = "HIGH" if confidence > 0.6 else "MEDIUM"

    return Detection(
        severity=severity,
        technique="Encoded Label Detection",
        domain=profile.domain,
        indicator=f"{encoded_count} encoded labels ({', '.join(f'{k}={v}' for k, v in encoding_types.items())})",
        detail=(f"Detected {encoded_count} subdomain labels with encoding patterns "
                f"for {profile.domain}. Encoding types: "
                f"{', '.join(f'{k}: {v}' for k, v in encoding_types.items())}. "
                f"This pattern is consistent with DNS C2 data exfiltration."),
        confidence=round(confidence, 3),
        mitre_technique="T1041",
        evidence={
            "encoded_count": encoded_count,
            "encoding_types": dict(encoding_types),
            "ratio": round(ratio, 3),
            "examples": [{"encoding": enc, "label": lbl[:60]} for enc, lbl in examples],
        },
        src_ips=sorted(profile.src_ips),
    )


def detect_long_labels(profile: DomainProfile,
                       thresholds: dict) -> Optional[Detection]:
    """
    Detect unusually long subdomain labels (data stuffing).
    """
    long_labels = []
    for sub in profile.subdomains:
        labels = sub.split(".")
        for label in labels:
            if len(label) >= thresholds["label_length_suspicious"]:
                long_labels.append(label)

    if not long_labels:
        return None

    ratio = len(long_labels) / max(len(profile.subdomains), 1)
    avg_len = statistics.mean(len(l) for l in long_labels)
    max_len = max(len(l) for l in long_labels)

    critical_count = sum(1 for l in long_labels
                         if len(l) >= thresholds["label_length_critical"])

    confidence = min(0.9, 0.2 + (ratio * 0.4) + (critical_count * 0.1))

    if confidence < 0.25:
        return None

    severity = "HIGH" if critical_count > 3 else "MEDIUM" if len(long_labels) > 5 else "LOW"

    return Detection(
        severity=severity,
        technique="Label Length Anomaly",
        domain=profile.domain,
        indicator=f"{len(long_labels)} labels above {thresholds['label_length_suspicious']} chars (max: {max_len})",
        detail=(f"Detected {len(long_labels)} unusually long subdomain labels for "
                f"{profile.domain}. Average length: {avg_len:.0f} chars, max: {max_len} chars. "
                f"Long labels are used to pack encoded data into DNS queries."),
        confidence=round(confidence, 3),
        mitre_technique="T1572",
        evidence={
            "long_label_count": len(long_labels),
            "avg_length": round(avg_len, 1),
            "max_length": max_len,
            "critical_count": critical_count,
            "ratio": round(ratio, 3),
        },
        src_ips=sorted(profile.src_ips),
    )


def detect_txt_abuse(profile: DomainProfile,
                     thresholds: dict) -> Optional[Detection]:
    """
    Detect TXT record query abuse (common for C2 data download).
    """
    txt_count = profile.query_types.get("TXT", 0) + profile.query_types.get("16", 0)
    total = profile.total_queries

    if txt_count < thresholds["txt_response_suspicious"]:
        return None

    txt_ratio = txt_count / total
    if txt_ratio < 0.3:
        return None

    confidence = min(0.85, 0.3 + (txt_ratio * 0.3) + (min(txt_count, 50) / 100))
    severity = "HIGH" if txt_ratio > 0.7 and txt_count > 20 else "MEDIUM"

    return Detection(
        severity=severity,
        technique="TXT Record Abuse",
        domain=profile.domain,
        indicator=f"{txt_count} TXT queries ({txt_ratio:.0%} of traffic)",
        detail=(f"Excessive TXT record queries to {profile.domain}: "
                f"{txt_count} TXT queries out of {total} total ({txt_ratio:.0%}). "
                f"TXT records are commonly abused for C2 data download channels."),
        confidence=round(confidence, 3),
        mitre_technique="T1071.004",
        evidence={
            "txt_query_count": txt_count,
            "total_queries": total,
            "txt_ratio": round(txt_ratio, 3),
            "query_type_distribution": dict(profile.query_types),
        },
        src_ips=sorted(profile.src_ips),
    )


def detect_nxdomain_flood(profile: DomainProfile,
                          thresholds: dict) -> Optional[Detection]:
    """
    Detect high NXDOMAIN rates indicating DGA or failed C2 lookups.
    """
    if profile.total_queries < 10:
        return None

    nx_ratio = profile.nxdomain_count / profile.total_queries
    if nx_ratio < 0.5 or profile.nxdomain_count < 5:
        return None

    confidence = min(0.9, 0.3 + (nx_ratio * 0.5) + (min(profile.nxdomain_count, 50) / 100))
    severity = "HIGH" if nx_ratio > 0.8 else "MEDIUM"

    return Detection(
        severity=severity,
        technique="NXDOMAIN Flood Detection",
        domain=profile.domain,
        indicator=f"{profile.nxdomain_count} NXDOMAIN responses ({nx_ratio:.0%})",
        detail=(f"High NXDOMAIN rate for {profile.domain}: "
                f"{profile.nxdomain_count}/{profile.total_queries} queries returned "
                f"NXDOMAIN ({nx_ratio:.0%}). Consistent with DGA activity or "
                f"failed C2 domain lookups."),
        confidence=round(confidence, 3),
        mitre_technique="T1568.002",
        evidence={
            "nxdomain_count": profile.nxdomain_count,
            "total_queries": profile.total_queries,
            "nxdomain_ratio": round(nx_ratio, 3),
        },
        src_ips=sorted(profile.src_ips),
    )


def detect_volume_anomaly(profiles: dict[str, DomainProfile],
                          thresholds: dict) -> list[Detection]:
    """
    Detect domains with anomalous query volumes using z-score.
    """
    detections = []
    volumes = [p.total_queries for p in profiles.values()]

    if len(volumes) < 5:
        return detections

    mean_vol = statistics.mean(volumes)
    stdev_vol = statistics.stdev(volumes) if len(volumes) > 1 else 0

    if stdev_vol == 0:
        return detections

    for domain, profile in profiles.items():
        zscore = (profile.total_queries - mean_vol) / stdev_vol
        if zscore < thresholds["volume_zscore"]:
            continue

        confidence = min(0.85, 0.3 + (zscore / 10))
        severity = "HIGH" if zscore > 5 else "MEDIUM"

        detections.append(Detection(
            severity=severity,
            technique="Volume Anomaly Detection",
            domain=domain,
            indicator=f"Z-score: {zscore:.1f} ({profile.total_queries} queries vs mean {mean_vol:.0f})",
            detail=(f"Anomalous query volume to {domain}: {profile.total_queries} queries "
                    f"(z-score {zscore:.1f}, mean across all domains: {mean_vol:.0f}). "
                    f"Excessive DNS queries to a single domain may indicate C2 or tunneling."),
            confidence=round(confidence, 3),
            mitre_technique="T1071.004",
            evidence={
                "query_count": profile.total_queries,
                "mean_volume": round(mean_vol, 1),
                "stdev_volume": round(stdev_vol, 1),
                "zscore": round(zscore, 2),
            },
            src_ips=sorted(profile.src_ips),
        ))

    return detections


# ---------------------------------------------------------------------------
# Composite scoring
# ---------------------------------------------------------------------------
def compute_threat_score(detections: list[Detection]) -> tuple[int, str]:
    """
    Compute a composite threat score for a domain based on multiple detections.
    Multiple detection techniques firing = higher confidence.
    """
    if not detections:
        return 0, "CLEAN"

    severity_weights = {"CRITICAL": 35, "HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 0}
    score = 0

    for d in detections:
        weight = severity_weights.get(d.severity, 0)
        score += int(weight * d.confidence)

    # Bonus for multiple techniques detecting the same domain
    techniques = set(d.technique for d in detections)
    if len(techniques) >= 3:
        score += 20
    elif len(techniques) >= 2:
        score += 10

    score = min(score, 100)

    if score >= 80:
        rating = "CRITICAL"
    elif score >= 60:
        rating = "HIGH"
    elif score >= 40:
        rating = "MEDIUM"
    elif score >= 20:
        rating = "LOW"
    else:
        rating = "CLEAN"

    return score, rating


# ---------------------------------------------------------------------------
# Analysis orchestrator
# ---------------------------------------------------------------------------
def analyze(queries: list[DNSQuery],
            thresholds: dict = None) -> dict:
    """
    Run all detection modules against parsed DNS queries.
    Returns a structured results dictionary.
    """
    if thresholds is None:
        thresholds = DEFAULT_THRESHOLDS.copy()

    profiles = build_domain_profiles(queries, thresholds["min_domain_queries"])

    # Run per-domain detections
    all_detections: dict[str, list[Detection]] = defaultdict(list)

    for domain, profile in profiles.items():
        detectors = [
            detect_beaconing,
            detect_high_entropy,
            detect_encoded_labels,
            detect_long_labels,
            detect_txt_abuse,
            detect_nxdomain_flood,
        ]
        for detector in detectors:
            result = detector(profile, thresholds)
            if result:
                all_detections[domain].append(result)

    # Volume anomaly runs across all profiles
    volume_detections = detect_volume_anomaly(profiles, thresholds)
    for d in volume_detections:
        all_detections[d.domain].append(d)

    # Score each domain
    domain_scores = {}
    for domain, dets in all_detections.items():
        score, rating = compute_threat_score(dets)
        domain_scores[domain] = {"score": score, "rating": rating}

    # Build results
    results = {
        "summary": {
            "total_queries_analyzed": len(queries),
            "unique_domains_profiled": len(profiles),
            "domains_with_detections": len(all_detections),
            "total_detections": sum(len(d) for d in all_detections.values()),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "detections_by_domain": {},
        "thresholds_used": thresholds,
    }

    # Sort domains by threat score (highest first)
    sorted_domains = sorted(all_detections.keys(),
                            key=lambda d: domain_scores[d]["score"],
                            reverse=True)

    for domain in sorted_domains:
        dets = all_detections[domain]
        results["detections_by_domain"][domain] = {
            "threat_score": domain_scores[domain]["score"],
            "threat_rating": domain_scores[domain]["rating"],
            "detection_count": len(dets),
            "techniques_triggered": list(set(d.technique for d in dets)),
            "src_ips": sorted(set(ip for d in dets for ip in d.src_ips)),
            "detections": [
                {
                    "severity": d.severity,
                    "technique": d.technique,
                    "indicator": d.indicator,
                    "detail": d.detail,
                    "confidence": d.confidence,
                    "mitre_technique": d.mitre_technique,
                    "evidence": d.evidence,
                    "sample_queries": d.sample_queries,
                }
                for d in sorted(dets, key=lambda x: x.confidence, reverse=True)
            ],
        }

    return results


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------
SEVERITY_SYMBOLS = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[i]"}
RATING_SYMBOLS = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "CLEAN": "⚪"}


def format_text_report(results: dict) -> str:
    """Generate human-readable text report."""
    lines = []
    w = 76

    lines.append("=" * w)
    lines.append("  DNS C2 DETECTION REPORT")
    lines.append("=" * w)

    s = results["summary"]
    lines.append(f"  Timestamp        : {s['timestamp']}")
    lines.append(f"  Queries Analyzed : {s['total_queries_analyzed']:,}")
    lines.append(f"  Domains Profiled : {s['unique_domains_profiled']:,}")
    lines.append(f"  Detections       : {s['total_detections']} across {s['domains_with_detections']} domain(s)")
    lines.append("=" * w)

    if not results["detections_by_domain"]:
        lines.append("")
        lines.append("  No C2 indicators detected.")
        lines.append("")
        lines.append("=" * w)
        return "\n".join(lines)

    for domain, data in results["detections_by_domain"].items():
        lines.append("")
        rating_sym = RATING_SYMBOLS.get(data["threat_rating"], "?")
        lines.append(f"  {rating_sym} {domain}")
        lines.append(f"     Threat Score: {data['threat_score']}/100 ({data['threat_rating']})")
        lines.append(f"     Techniques: {', '.join(data['techniques_triggered'])}")
        lines.append(f"     Source IPs: {', '.join(data['src_ips'][:5])}")
        lines.append(f"     {'-' * (w - 5)}")

        for det in data["detections"]:
            sym = SEVERITY_SYMBOLS.get(det["severity"], "[?]")
            lines.append(f"     {sym} [{det['severity']}] {det['technique']}")
            lines.append(f"         Confidence: {det['confidence']:.0%}")
            lines.append(f"         Indicator: {det['indicator']}")
            if det["mitre_technique"]:
                lines.append(f"         MITRE: {det['mitre_technique']}")
            for dl in textwrap.wrap(det["detail"], width=w - 12):
                lines.append(f"         {dl}")

            if det.get("sample_queries"):
                lines.append(f"         Sample queries:")
                for sq in det["sample_queries"][:3]:
                    lines.append(f"           - {sq}")
            lines.append("")

    # MITRE summary
    mitre_set = set()
    for data in results["detections_by_domain"].values():
        for det in data["detections"]:
            if det["mitre_technique"]:
                mitre_set.add(det["mitre_technique"])

    if mitre_set:
        lines.append("[ MITRE ATT&CK COVERAGE ]")
        lines.append("-" * w)
        technique_info = {
            "T1071.004": "Application Layer Protocol: DNS",
            "T1568.002": "Dynamic Resolution: Domain Generation Algorithms",
            "T1572": "Protocol Tunneling",
            "T1041": "Exfiltration Over C2 Channel",
        }
        for t in sorted(mitre_set):
            desc = technique_info.get(t, "")
            lines.append(f"  {t} — {desc}")
        lines.append("")

    lines.append("=" * w)
    lines.append("  End of Report")
    lines.append("=" * w)
    return "\n".join(lines)


def format_json_report(results: dict) -> str:
    """Generate JSON report."""
    return json.dumps(results, indent=2, default=str)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns_c2_detector",
        description=textwrap.dedent("""\
            DNS C2 Detector — identify command-and-control communication
            patterns in DNS log data. Detects beaconing, high-entropy
            subdomains, encoded payloads, volume anomalies, TXT abuse,
            and NXDOMAIN floods.
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s dns.log
              %(prog)s --format json --output report.json zeek_dns.log
              %(prog)s --threshold entropy_high=3.8 captured.csv
              %(prog)s --verbose dns_queries.json

            Supported log formats:
              - Zeek dns.log (TSV or JSON)
              - Generic CSV with timestamp + query columns
              - JSON lines with DNS query fields

            MITRE ATT&CK Coverage:
              T1071.004 — Application Layer Protocol: DNS
              T1568.002 — Dynamic Resolution: DGA
              T1572     — Protocol Tunneling
              T1041     — Exfiltration Over C2 Channel
        """),
    )

    parser.add_argument(
        "logfile",
        nargs="+",
        help="DNS log file(s) to analyze (Zeek TSV/JSON, CSV, or JSON lines)",
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
        "--threshold",
        action="append",
        metavar="KEY=VALUE",
        help="Override a detection threshold (repeatable). "
             "E.g.: --threshold entropy_high=3.8 --threshold beacon_jitter_max=0.15",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        metavar="N",
        help="Only report domains with threat score >= N (default: 0)",
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

    # Build thresholds
    thresholds = DEFAULT_THRESHOLDS.copy()
    if args.threshold:
        for spec in args.threshold:
            if "=" not in spec:
                print(f"[!] Invalid threshold format: {spec} (expected KEY=VALUE)", file=sys.stderr)
                sys.exit(1)
            key, val = spec.split("=", 1)
            if key not in thresholds:
                print(f"[!] Unknown threshold key: {key}", file=sys.stderr)
                print(f"    Valid keys: {', '.join(sorted(thresholds.keys()))}", file=sys.stderr)
                sys.exit(1)
            try:
                thresholds[key] = type(thresholds[key])(val)
            except ValueError:
                print(f"[!] Invalid value for {key}: {val}", file=sys.stderr)
                sys.exit(1)

    # Parse all log files
    all_queries = []
    for logfile in args.logfile:
        if args.verbose:
            print(f"[*] Parsing {logfile}...", file=sys.stderr)
        try:
            queries = auto_parse(logfile)
            if args.verbose:
                print(f"    Loaded {len(queries)} queries", file=sys.stderr)
            all_queries.extend(queries)
        except FileNotFoundError:
            print(f"[!] File not found: {logfile}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error parsing {logfile}: {e}", file=sys.stderr)
            sys.exit(1)

    if not all_queries:
        print("[!] No DNS queries found in input file(s)", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"[*] Analyzing {len(all_queries)} total queries...", file=sys.stderr)

    # Run analysis
    results = analyze(all_queries, thresholds)

    # Apply minimum score filter
    if args.min_score > 0:
        results["detections_by_domain"] = {
            domain: data for domain, data in results["detections_by_domain"].items()
            if data["threat_score"] >= args.min_score
        }

    if args.verbose:
        s = results["summary"]
        print(f"[*] Found {s['total_detections']} detections across "
              f"{s['domains_with_detections']} domain(s)", file=sys.stderr)

    # Format output
    if args.format == "json":
        output = format_json_report(results)
    else:
        output = format_text_report(results)

    # Write
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        if args.verbose:
            print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code: non-zero if C2 indicators detected
    has_detections = bool(results["detections_by_domain"])
    sys.exit(1 if has_detections else 0)


if __name__ == "__main__":
    main()
