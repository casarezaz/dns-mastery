#!/usr/bin/env python3
"""
DNS Threat Hunt Playbook — Lab 12 of the DNS Mastery Study Plan
=================================================================
Comprehensive DNS threat hunting playbook with executable queries,
detection logic, and response procedures for all DNS-based threats
covered in the DNS Mastery curriculum.

Includes 10 built-in hunts covering:
  1. DNS Tunneling
  2. C2 over DNS
  3. DGA Detection
  4. DNS Cache Poisoning
  5. Zone Transfer Abuse
  6. DNSSEC Validation Failures
  7. DNS Amplification/Reflection
  8. DoH Bypass
  9. Fast-Flux Detection
  10. DNS Data Exfiltration

MITRE ATT&CK Mapping:
  T1071.004 — Application Layer Protocol: DNS
  T1572     — Protocol Tunneling
  T1568.002 — Dynamic Resolution: DGA
  T1048.003 — Exfiltration Over Alternative Protocol
  T1583.001 — Acquire Infrastructure: Domains
  T1557.004 — Adversary-in-the-Middle: DNS Spoofing
  T1590.002 — Gather Victim Network Information: DNS

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Any

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class Severity(Enum):
    """Hunt severity level."""
    INFO = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self):
        return self.name


class DataSource(Enum):
    """Data source type for hunts."""
    DNS_LOGS = "DNS Logs"
    ZEEK_DNS = "Zeek DNS"
    SPLUNK = "Splunk"
    ELASTIC = "Elastic"
    CLOUDFLARE = "Cloudflare"
    NETWORK_TRAFFIC = "Network Traffic"

    def __str__(self):
        return self.value


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------
@dataclass
class HuntQuery:
    """A single query in a hunt (SPL, KQL, or Sigma)."""
    query_type: str  # "splunk_spl", "kql", "sigma"
    query: str
    description: str


@dataclass
class Hunt:
    """A single threat hunt hypothesis."""
    hunt_id: str
    name: str
    hypothesis: str
    severity: Severity
    mitre_ids: list[str]
    data_sources: list[DataSource]
    queries: list[HuntQuery]
    detection_logic: str
    indicators_of_compromise: list[str]
    response_procedure: str
    false_positive_mitigation: str
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hunt_id": self.hunt_id,
            "name": self.name,
            "hypothesis": self.hypothesis,
            "severity": str(self.severity),
            "mitre_ids": self.mitre_ids,
            "data_sources": [str(ds) for ds in self.data_sources],
            "queries": [{"type": q.query_type, "description": q.description, "query": q.query} for q in self.queries],
            "detection_logic": self.detection_logic,
            "indicators_of_compromise": self.indicators_of_compromise,
            "response_procedure": self.response_procedure,
            "false_positive_mitigation": self.false_positive_mitigation,
            "references": self.references,
        }


@dataclass
class HuntFinding:
    """Result of a hunt execution."""
    hunt_id: str
    hunt_name: str
    severity: Severity
    timestamp: str
    indicator: str
    details: str
    suggested_response: str


@dataclass
class PlaybookExport:
    """Exported playbook document."""
    title: str
    generated_at: str
    total_hunts: int
    hunts: list[dict]
    coverage_matrix: dict
    version: str = __version__


@dataclass
class CoverageMatrix:
    """Coverage matrix: MITRE technique → hunts."""
    matrix: dict[str, list[str]] = field(default_factory=dict)  # technique → [hunt_ids]

    def add(self, technique: str, hunt_id: str):
        """Add a hunt to a technique."""
        if technique not in self.matrix:
            self.matrix[technique] = []
        if hunt_id not in self.matrix[technique]:
            self.matrix[technique].append(hunt_id)

    def to_dict(self) -> dict[str, list[str]]:
        """Return as dict."""
        return self.matrix


# ---------------------------------------------------------------------------
# Hunt Library — All 10 DNS threat hunts
# ---------------------------------------------------------------------------
def build_hunt_library() -> list[Hunt]:
    """Build the complete hunt library covering all DNS threats."""
    hunts = []

    # 1. DNS Tunneling
    hunts.append(Hunt(
        hunt_id="H001",
        name="DNS Tunneling Detection",
        hypothesis="Attackers tunnel traffic through DNS queries to exfiltrate data or establish covert channels.",
        severity=Severity.HIGH,
        mitre_ids=["T1572", "T1048.003"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect high-entropy subdomains indicating encoded tunnel data",
                query="""
source="dns.log"
| stats avg(entropy) as avg_entropy by src_ip, query_name
| where avg_entropy > 3.5
| table src_ip, query_name, avg_entropy
"""
            ),
            HuntQuery(
                query_type="kql",
                description="KQL query for tunnel detection",
                query="""
DnsQuery
| where entropy > 3.5
| summarize EntropyAvg=avg(entropy) by SrcAddr, DnsName
"""
            ),
        ],
        detection_logic=(
            "Identify DNS tunnels by analyzing subdomain entropy. Legitimate DNS queries use "
            "low-entropy labels (www, mail, etc.). Tunneling tools like iodine encode data as "
            "high-entropy base32/64 strings. Calculate Shannon entropy of subdomain labels; "
            "average > 3.5 bits/char indicates encoding."
        ),
        indicators_of_compromise=[
            "Subdomain entropy > 3.5 bits/character",
            "Long DNS labels (> 24 chars) from single source",
            "Repeating base32/64 patterns in labels",
            "Consistent query volume (100+ queries/hour to same domain)",
        ],
        response_procedure=(
            "1. Isolate the source IP from network\n"
            "2. Capture full DNS traffic for forensics\n"
            "3. Check for related DNS domains or C2 infrastructure\n"
            "4. Review process memory on source host for tunnel tools\n"
            "5. Search logs for lateral movement from compromised host"
        ),
        false_positive_mitigation=(
            "Whitelist CDN domains (cloudflare.com, akamaiedge.net). Exclude DKIM/SPF records "
            "(_dmarc, _domainkey). Verify queries to known-good infrastructure."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1572/",
            "https://attack.mitre.org/techniques/T1048/003/",
        ],
    ))

    # 2. C2 over DNS
    hunts.append(Hunt(
        hunt_id="H002",
        name="Command & Control (C2) over DNS",
        hypothesis="Malware communicates with C2 servers using DNS as the command channel.",
        severity=Severity.CRITICAL,
        mitre_ids=["T1071.004", "T1041"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect beacon-like query patterns",
                query="""
source="dns.log"
| stats count as query_count, values(timestamp) as timestamps by src_ip, query_name
| where query_count > 10
| eval intervals=array_slice(timestamps, 1, -1)
| where stddev(intervals) < 5
| table src_ip, query_name, query_count
"""
            ),
            HuntQuery(
                query_type="sigma",
                description="Sigma rule for beacon detection",
                query="""
title: DNS C2 Beacon Detection
logsource:
  product: dns
  service: dns_query
detection:
  selection:
    entropy: ">3.5"
    query_count: ">10"
    jitter_ratio: "<0.20"
  condition: selection
level: high
"""
            ),
        ],
        detection_logic=(
            "Detect C2 beacons via coefficient-of-variation analysis of query timing. "
            "Legitimate DNS has irregular timing (high variance); C2 beacons have regular "
            "check-in intervals with low jitter. Combine with entropy analysis to identify "
            "encoded commands in query names."
        ),
        indicators_of_compromise=[
            "Regular query intervals (60s, 300s, etc.) with jitter < 20%",
            "High-entropy subdomain labels (base32/64 encoding)",
            "TXT record abuse (> 50% of queries)",
            "NXDOMAIN rate > 50% (DGA signals)",
            "Queries to known C2 domains",
        ],
        response_procedure=(
            "1. Block the domain at DNS level (sinkhole)\n"
            "2. Isolate infected host immediately\n"
            "3. Acquire memory dump and disk image\n"
            "4. Kill suspected C2 processes and examine parent chain\n"
            "5. Hunt for similar patterns (same domain, timing, entropy across network)\n"
            "6. Check for lateral movement and credential compromise"
        ),
        false_positive_mitigation=(
            "Health-check services (Windows Update, AV updates) may show regular patterns. "
            "Whitelist known periodic services. Require high entropy OR beacon pattern, "
            "not either alone."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1071/004/",
        ],
    ))

    # 3. DGA Detection
    hunts.append(Hunt(
        hunt_id="H003",
        name="Domain Generation Algorithm (DGA) Detection",
        hypothesis="Malware generates domains algorithmically to evade sinkholing.",
        severity=Severity.HIGH,
        mitre_ids=["T1568.002"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect high NXDOMAIN rates",
                query="""
source="dns.log"
| stats count as total_queries,
         count(eval(rcode="NXDOMAIN")) as nxdomain_count
         by src_ip
| eval nxdomain_ratio = nxdomain_count / total_queries
| where nxdomain_ratio > 0.5 AND total_queries > 50
| table src_ip, total_queries, nxdomain_count, nxdomain_ratio
"""
            ),
        ],
        detection_logic=(
            "DGAs generate hundreds of random domains. Most fail (NXDOMAIN); a few resolve "
            "and connect to C2. Detect by finding hosts with high NXDOMAIN rates. Combine with "
            "domain entropy and character distribution analysis. DGA domains often have unusual "
            "TLD patterns or rapid subdomain changes."
        ),
        indicators_of_compromise=[
            "NXDOMAIN rate > 50%",
            "Query volume > 100 domains/hour",
            "Domains with random character distribution",
            "Queries to non-existent TLDs or unusual TLD patterns",
            "Same TLD queried by many different domains",
        ],
        response_procedure=(
            "1. Extract all queried domains from the hour\n"
            "2. Analyze domain names for entropy and patterns\n"
            "3. Check if domains match known DGA seeding lists\n"
            "4. Monitor for successful resolutions (those are C2s)\n"
            "5. Isolate host and run DGA identification tools\n"
            "6. Acquire sample for reverse engineering"
        ),
        false_positive_mitigation=(
            "DNS enumeration tools, scanners, and legitimate DNSBL queries can cause "
            "high NXDOMAIN rates. Require query volume > 100 AND nxdomain_ratio > 50%. "
            "Whitelist security scanners."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1568/002/",
        ],
    ))

    # 4. DNS Cache Poisoning
    hunts.append(Hunt(
        hunt_id="H004",
        name="DNS Cache Poisoning Detection",
        hypothesis="Attacker sends spoofed DNS responses to poison resolver cache.",
        severity=Severity.CRITICAL,
        mitre_ids=["T1557.004"],
        data_sources=[DataSource.DNS_LOGS, DataSource.NETWORK_TRAFFIC],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect multiple A records for same domain from different sources",
                query="""
source="dns.log" rcode="NOERROR"
| stats values(answer) as answers, count as response_count by query_name, server_ip
| eval answer_count = mvcount(answers)
| where answer_count > 2
| table query_name, server_ip, answer_count, answers
"""
            ),
        ],
        detection_logic=(
            "DNS cache poisoning typically involves attacker injecting false A records. "
            "Detect by finding query_name/server pairs that return multiple unrelated A records "
            "or A records inconsistent with authoritative responses. Monitor for TTL manipulation "
            "(very low TTL values). Check for query with DNSSEC disabled (ad=false)."
        ),
        indicators_of_compromise=[
            "Multiple conflicting A record responses for same domain",
            "TTL values < 5 seconds on normally cached entries",
            "Responses from non-authoritative sources",
            "Query/response with unusual port pairs",
            "Rapid DNS changes (same domain resolved to new IP in seconds)",
        ],
        response_procedure=(
            "1. Immediately flush DNS cache on affected resolvers\n"
            "2. Contact domain owner and authoritative DNS provider\n"
            "3. Verify current authoritative DNS records\n"
            "4. Check server logs for DNSSEC validation failures\n"
            "5. Deploy DNS query rate limiting and response validation\n"
            "6. Monitor for subsequent cache poisoning attempts"
        ),
        false_positive_mitigation=(
            "Round-robin DNS and geolocation-based responses return different A records. "
            "Whitelist CDNs and load balancers. Require response inconsistency over time, "
            "not just one response with multiple As."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1557/004/",
        ],
    ))

    # 5. Zone Transfer Abuse
    hunts.append(Hunt(
        hunt_id="H005",
        name="Zone Transfer Abuse Detection",
        hypothesis="Attacker performs unauthorized AXFR to enumerate zone contents.",
        severity=Severity.HIGH,
        mitre_ids=["T1590.002"],
        data_sources=[DataSource.DNS_LOGS, DataSource.NETWORK_TRAFFIC],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect AXFR attempts",
                query="""
source="dns.log" qtype="AXFR"
| stats count as axfr_count by src_ip, query_name
| where axfr_count > 0
| table src_ip, query_name, axfr_count
"""
            ),
        ],
        detection_logic=(
            "AXFR (full zone transfer) is a legitimate operation but should only succeed "
            "to authorized secondary DNS servers. Detect by looking for AXFR queries (qtype=252) "
            "from unexpected sources or successful transfers. A successful AXFR returns entire "
            "zone contents in a single response (multiple records, high byte count)."
        ),
        indicators_of_compromise=[
            "AXFR query from non-authoritative source IP",
            "AXFR response with > 100 records",
            "AXFR from IP not in NS records",
            "AXFR for domain not in configuration",
            "Failed AXFR attempts followed by zone enumeration queries",
        ],
        response_procedure=(
            "1. Block source IP from making further DNS queries\n"
            "2. Retrieve complete transferred zone data\n"
            "3. Enumerate exposed internal hostnames and IPs\n"
            "4. Assess sensitivity of exposed records\n"
            "5. Implement DNS ACLs to restrict AXFR to authorized IPs\n"
            "6. Enable DNSSEC to prevent future zone enumeration"
        ),
        false_positive_mitigation=(
            "Legitimate secondary DNS servers perform AXFR. Whitelist their IPs. "
            "Require response completion (SOA record) and byte count > 1024 bytes."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1590/002/",
        ],
    ))

    # 6. DNSSEC Validation Failures
    hunts.append(Hunt(
        hunt_id="H006",
        name="DNSSEC Validation Failure Detection",
        hypothesis="DNSSEC validation failures may indicate spoofing or misconfiguration.",
        severity=Severity.MEDIUM,
        mitre_ids=["T1557.004"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect DNSSEC validation failures",
                query="""
source="dns.log" ad=false
| stats count as failure_count by src_ip, query_name, rcode
| where rcode="SERVFAIL" OR rcode="BOGUS"
| table src_ip, query_name, failure_count, rcode
"""
            ),
        ],
        detection_logic=(
            "DNSSEC-validating resolvers should set the 'ad' (authenticated data) flag "
            "in responses. Failures (rcode=SERVFAIL, ad=false) indicate broken signatures. "
            "This can be legitimate (zone transition, signature expiration) but may also "
            "indicate an attacker preventing signature validation."
        ),
        indicators_of_compromise=[
            "Repeated SERVFAIL for same domain",
            "SERVFAIL followed by unvalidated response",
            "ad=false with rcode=BOGUS",
            "DNSSEC validation failing for high-profile domains",
            "Resolver accepting invalid signatures",
        ],
        response_procedure=(
            "1. Verify DNSSEC chain for affected domain\n"
            "2. Check domain registrar for delegation issues\n"
            "3. Verify resolver's DNSSEC keys are current\n"
            "4. Check for clock skew on resolver\n"
            "5. Monitor for subsequent spoofing attempts\n"
            "6. Contact domain owner if signature issues persist"
        ),
        false_positive_mitigation=(
            "Zone transitions and maintenance cause legitimate failures. Whitelist "
            "zones under migration. Require persistence (> 5 failures) or severity flag."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1557/004/",
        ],
    ))

    # 7. DNS Amplification/Reflection Attack
    hunts.append(Hunt(
        hunt_id="H007",
        name="DNS Amplification & Reflection Attack Detection",
        hypothesis="Attacker uses DNS servers as amplifiers in DDoS attacks.",
        severity=Severity.HIGH,
        mitre_ids=["T1048.003"],
        data_sources=[DataSource.DNS_LOGS, DataSource.NETWORK_TRAFFIC],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect amplification via large responses",
                query="""
source="dns.log" rcode="NOERROR"
| stats avg(response_bytes) as avg_resp_size, count as query_count by query_name
| eval amplification_factor = avg_resp_size / 60
| where amplification_factor > 10 AND query_count > 100
| table query_name, avg_resp_size, query_count, amplification_factor
"""
            ),
        ],
        detection_logic=(
            "DNS amplification attacks use queries with small size that generate large "
            "responses (e.g., DNSSEC, ANY, TXT). Detect by finding query/response pairs "
            "where response is 10x+ larger than query. Look for queries from spoofed sources "
            "(not your customers). Monitor for queries to recursive resolvers from outside "
            "your network."
        ),
        indicators_of_compromise=[
            "Response > 10x query size",
            "Large responses (> 512 bytes) to queries from spoofed IPs",
            "DNSSEC/ANY/TXT queries from multiple spoofed sources",
            "Same query pattern repeated 1000s of times",
            "Queries from IPs never seen before",
        ],
        response_procedure=(
            "1. Implement rate limiting on recursive resolver\n"
            "2. Block or restrict DNSSEC/ANY/TXT queries from external IPs\n"
            "3. Consider response size caps\n"
            "4. Enable DNS firewall rules\n"
            "5. Contact upstream ISP for DDoS mitigation\n"
            "6. Implement source IP spoofing detection"
        ),
        false_positive_mitigation=(
            "Legitimate DNSSEC/TXT queries may be large. Whitelist known customers. "
            "Require external source + high volume (> 100 qps) to trigger alert."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1048/003/",
        ],
    ))

    # 8. DoH (DNS over HTTPS) Bypass
    hunts.append(Hunt(
        hunt_id="H008",
        name="DNS over HTTPS (DoH) Bypass Detection",
        hypothesis="Hosts using DoH bypass corporate DNS controls and policies.",
        severity=Severity.MEDIUM,
        mitre_ids=["T1071.004"],
        data_sources=[DataSource.NETWORK_TRAFFIC, DataSource.SPLUNK],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect HTTPS traffic to known DoH providers",
                query="""
source="firewall" proto="tcp" dst_port=443
| regex dest_ip in (8.8.8.8, 1.1.1.1, 45.33.32.156)
| where bytes_in > 100 AND bytes_out > 100
| stats count as conn_count, sum(bytes_in) as total_in by src_ip, dest_ip
| table src_ip, dest_ip, conn_count, total_in
"""
            ),
        ],
        detection_logic=(
            "DoH providers (Google, Cloudflare, Quad9, etc.) handle DNS queries over HTTPS "
            "on port 443. Detect by identifying HTTPS connections to known DoH IPs. Monitor "
            "certificate names (dns.google, cloudflare-dns.com). Look for suspiciously "
            "consistent query volume over HTTPS."
        ),
        indicators_of_compromise=[
            "Connection to known DoH provider IP on 443",
            "SNI hostname matches DoH service (dns.google, 1.1.1.1.1)",
            "Consistent HTTPS traffic volume (similar pattern to DNS)",
            "Browser configured with custom DoH in hosts file or config",
            "Multiple hosts querying same DoH provider",
        ],
        response_procedure=(
            "1. Block destination IP or FQDN at network boundary\n"
            "2. Check host for malware or unauthorized configuration\n"
            "3. Review process memory for suspicious DNS query patterns\n"
            "4. Check browser history and preferences\n"
            "5. Deploy network policy to block DoH (if not approved)\n"
            "6. Monitor for persistence mechanisms"
        ),
        false_positive_mitigation=(
            "Legitimate users may use DoH intentionally. Whitelist approved DoH providers. "
            "Require policy violation OR suspicious query patterns (C2-like timing/entropy)."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1071/004/",
        ],
    ))

    # 9. Fast-Flux Detection
    hunts.append(Hunt(
        hunt_id="H009",
        name="Fast-Flux Domain Detection",
        hypothesis="Attacker rapidly changes DNS A records to evade sinkholing.",
        severity=Severity.HIGH,
        mitre_ids=["T1583.001"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect rapid A record changes",
                query="""
source="dns.log" qtype="A" rcode="NOERROR"
| stats values(answer) as answers by query_name, _time
| stats dc(answers) as unique_ips, count as response_count by query_name
| where unique_ips > 5 AND response_count < 100
| table query_name, unique_ips, response_count
"""
            ),
        ],
        detection_logic=(
            "Fast-flux networks rapidly rotate IP addresses for phishing/malware domains. "
            "Detect by tracking A record changes over time. If a domain resolves to > 5 "
            "different IPs within a short period, it's likely fast-flux. Look for IPs in "
            "non-routable spaces or from bulletproof hosting."
        ),
        indicators_of_compromise=[
            "Domain with > 5 A records in 1-hour window",
            "TTL < 60 seconds with frequent A record changes",
            "Rotating IPs from suspicious ASNs or hosting providers",
            "Same domain owned by multiple IPs (check PTR records)",
            "IPs in bulletproof/hijacked hosting ranges",
        ],
        response_procedure=(
            "1. Extract all IPs associated with the domain\n"
            "2. Check ASNs and hosting providers for reputation\n"
            "3. Extract all connected domains (reverse DNS, WHOIS)\n"
            "4. Sink the entire domain + IP network if possible\n"
            "5. Monitor for related infrastructure\n"
            "6. Check for hosts with connections to fast-flux IPs"
        ),
        false_positive_mitigation=(
            "CDNs and load balancers have multiple A records. Whitelist known CDNs "
            "(Akamai, Cloudflare, AWS). Require rapid changes within time window, "
            "not just multiple IPs."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1583/001/",
        ],
    ))

    # 10. DNS Data Exfiltration
    hunts.append(Hunt(
        hunt_id="H010",
        name="DNS Data Exfiltration Detection",
        hypothesis="Attacker exfiltrates data by encoding it in DNS query names.",
        severity=Severity.HIGH,
        mitre_ids=["T1048.003"],
        data_sources=[DataSource.DNS_LOGS, DataSource.ZEEK_DNS],
        queries=[
            HuntQuery(
                query_type="splunk_spl",
                description="Detect exfiltration via subdomain encoding",
                query="""
source="dns.log"
| eval subdomain_length = len(query_name) - len(query_domain)
| stats avg(subdomain_length) as avg_len, max(subdomain_length) as max_len, count as query_count by src_ip
| where avg_len > 30 OR max_len > 60
| table src_ip, avg_len, max_len, query_count
"""
            ),
        ],
        detection_logic=(
            "Data exfiltration via DNS encodes sensitive data in long subdomain labels. "
            "Legitimate subdomains are short (< 20 chars); exfiltration uses 50+ char labels. "
            "Detect by measuring average/max subdomain label length per source. Combine with "
            "entropy analysis to confirm encoding. Monitor for query volume over time."
        ),
        indicators_of_compromise=[
            "Subdomain labels > 50 characters",
            "Average label length > 30 characters",
            "High entropy subdomains with NXDOMAIN responses",
            "Queries to attacker-controlled domain",
            "Consistent query pattern (exfil tool signature)",
        ],
        response_procedure=(
            "1. Extract all queries from the source IP to the suspected domain\n"
            "2. Decode subdomain labels (base32/64 or other scheme)\n"
            "3. Identify what data was exfiltrated\n"
            "4. Determine compromise scope and affected systems\n"
            "5. Isolate source host immediately\n"
            "6. Hunt for similar exfiltration patterns\n"
            "7. Preserve all evidence for incident response"
        ),
        false_positive_mitigation=(
            "Some legitimate services use long subdomains (authentication tokens). "
            "Whitelist known services. Require NXDOMAIN OR multiple exfil-like queries, "
            "not single long query."
        ),
        references=[
            "https://attack.mitre.org/techniques/T1048/003/",
        ],
    ))

    return hunts


# ---------------------------------------------------------------------------
# Playbook Engine
# ---------------------------------------------------------------------------
class DNSThreatHuntPlaybook:
    """DNS Threat Hunt Playbook engine."""

    def __init__(self, hunts: Optional[list[Hunt]] = None):
        """Initialize with hunt library."""
        self.hunts = hunts or build_hunt_library()
        self.findings: list[HuntFinding] = []
        self._build_coverage_matrix()

    def _build_coverage_matrix(self) -> None:
        """Build MITRE coverage matrix."""
        self.coverage = CoverageMatrix()
        for hunt in self.hunts:
            for technique in hunt.mitre_ids:
                self.coverage.add(technique, hunt.hunt_id)

    def get_hunt(self, hunt_id: str) -> Optional[Hunt]:
        """Get hunt by ID."""
        for hunt in self.hunts:
            if hunt.hunt_id == hunt_id:
                return hunt
        return None

    def list_hunts(
        self,
        severity: Optional[Severity] = None,
        data_source: Optional[DataSource] = None,
        mitre_technique: Optional[str] = None,
    ) -> list[Hunt]:
        """List hunts with optional filtering."""
        result = list(self.hunts)

        if severity:
            result = [h for h in result if h.severity == severity]

        if data_source:
            result = [h for h in result if data_source in h.data_sources]

        if mitre_technique:
            result = [h for h in result if mitre_technique in h.mitre_ids]

        return result

    def get_queries_for_hunt(self, hunt_id: str, query_type: Optional[str] = None) -> list[HuntQuery]:
        """Get queries for a hunt, optionally filtered by type."""
        hunt = self.get_hunt(hunt_id)
        if not hunt:
            return []

        if query_type:
            return [q for q in hunt.queries if q.query_type == query_type]
        return hunt.queries

    def export_playbook(self, format_type: str = "text") -> str:
        """Export playbook document in specified format."""
        if format_type == "json":
            return self._export_json()
        elif format_type == "markdown":
            return self._export_markdown()
        else:
            return self._export_text()

    def _export_text(self) -> str:
        """Export as plain text."""
        lines = []
        lines.append("=" * 80)
        lines.append("DNS THREAT HUNT PLAYBOOK")
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
        lines.append(f"Version: {__version__}")
        lines.append("")

        lines.append("HUNT LIBRARY")
        lines.append("-" * 80)
        for hunt in self.hunts:
            lines.append(f"\n[{hunt.hunt_id}] {hunt.name}")
            lines.append(f"Severity: {hunt.severity}")
            lines.append(f"MITRE: {', '.join(hunt.mitre_ids)}")
            lines.append(f"Hypothesis: {hunt.hypothesis}")
            lines.append(f"\nDetection Logic:\n{textwrap.indent(hunt.detection_logic, '  ')}")
            lines.append(f"\nIndicators of Compromise:")
            for ioc in hunt.indicators_of_compromise:
                lines.append(f"  - {ioc}")
            lines.append(f"\nResponse Procedure:")
            lines.append(textwrap.indent(hunt.response_procedure, "  "))
            lines.append(f"\nData Sources: {', '.join(str(ds) for ds in hunt.data_sources)}")
            lines.append("-" * 80)

        lines.append("\n\nCOVERAGE MATRIX")
        lines.append("-" * 80)
        matrix = self.coverage.to_dict()
        for technique in sorted(matrix.keys()):
            hunt_ids = matrix[technique]
            lines.append(f"{technique}: {', '.join(hunt_ids)}")

        return "\n".join(lines)

    def _export_json(self) -> str:
        """Export as JSON."""
        export_data = {
            "title": "DNS Threat Hunt Playbook",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "version": __version__,
            "total_hunts": len(self.hunts),
            "hunts": [hunt.to_dict() for hunt in self.hunts],
            "coverage_matrix": self.coverage.to_dict(),
        }
        return json.dumps(export_data, indent=2)

    def _export_markdown(self) -> str:
        """Export as Markdown."""
        lines = []
        lines.append("# DNS Threat Hunt Playbook\n")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
        lines.append(f"**Version:** {__version__}\n")

        lines.append("## Hunt Library\n")
        for hunt in self.hunts:
            lines.append(f"### [{hunt.hunt_id}] {hunt.name}\n")
            lines.append(f"**Severity:** {hunt.severity}\n")
            lines.append(f"**MITRE Techniques:** {', '.join(hunt.mitre_ids)}\n")
            lines.append(f"**Data Sources:** {', '.join(str(ds) for ds in hunt.data_sources)}\n")
            lines.append(f"**Hypothesis:** {hunt.hypothesis}\n")
            lines.append(f"**Detection Logic:**\n{hunt.detection_logic}\n")
            lines.append("**Indicators of Compromise:**\n")
            for ioc in hunt.indicators_of_compromise:
                lines.append(f"- {ioc}\n")
            lines.append("**Response Procedure:**\n")
            lines.append(hunt.response_procedure + "\n")
            lines.append("---\n")

        lines.append("## MITRE ATT&CK Coverage\n")
        matrix = self.coverage.to_dict()
        for technique in sorted(matrix.keys()):
            hunt_ids = matrix[technique]
            lines.append(f"- **{technique}**: {', '.join(hunt_ids)}\n")

        return "".join(lines)

    def get_coverage_stats(self) -> dict[str, Any]:
        """Get coverage statistics."""
        return {
            "total_hunts": len(self.hunts),
            "total_mitre_techniques": len(self.coverage.matrix),
            "hunts_by_severity": {
                "CRITICAL": len([h for h in self.hunts if h.severity == Severity.CRITICAL]),
                "HIGH": len([h for h in self.hunts if h.severity == Severity.HIGH]),
                "MEDIUM": len([h for h in self.hunts if h.severity == Severity.MEDIUM]),
                "INFO": len([h for h in self.hunts if h.severity == Severity.INFO]),
            },
            "mitre_techniques": sorted(self.coverage.matrix.keys()),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="DNS Threat Hunt Playbook - comprehensive hunting guide for DNS-based threats",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
Examples:
  %(prog)s list
  %(prog)s list --severity HIGH
  %(prog)s show H002
  %(prog)s export --format json > playbook.json
  %(prog)s export --format markdown > playbook.md
  %(prog)s coverage
        """),
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # list command
    list_parser = subparsers.add_parser("list", help="List all hunts")
    list_parser.add_argument("--severity", choices=["INFO", "MEDIUM", "HIGH", "CRITICAL"],
                             help="Filter by severity")
    list_parser.add_argument("--data-source", help="Filter by data source")
    list_parser.add_argument("--mitre", help="Filter by MITRE technique")

    # show command
    show_parser = subparsers.add_parser("show", help="Show hunt details")
    show_parser.add_argument("hunt_id", help="Hunt ID (e.g., H001)")

    # export command
    export_parser = subparsers.add_parser("export", help="Export playbook")
    export_parser.add_argument("--format", choices=["text", "json", "markdown"],
                               default="text", help="Export format")
    export_parser.add_argument("--output", "-o", help="Output file (default: stdout)")

    # coverage command
    coverage_parser = subparsers.add_parser("coverage", help="Show MITRE coverage matrix")

    # stats command
    stats_parser = subparsers.add_parser("stats", help="Show playbook statistics")

    args = parser.parse_args()

    playbook = DNSThreatHuntPlaybook()

    if not args.command or args.command == "list":
        severity = Severity[args.severity] if hasattr(args, "severity") and args.severity else None
        hunts = playbook.list_hunts(severity=severity)
        print(f"Total hunts: {len(hunts)}\n")
        for hunt in hunts:
            print(f"[{hunt.hunt_id}] {hunt.name}")
            print(f"  Severity: {hunt.severity}")
            print(f"  MITRE: {', '.join(hunt.mitre_ids)}")
            print()

    elif args.command == "show":
        hunt = playbook.get_hunt(args.hunt_id)
        if hunt:
            print(f"[{hunt.hunt_id}] {hunt.name}\n")
            print(f"Severity: {hunt.severity}")
            print(f"MITRE: {', '.join(hunt.mitre_ids)}")
            print(f"Data Sources: {', '.join(str(ds) for ds in hunt.data_sources)}\n")
            print(f"Hypothesis:\n{hunt.hypothesis}\n")
            print(f"Detection Logic:\n{hunt.detection_logic}\n")
            print(f"Indicators of Compromise:")
            for ioc in hunt.indicators_of_compromise:
                print(f"  - {ioc}")
            print(f"\nResponse Procedure:\n{hunt.response_procedure}\n")
            print(f"False Positive Mitigation:\n{hunt.false_positive_mitigation}\n")
            print(f"Queries:")
            for q in hunt.queries:
                print(f"  [{q.query_type}] {q.description}")
                print(f"    {q.query}\n")
        else:
            print(f"Hunt {args.hunt_id} not found", file=sys.stderr)
            sys.exit(1)

    elif args.command == "export":
        output = playbook.export_playbook(args.format)
        if hasattr(args, "output") and args.output:
            with open(args.output, "w") as f:
                f.write(output)
            print(f"Exported to {args.output}", file=sys.stderr)
        else:
            print(output)

    elif args.command == "coverage":
        matrix = playbook.coverage.to_dict()
        print("MITRE ATT&CK Coverage Matrix:\n")
        for technique in sorted(matrix.keys()):
            hunt_ids = matrix[technique]
            print(f"{technique}: {', '.join(hunt_ids)}")

    elif args.command == "stats":
        stats = playbook.get_coverage_stats()
        print(f"Total Hunts: {stats['total_hunts']}")
        print(f"Total MITRE Techniques: {stats['total_mitre_techniques']}")
        print(f"\nHunts by Severity:")
        for severity, count in stats["hunts_by_severity"].items():
            print(f"  {severity}: {count}")
        print(f"\nMITRE Techniques:")
        for technique in stats["mitre_techniques"]:
            print(f"  {technique}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
