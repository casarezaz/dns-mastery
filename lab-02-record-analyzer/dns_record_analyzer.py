#!/usr/bin/env python3
"""
DNS Record Type Analyzer
Lab 2 - DNS Mastery Curriculum

Queries and displays all DNS record types for a given domain.
Highlights security-relevant records (SPF, DKIM, DMARC, CAA).
Supports terminal output, JSON export, and HTML report generation.

Author: Angie Casarez
License: MIT
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# Standard record types to query
STANDARD_RECORD_TYPES = [
    "A", "AAAA", "MX", "CNAME", "TXT", "SOA", "NS", "SRV", "CAA", "PTR"
]

# Additional record types for comprehensive mode
EXTENDED_RECORD_TYPES = [
    "DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG", "TLSA", "SSHFP",
    "LOC", "NAPTR", "HINFO", "RP"
]

# Security-relevant TXT record patterns
SECURITY_PATTERNS = {
    "SPF": re.compile(r"v=spf1", re.IGNORECASE),
    "DKIM": re.compile(r"v=DKIM1", re.IGNORECASE),
    "DMARC": re.compile(r"v=DMARC1", re.IGNORECASE),
    "BIMI": re.compile(r"v=BIMI1", re.IGNORECASE),
    "MTA-STS": re.compile(r"v=STSv1", re.IGNORECASE),
    "TLSRPT": re.compile(r"v=TLSRPTv1", re.IGNORECASE),
    "DANE": re.compile(r"v=DANE", re.IGNORECASE),
    "GOOGLE_VERIFY": re.compile(r"google-site-verification", re.IGNORECASE),
    "MS_VERIFY": re.compile(r"MS=ms", re.IGNORECASE),
    "DOCUSIGN": re.compile(r"docusign", re.IGNORECASE),
    "FACEBOOK_VERIFY": re.compile(r"facebook-domain-verification", re.IGNORECASE),
}

# ANSI color codes for terminal output
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class DNSRecord:
    """Represents a single DNS record."""
    name: str
    ttl: int
    record_class: str
    record_type: str
    value: str
    security_tags: list = field(default_factory=list)


@dataclass
class RecordTypeResult:
    """Results for a single record type query."""
    record_type: str
    records: list = field(default_factory=list)
    error: Optional[str] = None
    query_time_ms: float = 0.0
    server: Optional[str] = None


@dataclass
class DomainAnalysis:
    """Complete analysis of all record types for a domain."""
    domain: str
    timestamp: str = ""
    record_results: list = field(default_factory=list)
    security_findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ─── DNS Query Engine ─────────────────────────────────────────────────────────

class DNSQueryEngine:
    """Handles DNS queries using dig."""

    def __init__(self, nameserver: Optional[str] = None, timeout: int = 10):
        self.nameserver = nameserver
        self.timeout = timeout
        self.logger = logging.getLogger("DNSQueryEngine")

    def query(self, domain: str, record_type: str) -> RecordTypeResult:
        """Query a specific record type for a domain."""
        cmd = ["dig", "+noall", "+answer", "+authority", "+stats",
               "+time=" + str(self.timeout)]

        if self.nameserver:
            cmd.append(f"@{self.nameserver}")

        cmd.extend([domain, record_type])

        self.logger.debug(f"Running: {' '.join(cmd)}")

        result = RecordTypeResult(record_type=record_type)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 5
            )

            output = proc.stdout.strip()
            if proc.returncode != 0:
                result.error = f"dig returned exit code {proc.returncode}"
                return result

            result = self._parse_dig_output(output, record_type)
            result.query_time_ms = self._extract_query_time(output)
            result.server = self._extract_server(output)

        except subprocess.TimeoutExpired:
            result.error = f"Query timed out after {self.timeout}s"
        except FileNotFoundError:
            result.error = "dig command not found. Install with: brew install bind"
        except Exception as e:
            result.error = str(e)

        return result

    def _parse_dig_output(self, output: str, record_type: str) -> RecordTypeResult:
        """Parse dig output into structured records."""
        result = RecordTypeResult(record_type=record_type)

        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue

            parts = line.split(None, 4)
            if len(parts) >= 5:
                try:
                    record = DNSRecord(
                        name=parts[0],
                        ttl=int(parts[1]),
                        record_class=parts[2],
                        record_type=parts[3],
                        value=parts[4]
                    )

                    # Tag security-relevant TXT records
                    if parts[3] == "TXT":
                        record.security_tags = self._identify_security_tags(parts[4])

                    result.records.append(record)
                except (ValueError, IndexError):
                    continue

        return result

    def _identify_security_tags(self, txt_value: str) -> list:
        """Identify security-relevant tags in TXT records."""
        tags = []
        for tag_name, pattern in SECURITY_PATTERNS.items():
            if pattern.search(txt_value):
                tags.append(tag_name)
        return tags

    def _extract_query_time(self, output: str) -> float:
        """Extract query time from dig stats."""
        match = re.search(r";; Query time: (\d+) msec", output)
        return float(match.group(1)) if match else 0.0

    def _extract_server(self, output: str) -> Optional[str]:
        """Extract responding server from dig stats."""
        match = re.search(r";; SERVER: (.+?)#", output)
        return match.group(1) if match else None


# ─── Security Analyzer ────────────────────────────────────────────────────────

class SecurityAnalyzer:
    """Analyzes DNS records for security posture."""

    def analyze(self, analysis: DomainAnalysis) -> list:
        """Run all security checks and return findings."""
        findings = []

        findings.extend(self._check_email_security(analysis))
        findings.extend(self._check_caa(analysis))
        findings.extend(self._check_dnssec(analysis))
        findings.extend(self._check_nameserver_diversity(analysis))
        findings.extend(self._check_mx_records(analysis))

        return findings

    def _get_records_by_type(self, analysis: DomainAnalysis, rtype: str) -> list:
        """Helper to get all records of a given type."""
        for result in analysis.record_results:
            if result.record_type == rtype:
                return result.records
        return []

    def _check_email_security(self, analysis: DomainAnalysis) -> list:
        """Check SPF, DKIM, DMARC configuration."""
        findings = []
        txt_records = self._get_records_by_type(analysis, "TXT")

        has_spf = any("SPF" in r.security_tags for r in txt_records)
        has_dmarc = any("DMARC" in r.security_tags for r in txt_records)

        if not has_spf:
            findings.append({
                "severity": "HIGH",
                "category": "Email Security",
                "finding": "No SPF record found",
                "recommendation": "Add a TXT record with SPF policy to prevent email spoofing",
                "mitre": "T1566 - Phishing"
            })
        else:
            spf_record = next(r for r in txt_records if "SPF" in r.security_tags)
            findings.append({
                "severity": "INFO",
                "category": "Email Security",
                "finding": f"SPF record present: {spf_record.value[:80]}...",
                "recommendation": "Verify SPF includes all legitimate senders",
                "mitre": "T1566 - Phishing"
            })
            # Check for permissive SPF
            if "+all" in spf_record.value:
                findings.append({
                    "severity": "CRITICAL",
                    "category": "Email Security",
                    "finding": "SPF record uses +all (allows any server to send)",
                    "recommendation": "Change to ~all or -all to restrict senders",
                    "mitre": "T1566.001 - Spearphishing Attachment"
                })

        if not has_dmarc:
            findings.append({
                "severity": "HIGH",
                "category": "Email Security",
                "finding": "No DMARC record found",
                "recommendation": "Add _dmarc TXT record to enforce email authentication",
                "mitre": "T1566 - Phishing"
            })

        return findings

    def _check_caa(self, analysis: DomainAnalysis) -> list:
        """Check Certificate Authority Authorization records."""
        findings = []
        caa_records = self._get_records_by_type(analysis, "CAA")

        if not caa_records:
            findings.append({
                "severity": "MEDIUM",
                "category": "Certificate Security",
                "finding": "No CAA records found",
                "recommendation": "Add CAA records to restrict which CAs can issue certificates",
                "mitre": "T1557 - Adversary-in-the-Middle"
            })
        else:
            cas = [r.value for r in caa_records]
            findings.append({
                "severity": "INFO",
                "category": "Certificate Security",
                "finding": f"CAA records restrict certificate issuance to: {', '.join(cas)}",
                "recommendation": "Periodically review authorized CAs",
                "mitre": "T1557 - Adversary-in-the-Middle"
            })

        return findings

    def _check_dnssec(self, analysis: DomainAnalysis) -> list:
        """Check for DNSSEC indicators."""
        findings = []
        dnskey_records = self._get_records_by_type(analysis, "DNSKEY")
        ds_records = self._get_records_by_type(analysis, "DS")

        has_dnssec = bool(dnskey_records) or bool(ds_records)

        if not has_dnssec:
            findings.append({
                "severity": "MEDIUM",
                "category": "DNS Security",
                "finding": "No DNSSEC records found (DNSKEY/DS)",
                "recommendation": "Enable DNSSEC to prevent DNS spoofing and cache poisoning",
                "mitre": "T1557.004 - DNS Spoofing"
            })
        else:
            findings.append({
                "severity": "INFO",
                "category": "DNS Security",
                "finding": "DNSSEC is enabled",
                "recommendation": "Ensure key rotation schedule is maintained",
                "mitre": "T1557.004 - DNS Spoofing"
            })

        return findings

    def _check_nameserver_diversity(self, analysis: DomainAnalysis) -> list:
        """Check nameserver configuration for resilience."""
        findings = []
        ns_records = self._get_records_by_type(analysis, "NS")

        if len(ns_records) < 2:
            findings.append({
                "severity": "HIGH",
                "category": "DNS Resilience",
                "finding": f"Only {len(ns_records)} nameserver(s) found",
                "recommendation": "Use at least 2 nameservers from different providers for redundancy",
                "mitre": "T1498 - Network Denial of Service"
            })
        else:
            # Check if all NS are from the same provider
            providers = set()
            for r in ns_records:
                # Extract base domain of NS
                parts = r.value.rstrip(".").split(".")
                if len(parts) >= 2:
                    providers.add(".".join(parts[-2:]))

            if len(providers) == 1:
                findings.append({
                    "severity": "LOW",
                    "category": "DNS Resilience",
                    "finding": f"All nameservers from single provider: {providers.pop()}",
                    "recommendation": "Consider using nameservers from multiple providers",
                    "mitre": "T1498 - Network Denial of Service"
                })

        return findings

    def _check_mx_records(self, analysis: DomainAnalysis) -> list:
        """Check MX record configuration."""
        findings = []
        mx_records = self._get_records_by_type(analysis, "MX")

        if not mx_records:
            findings.append({
                "severity": "INFO",
                "category": "Email Configuration",
                "finding": "No MX records found (domain may not handle email)",
                "recommendation": "If email is not used, consider adding a null MX record (RFC 7505)",
                "mitre": "N/A"
            })
        else:
            # Check for backup MX
            priorities = []
            for r in mx_records:
                parts = r.value.split()
                if parts:
                    try:
                        priorities.append(int(parts[0]))
                    except ValueError:
                        pass

            if len(set(priorities)) == 1 and len(mx_records) > 1:
                findings.append({
                    "severity": "LOW",
                    "category": "Email Configuration",
                    "finding": "All MX records have the same priority",
                    "recommendation": "Set different priorities for primary/backup mail servers",
                    "mitre": "N/A"
                })

        return findings


# ─── Terminal Renderer ────────────────────────────────────────────────────────

class TerminalRenderer:
    """Renders analysis results to the terminal."""

    def render(self, analysis: DomainAnalysis):
        """Render complete domain analysis."""
        c = Colors

        # Header
        print(f"\n{c.BOLD}{c.CYAN}DNS Record Analysis: {analysis.domain}{c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")
        print(f"{c.DIM}Timestamp: {analysis.timestamp}{c.RESET}")
        print()

        # Record type results
        for result in analysis.record_results:
            self._render_record_type(result)

        # Security findings
        if analysis.security_findings:
            self._render_security_findings(analysis.security_findings)

        # Summary
        self._render_summary(analysis.summary)

    def _render_record_type(self, result: RecordTypeResult):
        """Render results for a single record type."""
        c = Colors

        if result.error:
            print(f"  {c.DIM}{result.record_type:6s}{c.RESET} "
                  f"{c.YELLOW}⚠ {result.error}{c.RESET}")
            return

        if not result.records:
            print(f"  {c.DIM}{result.record_type:6s} — no records —{c.RESET}")
            return

        # Print header for this record type
        type_color = self._type_color(result.record_type)
        print(f"  {c.BOLD}{type_color}{result.record_type:6s}{c.RESET} "
              f"{c.DIM}({len(result.records)} record{'s' if len(result.records) != 1 else ''}, "
              f"{result.query_time_ms:.0f}ms){c.RESET}")

        for record in result.records:
            value_display = record.value
            if len(value_display) > 80:
                value_display = value_display[:77] + "..."

            # Highlight security-tagged records
            if record.security_tags:
                tags = " ".join(f"[{t}]" for t in record.security_tags)
                print(f"    {c.GREEN}● {value_display}{c.RESET}")
                print(f"      {c.MAGENTA}{tags}{c.RESET}")
            else:
                print(f"    {value_display}")

            # Show TTL
            ttl_str = self._format_ttl(record.ttl)
            print(f"      {c.DIM}TTL: {record.ttl}s ({ttl_str}){c.RESET}")

        print()

    def _render_security_findings(self, findings: list):
        """Render security analysis findings."""
        c = Colors

        print(f"\n{c.BOLD}{c.YELLOW}Security Analysis{c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 5))

        for finding in sorted_findings:
            severity = finding["severity"]
            icon, color = self._severity_style(severity)

            print(f"\n  {color}{icon} [{severity}]{c.RESET} {finding['category']}")
            print(f"    {finding['finding']}")
            print(f"    {c.DIM}→ {finding['recommendation']}{c.RESET}")
            if finding.get("mitre") and finding["mitre"] != "N/A":
                print(f"    {c.DIM}MITRE ATT&CK: {finding['mitre']}{c.RESET}")

    def _render_summary(self, summary: dict):
        """Render summary statistics."""
        c = Colors
        print(f"\n{c.DIM}{'─' * 60}{c.RESET}")
        print(f"  {c.BOLD}Summary:{c.RESET} "
              f"{summary.get('total_records', 0)} records across "
              f"{summary.get('types_with_records', 0)} types | "
              f"{summary.get('security_findings_count', 0)} security findings | "
              f"Total query time: {summary.get('total_query_time_ms', 0):.0f}ms")
        print()

    def _type_color(self, record_type: str) -> str:
        """Get color for record type."""
        c = Colors
        colors = {
            "A": c.GREEN, "AAAA": c.GREEN,
            "MX": c.CYAN, "NS": c.BLUE,
            "TXT": c.YELLOW, "CNAME": c.MAGENTA,
            "SOA": c.WHITE, "CAA": c.RED,
            "SRV": c.CYAN, "PTR": c.MAGENTA,
            "DNSKEY": c.RED, "DS": c.RED,
            "RRSIG": c.RED,
        }
        return colors.get(record_type, c.WHITE)

    def _severity_style(self, severity: str) -> tuple:
        """Get icon and color for severity level."""
        c = Colors
        styles = {
            "CRITICAL": ("🔴", c.RED + c.BOLD),
            "HIGH": ("🟠", c.RED),
            "MEDIUM": ("🟡", c.YELLOW),
            "LOW": ("🔵", c.BLUE),
            "INFO": ("ℹ️ ", c.DIM),
        }
        return styles.get(severity, ("•", c.WHITE))

    def _format_ttl(self, ttl: int) -> str:
        """Format TTL in human-readable form."""
        if ttl >= 86400:
            return f"{ttl // 86400}d {(ttl % 86400) // 3600}h"
        elif ttl >= 3600:
            return f"{ttl // 3600}h {(ttl % 3600) // 60}m"
        elif ttl >= 60:
            return f"{ttl // 60}m {ttl % 60}s"
        return f"{ttl}s"


# ─── File Exporters ───────────────────────────────────────────────────────────

class JSONExporter:
    """Export analysis results to JSON."""

    def export(self, analysis: DomainAnalysis, filepath: str):
        """Export to JSON file."""
        data = {
            "domain": analysis.domain,
            "timestamp": analysis.timestamp,
            "record_results": [],
            "security_findings": analysis.security_findings,
            "summary": analysis.summary
        }

        for result in analysis.record_results:
            type_data = {
                "record_type": result.record_type,
                "query_time_ms": result.query_time_ms,
                "server": result.server,
                "error": result.error,
                "records": [asdict(r) for r in result.records]
            }
            data["record_results"].append(type_data)

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


class HTMLExporter:
    """Export analysis results to an HTML report."""

    def export(self, analysis: DomainAnalysis, filepath: str):
        """Export to HTML file."""
        html = self._build_html(analysis)
        with open(filepath, "w") as f:
            f.write(html)

    def _build_html(self, analysis: DomainAnalysis) -> str:
        """Build HTML report content."""
        records_html = ""
        for result in analysis.record_results:
            records_html += self._render_record_type_html(result)

        findings_html = ""
        for finding in analysis.security_findings:
            severity_class = finding["severity"].lower()
            findings_html += f"""
            <div class="finding {severity_class}">
                <span class="severity">{finding["severity"]}</span>
                <strong>{finding["category"]}</strong>
                <p>{finding["finding"]}</p>
                <p class="recommendation">→ {finding["recommendation"]}</p>
                {"<p class='mitre'>MITRE ATT&CK: " + finding["mitre"] + "</p>" if finding.get("mitre") and finding["mitre"] != "N/A" else ""}
            </div>"""

        summary = analysis.summary

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Analysis: {analysis.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', 'Fira Code', monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 0.5rem; }}
        h2 {{ color: #ffd700; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
        .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 2rem; }}
        .record-type {{ margin-bottom: 1.5rem; }}
        .type-header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }}
        .type-badge {{ background: #2a2a4a; padding: 0.2rem 0.6rem; border-radius: 4px; font-weight: bold; min-width: 60px; text-align: center; }}
        .type-A .type-badge, .type-AAAA .type-badge {{ color: #00ff88; border: 1px solid #00ff88; }}
        .type-MX .type-badge {{ color: #00d4ff; border: 1px solid #00d4ff; }}
        .type-NS .type-badge {{ color: #4488ff; border: 1px solid #4488ff; }}
        .type-TXT .type-badge {{ color: #ffd700; border: 1px solid #ffd700; }}
        .type-CNAME .type-badge {{ color: #ff88ff; border: 1px solid #ff88ff; }}
        .type-SOA .type-badge {{ color: #ffffff; border: 1px solid #ffffff; }}
        .type-CAA .type-badge {{ color: #ff4444; border: 1px solid #ff4444; }}
        .type-SRV .type-badge {{ color: #00d4ff; border: 1px solid #00d4ff; }}
        .record {{ background: #16213e; padding: 0.75rem 1rem; margin: 0.25rem 0; border-radius: 4px; font-size: 0.9rem; word-break: break-all; }}
        .record .ttl {{ color: #888; font-size: 0.8rem; }}
        .security-tag {{ background: #ff00ff22; color: #ff88ff; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.75rem; margin-left: 0.5rem; }}
        .no-records {{ color: #666; font-style: italic; }}
        .error {{ color: #ff8800; }}
        .finding {{ padding: 1rem; margin: 0.5rem 0; border-radius: 4px; border-left: 4px solid; }}
        .finding.critical {{ background: #ff000015; border-color: #ff0000; }}
        .finding.high {{ background: #ff440015; border-color: #ff4400; }}
        .finding.medium {{ background: #ffaa0015; border-color: #ffaa00; }}
        .finding.low {{ background: #4488ff15; border-color: #4488ff; }}
        .finding.info {{ background: #88888815; border-color: #888; }}
        .severity {{ font-weight: bold; font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 3px; margin-right: 0.5rem; }}
        .critical .severity {{ background: #ff0000; color: white; }}
        .high .severity {{ background: #ff4400; color: white; }}
        .medium .severity {{ background: #ffaa00; color: black; }}
        .low .severity {{ background: #4488ff; color: white; }}
        .info .severity {{ background: #888; color: white; }}
        .recommendation {{ color: #aaa; margin-top: 0.5rem; }}
        .mitre {{ color: #888; font-size: 0.85rem; }}
        .summary {{ background: #16213e; padding: 1.5rem; border-radius: 8px; margin-top: 2rem; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 1rem; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 2rem; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ font-size: 0.8rem; color: #888; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Record Analysis</h1>
        <p class="meta">{analysis.domain} &mdash; {analysis.timestamp}</p>

        <h2>Records</h2>
        {records_html}

        <h2>Security Analysis</h2>
        {findings_html if findings_html else '<p class="no-records">No security findings.</p>'}

        <div class="summary">
            <h2 style="margin-top:0; border:none;">Summary</h2>
            <div class="summary-grid">
                <div class="stat">
                    <div class="stat-value">{summary.get('total_records', 0)}</div>
                    <div class="stat-label">Total Records</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('types_with_records', 0)}</div>
                    <div class="stat-label">Record Types</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('security_findings_count', 0)}</div>
                    <div class="stat-label">Security Findings</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('total_query_time_ms', 0):.0f}ms</div>
                    <div class="stat-label">Query Time</div>
                </div>
            </div>
        </div>

        <p class="meta" style="margin-top: 2rem; text-align: center;">
            Generated by DNS Record Type Analyzer v{VERSION} &mdash; DNS Mastery Lab 2
        </p>
    </div>
</body>
</html>"""

    def _render_record_type_html(self, result: RecordTypeResult) -> str:
        """Render a single record type to HTML."""
        if result.error:
            return f"""
        <div class="record-type">
            <div class="type-header">
                <span class="type-badge">{result.record_type}</span>
                <span class="error">⚠ {result.error}</span>
            </div>
        </div>"""

        if not result.records:
            return f"""
        <div class="record-type type-{result.record_type}">
            <div class="type-header">
                <span class="type-badge">{result.record_type}</span>
                <span class="no-records">No records found</span>
            </div>
        </div>"""

        records_html = ""
        for record in result.records:
            tags = "".join(f'<span class="security-tag">{t}</span>' for t in record.security_tags)
            records_html += f"""
            <div class="record">
                {record.value}{tags}
                <div class="ttl">TTL: {record.ttl}s</div>
            </div>"""

        return f"""
        <div class="record-type type-{result.record_type}">
            <div class="type-header">
                <span class="type-badge">{result.record_type}</span>
                <span style="color: #888; font-size: 0.85rem;">
                    {len(result.records)} record{"s" if len(result.records) != 1 else ""} &middot;
                    {result.query_time_ms:.0f}ms
                </span>
            </div>
            {records_html}
        </div>"""


# ─── Main Analyzer ────────────────────────────────────────────────────────────

class DNSRecordAnalyzer:
    """Main orchestrator for DNS record analysis."""

    def __init__(self, nameserver: Optional[str] = None, timeout: int = 10,
                 extended: bool = False, output_dir: str = "output"):
        self.engine = DNSQueryEngine(nameserver=nameserver, timeout=timeout)
        self.security = SecurityAnalyzer()
        self.renderer = TerminalRenderer()
        self.json_exporter = JSONExporter()
        self.html_exporter = HTMLExporter()
        self.extended = extended
        self.output_dir = output_dir
        self.logger = logging.getLogger("DNSRecordAnalyzer")

        os.makedirs(output_dir, exist_ok=True)

    def analyze(self, domain: str) -> DomainAnalysis:
        """Perform complete analysis of a domain."""
        analysis = DomainAnalysis(domain=domain)

        # Determine which record types to query
        record_types = list(STANDARD_RECORD_TYPES)
        if self.extended:
            record_types.extend(EXTENDED_RECORD_TYPES)

        # Also check for DMARC specifically
        dmarc_domain = f"_dmarc.{domain}"

        # Query each record type
        for rtype in record_types:
            self.logger.info(f"Querying {rtype} records for {domain}")
            result = self.engine.query(domain, rtype)
            analysis.record_results.append(result)

        # Query DMARC subdomain
        self.logger.info(f"Querying DMARC at {dmarc_domain}")
        dmarc_result = self.engine.query(dmarc_domain, "TXT")
        if dmarc_result.records:
            # Tag DMARC records and add to TXT results
            for record in dmarc_result.records:
                record.security_tags = self.engine._identify_security_tags(record.value)
            # Find existing TXT result and append DMARC records
            for result in analysis.record_results:
                if result.record_type == "TXT":
                    result.records.extend(dmarc_result.records)
                    break

        # Run security analysis
        analysis.security_findings = self.security.analyze(analysis)

        # Build summary
        total_records = sum(len(r.records) for r in analysis.record_results)
        types_with_records = sum(1 for r in analysis.record_results if r.records)
        total_query_time = sum(r.query_time_ms for r in analysis.record_results)

        analysis.summary = {
            "total_records": total_records,
            "types_queried": len(record_types),
            "types_with_records": types_with_records,
            "security_findings_count": len(analysis.security_findings),
            "total_query_time_ms": total_query_time,
            "extended_mode": self.extended
        }

        return analysis

    def run(self, domain: str, no_color: bool = False, no_html: bool = False):
        """Run analysis, render, and export."""
        if no_color:
            Colors.disable()

        # Perform analysis
        analysis = self.analyze(domain)

        # Render to terminal
        self.renderer.render(analysis)

        # Export files
        safe_domain = domain.replace(".", "_")

        json_path = os.path.join(self.output_dir, f"{safe_domain}.json")
        self.json_exporter.export(analysis, json_path)
        self.logger.info(f"JSON saved to {json_path}")

        if not no_html:
            html_path = os.path.join(self.output_dir, f"{safe_domain}.html")
            self.html_exporter.export(analysis, html_path)
            self.logger.info(f"HTML report saved to {html_path}")

        return analysis


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Build argument parser."""
    parser = argparse.ArgumentParser(
        prog="dns_record_analyzer",
        description="DNS Record Type Analyzer - Query and analyze all DNS record types "
                    "for a domain with security assessment.",
        epilog="Part of the DNS Mastery curriculum - Lab 2"
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain(s) to analyze"
    )

    parser.add_argument(
        "--defaults",
        action="store_true",
        help="Analyze default sample domains (google.com, github.com, nasa.gov, "
             "microsoft.com, cloudflare.com)"
    )

    parser.add_argument(
        "--nameserver", "-n",
        help="Use a specific nameserver (e.g., 8.8.8.8, 1.1.1.1)"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Query timeout in seconds (default: 10)"
    )

    parser.add_argument(
        "--extended", "-e",
        action="store_true",
        help="Query extended record types (DNSSEC, TLSA, SSHFP, etc.)"
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="output",
        help="Output directory (default: output)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output"
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation"
    )

    parser.add_argument(
        "--compare",
        nargs=2,
        metavar=("DOMAIN1", "DOMAIN2"),
        help="Compare DNS records between two domains"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser


def compare_domains(analyzer: DNSRecordAnalyzer, domain1: str, domain2: str):
    """Compare DNS configurations of two domains."""
    c = Colors

    analysis1 = analyzer.analyze(domain1)
    analysis2 = analyzer.analyze(domain2)

    print(f"\n{c.BOLD}{c.CYAN}DNS Comparison: {domain1} vs {domain2}{c.RESET}")
    print(f"{c.DIM}{'─' * 60}{c.RESET}\n")

    all_types = set()
    for a in [analysis1, analysis2]:
        for r in a.record_results:
            if r.records:
                all_types.add(r.record_type)

    for rtype in sorted(all_types):
        records1 = []
        records2 = []
        for r in analysis1.record_results:
            if r.record_type == rtype:
                records1 = r.records
        for r in analysis2.record_results:
            if r.record_type == rtype:
                records2 = r.records

        print(f"  {c.BOLD}{rtype}{c.RESET}")
        print(f"    {domain1:30s} {domain2}")
        print(f"    {len(records1):>3} record(s){' ' * 19}{len(records2):>3} record(s)")

        if rtype == "TXT":
            tags1 = set()
            tags2 = set()
            for r in records1:
                tags1.update(r.security_tags)
            for r in records2:
                tags2.update(r.security_tags)
            if tags1 or tags2:
                print(f"    {c.MAGENTA}Security: {', '.join(tags1) or 'none':20s} "
                      f"{', '.join(tags2) or 'none'}{c.RESET}")
        print()

    # Compare security findings
    sev_count1 = {}
    sev_count2 = {}
    for f in analysis1.security_findings:
        sev_count1[f["severity"]] = sev_count1.get(f["severity"], 0) + 1
    for f in analysis2.security_findings:
        sev_count2[f["severity"]] = sev_count2.get(f["severity"], 0) + 1

    print(f"  {c.BOLD}Security Findings{c.RESET}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c1 = sev_count1.get(sev, 0)
        c2 = sev_count2.get(sev, 0)
        if c1 or c2:
            print(f"    {sev:10s} {c1:>3} vs {c2:>3}")


def main():
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # Determine domains
    domains = list(args.domains) if args.domains else []

    if args.defaults:
        domains = ["google.com", "github.com", "nasa.gov", "microsoft.com", "cloudflare.com"]

    if args.compare:
        analyzer = DNSRecordAnalyzer(
            nameserver=args.nameserver,
            timeout=args.timeout,
            extended=args.extended,
            output_dir=args.output_dir
        )
        compare_domains(analyzer, args.compare[0], args.compare[1])
        return

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Create analyzer
    analyzer = DNSRecordAnalyzer(
        nameserver=args.nameserver,
        timeout=args.timeout,
        extended=args.extended,
        output_dir=args.output_dir
    )

    # Analyze each domain
    for domain in domains:
        analyzer.run(domain, no_color=args.no_color, no_html=args.no_html)


if __name__ == "__main__":
    main()
