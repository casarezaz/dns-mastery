#!/usr/bin/env python3
"""
Zone Transfer Auditor
Lab 4 - DNS Mastery Curriculum

AXFR misconfiguration scanner that tests nameservers for unauthorized
zone transfers, analyzes exposed records for sensitive information,
and generates security audit reports with remediation guidance.

IMPORTANT: Only use this tool on domains you own or have explicit
authorization to test. Unauthorized zone transfer attempts may violate
computer crime laws in your jurisdiction.

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

# Known intentionally-vulnerable AXFR test domains
# These are set up specifically for security education and testing
SAFE_TEST_DOMAINS = {
    "zonetransfer.me": "Maintained by DigiNinja for AXFR testing",
    "nsztm1.digi.ninja": "DigiNinja test nameserver",
}

# Patterns that indicate sensitive records
SENSITIVE_PATTERNS = {
    "internal_ip": {
        "pattern": re.compile(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3})\b"
        ),
        "severity": "HIGH",
        "description": "Internal/RFC1918 IP address exposed",
        "mitre": "T1590.002 - Gather Victim Network Information: DNS",
    },
    "admin_host": {
        "pattern": re.compile(
            r"\b(admin|management|mgmt|vpn|internal|intranet|"
            r"staging|dev|test|backup|db|database|sql|mysql|"
            r"postgres|redis|mongo|elastic|kibana|grafana|"
            r"jenkins|gitlab|ci|cd|deploy|ansible|puppet|"
            r"chef|docker|kube|k8s|aws|azure|gcp)\b",
            re.IGNORECASE
        ),
        "severity": "MEDIUM",
        "description": "Infrastructure hostname revealing internal architecture",
        "mitre": "T1590.002 - Gather Victim Network Information: DNS",
    },
    "mail_server": {
        "pattern": re.compile(
            r"\b(mail|smtp|imap|pop3|exchange|mx|postfix|"
            r"sendmail|dovecot|zimbra|roundcube)\b",
            re.IGNORECASE
        ),
        "severity": "LOW",
        "description": "Mail server hostname exposed",
        "mitre": "T1589.002 - Gather Victim Identity Information: Email",
    },
    "version_info": {
        "pattern": re.compile(
            r"(TXT|HINFO).*?(v\d|version|os=|arch=|platform)",
            re.IGNORECASE
        ),
        "severity": "MEDIUM",
        "description": "Version or platform information in DNS records",
        "mitre": "T1592.002 - Gather Victim Host Information: Software",
    },
    "spf_all_pass": {
        "pattern": re.compile(r"v=spf1.*\+all", re.IGNORECASE),
        "severity": "CRITICAL",
        "description": "SPF record allows all senders (+all)",
        "mitre": "T1566 - Phishing",
    },
    "credential_hint": {
        "pattern": re.compile(
            r"\b(password|passwd|secret|token|key|credential|"
            r"apikey|api-key|auth)\b",
            re.IGNORECASE
        ),
        "severity": "CRITICAL",
        "description": "Potential credential or secret in DNS record",
        "mitre": "T1552.001 - Unsecured Credentials",
    },
}

# ANSI colors
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

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class ZoneRecord:
    """A DNS record from a zone transfer."""
    name: str
    ttl: int
    record_class: str
    record_type: str
    value: str
    sensitive_flags: list = field(default_factory=list)


@dataclass
class NameserverResult:
    """Zone transfer result for a single nameserver."""
    nameserver: str
    transfer_allowed: bool = False
    error: Optional[str] = None
    records: list = field(default_factory=list)
    record_count: int = 0
    unique_hostnames: int = 0
    record_type_counts: dict = field(default_factory=dict)
    transfer_time_ms: float = 0.0


@dataclass
class SensitiveFinding:
    """A sensitive record finding."""
    severity: str
    category: str
    description: str
    record_name: str
    record_type: str
    record_value: str
    mitre: str


@dataclass
class ZoneAudit:
    """Complete zone transfer audit results."""
    domain: str
    timestamp: str = ""
    nameservers: list = field(default_factory=list)
    nameserver_results: list = field(default_factory=list)
    sensitive_findings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ─── Zone Transfer Engine ────────────────────────────────────────────────────

class ZoneTransferEngine:
    """Performs zone transfer attempts and parses results."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.logger = logging.getLogger("ZoneTransferEngine")

    def get_nameservers(self, domain: str) -> list:
        """Get authoritative nameservers for a domain."""
        cmd = ["dig", "+short", "NS", domain]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
            nameservers = [
                ns.rstrip(".") for ns in proc.stdout.strip().split("\n")
                if ns.strip() and not ns.startswith(";")
            ]
            return nameservers
        except Exception as e:
            self.logger.error(f"Failed to get nameservers: {e}")
            return []

    def attempt_transfer(self, domain: str, nameserver: str) -> NameserverResult:
        """Attempt an AXFR zone transfer against a specific nameserver."""
        result = NameserverResult(nameserver=nameserver)

        cmd = ["dig", f"@{nameserver}", domain, "AXFR",
               f"+time={self.timeout}", "+tries=1"]

        self.logger.info(f"Attempting AXFR from {nameserver} for {domain}")

        try:
            import time
            start = time.monotonic()
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 10
            )
            elapsed = (time.monotonic() - start) * 1000
            result.transfer_time_ms = elapsed

            output = proc.stdout.strip()

            # Check for transfer failure indicators
            if "Transfer failed" in output or "transfer failed" in output.lower():
                result.transfer_allowed = False
                result.error = "Transfer refused by server"
                return result

            if "connection timed out" in output.lower():
                result.transfer_allowed = False
                result.error = "Connection timed out"
                return result

            if "connection refused" in output.lower():
                result.transfer_allowed = False
                result.error = "Connection refused"
                return result

            if "; Transfer size:" in output:
                result.transfer_allowed = True
                result.records = self._parse_zone_records(output)
                result.record_count = len(result.records)
                result.unique_hostnames = len(set(r.name for r in result.records))
                result.record_type_counts = self._count_record_types(result.records)
                return result

            # Check if we got actual records (some servers don't include Transfer size)
            records = self._parse_zone_records(output)
            if len(records) > 2:  # More than just SOA records
                result.transfer_allowed = True
                result.records = records
                result.record_count = len(records)
                result.unique_hostnames = len(set(r.name for r in records))
                result.record_type_counts = self._count_record_types(records)
            else:
                result.transfer_allowed = False
                result.error = "Transfer refused or no records returned"

        except subprocess.TimeoutExpired:
            result.error = f"Transfer timed out after {self.timeout}s"
        except Exception as e:
            result.error = str(e)

        return result

    def _parse_zone_records(self, output: str) -> list:
        """Parse AXFR output into ZoneRecord objects."""
        records = []
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("<<>>"):
                continue

            parts = line.split(None, 4)
            if len(parts) >= 5:
                try:
                    record = ZoneRecord(
                        name=parts[0],
                        ttl=int(parts[1]),
                        record_class=parts[2],
                        record_type=parts[3],
                        value=parts[4]
                    )
                    records.append(record)
                except (ValueError, IndexError):
                    continue

        return records

    def _count_record_types(self, records: list) -> dict:
        """Count records by type."""
        counts = {}
        for record in records:
            counts[record.record_type] = counts.get(record.record_type, 0) + 1
        return counts


# ─── Sensitivity Analyzer ─────────────────────────────────────────────────────

class SensitivityAnalyzer:
    """Analyzes zone transfer records for sensitive information."""

    def __init__(self):
        self.logger = logging.getLogger("SensitivityAnalyzer")

    def analyze(self, records: list) -> list:
        """Analyze records for sensitive information exposure."""
        findings = []

        for record in records:
            record_text = f"{record.name} {record.record_type} {record.value}"

            for category, config in SENSITIVE_PATTERNS.items():
                if config["pattern"].search(record_text):
                    finding = SensitiveFinding(
                        severity=config["severity"],
                        category=category,
                        description=config["description"],
                        record_name=record.name,
                        record_type=record.record_type,
                        record_value=record.value[:200],
                        mitre=config["mitre"]
                    )
                    findings.append(finding)
                    record.sensitive_flags.append(category)

        return findings

    def generate_remediation(self, audit: ZoneAudit) -> list:
        """Generate remediation recommendations."""
        recommendations = []

        # Check if any transfers were allowed
        vulnerable_ns = [
            r for r in audit.nameserver_results if r.transfer_allowed
        ]

        if vulnerable_ns:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Restrict Zone Transfers (AXFR)",
                "detail": (
                    f"{len(vulnerable_ns)} nameserver(s) allow unrestricted zone transfers. "
                    "This exposes your entire DNS zone to anyone who asks."
                ),
                "remediation": [
                    "BIND: Add 'allow-transfer { trusted-servers; };' to zone config",
                    "Windows DNS: Set zone transfer restrictions in DNS Manager",
                    "PowerDNS: Set 'allow-axfr-ips' in configuration",
                    "Consider using TSIG keys for authenticated zone transfers",
                ],
                "servers": [r.nameserver for r in vulnerable_ns]
            })

        # Check for internal IP exposure
        internal_findings = [
            f for f in audit.sensitive_findings if f.category == "internal_ip"
        ]
        if internal_findings:
            recommendations.append({
                "priority": "HIGH",
                "title": "Remove Internal IP Addresses from Public DNS",
                "detail": (
                    f"{len(internal_findings)} records expose RFC1918 internal addresses. "
                    "This reveals internal network topology to attackers."
                ),
                "remediation": [
                    "Use split-horizon DNS to serve different records internally vs externally",
                    "Remove internal-only records from public zone files",
                    "Use DNS views in BIND to separate internal/external zones",
                ],
                "examples": [
                    f"{f.record_name} → {f.record_value}" for f in internal_findings[:5]
                ]
            })

        # Check for infrastructure hostnames
        infra_findings = [
            f for f in audit.sensitive_findings if f.category == "admin_host"
        ]
        if infra_findings:
            recommendations.append({
                "priority": "MEDIUM",
                "title": "Minimize Infrastructure Hostname Exposure",
                "detail": (
                    f"{len(infra_findings)} hostnames reveal internal infrastructure "
                    "(databases, admin panels, CI/CD, etc.)."
                ),
                "remediation": [
                    "Use generic hostnames that don't reveal service types",
                    "Move administrative services behind VPN-only DNS",
                    "Consider using private DNS zones for internal services",
                ],
                "examples": [
                    f.record_name for f in infra_findings[:10]
                ]
            })

        # Check for credential hints
        cred_findings = [
            f for f in audit.sensitive_findings if f.category == "credential_hint"
        ]
        if cred_findings:
            recommendations.append({
                "priority": "CRITICAL",
                "title": "Remove Credential-Related Information from DNS",
                "detail": (
                    f"{len(cred_findings)} records contain potential credential "
                    "or secret references."
                ),
                "remediation": [
                    "Never store credentials, tokens, or secrets in DNS records",
                    "Audit all TXT records for sensitive information",
                    "Use a secrets manager instead of DNS for configuration",
                ],
                "examples": [
                    f"{f.record_name} ({f.record_type})" for f in cred_findings[:5]
                ]
            })

        return recommendations


# ─── Terminal Renderer ────────────────────────────────────────────────────────

class TerminalRenderer:
    """Renders audit results to terminal."""

    def render(self, audit: ZoneAudit, recommendations: list):
        """Render complete audit."""
        c = Colors

        print(f"\n{c.BOLD}{'═' * 60}{c.RESET}")
        print(f"{c.BOLD}{c.CYAN}  Zone Transfer Audit: {audit.domain}{c.RESET}")
        print(f"{c.BOLD}{'═' * 60}{c.RESET}")
        print(f"{c.DIM}Timestamp: {audit.timestamp}{c.RESET}")

        # Nameserver results
        print(f"\n{c.BOLD}{c.YELLOW}Nameservers ({len(audit.nameservers)}){c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        for result in audit.nameserver_results:
            self._render_ns_result(result)

        # Sensitive findings
        if audit.sensitive_findings:
            self._render_findings(audit.sensitive_findings)

        # Zone statistics (for successful transfers)
        for result in audit.nameserver_results:
            if result.transfer_allowed:
                self._render_zone_stats(result)

        # Remediation
        if recommendations:
            self._render_remediation(recommendations)

        # Summary
        self._render_summary(audit.summary)

    def _render_ns_result(self, result: NameserverResult):
        """Render a single nameserver result."""
        c = Colors

        if result.transfer_allowed:
            status = f"{c.RED}{c.BOLD}⚠ VULNERABLE - AXFR ALLOWED{c.RESET}"
            detail = (f"  {c.RED}Received {result.record_count} records "
                      f"({result.unique_hostnames} unique hostnames) "
                      f"in {result.transfer_time_ms:.0f}ms{c.RESET}")
        elif result.error:
            status = f"{c.GREEN}✓ Protected{c.RESET} {c.DIM}({result.error}){c.RESET}"
            detail = ""
        else:
            status = f"{c.GREEN}✓ Transfer refused{c.RESET}"
            detail = ""

        print(f"\n  {c.BOLD}{result.nameserver}{c.RESET}")
        print(f"    {status}")
        if detail:
            print(detail)

    def _render_findings(self, findings: list):
        """Render sensitive findings."""
        c = Colors

        print(f"\n{c.BOLD}{c.RED}Sensitive Records Found ({len(findings)}){c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.severity, 4)
        )

        # Group by category
        categories = {}
        for finding in sorted_findings:
            if finding.category not in categories:
                categories[finding.category] = []
            categories[finding.category].append(finding)

        for category, cat_findings in categories.items():
            severity = cat_findings[0].severity
            icon, color = self._severity_style(severity)

            print(f"\n  {color}{icon} {cat_findings[0].description} "
                  f"({len(cat_findings)} records){c.RESET}")

            for f in cat_findings[:5]:  # Show first 5
                name_display = f.record_name
                if len(name_display) > 35:
                    name_display = name_display[:32] + "..."
                value_display = f.record_value
                if len(value_display) > 50:
                    value_display = value_display[:47] + "..."
                print(f"    {c.DIM}{name_display:35s} {f.record_type:6s} "
                      f"{value_display}{c.RESET}")

            if len(cat_findings) > 5:
                print(f"    {c.DIM}... and {len(cat_findings) - 5} more{c.RESET}")

    def _render_zone_stats(self, result: NameserverResult):
        """Render zone statistics."""
        c = Colors

        print(f"\n{c.BOLD}{c.BLUE}Zone Statistics ({result.nameserver}){c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        print(f"  Total records:      {result.record_count}")
        print(f"  Unique hostnames:   {result.unique_hostnames}")
        print(f"  Transfer time:      {result.transfer_time_ms:.0f}ms")
        print(f"\n  Record type breakdown:")

        for rtype, count in sorted(
            result.record_type_counts.items(),
            key=lambda x: x[1], reverse=True
        ):
            bar_len = min(count, 40)
            bar = "█" * bar_len
            type_color = self._type_color(rtype)
            print(f"    {type_color}{rtype:8s}{c.RESET} {count:>5}  {c.DIM}{bar}{c.RESET}")

    def _render_remediation(self, recommendations: list):
        """Render remediation recommendations."""
        c = Colors

        print(f"\n{c.BOLD}{c.MAGENTA}Remediation Recommendations{c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        for i, rec in enumerate(recommendations, 1):
            priority = rec["priority"]
            icon, color = self._severity_style(priority)

            print(f"\n  {color}{icon} [{priority}] {rec['title']}{c.RESET}")
            print(f"    {rec['detail']}")

            print(f"    {c.BOLD}Steps:{c.RESET}")
            for step in rec["remediation"]:
                print(f"      • {step}")

            if "examples" in rec:
                print(f"    {c.DIM}Examples:{c.RESET}")
                for ex in rec["examples"][:3]:
                    print(f"      {c.DIM}{ex}{c.RESET}")

    def _render_summary(self, summary: dict):
        """Render audit summary."""
        c = Colors

        print(f"\n{c.DIM}{'─' * 60}{c.RESET}")

        vuln = summary.get("vulnerable_nameservers", 0)
        total = summary.get("total_nameservers", 0)
        findings = summary.get("total_sensitive_findings", 0)

        if vuln > 0:
            verdict = f"{c.RED}{c.BOLD}FAIL{c.RESET}"
        else:
            verdict = f"{c.GREEN}{c.BOLD}PASS{c.RESET}"

        print(f"  {c.BOLD}Audit Verdict:{c.RESET} {verdict}")
        print(f"  Nameservers: {vuln}/{total} allow zone transfers")
        print(f"  Sensitive findings: {findings}")
        print(f"  Records exposed: {summary.get('total_records_exposed', 0)}")
        print()

    def _severity_style(self, severity: str) -> tuple:
        c = Colors
        styles = {
            "CRITICAL": ("🔴", c.RED + c.BOLD),
            "HIGH": ("🟠", c.RED),
            "MEDIUM": ("🟡", c.YELLOW),
            "LOW": ("🔵", c.BLUE),
            "INFO": ("ℹ️ ", c.DIM),
        }
        return styles.get(severity, ("•", c.WHITE))

    def _type_color(self, record_type: str) -> str:
        c = Colors
        colors = {
            "A": c.GREEN, "AAAA": c.GREEN, "MX": c.CYAN,
            "NS": c.BLUE, "TXT": c.YELLOW, "CNAME": c.MAGENTA,
            "SOA": c.WHITE, "SRV": c.CYAN, "PTR": c.MAGENTA,
        }
        return colors.get(record_type, c.WHITE)


# ─── File Exporters ───────────────────────────────────────────────────────────

class JSONExporter:
    """Export audit results to JSON."""

    def export(self, audit: ZoneAudit, recommendations: list, filepath: str):
        data = {
            "domain": audit.domain,
            "timestamp": audit.timestamp,
            "nameservers": audit.nameservers,
            "nameserver_results": [],
            "sensitive_findings": [asdict(f) for f in audit.sensitive_findings],
            "recommendations": recommendations,
            "summary": audit.summary
        }

        for result in audit.nameserver_results:
            ns_data = {
                "nameserver": result.nameserver,
                "transfer_allowed": result.transfer_allowed,
                "error": result.error,
                "record_count": result.record_count,
                "unique_hostnames": result.unique_hostnames,
                "record_type_counts": result.record_type_counts,
                "transfer_time_ms": result.transfer_time_ms,
                "records": [asdict(r) for r in result.records] if result.transfer_allowed else []
            }
            data["nameserver_results"].append(ns_data)

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


class HTMLExporter:
    """Export audit results to HTML report."""

    def export(self, audit: ZoneAudit, recommendations: list, filepath: str):
        ns_html = ""
        for result in audit.nameserver_results:
            if result.transfer_allowed:
                status_class = "vulnerable"
                status_text = f"⚠ VULNERABLE — {result.record_count} records exposed"
            else:
                status_class = "protected"
                status_text = f"✓ Protected — {result.error or 'Transfer refused'}"

            ns_html += f"""
            <div class="ns-result {status_class}">
                <strong>{result.nameserver}</strong>
                <span class="status">{status_text}</span>
            </div>"""

        findings_html = ""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            audit.sensitive_findings,
            key=lambda f: severity_order.get(f.severity, 4)
        )
        for finding in sorted_findings[:50]:
            findings_html += f"""
            <tr class="{finding.severity.lower()}">
                <td><span class="severity-badge">{finding.severity}</span></td>
                <td>{finding.record_name}</td>
                <td>{finding.record_type}</td>
                <td>{finding.description}</td>
                <td class="dim">{finding.mitre}</td>
            </tr>"""

        rec_html = ""
        for rec in recommendations:
            steps = "".join(f"<li>{s}</li>" for s in rec["remediation"])
            rec_html += f"""
            <div class="finding {rec['priority'].lower()}">
                <span class="severity-badge">{rec["priority"]}</span>
                <strong>{rec["title"]}</strong>
                <p>{rec["detail"]}</p>
                <ul>{steps}</ul>
            </div>"""

        # Record type chart data
        chart_data = {}
        for result in audit.nameserver_results:
            if result.transfer_allowed:
                chart_data = result.record_type_counts
                break

        summary = audit.summary
        vuln = summary.get("vulnerable_nameservers", 0)
        verdict_class = "fail" if vuln > 0 else "pass"
        verdict_text = "FAIL — Zone Transfers Allowed" if vuln > 0 else "PASS — Zone Transfers Restricted"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zone Transfer Audit: {audit.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', 'Fira Code', monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 0.5rem; }}
        h2 {{ color: #ffd700; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
        .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 2rem; }}
        .verdict {{ padding: 1.5rem; border-radius: 8px; text-align: center; font-size: 1.3rem; font-weight: bold; margin: 1rem 0; }}
        .verdict.fail {{ background: #ff000020; border: 2px solid #ff0000; color: #ff4444; }}
        .verdict.pass {{ background: #00ff8820; border: 2px solid #00ff88; color: #00ff88; }}
        .ns-result {{ padding: 1rem; margin: 0.5rem 0; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }}
        .ns-result.vulnerable {{ background: #ff000015; border-left: 4px solid #ff0000; }}
        .ns-result.protected {{ background: #00ff8815; border-left: 4px solid #00ff88; }}
        .ns-result .status {{ font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
        th {{ text-align: left; padding: 0.5rem; color: #888; border-bottom: 1px solid #333; background: #0f3460; }}
        td {{ padding: 0.5rem; border-bottom: 1px solid #222; word-break: break-all; }}
        tr.critical td {{ border-left: 3px solid #ff0000; }}
        tr.high td {{ border-left: 3px solid #ff4400; }}
        tr.medium td {{ border-left: 3px solid #ffaa00; }}
        tr.low td {{ border-left: 3px solid #4488ff; }}
        .severity-badge {{ font-size: 0.7rem; padding: 0.15rem 0.4rem; border-radius: 3px; font-weight: bold; }}
        .critical .severity-badge {{ background: #ff0000; color: white; }}
        .high .severity-badge {{ background: #ff4400; color: white; }}
        .medium .severity-badge {{ background: #ffaa00; color: black; }}
        .low .severity-badge {{ background: #4488ff; color: white; }}
        .finding {{ padding: 1rem; margin: 0.5rem 0; border-radius: 4px; border-left: 4px solid; }}
        .finding.critical {{ background: #ff000015; border-color: #ff0000; }}
        .finding.high {{ background: #ff440015; border-color: #ff4400; }}
        .finding.medium {{ background: #ffaa0015; border-color: #ffaa00; }}
        .finding ul {{ margin: 0.5rem 0 0 1.5rem; }}
        .finding li {{ margin: 0.3rem 0; }}
        .dim {{ color: #888; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }}
        .stat {{ background: #16213e; padding: 1rem; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 1.8rem; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ font-size: 0.75rem; color: #888; margin-top: 0.3rem; }}
        .chart-container {{ background: #16213e; padding: 1.5rem; border-radius: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Zone Transfer Audit</h1>
        <p class="meta">{audit.domain} &mdash; {audit.timestamp}</p>

        <div class="verdict {verdict_class}">{verdict_text}</div>

        <div class="stat-grid">
            <div class="stat">
                <div class="stat-value">{summary.get('total_nameservers', 0)}</div>
                <div class="stat-label">Nameservers</div>
            </div>
            <div class="stat">
                <div class="stat-value" style="color: {'#ff4444' if vuln > 0 else '#00ff88'};">{vuln}</div>
                <div class="stat-label">Vulnerable</div>
            </div>
            <div class="stat">
                <div class="stat-value">{summary.get('total_records_exposed', 0)}</div>
                <div class="stat-label">Records Exposed</div>
            </div>
            <div class="stat">
                <div class="stat-value">{summary.get('total_sensitive_findings', 0)}</div>
                <div class="stat-label">Sensitive Findings</div>
            </div>
        </div>

        <h2>Nameserver Results</h2>
        {ns_html}

        {"<h2>Sensitive Records</h2><table><thead><tr><th>Severity</th><th>Name</th><th>Type</th><th>Finding</th><th>MITRE</th></tr></thead><tbody>" + findings_html + "</tbody></table>" if findings_html else ""}

        {f"<h2>Record Type Distribution</h2><div class='chart-container'><canvas id='typeChart'></canvas></div>" if chart_data else ""}

        {"<h2>Remediation</h2>" + rec_html if rec_html else ""}

        <p class="meta" style="margin-top: 2rem; text-align: center;">
            Generated by Zone Transfer Auditor v{VERSION} &mdash; DNS Mastery Lab 4
        </p>
    </div>

    {f'''<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script>
    const typeData = {json.dumps(chart_data)};
    const labels = Object.keys(typeData);
    const values = Object.values(typeData);
    const colors = labels.map((_, i) => [
        '#00d4ff', '#00ff88', '#ff88ff', '#ffaa00', '#ff4444',
        '#4488ff', '#ff00ff', '#00ffff', '#ffff00', '#ff8800'
    ][i % 10]);

    new Chart(document.getElementById('typeChart'), {{
        type: 'bar',
        data: {{
            labels: labels,
            datasets: [{{ label: 'Record Count', data: values, backgroundColor: colors }}]
        }},
        options: {{
            responsive: true,
            plugins: {{
                legend: {{ display: false }},
                title: {{ display: true, text: 'Records by Type', color: '#e0e0e0' }}
            }},
            scales: {{
                x: {{ ticks: {{ color: '#888' }}, grid: {{ color: '#333' }} }},
                y: {{ ticks: {{ color: '#888' }}, grid: {{ color: '#333' }} }}
            }}
        }}
    }});
    </script>''' if chart_data else ""}
</body>
</html>"""

        with open(filepath, "w") as f:
            f.write(html)


# ─── Main Auditor ─────────────────────────────────────────────────────────────

class ZoneTransferAuditor:
    """Main orchestrator for zone transfer audits."""

    def __init__(self, timeout: int = 15, output_dir: str = "output"):
        self.engine = ZoneTransferEngine(timeout=timeout)
        self.sensitivity = SensitivityAnalyzer()
        self.renderer = TerminalRenderer()
        self.json_exporter = JSONExporter()
        self.html_exporter = HTMLExporter()
        self.output_dir = output_dir
        self.logger = logging.getLogger("ZoneTransferAuditor")

        os.makedirs(output_dir, exist_ok=True)

    def audit(self, domain: str) -> ZoneAudit:
        """Perform complete zone transfer audit."""
        audit = ZoneAudit(domain=domain)

        # Get nameservers
        self.logger.info(f"Getting nameservers for {domain}")
        audit.nameservers = self.engine.get_nameservers(domain)

        if not audit.nameservers:
            self.logger.error(f"No nameservers found for {domain}")
            return audit

        self.logger.info(f"Found {len(audit.nameservers)} nameservers")

        # Attempt transfer from each nameserver
        all_records = []
        for ns in audit.nameservers:
            result = self.engine.attempt_transfer(domain, ns)
            audit.nameserver_results.append(result)
            if result.transfer_allowed:
                all_records.extend(result.records)

        # Analyze for sensitive records
        if all_records:
            audit.sensitive_findings = self.sensitivity.analyze(all_records)

        # Build summary
        vulnerable = sum(
            1 for r in audit.nameserver_results if r.transfer_allowed
        )
        total_exposed = sum(
            r.record_count for r in audit.nameserver_results if r.transfer_allowed
        )

        audit.summary = {
            "total_nameservers": len(audit.nameservers),
            "vulnerable_nameservers": vulnerable,
            "protected_nameservers": len(audit.nameservers) - vulnerable,
            "total_records_exposed": total_exposed,
            "total_sensitive_findings": len(audit.sensitive_findings),
            "critical_findings": sum(
                1 for f in audit.sensitive_findings if f.severity == "CRITICAL"
            ),
            "high_findings": sum(
                1 for f in audit.sensitive_findings if f.severity == "HIGH"
            ),
        }

        return audit

    def run(self, domain: str, no_color: bool = False,
            no_html: bool = False) -> ZoneAudit:
        """Run full audit with rendering and export."""
        if no_color:
            Colors.disable()

        # Safety check
        if domain not in SAFE_TEST_DOMAINS:
            c = Colors
            print(f"\n{c.YELLOW}{c.BOLD}⚠  Authorization Notice{c.RESET}")
            print(f"{c.YELLOW}You are about to test zone transfers for: {domain}")
            print(f"Ensure you have authorization to test this domain.")
            print(f"For safe practice, use: zonetransfer.me{c.RESET}\n")

        audit = self.audit(domain)
        recommendations = self.sensitivity.generate_remediation(audit)

        # Render
        self.renderer.render(audit, recommendations)

        # Export
        safe_domain = domain.replace(".", "_")

        json_path = os.path.join(self.output_dir, f"{safe_domain}_axfr.json")
        self.json_exporter.export(audit, recommendations, json_path)
        self.logger.info(f"JSON saved to {json_path}")

        if not no_html:
            html_path = os.path.join(self.output_dir, f"{safe_domain}_axfr.html")
            self.html_exporter.export(audit, recommendations, html_path)
            self.logger.info(f"HTML report saved to {html_path}")

        return audit


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zone_transfer_auditor",
        description="Zone Transfer Auditor - Test for AXFR misconfigurations, "
                    "analyze exposed records, and generate security audit reports.",
        epilog=(
            "Part of the DNS Mastery curriculum - Lab 4\n\n"
            "SAFE TEST DOMAINS:\n"
            "  zonetransfer.me    — Intentionally vulnerable AXFR test domain\n"
            "  nsztm1.digi.ninja  — DigiNinja test nameserver\n\n"
            "Only test domains you own or have explicit authorization to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain(s) to audit"
    )

    parser.add_argument(
        "--safe-test",
        action="store_true",
        help="Run against zonetransfer.me (safe, intentionally vulnerable)"
    )

    parser.add_argument(
        "--nameserver", "-n",
        help="Test a specific nameserver instead of discovering them"
    )

    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=15,
        help="Query timeout in seconds (default: 15)"
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="output",
        help="Output directory (default: output)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation"
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


def main():
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    domains = list(args.domains) if args.domains else []

    if args.safe_test:
        domains = ["zonetransfer.me"]

    if not domains:
        parser.print_help()
        print("\n💡 Tip: Use --safe-test to run against zonetransfer.me (safe practice domain)")
        sys.exit(1)

    auditor = ZoneTransferAuditor(
        timeout=args.timeout,
        output_dir=args.output_dir
    )

    for domain in domains:
        auditor.run(
            domain=domain,
            no_color=args.no_color,
            no_html=args.no_html
        )


if __name__ == "__main__":
    main()
