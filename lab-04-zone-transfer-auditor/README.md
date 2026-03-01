# Lab 4: Zone Transfer Auditor

> **DNS Mastery Curriculum** — Week 4: Zone Files & AXFR Security

## Overview

An AXFR misconfiguration scanner that tests nameservers for unauthorized zone transfers, analyzes exposed records for sensitive information (internal IPs, admin hostnames, credentials), and generates security audit reports with MITRE ATT&CK mapping and remediation guidance.

## What This Tool Does

Given a domain, the auditor:
1. Discovers all authoritative nameservers via NS lookup
2. Attempts AXFR (zone transfer) against each nameserver
3. Identifies which servers allow unrestricted transfers (vulnerability)
4. Scans exposed records for sensitive information patterns
5. Generates remediation recommendations with server-specific fix commands
6. Exports results as JSON and styled HTML audit reports

## Key Concepts Demonstrated

- **Zone Transfers (AXFR)**: How DNS servers replicate zone data and why unrestricted transfers are dangerous
- **Zone File Structure**: Understanding the complete contents of a DNS zone
- **Information Leakage**: Internal IPs, infrastructure hostnames, and credentials exposed through DNS
- **Split-Horizon DNS**: Serving different records internally vs externally
- **TSIG Authentication**: Securing zone transfers with shared keys
- **Attack Surface Mapping**: How attackers use zone transfers for reconnaissance

## Quick Start

### Prerequisites

```bash
# macOS
brew install bind    # provides dig
```

### Usage

```bash
# Safe practice — test against intentionally-vulnerable domain
python3 zone_transfer_auditor.py --safe-test

# Audit a specific domain (must have authorization!)
python3 zone_transfer_auditor.py example.com

# Test against a specific nameserver
python3 zone_transfer_auditor.py example.com -n ns1.example.com

# All options
python3 zone_transfer_auditor.py --help
```

### Safe Test Domain

`zonetransfer.me` is maintained by DigiNinja specifically for AXFR security testing. It's intentionally configured to allow zone transfers so students can practice safely. Always start here:

```bash
python3 zone_transfer_auditor.py --safe-test
```

## Architecture

```
zone_transfer_auditor.py
├── ZoneTransferEngine    # NS discovery + AXFR attempts via dig
├── SensitivityAnalyzer   # Pattern matching for sensitive records + remediation
├── TerminalRenderer      # Color-coded audit display with severity indicators
├── JSONExporter          # Structured JSON audit output
├── HTMLExporter          # Styled HTML report with Chart.js visualizations
└── ZoneTransferAuditor   # Main orchestrator
```

### Design Decisions

- **Authorization warning**: Displays a prominent warning when testing domains not in the safe-test list. Ethical security practice starts with the tooling.
- **dig over dnspython**: Direct `dig AXFR` calls for transparency — you see exactly what's happening on the wire.
- **Sensitivity patterns**: Regex-based detection for internal IPs (RFC1918), infrastructure hostnames, credential hints, permissive SPF, and version information.
- **Remediation by server type**: Provides BIND, Windows DNS, and PowerDNS fix commands because real-world remediation varies by platform.

## Sensitive Record Detection

The tool scans for:

| Category | Pattern | Severity | Example |
|----------|---------|----------|---------|
| Internal IPs | RFC1918 addresses (10.x, 172.16-31.x, 192.168.x) | HIGH | `internal.example.com → 10.0.1.50` |
| Admin Hostnames | admin, vpn, staging, jenkins, database, etc. | MEDIUM | `jenkins.example.com` |
| Mail Servers | smtp, imap, exchange, postfix | LOW | `smtp.example.com` |
| Version Info | Platform/version strings in TXT/HINFO | MEDIUM | `TXT "platform=Linux 5.4"` |
| Permissive SPF | v=spf1 +all | CRITICAL | Allows anyone to spoof email |
| Credential Hints | password, token, apikey, secret | CRITICAL | `TXT "apikey=..."` |

## MITRE ATT&CK Mapping

| Technique | Connection |
|-----------|------------|
| T1590.002 - Gather Victim Network Information: DNS | Zone transfers reveal complete DNS infrastructure |
| T1589.002 - Gather Victim Identity Information: Email | Exposed MX records enable targeted phishing |
| T1592.002 - Gather Victim Host Information: Software | Version strings in records reveal attack surface |
| T1552.001 - Unsecured Credentials | Credentials/tokens accidentally stored in DNS |
| T1566 - Phishing | Permissive SPF enables domain spoofing |

## Security & Ethics

This tool is designed for authorized security testing only.

**Legal considerations:**
- Only test domains you own or have written authorization to test
- Unauthorized zone transfer attempts may violate the CFAA (US) or equivalent laws
- The `--safe-test` flag uses zonetransfer.me, which is explicitly provided for testing
- Always follow your organization's rules of engagement for security assessments

**Responsible disclosure:**
- If you discover an open zone transfer on a third-party domain, follow responsible disclosure practices
- Contact the domain owner's security team (check security.txt or abuse@ contact)

## Connections to Other Labs

- **Lab 2 (Record Analyzer)**: Zone transfer exposes the complete set of records analyzed in Lab 2
- **Lab 5 (Reconnaissance Framework)**: AXFR is a key reconnaissance technique in the framework
- **Lab 8 (DNSSEC Validator)**: DNSSEC doesn't prevent AXFR but authenticates transferred data
- **Lab 10 (DNS Firewall)**: RPZ policies can detect/block AXFR attempts

## Reading Assignment

- *DNS and BIND*, Ch. 10: Zone Transfers (AXFR/IXFR)
- *DNS and BIND*, Ch. 11: Security — Restricting zone transfers
- *The Hidden Potential of DNS in Security*, Ch. 5: DNS as an Attack Vector

## License

MIT
