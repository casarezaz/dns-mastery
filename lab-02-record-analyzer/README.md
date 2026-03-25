# Lab 2: DNS Record Type Analyzer

> **DNS Mastery Curriculum** — Week 2: Record Types Deep Dive

## Overview

A comprehensive DNS record type query tool that retrieves, displays, and analyzes all standard record types for any domain. Highlights security-relevant records (SPF, DKIM, DMARC, CAA) and provides an automated security posture assessment with MITRE ATT&CK mapping.

## What This Tool Does

Given a domain, the analyzer:
1. Queries all standard DNS record types (A, AAAA, MX, CNAME, TXT, SOA, NS, SRV, CAA, PTR)
2. Optionally queries extended types (DNSKEY, DS, RRSIG, TLSA, SSHFP, etc.)
3. Automatically checks `_dmarc.` subdomain for DMARC records
4. Identifies security-relevant TXT records (SPF, DKIM, DMARC, BIMI, MTA-STS, TLSRPT)
5. Performs automated security analysis with findings and recommendations
6. Exports results as JSON and styled HTML reports

## Key Concepts Demonstrated

- **DNS Record Types**: Understanding the purpose and structure of each record type
- **Email Security Triad**: SPF + DKIM + DMARC working together to prevent spoofing
- **Certificate Authority Authorization**: CAA records restricting certificate issuance
- **DNSSEC**: Digital signatures for DNS integrity
- **Nameserver Resilience**: Diversity and redundancy in NS configurations
- **MITRE ATT&CK**: Mapping DNS security gaps to known attack techniques

## Quick Start

### Prerequisites

```bash
# macOS
brew install bind # provides dig
```

### Usage

```bash
# Analyze a single domain
python3 dns_record_analyzer.py google.com

# Analyze default sample domains
python3 dns_record_analyzer.py --defaults

# Extended mode (includes DNSSEC records)
python3 dns_record_analyzer.py --extended nasa.gov

# Use a specific nameserver
python3 dns_record_analyzer.py -n 8.8.8.8 cloudflare.com

# Compare two domains
python3 dns_record_analyzer.py --compare google.com microsoft.com

# All options
python3 dns_record_analyzer.py --help
```

### Output

Each analysis produces:
- **Terminal output**: Color-coded records with security tags and findings
- **JSON file**: `output/<domain>.json` — structured data for programmatic use
- **HTML report**: `output/<domain>.html` — styled report for portfolio/presentation

## Architecture

```
dns_record_analyzer.py
├── DNSQueryEngine # Runs dig queries, parses output
├── SecurityAnalyzer # Checks email security, CAA, DNSSEC, NS diversity
├── TerminalRenderer # Color-coded terminal display
├── JSONExporter # Structured JSON output
├── HTMLExporter # Styled HTML report generation
└── DNSRecordAnalyzer # Main orchestrator
```

### Design Decisions

- **dig over dnspython**: Uses `dig` directly for transparency — you can see exactly what queries are being made, which reinforces learning. No pip dependencies.
- **Security-first TXT parsing**: TXT records are automatically scanned against known security record patterns (SPF, DKIM, DMARC, BIMI, MTA-STS, etc.)
- **DMARC auto-discovery**: Automatically queries `_dmarc.<domain>` since DMARC records live at a subdomain, not the apex.
- **Separated data and rendering**: `DNSRecord` and `RecordTypeResult` dataclasses keep data clean; renderers handle display. Easy to add new export formats.

## Security Analysis

The tool checks for:

| Check | Severity | MITRE ATT&CK |
|-------|----------|---------------|
| Missing SPF record | HIGH | T1566 - Phishing |
| Permissive SPF (+all) | CRITICAL | T1566.001 - Spearphishing |
| Missing DMARC record | HIGH | T1566 - Phishing |
| Missing CAA records | MEDIUM | T1557 - Adversary-in-the-Middle |
| No DNSSEC | MEDIUM | T1557.004 - DNS Spoofing |
| Single NS provider | LOW | T1498 - Network DoS |
| No MX / null MX | INFO | N/A |

## Sample Output

```
DNS Record Analysis: google.com
────────────────────────────────────────────────────────────

 A (1 record, 24ms)
 142.250.80.46
 TTL: 300s (5m 0s)

 MX (5 records, 31ms)
 10 smtp.google.com.
 TTL: 300s (5m 0s)
 ...

 TXT (4 records, 28ms)
 ● "v=spf1 include:_spf.google.com ~all"
 [SPF]
 TTL: 300s (5m 0s)

Security Analysis
────────────────────────────────────────────────────────────

 ℹ️ [INFO] Email Security
 SPF record present: "v=spf1 include:_spf.google.com ~all"...
 → Verify SPF includes all legitimate senders
 MITRE ATT&CK: T1566 - Phishing
```

## MITRE ATT&CK Mapping

| Technique | Relevance |
|-----------|-----------|
| T1566 - Phishing | Email authentication prevents domain spoofing |
| T1566.001 - Spearphishing Attachment | SPF/DMARC detect forged sender domains |
| T1557 - Adversary-in-the-Middle | CAA prevents unauthorized certificate issuance |
| T1557.004 - DNS Spoofing | DNSSEC provides cryptographic integrity |
| T1498 - Network DoS | NS diversity prevents single-point-of-failure |

## Portfolio Application

This tool demonstrates:
- Understanding of all major DNS record types and their security implications
- Automated security posture assessment methodology
- Mapping technical findings to the MITRE ATT&CK framework
- Clean Python architecture with separated concerns
- Professional reporting (terminal, JSON, HTML)

## Connections to Other Labs

- **Lab 1 (Hierarchy Mapper)**: Understanding delegation before querying records
- **Lab 5 (Reconnaissance Framework)**: This tool becomes a module in the larger recon toolkit
- **Lab 8 (DNSSEC Validator)**: Extended mode here previews DNSSEC deep dive
- **Lab 12 (Capstone)**: Security findings feed into the unified analysis platform

## Reading Assignment

- *DNS and BIND*, Ch. 4: DNS Record Types
- *DNS and BIND*, Ch. 16: Security (SPF, DKIM, DMARC)
- *The Hidden Potential of DNS in Security*, Ch. 3: DNS as a Security Tool

## License

MIT
