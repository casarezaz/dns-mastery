# Lab 02 — Zone Transfer Auditor

A security auditing tool that tests DNS servers for unauthorized **AXFR zone transfers**, analyzes leaked zone data for sensitive records, and produces actionable audit reports with MITRE ATT&CK mapping.

Zone transfers (AXFR/IXFR) are designed for replicating DNS data between authoritative servers, but misconfigured servers that allow transfers to any client expose the **entire zone file** — giving attackers a complete map of hostnames, IPs, mail servers, service records, and internal infrastructure.

## Features

- **Zero external dependencies** — pure Python 3.10+ using only the standard library (raw DNS wire protocol implementation)
- **Automatic NS discovery** — resolves authoritative nameservers via public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9)
- **Full AXFR implementation** — TCP-based zone transfer with proper SOA framing and multi-message handling
- **Zone data analysis engine** with 9 detection modules:
  - Record type distribution & zone statistics
  - Sensitive TXT record detection (SPF, DKIM, DMARC, API keys, tokens, credentials)
  - Internal hostname pattern matching (dev, staging, admin, vpn, db, CI/CD tools)
  - RFC 1918 private IP leak detection
  - SRV record service enumeration
  - MX record mail infrastructure mapping
  - Wildcard record identification
  - Low TTL anomaly detection
  - CAA record absence warning
- **Risk scoring** (0–100) with severity ratings (PASS → LOW → MEDIUM → HIGH → CRITICAL)
- **Multiple output formats** — human-readable text reports, structured JSON, and CSV record export
- **Actionable remediation guidance** with BIND and Windows DNS configuration examples
- **8 production Splunk SPL detection queries** for SOC monitoring

## MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|-----------|------|-----------|
| [T1590.002](https://attack.mitre.org/techniques/T1590/002/) | Gather Victim Network Information: DNS | Primary — zone transfers enumerate all DNS records in a domain |
| [T1018](https://attack.mitre.org/techniques/T1018/) | Remote System Discovery | Leaked A/AAAA records and internal hostnames reveal network topology |
| [T1526](https://attack.mitre.org/techniques/T1526/) | Cloud Service Discovery | SRV and CNAME records expose cloud services and infrastructure |

## Installation

No installation required — clone and run:

```bash
git clone https://github.com/casarezaz/dns-mastery.git
cd dns-mastery/lab02-zone-transfer-auditor
python3 zone_transfer_auditor.py --help
```

**Requirements:** Python 3.10+ (uses `match` syntax and type hints)

## Usage

### Basic audit (auto-discovers nameservers)

```bash
python3 zone_transfer_auditor.py example.com
```

### Test against a known-vulnerable domain

```bash
python3 zone_transfer_auditor.py zonetransfer.me --verbose
```

### Specify nameservers manually

```bash
python3 zone_transfer_auditor.py example.com \
    --server ns1.example.com:1.2.3.4 \
    --server ns2.example.com:5.6.7.8
```

### JSON report output

```bash
python3 zone_transfer_auditor.py example.com --format json --output report.json
```

### Export transferred records to CSV

```bash
python3 zone_transfer_auditor.py zonetransfer.me --export-records zone_records.csv
```

### Full options

```
usage: zone_transfer_auditor [-h] [--server HOST:IP] [--format {text,json}]
                              [--output FILE] [--export-records FILE]
                              [--timeout SECONDS] [--verbose] [--version]
                              domain

positional arguments:
  domain                Target domain to audit (e.g., example.com)

options:
  --server, -s HOST:IP  Specify nameserver(s) manually (repeatable)
  --format, -f          Output format: text (default) or json
  --output, -o FILE     Write report to file instead of stdout
  --export-records FILE Export transferred records to CSV
  --timeout, -t SECS    TCP connection timeout (default: 10)
  --verbose, -v         Print progress to stderr
  --version, -V         Show version and exit
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | All servers denied zone transfers (secure) |
| `1`  | One or more servers allowed zone transfers (vulnerable) |

This makes the tool composable in scripts and CI/CD pipelines:

```bash
python3 zone_transfer_auditor.py yourdomain.com || echo "ALERT: Zone transfer vulnerability detected!"
```

## Sample Output

```
========================================================================
  ZONE TRANSFER AUDIT REPORT
========================================================================
  Domain     : zonetransfer.me
  Timestamp  : 2026-03-25T12:00:00Z
  Risk Score : 75/100 (CRITICAL)
========================================================================

[ SERVER RESULTS ]
------------------------------------------------------------------------
  [!!] nsztm1.digi.ninja (81.4.108.41)
       Transfer: ALLOWED  |  Records: 52  |  Time: 245.3ms
  [!!] nsztm2.digi.ninja (34.225.33.2)
       Transfer: ALLOWED  |  Records: 52  |  Time: 312.7ms

[ ZONE STATISTICS ]
------------------------------------------------------------------------
         A :    15  ###############
      AAAA :     2  ##
     CNAME :     3  ###
        MX :     2  ##
        NS :     2  ##
       SOA :     2  ##
       SRV :     3  ###
       TXT :    12  ############
     TOTAL :    52
  Unique hostnames : 28
  Unique IPs       : 12

[ FINDINGS ]
------------------------------------------------------------------------
  [!] [HIGH] RFC 1918 private IP leaked: 192.168.1.100
       Category: Internal Exposure
       MITRE: T1018
       staging.zonetransfer.me A 192.168.1.100 (in 192.168.0.0/16)
  ...
```

## Detection Queries

The `detections/` directory contains **8 production-ready Splunk SPL queries**:

| # | Query | Log Source | Purpose |
|---|-------|-----------|---------|
| 1 | AXFR query detection | Zeek dns.log | Catch AXFR/IXFR queries by source IP |
| 2 | Large TCP DNS responses | Zeek conn.log | Wire-level transfer detection via response size |
| 3 | Windows DNS audit events | Windows DNS Server | Event IDs 6001/6002/6004 |
| 4 | Outbound DNS TCP sessions | Firewall logs | Internal hosts initiating TCP/53 externally |
| 5 | AXFR tool execution | Sysmon | Process creation for dig, nslookup, dnsrecon, etc. |
| 6 | IDS alert correlation | Suricata/Snort | Zone transfer signature matching |
| 7 | First-time AXFR sources | Zeek dns.log | Anomaly detection for new AXFR source IPs |
| 8 | Activity time-series | Zeek dns.log | SOC dashboard baseline and spike detection |

## Project Structure

```
lab02-zone-transfer-auditor/
├── zone_transfer_auditor.py      # Main CLI tool (zero dependencies)
├── detections/
│   └── zone_transfer_splunk.spl  # 8 Splunk SPL detection queries
└── README.md                     # This file
```

## How It Works

1. **NS Resolution** — Queries public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9) for the domain's authoritative NS records, then resolves each NS hostname to an IP.

2. **AXFR Attempt** — Opens a TCP connection to each nameserver on port 53, sends a properly formatted AXFR query (QTYPE=252), and reads the response stream. The transfer is framed by two SOA records (start and end).

3. **Zone Analysis** — If a transfer succeeds, the engine runs 9 analysis modules over the zone data, identifying security-relevant findings like private IPs, internal hostnames, sensitive TXT records, and service enumeration opportunities.

4. **Risk Scoring** — Computes a 0–100 risk score based on whether transfers were allowed and the severity of findings. Scores map to ratings: PASS, LOW, MEDIUM, HIGH, CRITICAL.

5. **Reporting** — Produces a formatted report with per-server results, zone statistics, prioritized findings with MITRE ATT&CK references, and remediation steps.

## References

- *DNS and BIND, 5th Edition* — Cricket Liu & Paul Albitz (O'Reilly) — Chapter 11: Security
- *The Hidden Potential of DNS in Security* — Joshua Kuo & Ross Gibson (Infoblox) — Zone Transfer Risks
- [RFC 5936](https://www.rfc-editor.org/rfc/rfc5936) — DNS Zone Transfer Protocol (AXFR)
- [RFC 1995](https://www.rfc-editor.org/rfc/rfc1995) — Incremental Zone Transfer (IXFR)
- [MITRE ATT&CK T1590.002](https://attack.mitre.org/techniques/T1590/002/) — Gather Victim Network Information: DNS

## Legal Notice

This tool is intended for **authorized security auditing only**. Only test domains you own or have explicit written permission to test. Unauthorized zone transfer attempts may violate computer fraud laws.

---

*Part of the [DNS Mastery Study Plan](https://github.com/casarezaz/dns-mastery) — a 12-week hands-on DNS security curriculum.*
