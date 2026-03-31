# Lab 09 — Encrypted DNS Analyzer

A comprehensive analyzer for **DNS encryption protocols (DoH, DoT, DoQ)** that detects which protocol is used, identifies bypass attempts, validates encryption configuration, and generates protocol comparison matrices. Works with simulated network metadata (JSON/CSV logs of connection data).

The DNS landscape is rapidly shifting toward encryption. Traditional plaintext DNS (port 53) is increasingly replaced by three modern encrypted protocols. This tool helps enterprises detect which protocols are in use, enforce encryption policies, and identify clients attempting to bypass DNS controls.

## What is Encrypted DNS?

DNS traditionally uses **unencrypted UDP on port 53**, exposing all queries to eavesdropping, MITM attacks, and ISP/government surveillance. Modern DNS encryption protocols solve this:

| Protocol | Transport | Port | RFC | Status |
|----------|-----------|------|-----|--------|
| **DoH** | HTTPS/HTTP2 | 443 | [RFC 8484](https://tools.ietf.org/html/rfc8484) | Widespread ✓ |
| **DoT** | TLS | 853 | [RFC 7858](https://tools.ietf.org/html/rfc7858) | Growing |
| **DoQ** | QUIC | 853 | [RFC 9250](https://tools.ietf.org/html/rfc9250) | Emerging |
| **Plaintext** | UDP/TCP | 53 | [RFC 1035](https://tools.ietf.org/html/rfc1035) | Legacy ⚠️ |

## Features

- **Zero external dependencies** — pure Python 3.10+ using only the standard library
- **Protocol detection engine** — identifies DoH, DoT, DoQ, and plaintext DNS from connection metadata:
  - DoT: TCP/TLS port 853
  - DoQ: QUIC/UDP port 853
  - DoH: HTTPS port 443 with `/dns-query` path or known provider domains/IPs
  - Plaintext: UDP/TCP port 53
- **Known DoH provider database** — recognizes 6+ major providers (Google, Cloudflare, Quad9, NextDNS, OpenDNS, AdGuard) by domain and IP
- **DoH bypass detection** — flags clients connecting to external DoH providers instead of enterprise resolver with severity rating
- **Encryption coverage analysis** — calculates percentage of encrypted vs plaintext DNS traffic
- **Protocol distribution reporting** — per-client and network-wide statistics
- **Protocol comparison matrix** — comprehensive feature comparison (encryption, performance, deployment, firewall-friendliness)
- **Multi-format input** — JSON and CSV connection logs with timestamp, client IP, server IP, port, protocol, domain, path, TLS version
- **Multiple output formats** — human-readable text, structured JSON, and CSV export
- **Production Splunk queries** — 8 ready-to-use SPL detection queries
- **Sigma detection rules** — 8 YAML detection rules for SIEM automation

## MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|-----------|------|-----------|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Monitoring encrypted DNS protocol usage |
| [T1573.002](https://attack.mitre.org/techniques/T1573/002/) | Encrypted Channel: Asymmetric Cryptography | Validating TLS/QUIC encryption |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | Detecting DoH as data exfiltration tunnel |

## Installation

No installation required — clone and run:

```bash
git clone https://github.com/casarezaz/dns-mastery.git
cd dns-mastery/lab-09-encrypted-dns-analyzer
python3 encrypted_dns_analyzer.py --help
```

**Requirements:** Python 3.10+

## Quick Start

### Generate sample data
```bash
cd sample_data
python generate_dns_traffic.py
cd ..
```

### Analyze traffic
```bash
python3 encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json
```

### JSON output
```bash
python3 encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json \
  --format json \
  --output report.json
```

### DoH/DoT/DoQ comparison
```bash
python3 encrypted_dns_analyzer.py --comparison-matrix --output protocols.json
```

## Usage

### Protocol Detection from Logs
```bash
# Analyze connection log
python3 encrypted_dns_analyzer.py connections.json

# Verbose output with per-client protocol usage
python3 encrypted_dns_analyzer.py connections.json --verbose

# JSON format for automation
python3 encrypted_dns_analyzer.py connections.json --format json -o report.json

# CSV export
python3 encrypted_dns_analyzer.py connections.json --export-csv detections.csv
```

### DoH Bypass Detection
The tool automatically detects:
- Clients using Google DNS (8.8.8.8, 8.8.4.4, dns.google.com)
- Clients using Cloudflare (1.1.1.1, one.one.one.one)
- Clients using Quad9 (9.9.9.9, dns.quad9.net)
- Clients using other known public providers

```bash
python3 encrypted_dns_analyzer.py connections.json --verbose
# Look for "DoH BYPASS ALERTS" section
```

### Protocol Comparison Matrix
```bash
python3 encrypted_dns_analyzer.py --comparison-matrix

# Save to file
python3 encrypted_dns_analyzer.py --comparison-matrix --output comparison.json
```

## Input Format

### JSON Connection Log
```json
[
  {
    "timestamp": "2024-03-01T12:34:56Z",
    "client_ip": "192.168.1.100",
    "server_ip": "8.8.8.8",
    "server_port": 443,
    "protocol": "HTTPS",
    "domain": "dns.google.com",
    "path": "/dns-query",
    "tls_version": "TLS 1.3"
  },
  {
    "timestamp": "2024-03-01T12:34:57Z",
    "client_ip": "192.168.1.100",
    "server_ip": "10.0.0.1",
    "server_port": 853,
    "protocol": "TLS",
    "domain": "resolver.local",
    "path": "",
    "tls_version": "TLS 1.3"
  }
]
```

### CSV Connection Log
```csv
timestamp,client_ip,server_ip,server_port,protocol,domain,path,tls_version
2024-03-01T12:34:56Z,192.168.1.100,8.8.8.8,443,HTTPS,dns.google.com,/dns-query,TLS 1.3
2024-03-01T12:34:57Z,192.168.1.100,10.0.0.1,853,TLS,resolver.local,,TLS 1.3
2024-03-01T12:34:58Z,192.168.1.101,1.1.1.1,443,HTTPS,one.one.one.one,/dns-query,TLS 1.3
2024-03-01T12:34:59Z,192.168.1.102,8.8.8.8,853,QUIC,dns.google,/dns-query,QUIC/TLS 1.3
```

## Output Examples

### Text Report
```
================================================================================
ENCRYPTED DNS ANALYZER - ANALYSIS REPORT
================================================================================
Analysis Timestamp: 2024-03-01T12:35:00Z

ENCRYPTION COVERAGE SUMMARY
--------------------------------------------------------------------------------
Total Connections Analyzed: 500
Encrypted Connections:      400
  - DoH (HTTPS):            175
  - DoT (TLS 853):          150
  - DoQ (QUIC 853):         75
Plaintext DNS (port 53):    100
Unknown Protocol:           0

Encryption Coverage:        80.0%
Plaintext Risk:             20.0%

PROTOCOL DISTRIBUTION
--------------------------------------------------------------------------------
  DoH                175 ( 35.0%)
  DoT                150 ( 30.0%)
  plaintext          100 ( 20.0%)
  DoQ                 75 ( 15.0%)

TOP DoH PROVIDERS
--------------------------------------------------------------------------------
  Google DNS              45 ( 25.7%)
  Cloudflare DNS          35 ( 20.0%)
  Quad9 DNS              12 (  6.9%)

DoH BYPASS ALERTS
--------------------------------------------------------------------------------
  [HIGH] 192.168.1.100 -> Google DNS
      Count: 10, Reason: Client using external DoH provider instead of enterprise resolver
  [MEDIUM] 192.168.1.102 -> Cloudflare DNS
      Count: 5, Reason: Client using external DoH provider instead of enterprise resolver

CLIENTS USING PLAINTEXT DNS
--------------------------------------------------------------------------------
  192.168.1.100
  192.168.1.101
  192.168.1.104

================================================================================
```

### Protocol Comparison Matrix
```json
{
  "protocols": {
    "DoH": {
      "name": "DNS over HTTPS",
      "rfc": "RFC 8484",
      "port": 443,
      "transport": "HTTPS/TLS",
      "encryption": "TLS 1.2+",
      "authentication": "Certificate-based (HTTPS PKI)",
      "performance": "Good (HTTP/2 multiplexing)",
      "firewall_friendly": true,
      "caching": "HTTP caching possible",
      "privacy": "Mixed (HTTPS SNI leaks destination)",
      "deployability": "High (uses standard HTTPS infrastructure)",
      "client_support": "Widespread (browsers, resolvers, OS)",
      "advantages": [
        "Uses standard HTTPS (port 443)",
        "Multiplexing via HTTP/2",
        "Works through most firewalls",
        "Wide browser/OS support"
      ],
      "disadvantages": [
        "Server IP visible in TLS handshake",
        "HTTP/2 header compression side-channel",
        "Higher latency than DoT"
      ]
    },
    "DoT": {
      "name": "DNS over TLS",
      "rfc": "RFC 7858",
      "port": 853,
      "transport": "TLS",
      "encryption": "TLS 1.2+",
      "authentication": "Certificate-based (DNS PKI)",
      "performance": "Excellent (minimal overhead)",
      "firewall_friendly": false,
      "caching": "Standard DNS caching",
      "privacy": "Excellent (dedicated encrypted channel)",
      "deployability": "Medium (port 853 often blocked)",
      "client_support": "Growing (mobile OS, resolvers)",
      "advantages": [
        "Dedicated encrypted channel",
        "Low latency",
        "Strong privacy guarantees"
      ],
      "disadvantages": [
        "Port 853 often blocked by firewalls",
        "Requires custom port 853 support",
        "Less compatible than DoH"
      ]
    },
    "DoQ": {
      "name": "DNS over QUIC",
      "rfc": "RFC 9250",
      "port": 853,
      "transport": "QUIC/UDP",
      "encryption": "QUIC (TLS 1.3 embedded)",
      "authentication": "Certificate-based (QUIC PKI)",
      "performance": "Excellent (0-RTT, connection migration)",
      "firewall_friendly": true,
      "caching": "Standard DNS caching",
      "privacy": "Excellent (encrypted UDP)",
      "deployability": "Growing (newer standard)",
      "client_support": "Limited (emerging)",
      "advantages": [
        "0-RTT connection establishment",
        "Connection migration (mobile)",
        "Minimal latency"
      ],
      "disadvantages": [
        "Emerging standard, limited support",
        "Complex QUIC implementation",
        "Client support still growing"
      ]
    }
  },
  "feature_comparison": {
    "Encryption": {
      "DoH": "Yes",
      "DoT": "Yes",
      "DoQ": "Yes",
      "Plaintext": "No"
    },
    "Firewall Friendly": {
      "DoH": "Yes",
      "DoT": "No",
      "DoQ": "Somewhat",
      "Plaintext": "Yes"
    },
    "Performance": {
      "DoH": "Good",
      "DoT": "Excellent",
      "DoQ": "Excellent",
      "Plaintext": "Excellent"
    }
  }
}
```

## Production Detections

### Splunk Queries
8 ready-to-use SPL queries in `detections/encrypted_dns_splunk.spl`:
1. DoH Detection — Find HTTPS DNS traffic
2. DoT Detection — Find TLS DNS traffic on 853
3. DoQ Detection — Find QUIC DNS traffic
4. Plaintext Detection — Find unencrypted DNS
5. DoH Bypass Detection — Find external provider usage
6. Encryption Coverage Summary — Track encryption adoption
7. Per-Client Protocol Usage — Identify anomalies
8. Suspicious DoH Patterns — Find exfiltration/C2

### Sigma Rules
8 Sigma detection rules in `detections/encrypted_dns_bypass.yml`:
1. DoH Bypass Detection
2. Plaintext DNS Detection
3. DoT Detection (informational)
4. DoQ Detection (informational)
5. Low Encryption Coverage Alert
6. Suspicious DoH Query Frequency
7. Protocol Mismatch (client inconsistency)
8. Known Malicious DoH Provider

## Architecture

### Protocol Detection Algorithms

**DoT (DNS over TLS)**
- Port 853 + TCP protocol + TLS version → DoT
- Confidence: 95%+

**DoQ (DNS over QUIC)**
- Port 853 + UDP/QUIC protocol → DoQ
- Confidence: 95%+

**DoH (DNS over HTTPS)**
- Port 443 + `/dns-query` path → DoH (RFC 8484 compliant)
- Port 443 + known provider IP/domain → DoH (confidence 85-95%)
- Heuristic: HTTPS + DNS-like pattern → potential DoH

**Plaintext DNS**
- Port 53 + UDP/TCP + no encryption → plaintext
- Confidence: 99%

### Bypass Detection Algorithm

For each DoH connection:
1. Is destination IP public (not RFC 1918)?
2. Is destination a known DoH provider (Google, Cloudflare, Quad9, etc.)?
3. If YES to both → flag as bypass
4. Assign severity: HIGH if multiple bypasses, MEDIUM if single

### Encryption Coverage Calculation

```
Coverage = (DoH + DoT + DoQ) / Total × 100%
Plaintext Risk = Plaintext / Total × 100%
```

## Testing

Run comprehensive unit tests:

```bash
python -m unittest test_encrypted_dns_analyzer -v
```

**Test Coverage:**
- Protocol detection (all 4 types)
- DoH provider identification (6 providers)
- Bypass detection (external vs internal)
- Encryption coverage calculation
- Per-client protocol tracking
- Report formatting (text, JSON, CSV)
- Edge cases and error handling
- File loading (JSON/CSV auto-detection)

All tests use standard library only (no external mocking frameworks).

## Data Flow

```
Connection Logs (JSON/CSV)
        ↓
    Load & Parse
        ↓
Protocol Detection Engine
  ├─ Port + Protocol analysis
  ├─ Domain/IP lookup
  ├─ TLS version inspection
  └─ Known provider matching
        ↓
Bypass Detection Engine
  ├─ External IP detection
  ├─ Provider matching
  └─ Alert generation
        ↓
Analysis & Reporting
  ├─ Statistics calculation
  ├─ Per-client aggregation
  ├─ Coverage computation
  └─ Format output (text/JSON/CSV)
        ↓
Output Reports & Alerts
```

## Sample Data

The `sample_data/` directory includes:

- **generate_dns_traffic.py** — Generator script (500 events, 4 protocols)
- **sample_dns_traffic.json** — Pre-generated sample data
- **MANIFEST.md** — Complete documentation

Distribution:
- 20% plaintext DNS (port 53)
- 30% DoT (TLS port 853)
- 35% DoH (HTTPS port 443)
- 15% DoQ (QUIC port 853)

## MITTRE ATT&CK Analysis

### T1071.004 — Application Layer Protocol: DNS

Adversaries may communicate over DNS for command & control or exfiltration:
- DoH bypasses traditional DNS monitoring (indistinguishable from HTTPS)
- DoT on port 853 is easier to detect but may be blocked
- Plaintext DNS is easiest to detect and monitor

**Detection Strategy:**
- Monitor DoH to external providers (bypass attempt)
- Alert on unusual DoH frequency (exfiltration)
- Track client protocol consistency (mixed usage is anomalous)

### T1572 — Protocol Tunneling

DoH can be abused for covert tunneling:
- Encodes data in DNS queries to external provider
- Bypasses network segmentation and filters
- Difficult to distinguish from legitimate DNS traffic

**Detection Strategy:**
- Baselined query frequency (100+ QPS is anomalous)
- Unusual query domains (randomized/encoded)
- Query pattern analysis (entropy-based)

## Performance Characteristics

- **Memory:** ~10MB for 10,000 connection records
- **Speed:** 5,000-10,000 records/second on modern hardware
- **Scalability:** Tested up to 100,000 records

## Known Limitations

1. **No packet inspection** — Works with metadata only, not wire protocol
2. **No certificate validation** — Assumes certificate data accurate
3. **Limited QUIC support** — DoQ detection relies on application-level hints
4. **Proxy transparency** — Can't detect DoH through corporate proxy unless proxy logs are analyzed
5. **IPv6 limited** — DoQ IPv6 addresses hardcoded (not auto-updated)

## Future Enhancements

- Real-time streaming analysis (Apache Kafka, etc.)
- Machine learning anomaly detection
- Integration with threat intelligence feeds
- Certificate chain validation
- DNSSEC validation for encrypted channels
- GUI dashboard for visualization
- Integration with commercial SIEMs

## Contributing

Contributions welcome! Areas of interest:
- More DoH provider database entries
- Additional detection heuristics
- Performance optimizations
- QUIC/DoQ improvements

## License

MIT License — See LICENSE file

## Author

Author : Angie Casarez (casarezaz)
GitHub: https://github.com/casarezaz
License: MIT

## References

- **RFC 8484** — DNS over HTTPS (DoH): https://tools.ietf.org/html/rfc8484
- **RFC 7858** — DNS over TLS (DoT): https://tools.ietf.org/html/rfc7858
- **RFC 9250** — DNS over QUIC (DoQ): https://tools.ietf.org/html/rfc9250
- **MITRE ATT&CK T1071** — Application Layer Protocol: https://attack.mitre.org/techniques/T1071/004/
- **MITRE ATT&CK T1572** — Protocol Tunneling: https://attack.mitre.org/techniques/T1572/
- **EFF** — HTTPS Everywhere DNS: https://www.eff.org/
- **Cloudflare Blog** — DNS Privacy: https://blog.cloudflare.com/

## Support

For issues, questions, or feature requests:
1. Check existing documentation
2. Review sample data and tests
3. File GitHub issue with details
