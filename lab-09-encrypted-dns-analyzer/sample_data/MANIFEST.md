# Sample Data Files — Lab 09 Encrypted DNS Analyzer

## Overview

This directory contains sample DNS traffic data for testing and demonstrating the Encrypted DNS Analyzer tool. The data simulates realistic network traffic with various DNS encryption protocols.

## Files

### generate_dns_traffic.py

Python script that generates `sample_dns_traffic.json` with synthetic network connection logs.

**Run it:**
```bash
python generate_dns_traffic.py
```

**Output:** `sample_dns_traffic.json` (JSON format)

**Features:**
- Generates 500 connection records by default
- Realistic protocol distribution
- Simulates both enterprise and bypass traffic
- Random seed for reproducibility

### sample_dns_traffic.json

Generated JSON file containing connection records from various DNS clients using different encryption protocols.

**Record structure:**
```json
{
  "timestamp": "2024-01-01T00:00:00Z",
  "client_ip": "192.168.1.100",
  "server_ip": "8.8.8.8",
  "server_port": 443,
  "protocol": "HTTPS",
  "domain": "dns.google.com",
  "path": "/dns-query",
  "tls_version": "TLS 1.3"
}
```

**Protocol Distribution (default generation):**

| Protocol | Count | Percentage | Notes |
|----------|-------|-----------|-------|
| Plaintext DNS | ~100 | 20% | UDP/TCP to enterprise resolver (port 53) |
| DoT (TLS 853) | ~150 | 30% | Encrypted TLS on port 853 |
| DoH (Enterprise) | ~125 | 25% | HTTPS to internal resolver (port 443) |
| DoQ (QUIC 853) | ~75 | 15% | QUIC on port 853 |
| DoH (Bypass) | ~50 | 10% | External provider usage (security issue) |

## Test Scenarios

### Scenario 1: Enterprise DNS Usage
**Connections:** Plaintext and DoT
- Clients: Internal IPs (192.168.1.x, 10.0.0.x)
- Resolvers: Enterprise servers (10.0.0.1, 10.0.0.2)
- Protocols: UDP/TCP port 53 (plaintext), TLS port 853 (DoT)
- Expected: High encryption coverage when DoT used

### Scenario 2: DoH via Enterprise Proxy
**Connections:** HTTPS port 443 to internal resolver
- Path: `/dns-query`
- Domain: `internal-resolver.local`
- TLS: 1.3
- Expected: Classified as encrypted DoH (not bypass)

### Scenario 3: DoH Bypass Attempts
**Connections:** HTTPS port 443 to external providers
- Providers: Google (8.8.8.8), Cloudflare (1.1.1.1), Quad9 (9.9.9.9)
- Domain: Provider domain (dns.google.com, one.one.one.one)
- Expected: Detected as HIGH severity DoH bypass alert

### Scenario 4: DoQ (Modern Protocol)
**Connections:** QUIC/UDP port 853
- Providers: Google, Cloudflare
- TLS: QUIC/TLS 1.3
- Expected: Classified as DoQ (modern encryption)

### Scenario 5: Plaintext Risk
**Connections:** UDP/TCP port 53 (unencrypted)
- Servers: Enterprise resolvers
- Expected: High plaintext percentage, client tracking

## Usage Examples

### Generate sample data
```bash
python generate_dns_traffic.py
```

### Analyze with encrypted_dns_analyzer
```bash
cd ..
python encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json
```

### Generate text report
```bash
python encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json --format text
```

### Generate JSON report for automation
```bash
python encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json \
  --format json \
  --output report.json
```

### Export detections to CSV
```bash
python encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json \
  --export-csv detections.csv
```

### Verbose output with per-client details
```bash
python encrypted_dns_analyzer.py sample_data/sample_dns_traffic.json \
  --format text \
  --verbose
```

### Generate protocol comparison matrix
```bash
python encrypted_dns_analyzer.py --comparison-matrix --output comparison.json
```

## Generating Custom Traffic

Edit `generate_dns_traffic.py` to customize:

```python
# Change number of events
traffic = generate_sample_traffic(num_events=1000, seed=123)

# Modify distribution percentages
distribution = {
    "plaintext": int(num_events * 0.30),      # Increase plaintext
    "dot": int(num_events * 0.25),
    "doh_enterprise": int(num_events * 0.20),
    "doq": int(num_events * 0.15),
    "doh_bypass": int(num_events * 0.10),
}

# Add more clients or providers
enterprise_clients.append("10.0.1.100")
```

Then regenerate:
```bash
python generate_dns_traffic.py
```

## Expected Analysis Results

When analyzing `sample_dns_traffic.json`, you should see:

```
Encryption Coverage:        70.0%
Plaintext Risk:            20.0%

PROTOCOL DISTRIBUTION
  DoT                150 ( 30.0%)
  DoH                175 ( 35.0%)
  DoQ                 75 ( 15.0%)
  plaintext          100 ( 20.0%)

TOP DoH PROVIDERS
  Google DNS         20 ( 11.4%)
  Cloudflare DNS     18 ( 10.3%)
  Quad9 DNS          12 (  6.9%)

DoH BYPASS ALERTS
  [MEDIUM] 192.168.1.100 -> Google DNS
  [MEDIUM] 192.168.1.102 -> Cloudflare DNS

CLIENTS USING PLAINTEXT DNS
  192.168.1.100
  192.168.1.101
  192.168.1.104
```

## Important Notes

- **Timestamps:** Generated with 1-second intervals starting from 2024-01-01
- **IP Ranges:**
  - Enterprise clients: 192.168.1.0/24, 10.0.0.0/24
  - Enterprise resolvers: 10.0.0.1-2, 192.168.1.1
  - Public providers: Real public IPs (Google, Cloudflare, Quad9)
- **Reproducibility:** Random seed ensures consistent generation for testing
- **Realism:** Protocol and port choices match real-world traffic patterns

## Extending the Data

To add more sophisticated scenarios:

1. **Add malicious clients:** Clients repeatedly bypassing DNS filter
2. **Unusual port combinations:** Connections to unexpected port numbers
3. **High-frequency patterns:** Detect potential C2 via DNS
4. **Mixed protocols:** Clients switching between DoH/DoT/plaintext
5. **Resolver diversity:** Multiple resolvers in enterprise (load balancing)

Modify `generate_dns_traffic.py` and regenerate to test detection logic.
