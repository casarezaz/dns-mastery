# Sample Hunt Data Manifest

## Overview

This directory contains the sample data generator for Lab 12 DNS Threat Hunt Playbook. The generator creates realistic DNS logs containing indicators for **all 10 hunt types** mixed together in a single dataset.

## Generated Dataset

**File:** `sample_hunt_data.log`
**Format:** TSV (Tab-Separated Values), Zeek-compatible
**Total Records:** ~1,100 DNS queries
**Time Window:** 1 hour
**Mix:** 45% benign baseline + 55% threat patterns

## Record Format

Each line is a TSV-formatted DNS query record with fields:

```
timestamp  src_ip  query_name  query_type  response_code  answer  server_ip
```

Example:
```
1711468800  10.0.0.5  KJZLMNOPQRSTUVWXYZ.evil.cc  A  NXDOMAIN    8.8.8.8
```

## Hunt Data Breakdown

The generator produces indicators for all 10 hunts distributed throughout the dataset:

### H001 — DNS Tunneling Detection
- **Count:** ~30 records
- **Pattern:** High-entropy subdomains (48-char base32-like labels)
- **Signature:** NXDOMAIN responses, entropy > 4.0
- **Source IP:** 192.168.100.* range
- **Domain:** Random malicious domain (evil.cc, etc.)
- **Detection:** Look for `entropy > 3.5` with `query_count > 10`

### H002 — Command & Control (C2) over DNS
- **Count:** ~60 records (50 A queries + 10 TXT queries)
- **Pattern:** Regular 60-second intervals with base32-encoded labels
- **Signature:** Beacon-like timing (jitter < 20%), responds to NOERROR
- **Source IP:** 192.168.100.* range
- **Domain:** Attacker C2 domain
- **Detection:** Look for `coefficient_variation < 0.20` with `query_count > 10`

### H003 — Domain Generation Algorithm (DGA)
- **Count:** ~200 records
- **Pattern:** Random 12-character domains, various TLDs (com, net, org, ru, cc)
- **Signature:** 90% NXDOMAIN rate, 200 unique domains
- **Source IP:** 192.168.200.* range
- **Detection:** Look for `nxdomain_ratio > 0.5` with `unique_domains > 50`

### H004 — DNS Cache Poisoning
- **Count:** ~20 records
- **Pattern:** Same query name (legitimate-bank.com) returns alternating IPs
- **Signature:** Multiple conflicting A records within seconds
- **Source IP:** 10.0.0.* range (internal)
- **Domain:** legitimate-bank.com (mimics real bank)
- **Detection:** Look for `unique_answers > 2` for same `query_name`

### H005 — Zone Transfer Abuse (AXFR)
- **Count:** ~11 records (1 AXFR + 10 enumeration queries)
- **Pattern:** AXFR attempt from external IP, followed by SOA/NS queries
- **Signature:** AXFR query (qtype=252) with REFUSED response
- **Source IP:** 203.0.113.50 (external attacker)
- **Domain:** internal.company.local (internal zone)
- **Detection:** Look for `query_type == AXFR` from non-authorized IP

### H006 — DNSSEC Validation Failures
- **Count:** ~15 records
- **Pattern:** SERVFAIL responses for dnssec-zone.com
- **Signature:** SERVFAIL rcode with ad_flag=false
- **Source IP:** 10.0.0.* range (internal)
- **Domain:** dnssec-zone.com
- **Detection:** Look for `response_code == SERVFAIL` with persistence

### H007 — DNS Amplification & Reflection
- **Count:** ~100 records
- **Pattern:** Large TXT record responses (700 bytes) to small queries (40 bytes)
- **Signature:** Amplification factor 10x+ from spoofed IPs
- **Source IP:** 192.168.100.* range (simulating attacker)
- **Domain:** Normal domains (google.com, etc.)
- **Detection:** Look for `response_bytes > 512` AND `response_to_query_ratio > 10`

### H008 — DoH (DNS over HTTPS) Bypass
- **Count:** ~30 records
- **Pattern:** HTTPS connections to known DoH provider IPs
- **Signature:** Port 443, protocol=https, bytes_in > 100
- **Source IP:** 192.168.100.* range
- **Destination IP:** 8.8.8.8, 1.1.1.1, or 45.33.32.156
- **Detection:** Look for connections to DoH provider IPs on port 443

### H009 — Fast-Flux Domain Detection
- **Count:** ~40 records
- **Pattern:** Same domain (evil.cc) resolving to different IPs
- **Signature:** 20 different A records for same domain within 60 seconds
- **Source IP:** 10.0.0.* range (internal victim)
- **Domain:** Attacker domain
- **Detection:** Look for `unique_ips >= 5` with `time_window <= 3600`

### H010 — DNS Data Exfiltration
- **Count:** ~50 records
- **Pattern:** Long base64-encoded subdomains (70+ characters)
- **Signature:** High-entropy labels returning NXDOMAIN
- **Source IP:** 192.168.100.* range
- **Domain:** Attacker domain
- **Detection:** Look for `subdomain_length > 50` OR `max_label_length > 50`

## Data Characteristics

### Threat Distribution
- **Benign queries:** 500 (45%)
- **Threat indicators:** 550 (55%)
  - DNS Tunneling: 5.4%
  - C2 Beacon: 10.9%
  - DGA: 36.4%
  - Cache Poisoning: 3.6%
  - Zone Transfer: 2.0%
  - DNSSEC Failure: 2.7%
  - DNS Amplification: 18.2%
  - DoH Bypass: 5.5%
  - Fast-Flux: 7.3%
  - Data Exfiltration: 9.1%

### IP Addresses Used
- **Internal (benign):** 10.0.0.1-10.0.0.10
- **Attacker/Threat:** 192.168.100.*, 192.168.200.*, 203.0.113.*
- **Resolver:** 8.8.8.8 (default)

### Domains
- **Benign:** google.com, facebook.com, twitter.com, github.com, etc. (15 total)
- **Attacker:** evil.cc, malware-c2.net, badactor.xyz, data-exfil.cc, botnet-control.ru
- **Internal:** internal.company.local
- **Target (poisoning):** legitimate-bank.com

## Generation Process

```bash
cd sample_data/
python3 generate_hunt_data.py
```

This creates `sample_hunt_data.log` in the current directory.

### Optional: Custom Output Path
```bash
python3 generate_hunt_data.py /path/to/custom/output.log
```

## Use Cases

### 1. Testing Hunt Queries
Import sample data into Splunk, Elasticsearch, or your SIEM:

```bash
# Splunk
splunk add oneshot sample_hunt_data.log -index main -sourcetype dns

# Elasticsearch
logstash -f parse_dns.conf
```

### 2. Training & Education
Use this data for DNS threat hunting workshops and certifications.

### 3. Detection Rule Validation
Run all 10 hunts against this data and verify they detect all threat types:

```bash
python3 ../threat_hunt_playbook.py list  # View hunts
# ... run each hunt's Splunk/KQL query ...
```

### 4. Performance Benchmarking
Measure SIEM query performance on realistic mixed threat data.

## Limitations

- **Synthetic data:** Generated programmatically, not from real incidents
- **Simplified:** Actual threat traffic is more complex and varied
- **Time compression:** 1-hour window with 1100 queries = 18 qps (realistic but compressed)
- **No packet-level data:** TSV format, not full DNS wire protocol
- **Simplified encodings:** Base32/64 labels are demonstrative, not from real tools

## Real-World Adaptation

To use with real data:
1. Export DNS logs from your SIEM/DNS server
2. Sample or truncate to ~1100 records for similar dataset size
3. Preserve original timestamps and IPs
4. Import into your test environment
5. Run hunts as documented

## File Structure

```
sample_data/
├── generate_hunt_data.py       # Generator script
├── sample_hunt_data.log        # Generated output (created on first run)
└── MANIFEST.md                 # This file
```

## Author

**Angie Casarez** (casarezaz)

## License

MIT License — See LICENSE in parent directory
