# Lab 12 — DNS Threat Hunt Playbook

**Capstone:** Comprehensive DNS threat hunting playbook with executable queries, detection logic, and response procedures for all DNS-based threats covered in the DNS Mastery curriculum.

DNS is the backbone of the internet but also one of the most exploited protocols by adversaries. This playbook consolidates 10 critical threat hunts covering DNS tunneling, C2 communication, DGA detection, cache poisoning, zone transfer abuse, DNSSEC failures, DNS amplification, DoH bypass, fast-flux networks, and data exfiltration.

## Features

- **Zero external dependencies** — pure Python 3.10+ standard library
- **10 comprehensive threat hunts** covering all DNS-based threats:
  1. DNS Tunneling (Protocol Tunneling)
  2. Command & Control (C2) over DNS
  3. Domain Generation Algorithm (DGA) Detection
  4. DNS Cache Poisoning
  5. Zone Transfer Abuse
  6. DNSSEC Validation Failures
  7. DNS Amplification & Reflection Attacks
  8. DoH (DNS over HTTPS) Bypass Detection
  9. Fast-Flux Domain Detection
  10. DNS Data Exfiltration
- **Full executable queries**:
  - Splunk SPL (Search Processing Language)
  - KQL (Kusto Query Language / Azure Log Analytics)
  - Sigma detection rules (YAML)
- **Complete threat intelligence**:
  - Hunt hypotheses and rationale
  - Detection logic (how to spot each threat)
  - Indicators of Compromise (IoCs)
  - Response procedures (investigation steps)
  - False positive mitigation strategies
- **MITRE ATT&CK mapping** with full coverage matrix
- **Playbook export modes**: text, JSON, Markdown
- **Hunt filtering** by severity, data source, or MITRE technique
- **Hunt coverage statistics** showing which hunts cover which MITRE techniques
- **CLI for all modes**: list hunts, view details, export playbook, show coverage

## MITRE ATT&CK Mapping

This capstone covers 7 critical DNS-related MITRE techniques:

| Technique | Name | Hunts |
|-----------|------|-------|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | H002, H008 |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | H001 |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Dynamic Resolution: DGA | H003 |
| [T1048.003](https://attack.mitre.org/techniques/T1048/003/) | Exfiltration Over Alternative Protocol | H001, H007, H010 |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | H009 |
| [T1557.004](https://attack.mitre.org/techniques/T1557/004/) | Adversary-in-the-Middle: DNS Spoofing | H004, H006 |
| [T1590.002](https://attack.mitre.org/techniques/T1590/002/) | Gather Victim Network Information: DNS | H005 |

## Installation

No installation required — clone and run:

```bash
cd dns-mastery/lab-12-threat-hunt-playbook
python3 threat_hunt_playbook.py --help
```

**Requirements:** Python 3.10+

## Quick Start

### List all hunts

```bash
python3 threat_hunt_playbook.py list
```

Output:
```
Total hunts: 10

[H001] DNS Tunneling Detection
  Severity: HIGH
  MITRE: T1572, T1048.003

[H002] Command & Control (C2) over DNS
  Severity: CRITICAL
  MITRE: T1071.004, T1041

...
```

### Show hunt details

```bash
python3 threat_hunt_playbook.py show H002
```

Output:
```
[H002] Command & Control (C2) over DNS

Severity: CRITICAL
MITRE: T1071.004, T1041
Data Sources: DNS Logs, Zeek DNS

Hypothesis:
Malware communicates with C2 servers using DNS as the command channel.

Detection Logic:
Detect C2 beacons via coefficient-of-variation analysis of query timing...

Indicators of Compromise:
  - Regular query intervals (60s, 300s, etc.) with jitter < 20%
  - High-entropy subdomain labels (base32/64 encoding)
  - TXT record abuse (> 50% of queries)
  ...

Response Procedure:
1. Block the domain at DNS level (sinkhole)
2. Isolate infected host immediately
...

Queries:
  [splunk_spl] Detect beacon-like query patterns
    source="dns.log"
    | stats count as query_count, values(timestamp) as timestamps by src_ip, query_name
    ...
```

### Export playbook as JSON

```bash
python3 threat_hunt_playbook.py export --format json > playbook.json
```

### Export as Markdown

```bash
python3 threat_hunt_playbook.py export --format markdown > playbook.md
```

### Filter by severity

```bash
python3 threat_hunt_playbook.py list --severity CRITICAL
```

### Filter by MITRE technique

```bash
python3 threat_hunt_playbook.py list --mitre T1572
```

### Show MITRE coverage matrix

```bash
python3 threat_hunt_playbook.py coverage
```

### Show statistics

```bash
python3 threat_hunt_playbook.py stats
```

## Full CLI Reference

```
usage: threat_hunt_playbook.py [-h] [--version]
                               {list,show,export,coverage,stats} ...

DNS Threat Hunt Playbook - comprehensive hunting guide for DNS-based threats

positional arguments:
  {list,show,export,coverage,stats}
    list                List all hunts
    show                Show hunt details
    export              Export playbook
    coverage            Show MITRE coverage matrix
    stats               Show playbook statistics

optional arguments:
  -h, --help            Show this help message and exit
  --version             Show version and exit

List options:
  --severity {INFO,MEDIUM,HIGH,CRITICAL}
                        Filter by severity
  --mitre TECHNIQUE     Filter by MITRE technique (e.g., T1572)

Export options:
  --format {text,json,markdown}
                        Export format (default: text)
  --output, -o FILE     Output file (default: stdout)
```

## Hunt Catalog

### [H001] DNS Tunneling Detection

Attackers tunnel traffic through DNS queries to exfiltrate data or establish covert channels.

**Severity:** HIGH
**MITRE:** T1572, T1048.003
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
Identify DNS tunnels by analyzing subdomain entropy. Legitimate DNS queries use low-entropy labels (www, mail, etc.). Tunneling tools like iodine encode data as high-entropy base32/64 strings. Calculate Shannon entropy of subdomain labels; average > 3.5 bits/char indicates encoding.

**Key Indicators:**
- Subdomain entropy > 3.5 bits/character
- Long DNS labels (> 24 chars) from single source
- Repeating base32/64 patterns in labels
- Consistent query volume (100+ queries/hour to same domain)

**Response:**
1. Isolate the source IP from network
2. Capture full DNS traffic for forensics
3. Check for related DNS domains or C2 infrastructure
4. Review process memory on source host for tunnel tools
5. Search logs for lateral movement from compromised host

---

### [H002] Command & Control (C2) over DNS

Malware communicates with C2 servers using DNS as the command channel.

**Severity:** CRITICAL
**MITRE:** T1071.004, T1041
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
Detect C2 beacons via coefficient-of-variation analysis of query timing. Legitimate DNS has irregular timing (high variance); C2 beacons have regular check-in intervals with low jitter. Combine with entropy analysis to identify encoded commands in query names.

**Key Indicators:**
- Regular query intervals (60s, 300s, etc.) with jitter < 20%
- High-entropy subdomain labels (base32/64 encoding)
- TXT record abuse (> 50% of queries)
- NXDOMAIN rate > 50% (DGA signals)
- Queries to known C2 domains

**Response:**
1. Block the domain at DNS level (sinkhole)
2. Isolate infected host immediately
3. Acquire memory dump and disk image
4. Kill suspected C2 processes and examine parent chain
5. Hunt for similar patterns across network
6. Check for lateral movement and credential compromise

---

### [H003] Domain Generation Algorithm (DGA) Detection

Malware generates domains algorithmically to evade sinkholing.

**Severity:** HIGH
**MITRE:** T1568.002
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
DGAs generate hundreds of random domains. Most fail (NXDOMAIN); a few resolve and connect to C2. Detect by finding hosts with high NXDOMAIN rates. Combine with domain entropy and character distribution analysis. DGA domains often have unusual TLD patterns or rapid subdomain changes.

**Key Indicators:**
- NXDOMAIN rate > 50%
- Query volume > 100 domains/hour
- Domains with random character distribution
- Queries to non-existent TLDs or unusual TLD patterns
- Same TLD queried by many different domains

**Response:**
1. Extract all queried domains from the hour
2. Analyze domain names for entropy and patterns
3. Check if domains match known DGA seeding lists
4. Monitor for successful resolutions (those are C2s)
5. Isolate host and run DGA identification tools
6. Acquire sample for reverse engineering

---

### [H004] DNS Cache Poisoning Detection

Attacker sends spoofed DNS responses to poison resolver cache.

**Severity:** CRITICAL
**MITRE:** T1557.004
**Data Sources:** DNS Logs, Network Traffic

**Detection Logic:**
DNS cache poisoning typically involves attacker injecting false A records. Detect by finding query_name/server pairs that return multiple unrelated A records or A records inconsistent with authoritative responses. Monitor for TTL manipulation (very low TTL values). Check for query with DNSSEC disabled (ad=false).

**Key Indicators:**
- Multiple conflicting A record responses for same domain
- TTL values < 5 seconds on normally cached entries
- Responses from non-authoritative sources
- Query/response with unusual port pairs
- Rapid DNS changes (same domain resolved to new IP in seconds)

**Response:**
1. Immediately flush DNS cache on affected resolvers
2. Contact domain owner and authoritative DNS provider
3. Verify current authoritative DNS records
4. Check server logs for DNSSEC validation failures
5. Deploy DNS query rate limiting and response validation
6. Monitor for subsequent cache poisoning attempts

---

### [H005] Zone Transfer Abuse Detection

Attacker performs unauthorized AXFR to enumerate zone contents.

**Severity:** HIGH
**MITRE:** T1590.002
**Data Sources:** DNS Logs, Network Traffic

**Detection Logic:**
AXFR (full zone transfer) is a legitimate operation but should only succeed to authorized secondary DNS servers. Detect by looking for AXFR queries (qtype=252) from unexpected sources or successful transfers. A successful AXFR returns entire zone contents in a single response (multiple records, high byte count).

**Key Indicators:**
- AXFR query from non-authoritative source IP
- AXFR response with > 100 records
- AXFR from IP not in NS records
- AXFR for domain not in configuration
- Failed AXFR attempts followed by zone enumeration queries

**Response:**
1. Block source IP from making further DNS queries
2. Retrieve complete transferred zone data
3. Enumerate exposed internal hostnames and IPs
4. Assess sensitivity of exposed records
5. Implement DNS ACLs to restrict AXFR to authorized IPs
6. Enable DNSSEC to prevent future zone enumeration

---

### [H006] DNSSEC Validation Failure Detection

DNSSEC validation failures may indicate spoofing or misconfiguration.

**Severity:** MEDIUM
**MITRE:** T1557.004
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
DNSSEC-validating resolvers should set the 'ad' (authenticated data) flag in responses. Failures (rcode=SERVFAIL, ad=false) indicate broken signatures. This can be legitimate (zone transition, signature expiration) but may also indicate an attacker preventing signature validation.

**Key Indicators:**
- Repeated SERVFAIL for same domain
- SERVFAIL followed by unvalidated response
- ad=false with rcode=BOGUS
- DNSSEC validation failing for high-profile domains
- Resolver accepting invalid signatures

**Response:**
1. Verify DNSSEC chain for affected domain
2. Check domain registrar for delegation issues
3. Verify resolver's DNSSEC keys are current
4. Check for clock skew on resolver
5. Monitor for subsequent spoofing attempts
6. Contact domain owner if signature issues persist

---

### [H007] DNS Amplification & Reflection Attack Detection

Attacker uses DNS servers as amplifiers in DDoS attacks.

**Severity:** HIGH
**MITRE:** T1048.003
**Data Sources:** DNS Logs, Network Traffic

**Detection Logic:**
DNS amplification attacks use queries with small size that generate large responses (e.g., DNSSEC, ANY, TXT). Detect by finding query/response pairs where response is 10x+ larger than query. Look for queries from spoofed sources (not your customers). Monitor for queries to recursive resolvers from outside your network.

**Key Indicators:**
- Response > 10x query size
- Large responses (> 512 bytes) to queries from spoofed IPs
- DNSSEC/ANY/TXT queries from multiple spoofed sources
- Same query pattern repeated 1000s of times
- Queries from IPs never seen before

**Response:**
1. Implement rate limiting on recursive resolver
2. Block or restrict DNSSEC/ANY/TXT queries from external IPs
3. Consider response size caps
4. Enable DNS firewall rules
5. Contact upstream ISP for DDoS mitigation
6. Implement source IP spoofing detection

---

### [H008] DNS over HTTPS (DoH) Bypass Detection

Hosts using DoH bypass corporate DNS controls and policies.

**Severity:** MEDIUM
**MITRE:** T1071.004
**Data Sources:** Network Traffic, Splunk

**Detection Logic:**
DoH providers (Google, Cloudflare, Quad9, etc.) handle DNS queries over HTTPS on port 443. Detect by identifying HTTPS connections to known DoH IPs. Monitor certificate names (dns.google, cloudflare-dns.com). Look for suspiciously consistent query volume over HTTPS.

**Key Indicators:**
- Connection to known DoH provider IP on 443
- SNI hostname matches DoH service (dns.google, 1.1.1.1.1)
- Consistent HTTPS traffic volume (similar pattern to DNS)
- Browser configured with custom DoH in hosts file or config
- Multiple hosts querying same DoH provider

**Response:**
1. Block destination IP or FQDN at network boundary
2. Check host for malware or unauthorized configuration
3. Review process memory for suspicious DNS query patterns
4. Check browser history and preferences
5. Deploy network policy to block DoH (if not approved)
6. Monitor for persistence mechanisms

---

### [H009] Fast-Flux Domain Detection

Attacker rapidly changes DNS A records to evade sinkholing.

**Severity:** HIGH
**MITRE:** T1583.001
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
Fast-flux networks rapidly rotate IP addresses for phishing/malware domains. Detect by tracking A record changes over time. If a domain resolves to > 5 different IPs within a short period, it's likely fast-flux. Look for IPs in non-routable spaces or from bulletproof hosting.

**Key Indicators:**
- Domain with > 5 A records in 1-hour window
- TTL < 60 seconds with frequent A record changes
- Rotating IPs from suspicious ASNs or hosting providers
- Same domain owned by multiple IPs (check PTR records)
- IPs in bulletproof/hijacked hosting ranges

**Response:**
1. Extract all IPs associated with the domain
2. Check ASNs and hosting providers for reputation
3. Extract all connected domains (reverse DNS, WHOIS)
4. Sink the entire domain + IP network if possible
5. Monitor for related infrastructure
6. Check for hosts with connections to fast-flux IPs

---

### [H010] DNS Data Exfiltration Detection

Attacker exfiltrates data by encoding it in DNS query names.

**Severity:** HIGH
**MITRE:** T1048.003
**Data Sources:** DNS Logs, Zeek DNS

**Detection Logic:**
Data exfiltration via DNS encodes sensitive data in long subdomain labels. Legitimate subdomains are short (< 20 chars); exfiltration uses 50+ char labels. Detect by measuring average/max subdomain label length per source. Combine with entropy analysis to confirm encoding. Monitor for query volume over time.

**Key Indicators:**
- Subdomain labels > 50 characters
- Average label length > 30 characters
- High entropy subdomains with NXDOMAIN responses
- Queries to attacker-controlled domain
- Consistent query pattern (exfil tool signature)

**Response:**
1. Extract all queries from source IP to suspected domain
2. Decode subdomain labels (base32/64 or other scheme)
3. Identify what data was exfiltrated
4. Determine compromise scope and affected systems
5. Isolate source host immediately
6. Hunt for similar exfiltration patterns
7. Preserve all evidence for incident response

---

## Sample Data

The `sample_data/` directory includes a comprehensive data generator that creates realistic DNS logs containing indicators for **all 10 hunt types mixed together** in a single realistic dataset. This provides a realistic "find the threats" scenario for testing and training.

### Generate sample data

```bash
python3 sample_data/generate_hunt_data.py
```

This generates `sample_data/sample_hunt_data.log` containing:
- Normal baseline traffic (benign queries)
- DNS tunnel traffic
- C2 beacon patterns
- DGA attempts
- Cache poisoning attacks
- Zone transfer attempts
- DNSSEC validation failures
- Amplification attack vectors
- DoH bypass traffic
- Fast-flux domains
- Data exfiltration patterns

See `sample_data/MANIFEST.md` for detailed description of generated data.

## Detection Queries

All 10 hunts include executable queries in multiple languages:

### Splunk SPL Queries

All Splunk queries are consolidated in `detections/capstone_splunk.spl`:

```splunk
# Hunt H001: DNS Tunneling Detection
source="dns.log"
| stats avg(entropy) as avg_entropy by src_ip, query_name
| where avg_entropy > 3.5

# Hunt H002: C2 Beacon Detection
source="dns.log"
| stats count as query_count, values(timestamp) as timestamps by src_ip, query_name
| where query_count > 10 AND stddev < 5

# ... and 8 more hunts
```

### Sigma Detection Rules

All Sigma rules are consolidated in `detections/capstone_sigma_rules.yml`:

```yaml
- title: DNS C2 Beacon Detection
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

# ... and 9 more rules
```

## Testing

Run comprehensive test suite:

```bash
python3 -m unittest test_hunt_playbook -v
```

All tests verify:
- All 10 hunts present and complete
- All queries valid and executable
- MITRE coverage matrix correct
- Hunt filtering works
- Playbook export in all formats
- Data structures and specifications

## Integration with Existing Labs

This capstone integrates and consolidates threat detection knowledge from:

- **Lab 04** — Zone Transfer Auditor → Hunt H005
- **Lab 05** — DNS C2 Detector → Hunt H002
- **Lab 06** — DNS Tunnel Hunter → Hunt H001
- **Lab 07** — DNSSEC Validator → Hunt H006
- **Lab 08** — (DGA Detection) → Hunt H003
- **Lab 09** — (DoH Detection) → Hunt H008

Additional hunts (H004, H007, H009, H010) complete the comprehensive threat landscape.

## References

- MITRE ATT&CK Framework: https://attack.mitre.org/
- Splunk Query Language: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/
- Kusto Query Language (KQL): https://learn.microsoft.com/en-us/azure/data-explorer/kusto/
- Sigma Rules Project: https://sigmahq.io/
- DNS Security (DNSSEC): https://www.icann.org/dnssec/
- Zeek DNS Logging: https://docs.zeek.org/en/master/logs/dns.html

## Author

**Angie Casarez** (casarezaz)

## License

MIT License — See LICENSE file for details
