# Lab 10 — RPZ Policy Builder

**Automated threat intelligence to Response Policy Zone pipeline.**

Integrates threat intelligence feeds (abuse.ch, PhishTank, Hagezi format) into BIND9 and Unbound resolver configurations. Automates RPZ zone file generation and deployment for blocking malicious domains at DNS query time.

Response Policy Zones (RPZ) enable DNS administrators to dynamically enforce security policies across an entire resolver, blocking known-malicious domains without requiring endpoint-level updates. This tool automates the ingestion of multiple threat intelligence feeds and generates RFC-compliant RPZ zones in BIND9 or Unbound configuration formats.

## Features

- **Zero external dependencies** — pure Python 3.10+ standard library
- **5 feed format parsers**:
  - abuse.ch domain blocklist (plain text)
  - abuse.ch URLhaus CSV
  - PhishTank CSV with timestamps
  - hosts-file format (Hagezi, StevenBlack)
  - plain domain lists
- **Dual resolver support**:
  - BIND9 RPZ zone file generation (RFC 8626)
  - Unbound local-zone configuration
- **4 policy actions**:
  - **NXDOMAIN** — block with non-existent domain response
  - **NODATA** — block with empty response
  - **PASSTHRU** — whitelist (allow to upstream resolver)
  - **REDIRECT** — send to walled-garden IP
- **Intelligent deduplication** across multiple feeds with overlap analysis
- **Whitelist support** — never-block domains for false-positive prevention
- **Zone validation** — syntax checking and format verification
- **Statistics** — domains per feed, overlap analysis, policy breakdown
- **Serial number management** — YYYYMMDDNN format for zone versioning
- **Multiple output formats** — BIND zone, Unbound config, JSON
- **CLI interface** with auto-format detection and tunable options
- **10 production Splunk SPL queries** for RPZ monitoring
- **5 Sigma detection rules** for bypass attempt detection
- **Sample data generator** with realistic threat intel feeds

## MITRE ATT&CK Mapping

| Technique | Name | What RPZ Blocks |
|-----------|------|-----------------|
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Blocks attacker-controlled C2 and malware domains |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Prevents DNS protocol abuse for C2 communication |
| [T1568](https://attack.mitre.org/techniques/T1568/) | Dynamic Resolution | Blocks domain generation algorithms and fast-flux networks |
| [T1557.004](https://attack.mitre.org/techniques/T1557/004/) | Adversary-in-the-Middle: DNS Spoofing | Prevents DNS hijacking by blocking malicious domains |

## Installation

No installation required — clone and run:

```bash
git clone https://github.com/casarezaz/dns-mastery.git
cd dns-mastery/lab-10-rpz-policy-builder
python3 rpz_policy_builder.py --help
```

**Requirements:** Python 3.10+

## Quick Start

### Generate sample data and create RPZ policy

```bash
# Generate sample threat intelligence feeds
python3 sample_data/generate_feeds.py

# Build RPZ zone file for BIND9
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    sample_data/phishtank_sample.csv \
    sample_data/hagezi_hosts.txt \
    sample_data/custom_blocklist.txt \
    --whitelist sample_data/whitelist.txt \
    --format bind \
    --output rpz_policy.zone

# Verify zone file
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    sample_data/phishtank_sample.csv \
    sample_data/hagezi_hosts.txt \
    sample_data/custom_blocklist.txt \
    --stats
```

### View generated BIND9 zone

```bash
head -50 rpz_policy.zone
```

### Generate Unbound configuration

```bash
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    sample_data/phishtank_sample.csv \
    --format unbound \
    --output rpz_policy.conf
```

### Generate JSON policy for API/integration

```bash
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    --format json \
    --output rpz_policy.json
```

### Block with NODATA instead of NXDOMAIN

```bash
python3 rpz_policy_builder.py \
    sample_data/custom_blocklist.txt \
    --action nodata \
    --output rpz_policy.zone
```

### Redirect blocked domains to walled garden

```bash
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    --action redirect \
    --redirect-ip 192.0.2.1 \
    --output rpz_policy.zone
```

### Whitelist critical domains

```bash
python3 rpz_policy_builder.py \
    sample_data/abuse_ch_domains.txt \
    sample_data/phishtank_sample.csv \
    --whitelist sample_data/whitelist.txt \
    --output rpz_policy.zone
```

## Command-Line Reference

```
usage: rpz_policy_builder [-h] [--zone-name NAME] [--action ACTION]
                          [--redirect-ip IP] [--whitelist FILE]
                          [--output FILE] [--format FORMAT]
                          [--validate] [--stats] [--serial SERIAL]
                          [--verbose] [--version]
                          [feeds ...]

positional arguments:
  feeds                 Feed files to process

options:
  --zone-name NAME      RPZ zone name (default: rpz.local)
  --action ACTION       Policy action: nxdomain, nodata, passthru, redirect
                        (default: nxdomain)
  --redirect-ip IP      IP address for redirect action (default: 0.0.0.0)
  --whitelist FILE      Whitelist file (one domain per line)
  --output FILE, -o     Output file (default: stdout)
  --format FORMAT       Output format: bind, unbound, json (default: bind)
  --validate            Validate zone file only and exit
  --stats               Print statistics and exit
  --serial SERIAL       SOA serial number (default: current YYYYMMDDNN)
  --verbose, -v         Print progress to stderr
  --version             Show version and exit
  --help, -h            Show this help message
```

## Exit Codes

- `0` — Success
- `1` — Validation failure or file error
- `2` — Invalid arguments

## Input Feed Formats

### Plain Domain List

One domain per line, comments with `#` prefix:

```
# Malware domains
badactor.com
malware.org
```

### abuse.ch Domain Blocklist

Same as plain list format:

```
# abuse.ch domains
botnet-c2.net
ransomware-server.ru
```

### PhishTank CSV

Standard CSV with `Domain` column:

```csv
Domain,First Seen,Last Seen,Status
phishing1.com,2024-01-01,2024-01-15,offline
phishing2.org,2024-01-05,2024-01-20,online
```

### abuse.ch URLhaus CSV

CSV with `domain` and optional `date_added`, `url` columns:

```csv
domain,url,date_added
badsite.com,http://badsite.com/malware,2024-01-01
malicious.org,http://malicious.org/phish,2024-01-02
```

### Hosts File (Hagezi/StevenBlack)

Traditional hosts format: `IP domain`:

```
0.0.0.0 malware.com
127.0.0.1 botnet.net
192.0.2.1 www.evil.org
```

## Output Formats

### BIND9 RPZ Zone File

RFC 8626 compliant zone file ready for BIND9:

```dns
$ORIGIN rpz.local.

@  3600  IN  SOA  ns1.rpz.local. hostmaster.rpz.local. (
    2024032700 ; serial
    3600       ; refresh
    1800       ; retry
    604800     ; expire
    3600 )     ; minimum

@  3600  IN  NS  ns1.rpz.local.
ns1.rpz.local.  3600  IN  A  127.0.0.1

; RPZ Policy Records (nxdomain)

example.com.  3600  IN  CNAME  .
evil.org.     3600  IN  CNAME  .
```

**RPZ Actions:**
- `CNAME  .` — NXDOMAIN (non-existent domain)
- `CNAME  *.` — NODATA (empty response)
- `CNAME  rpz-passthru.` — PASSTHRU (whitelist)
- `CNAME  192.0.2.1.rpz-ip.` — REDIRECT to IP

### Unbound Configuration

Unbound local-zone configuration format:

```
# Unbound RPZ Policy Configuration

local-zone: "example.com" always_nxdomain
local-zone: "evil.org" always_nxdomain
```

### JSON

Machine-readable JSON for integration:

```json
{
  "zone_name": "rpz.local",
  "serial": 2024032700,
  "action": "nxdomain",
  "generated": "2024-03-27T12:34:56.789Z",
  "statistics": {
    "total_domains": 40,
    "whitelist_size": 5
  },
  "policies": {
    "example.com": {
      "action": "nxdomain",
      "trigger_type": "qname",
      "redirect_ip": "",
      "sources": ["feed1", "feed2"],
      "comment": ""
    }
  }
}
```

## Python API

Use the RPZ Policy Builder as a library:

```python
from rpz_policy_builder import RPZPolicyBuilder, FeedSource, FeedFormat
from pathlib import Path

# Initialize builder
builder = RPZPolicyBuilder(zone_name="production.rpz")

# Add feed source
feed = FeedSource(
    name="abuse-ch",
    feed_format=FeedFormat.PLAIN_DOMAINS,
    file_path=Path("domains.txt"),
    description="abuse.ch domain blocklist"
)
builder.add_feed(feed)

# Load whitelist
builder.add_whitelist(Path("whitelist.txt"))

# Build policy
zone = builder.build_policy()

# Get statistics
stats = builder.get_statistics()
print(f"Total domains: {stats.total_domains}")
print(f"NXDOMAIN blocks: {stats.blocked_nxdomain}")

# Export formats
bind_zone = builder.export_bind()
unbound_config = builder.export_unbound()
json_output = builder.export_json()
```

## Advanced Features

### Deduplication and Overlap Analysis

Automatically deduplicates domains across feeds and tracks which feeds contain each domain:

```bash
python3 rpz_policy_builder.py feed1.txt feed2.txt feed3.txt --stats

# Output shows:
# Entries per feed:
#   feed1.txt: 100
#   feed2.txt: 50
#   feed3.txt: 75
# Total unique entries: 180
# Duplicate entries removed: 45
```

### Zone Validation

Validate zone syntax without generating output:

```bash
python3 rpz_policy_builder.py feed.txt --validate
```

### Serial Number Management

Automatically uses current date in YYYYMMDDNN format:

```
2024032700  # March 27, 2024, version 00
2024032701  # March 27, 2024, version 01
2024032800  # March 28, 2024, version 00
```

Optionally specify custom serial:

```bash
python3 rpz_policy_builder.py feed.txt --serial 2025010100
```

## Integration with BIND9

1. Generate zone file:
   ```bash
   python3 rpz_policy_builder.py feeds/* --output /etc/bind/rpz_policy.zone
   ```

2. Configure in `named.conf`:
   ```
   response-policy-zone "rpz.local" {
       file "/etc/bind/rpz_policy.zone";
       max-cache-ttl 60;
       min-update-interval 15;
   };
   ```

3. Reload BIND9:
   ```bash
   sudo systemctl reload bind9
   ```

## Integration with Unbound

1. Generate config:
   ```bash
   python3 rpz_policy_builder.py feeds/* --format unbound \
       --output /etc/unbound/rpz_policy.conf
   ```

2. Include in `unbound.conf`:
   ```
   include: /etc/unbound/rpz_policy.conf
   ```

3. Restart Unbound:
   ```bash
   sudo systemctl restart unbound
   ```

## Detection and Monitoring

### Splunk Queries

10 pre-built Splunk queries in `detections/rpz_monitoring_splunk.spl`:

- RPZ block hits by policy action
- Policy enforcement rate tracking
- Top blocked domains
- RPZ bypass attempt detection
- Clients with highest block rates
- Block activity spike detection
- Failed redirects
- Whitelist validation
- Coverage analysis by subnet
- Zone serial change detection

**Example:**
```spl
index=dns sourcetype=named:query response_code=NXDOMAIN
| stats count by host, query
| sort - count
| head 20
```

### Sigma Detection Rules

5 detection rules in `detections/rpz_policy_bypass.yml`:

- Fast-flux domain rotation
- Subdomain enumeration
- Response anomalies (should be blocked but aren't)
- Zone transfer reconnaissance
- DGA activity (excessive NXDOMAIN)

## Performance Considerations

### Zone Size

- **Small:** <1,000 domains — minimal overhead
- **Medium:** 1,000-10,000 domains — recommended
- **Large:** 10,000+ domains — consider splitting into multiple zones

### Update Frequency

- **Daily:** Standard feed update cycle
- **Hourly:** For real-time threat feeds
- **On-demand:** For emergency blocks

### Serial Number Strategy

Use YYYYMMDDNN format:
- YYYY = year
- MM = month
- DD = day
- NN = version counter (00-99)

Example: 2024032700 = March 27, 2024, version 00

## Troubleshooting

### Zone file not loading in BIND9

- Check syntax: `named-checkzone rpz.local rpz_policy.zone`
- Verify zone name matches configuration
- Ensure SOA serial is valid integer
- Check file permissions (readable by named user)

### Unbound not applying rules

- Verify format matches expected syntax
- Check Unbound logs: `journalctl -u unbound -f`
- Test query: `dig @localhost example.com +short`
- Reload config: `unbound-control reload`

### Feed parsing errors

- Ensure feed file exists and is readable
- Check encoding (UTF-8 recommended)
- Verify format matches expected structure
- Use `--verbose` flag for detailed logging

## Testing

Run comprehensive unit tests:

```bash
python3 -m unittest test_rpz_builder -v

# Expected output:
# test_domain_normalization (TestFeedEntry) ... ok
# test_hash_for_deduplication (TestFeedEntry) ... ok
# test_parse_plain_domains (TestFeedParsers) ... ok
# ... (60+ tests total)
# Ran 63 tests in 0.234s
# OK
```

## Real-World Deployment

### Step 1: Set up feeds

```bash
# Download latest feeds
wget https://abuse.ch/domains.txt
wget https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/all.txt

# Generate policy
python3 rpz_policy_builder.py domains.txt all.txt \
    --whitelist safe_domains.txt \
    --output production_rpz.zone
```

### Step 2: Validate

```bash
# Check syntax
named-checkzone rpz.prod production_rpz.zone

# Verify statistics
python3 rpz_policy_builder.py domains.txt all.txt --stats
```

### Step 3: Deploy

```bash
# Copy to BIND
sudo cp production_rpz.zone /etc/bind/

# Reload BIND
sudo systemctl reload bind9

# Monitor logs
sudo tail -f /var/log/bind/query.log
```

### Step 4: Monitor

```bash
# Track policy enforcement
splunk search 'index=dns response_code=NXDOMAIN | stats count by query'

# Monitor for bypasses
splunk search 'index=dns query=malware* response_code!=NXDOMAIN'
```

## Author

**Angie Casarez** (casarezaz)

## License

MIT License — See LICENSE file for details

## References

- [RFC 8626 — DNS Response Policy Zones (RPZ)](https://tools.ietf.org/html/rfc8626)
- [ISC BIND9 RPZ Documentation](https://bind9.readthedocs.io/en/latest/reference/configuration.html#statements-view)
- [Unbound local-zone Documentation](https://unbound.docs.nlnetlabs.nl/en/latest/reference/unbound.conf.html)
- [The Hidden Potential of DNS in Security — Ch. 11-12](https://example.com)
- [NIST SP 800-81 — Secure Domain Name System (DNS) Deployment](https://csrc.nist.gov/publications/detail/sp/800-81/final)

---

**DNS Mastery Study Plan** | Lab 10 of 12 | Week 10
