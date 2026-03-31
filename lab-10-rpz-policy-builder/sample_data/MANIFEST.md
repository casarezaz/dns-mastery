# Sample Data Manifest

This directory contains generated threat intelligence feeds in multiple formats for testing the RPZ Policy Builder.

## Feed Files

| File | Format | Description | Entries |
|------|--------|-------------|---------|
| `abuse_ch_domains.txt` | Plain text (abuse.ch) | Domain blocklist from abuse.ch | 30 malware/botnet/ransomware domains |
| `phishtank_sample.csv` | PhishTank CSV | Phishing domain CSV with timestamps | 10 phishing domains |
| `hagezi_hosts.txt` | Hosts file | Hagezi/StevenBlack format with redirects | 30+ entries (domains + subdomains) |
| `custom_blocklist.txt` | Plain domain list | Custom blocklist format | 20 botnet/ransomware domains |
| `whitelist.txt` | Plain domain list | Safe domains to never block | 5 major domains |

## Domain Categories

### Malware & Botnet
- C2 (command & control) infrastructure
- Botnet control servers
- Trojan/worm distribution
- Rootkit command channels
- Adware/spyware beacons

**Example:** malware-c2.com, botnet-control.net, dga-seed1.net

### Phishing
- Credential harvesting domains
- Social engineering sites
- Imitated banking/payment services

**Example:** paypal-login-verify.com, amazon-account-confirm.org

### Ransomware
- Ransom payment gateways
- Decryption portals
- Leak sites

**Example:** locky-decryption.com, wannacry-payment.org

### Whitelisted (Safe)
- Major tech platforms (Google, Facebook, GitHub, etc.)
- Used in validation testing

## Statistics

- **Total unique malicious domains:** ~40
- **Total phishing domains:** 10
- **Total botnet domains:** 10
- **Total ransomware domains:** 10
- **Whitelisted safe domains:** 5
- **Feed formats tested:** 5 (abuse-ch, phishtank, hosts, plain, CSV)

## Feed Characteristics

### Abuse.ch Format
- Plain text list, one domain per line
- Supports comments (# prefix)
- No timestamps or metadata

### PhishTank CSV
- Standard CSV with headers: Domain, First Seen, Last Seen, Status
- ISO 8601 timestamps
- Online/offline status tracking

### Hagezi Hosts File
- Traditional hosts file format: IP Domain
- IP can be 0.0.0.0, 127.0.0.1, or redirect IP
- Multiple subdomains per domain
- Supports comments

### Custom Blocklist
- Plain text, one domain per line
- Comment lines with # prefix
- No additional metadata

### Whitelist
- Plain text, one safe domain per line
- Used to prevent blocking of legitimate services

## Usage Example

```bash
# Build RPZ policy from all feeds
python3 ../rpz_policy_builder.py \
    abuse_ch_domains.txt \
    phishtank_sample.csv \
    hagezi_hosts.txt \
    custom_blocklist.txt \
    --whitelist whitelist.txt \
    --format bind \
    --output rpz_policy.zone

# Get statistics
python3 ../rpz_policy_builder.py \
    abuse_ch_domains.txt \
    phishtank_sample.csv \
    hagezi_hosts.txt \
    custom_blocklist.txt \
    --stats
```

## Notes

- Domains are normalized to lowercase
- Duplicates are automatically deduplicated
- Whitelisted domains are excluded from the final policy
- All generated timestamps are from the generation date
- Feed formats are auto-detected based on filename patterns
