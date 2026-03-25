# Lab 05 — DNS C2 Detector

A detection engine that identifies **DNS-based command-and-control (C2) communication** in DNS log data. Analyzes query timing for beacon intervals, measures subdomain entropy to detect encoded payloads, flags anomalous query volumes, and identifies base32/base64/hex encoding in subdomain labels.

DNS is the most commonly abused legitimate protocol for C2 because it's rarely blocked, often unmonitored, and can traverse most network boundaries. This tool detects the telltale statistical signatures that distinguish C2 DNS traffic from normal resolution.

## Features

- **Zero external dependencies** — pure Python 3.10+ standard library
- **6 detection modules**:
  - **Beacon interval analysis** — coefficient-of-variation scoring to detect periodic query timing with jitter
  - **Subdomain entropy analysis** — Shannon entropy calculation to detect encoded data in labels
  - **Encoded label detection** — regex matching for base32, base64, and hex encoding patterns
  - **Label length anomaly** — flags subdomain labels exceeding typical length thresholds
  - **TXT record abuse** — detects excessive TXT queries used for C2 data download
  - **NXDOMAIN flood / DGA detection** — high NXDOMAIN rates indicating domain generation algorithms
  - **Volume anomaly detection** — z-score analysis across all domains
- **Composite threat scoring** (0–100) with multi-technique correlation bonus
- **Auto-format detection** — supports Zeek dns.log (TSV and JSON), generic CSV, and JSON lines
- **Tunable thresholds** — all detection parameters configurable via CLI flags
- **8 production Splunk SPL queries** and **5 Sigma detection rules**
- **Sample data generator** with 5 embedded C2 profiles for testing and training

## MITRE ATT&CK Mapping

| Technique | Name | Detection Module |
|-----------|------|-----------------|
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Beacon analysis, entropy, TXT abuse, volume anomaly |
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Dynamic Resolution: DGA | NXDOMAIN flood detection |
| [T1572](https://attack.mitre.org/techniques/T1572/) | Protocol Tunneling | Encoded labels, label length anomaly |
| [T1041](https://attack.mitre.org/techniques/T1041/) | Exfiltration Over C2 Channel | Encoded label detection |

## Installation

No installation required — clone and run:

```bash
git clone https://github.com/casarezaz/dns-mastery.git
cd dns-mastery/lab-05-dns-c2-detector
python3 dns_c2_detector.py --help
```

**Requirements:** Python 3.10+

## Quick Start

### Generate sample data and run detection

```bash
# Generate sample DNS logs with embedded C2 patterns
python3 sample_data/generate_sample_logs.py

# Run the detector
python3 dns_c2_detector.py sample_data/sample_dns.log --verbose
```

### Analyze real Zeek DNS logs

```bash
python3 dns_c2_detector.py /var/log/zeek/current/dns.log
```

### JSON output with custom thresholds

```bash
python3 dns_c2_detector.py --format json \
    --threshold entropy_high=3.8 \
    --threshold beacon_jitter_max=0.15 \
    --output report.json \
    dns_queries.log
```

### Filter to high-confidence detections only

```bash
python3 dns_c2_detector.py --min-score 60 dns.log
```

### Full options

```
usage: dns_c2_detector [-h] [--format {text,json}] [--output FILE]
                        [--threshold KEY=VALUE] [--min-score N]
                        [--verbose] [--version]
                        logfile [logfile ...]

positional arguments:
  logfile               DNS log file(s) to analyze

options:
  --format, -f          Output format: text (default) or json
  --output, -o FILE     Write report to file instead of stdout
  --threshold KEY=VALUE Override detection threshold (repeatable)
  --min-score N         Only report domains with threat score >= N
  --verbose, -v         Print progress to stderr
  --version, -V         Show version and exit
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No C2 indicators detected |
| `1`  | C2 indicators detected (one or more domains flagged) |

## Detection Techniques

### 1. Beacon Interval Analysis

C2 implants "check in" with their controller at regular intervals (e.g., every 60 seconds). We measure the **coefficient of variation (CV)** of inter-query intervals — legitimate DNS traffic has irregular timing (high CV), while beacons have regular timing (low CV).

**Threshold:** CV < 0.20 with minimum 10 queries.

### 2. Subdomain Entropy Analysis

C2 tools encode commands and data in subdomain labels using base32/64/hex. These encoded strings have **high Shannon entropy** (typically > 3.5 bits/char) compared to legitimate subdomains like `www` or `mail` (typically < 2.5 bits/char).

**Threshold:** Average entropy > 3.5 bits across subdomain queries.

### 3. Encoded Label Detection

Regex-based detection of base32 (`[A-Z2-7]{16,}`), base64 (`[A-Za-z0-9+/]{16,}`), and hex (`[0-9a-fA-F]{16,}`) patterns in subdomain labels. Matches the encoding signatures of tools like iodine, dnscat2, and dns2tcp.

### 4. Label Length Anomaly

DNS labels can be up to 63 characters. Legitimate subdomains rarely exceed 20 characters. Labels > 24 characters are suspicious; > 40 characters are very likely C2 data encoding.

### 5. TXT Record Abuse

TXT records can carry up to 255 bytes per string. C2 frameworks use TXT queries to download commands (the response contains encoded instructions). A domain receiving > 50% TXT queries is flagged.

### 6. NXDOMAIN Flood / DGA Detection

Domain Generation Algorithms (DGAs) generate hundreds of random domains per hour. Most return NXDOMAIN; the few that resolve reach the C2 server. An NXDOMAIN rate > 50% with high query volume triggers this detection.

### 7. Volume Anomaly (Cross-Domain)

Uses z-score analysis across all profiled domains to identify statistical outliers in query volume. A domain receiving significantly more queries than the population mean may indicate C2 or tunneling.

## Sample Data

The `sample_data/` directory includes a generator that creates realistic DNS logs with 5 embedded C2 profiles:

| Profile | Domain | Interval | Jitter | Technique |
|---------|--------|----------|--------|-----------|
| beacon-low | update-service.badactor.xyz | 60s | 5% | Low-frequency A record beacon |
| beacon-high | cdn-check.malware-c2.net | 300s | 8% | Base32-encoded TXT beacon |
| exfil | ns1.data-exfil.evil | 10s | 30% | Hex-encoded fast exfiltration |
| dga | (random domains) | 5s | 50% | DGA with 85% NXDOMAIN rate |
| txt-tunnel | t.dns-tunnel.cc | 2s | 15% | Base64 TXT tunnel |

Generate with:
```bash
python3 sample_data/generate_sample_logs.py
```

## Detection Rules

### Splunk SPL (`detections/c2_beacon_splunk.spl`)

8 production queries covering beacon intervals, entropy, encoding, TXT abuse, NXDOMAIN floods, label length, composite scoring, and time-series dashboards.

### Sigma Rules (`detections/dns_c2_beacon.yml`)

5 rules for cross-SIEM deployment:

| Rule | Technique | Level |
|------|-----------|-------|
| High Entropy Subdomains | T1071.004 | High |
| Periodic Query Intervals | T1071.004 | Medium |
| Excessive TXT Queries | T1071.004, T1041 | High |
| High NXDOMAIN Rate (DGA) | T1568.002 | High |
| Encoded Subdomain Labels | T1572, T1041 | High |

## Project Structure

```
lab-05-dns-c2-detector/
├── dns_c2_detector.py               # Main detection engine (zero dependencies)
├── detections/
│   ├── c2_beacon_splunk.spl         # 8 Splunk SPL detection queries
│   └── dns_c2_beacon.yml            # 5 Sigma detection rules
├── sample_data/
│   ├── generate_sample_logs.py      # Sample data generator with C2 profiles
│   ├── sample_dns.log               # Generated Zeek TSV (after running generator)
│   ├── sample_dns.csv               # Generated CSV (after running generator)
│   └── MANIFEST.md                  # Data manifest describing embedded patterns
├── test_c2_detector.py              # Unit tests
└── README.md                        # This file
```

## AI×Cyber Convergence

This lab feeds directly into the **AI×Cyber Convergence curriculum** as Project 2 (after CICIDS2017 NIDS). The statistical detection techniques here (entropy, interval analysis, z-scores) serve as the foundation for building ML-based DNS anomaly classifiers in Lab 08 (DGA Classifier).

## References

- *The Hidden Potential of DNS in Security* — Joshua Kuo & Ross Gibson — C2 detection chapters
- [SANS ISC: Detecting DNS Tunneling](https://isc.sans.edu/diary/Detecting+DNS+Tunneling/23837)
- [MITRE ATT&CK T1071.004](https://attack.mitre.org/techniques/T1071/004/) — Application Layer Protocol: DNS
- [Akamai: DNS Exfiltration and Tunneling Detection](https://www.akamai.com/blog/security/dns-exfiltration-detection)
- CICIDS2017 Dataset — Canadian Institute for Cybersecurity

## Legal Notice

This tool is intended for **authorized security monitoring and threat hunting only**. Only analyze DNS logs from networks you own or have explicit authorization to monitor.

---

*Part of the [DNS Mastery Study Plan](https://github.com/casarezaz/dns-mastery) — a 12-week hands-on DNS security curriculum.*
