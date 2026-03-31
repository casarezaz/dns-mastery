# Lab 11 Sample Data Manifest

## Files

### before_architecture.json
Weak DNS configuration: plaintext, no DNSSEC, no RPZ, no logging

### after_architecture.json
Hardened configuration: DoH encryption, DNSSEC, RPZ blocklists, detailed logging

### incident_events.json
Simulated malware C2 incident with DGA activity and data exfiltration

## Usage

```bash
python3 ../dns_threat_model.py analyze before_architecture.json
python3 ../dns_threat_model.py compare before_architecture.json after_architecture.json
python3 ../dns_threat_model.py timeline incident_events.json --name "Malware C2 Incident"
python3 ../dns_threat_model.py diagram before_architecture.json
```

## Techniques

Demonstrates MITRE ATT&CK:
- T1071.004 — Application Layer Protocol: DNS
- T1590.002 — Gather Victim Network Information: DNS
- T1557.004 — Adversary-in-the-Middle: DNS Spoofing
