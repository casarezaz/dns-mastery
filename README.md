# 🔒 DNS Mastery — Lab Portfolio

**A 12-Week Curriculum for Security Practitioners**

> *"It's always DNS" is the most repeated phrase in IT, yet DNS is one of the most poorly taught subjects in cybersecurity. This curriculum changes that.*

This repository contains 12 hands-on labs that build a complete understanding of DNS from the ground up — from how the namespace tree works to how nation-state actors abuse it for command-and-control operations. Each lab produces a portfolio-quality deliverable: functional tools, detection rules, and research artifacts.

**Author:** Angie Agee | CISSP, GCIH, GSEC, eJPT

---

## Curriculum Overview

### Phase 1: DNS Foundations (Weeks 1–4)

| Lab | Project | Status | Description |
|-----|---------|--------|-------------|
| 01 | [Hierarchy Mapper](lab-01-hierarchy-mapper/) | ✅ Complete | Traces full delegation chain from root → authoritative NS with visual output |
| 02 | [Record Type Analyzer](lab-02-record-analyzer/) | ✅ Complete | Comprehensive DNS enumeration + security posture assessment |
| 03 | [Cache Analyzer](lab-03-cache-analyzer/) | ✅ Complete | Resolution path tracing with latency measurement + anomaly detection |
| 04 | [Zone Transfer Auditor](lab-04-zone-transfer-auditor/) | ✅ Complete | AXFR misconfiguration scanner + sensitive record identification |

### Phase 2: DNS Security & Attack Techniques (Weeks 5–8)

| Lab | Project | Status | Description |
|-----|---------|--------|-------------|
| 05 | [DNS C2 Detector](lab-05-dns-c2-detector/) | ✅ Complete | Beacon pattern + high-entropy subdomain detection (Splunk SPL + Sigma) |
| 06 | [Tunnel Hunter](lab-06-tunnel-hunter/) | ✅ Complete | DNS tunneling detection engine — tested against iodine, dnscat2, dns2tcp |
| 07 | [DNSSEC Validator](lab-07-dnssec-validator/) | ✅ Complete | Full chain-of-trust validation from root KSK → target RRSIG |
| 08 | [DGA Classifier](lab-08-dga-classifier/) | ✅ Complete | ML model distinguishing DGA-generated domains from legitimate (AI×Cyber) |

### Phase 3: Modern DNS & Defensive Architecture (Weeks 9–12)

| Lab | Project | Status | Description |
|-----|---------|--------|-------------|
| 09 | [Encrypted DNS Analyzer](lab-09-encrypted-dns-analyzer/) | ✅ Complete | DoH/DoT/DoQ identification, bypass detection, certificate validation |
| 10 | [RPZ Policy Builder](lab-10-rpz-policy-builder/) | ✅ Complete | Automated threat intel → Response Policy Zone pipeline |
| 11 | [Personal Threat Model](lab-11-personal-threat-model/) | ✅ Complete | Real-world DNS incident response case study + hardened architecture |
| 12 | [Threat Hunt Playbook](lab-12-threat-hunt-playbook/) | ✅ Complete | Capstone — comprehensive DNS threat hunting guide with executable queries |

---

## MITRE ATT&CK Coverage

| Lab | Technique | ID | Tactic |
|-----|-----------|-----|--------|
| 01 | Gather Victim Network Information: DNS | T1590.002 | Reconnaissance |
| 04 | Gather Victim Network Information: DNS | T1590.002 | Reconnaissance |
| 05 | Application Layer Protocol: DNS | T1071.004 | Command & Control |
| 06 | Protocol Tunneling | T1572 | Command & Control |
| 07 | Adversary-in-the-Middle | T1557 | Credential Access |
| 08 | Dynamic Resolution: Domain Generation Algorithms | T1568.002 | Command & Control |
| 10 | Compromise Infrastructure: DNS Server | T1584.002 | Resource Development |
| 12 | Multiple (comprehensive) | — | Full kill chain |

---

## Getting Started

### Prerequisites

```bash
# macOS (Homebrew)
brew install bind graphviz python@3.12

# Verify
dig -v && dot -V && python3 --version
```

### Run Lab 1

```bash
cd lab-01-hierarchy-mapper
python3 dns_hierarchy_mapper.py --defaults
```

See each lab's `README.md` for specific setup and usage instructions.

---

## Repository Structure

```
dns-mastery/
├── README.md                        # ← You are here
├── LICENSE
├── .gitignore
│
├── lab-01-hierarchy-mapper/         # Phase 1: Foundations
│   ├── dns_hierarchy_mapper.py
│   ├── README.md
│   ├── requirements.txt
│   ├── output/                      # Generated (gitignored)
│   └── samples/                     # Sample output for reference
│
├── lab-02-record-analyzer/
├── lab-03-cache-analyzer/
├── lab-04-zone-transfer-auditor/
├── lab-05-dns-c2-detector/          # Phase 2: Security & Attacks
├── lab-06-tunnel-hunter/
├── lab-07-dnssec-validator/
├── lab-08-dga-classifier/
├── lab-09-encrypted-dns-analyzer/   # Phase 3: Modern DNS & Defense
├── lab-10-rpz-policy-builder/
├── lab-11-personal-threat-model/
├── lab-12-threat-hunt-playbook/
│
├── docs/                            # Guides and references
│   └── setup-guide.md
│
└── resources/                       # Shared reference material
    └── references.md
```

---

## Required Reading

| Priority | Resource | Notes |
|----------|----------|-------|
| Primary | **The Hidden Potential of DNS in Security** — Joshua Kuo & Ross Gibson | Security-focused — read cover to cover during Phase 2 |
| Primary | **DNS and BIND, 5th Edition** — Cricket Liu & Paul Albitz | Deep technical foundation — Chapters 1–6 for Phase 1 |
| Free | [Cloudflare Learning Center](https://cloudflare.com/learning/dns/) | Visual reinforcement for every concept |
| Free | RFC 1034 & 1035 | Original DNS specification |
| Free | NIST SP 800-81 | Secure DNS Deployment Guide |

---

## AI×Cyber Convergence Integration

Three labs from this curriculum feed directly into the AI×Cyber Convergence curriculum:

| DNS Lab | AI×Cyber Slot | AI Component |
|---------|---------------|--------------|
| Lab 5: DNS C2 Detector | Project 2 (after CICIDS2017 NIDS) | Statistical anomaly detection |
| Lab 8: DGA Classifier | ML Classification Project | Supervised ML (Random Forest, LSTM) |
| Lab 12: Threat Hunt Playbook | Capstone Reference | Automated threat scoring |

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

*Built as part of a structured self-study program in DNS security. Not just learning DNS as a network engineer — learning it as a detection engineer who uses DNS as a weapon against adversaries.*
