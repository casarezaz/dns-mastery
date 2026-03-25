# References & Resources

**DNS Mastery Curriculum**

---

## Primary Textbooks

| Resource | Authors | Use |
|----------|---------|-----|
| **DNS and BIND, 5th Edition** | Cricket Liu & Paul Albitz (O'Reilly) | Phase 1 deep technical foundation — Chapters 1–6 |
| **The Hidden Potential of DNS in Security** | Joshua Kuo & Ross Gibson (Infoblox) | Phase 2 cover-to-cover, Phase 3 Chapters 8–12 |

---

## RFCs

| RFC | Title | Relevant Labs |
|-----|-------|---------------|
| RFC 1034 | Domain Names — Concepts and Facilities | All (foundational) |
| RFC 1035 | Domain Names — Implementation and Specification | All (foundational) |
| RFC 1995 | Incremental Zone Transfer (IXFR) | Lab 4 |
| RFC 1996 | DNS NOTIFY | Lab 4 |
| RFC 2136 | Dynamic Updates in DNS | Lab 4 |
| RFC 2845 | Secret Key Transaction Authentication (TSIG) | Lab 4, 10 |
| RFC 4033 | DNS Security Introduction and Requirements (DNSSEC) | Lab 7 |
| RFC 4034 | Resource Records for DNSSEC | Lab 7 |
| RFC 4035 | Protocol Modifications for DNSSEC | Lab 7 |
| RFC 7858 | DNS over TLS (DoT) | Lab 9 |
| RFC 8484 | DNS Queries over HTTPS (DoH) | Lab 9 |
| RFC 9250 | DNS over Dedicated QUIC Connections (DoQ) | Lab 9 |

---

## Free Online Resources

| Resource | URL | Use |
|----------|-----|-----|
| Cloudflare Learning Center | https://cloudflare.com/learning/dns/ | Visual reinforcement — read alongside every week |
| NIST SP 800-81 Rev 1 | https://csrc.nist.gov/publications/detail/sp/800-81/rev-1/final | Secure DNS Deployment Guide — Phase 3 |
| SANS Reading Room (DNS) | https://www.sans.org/reading-room/ | Whitepapers on DNS security — Phase 2 |
| DNSViz | https://dnsviz.net/ | DNSSEC visualization reference — Lab 7 |

---

## Datasets

| Dataset | Source | Relevant Labs |
|---------|--------|---------------|
| CICIDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | Lab 5 (DNS C2 Detector) |
| DGArchive | https://dgarchive.caad.fkie.fraunhofer.de/ | Lab 8 (DGA Classifier) |
| Bambenek DGA Feed | https://osint.bambenekconsulting.com/feeds/ | Lab 8 (DGA Classifier) |

---

## Threat Intelligence Feeds (Lab 10: RPZ)

| Feed | URL | Type |
|------|-----|------|
| abuse.ch URLhaus | https://urlhaus.abuse.ch/ | Malware URLs |
| PhishTank | https://phishtank.org/ | Phishing domains |
| Hagezi DNS Blocklists | https://github.com/hagezi/dns-blocklists | Multi-category blocklists |

---

## MITRE ATT&CK References

| Technique | ID | URL |
|-----------|----|-----|
| Gather Victim Network Info: DNS | T1590.002 | https://attack.mitre.org/techniques/T1590/002/ |
| Application Layer Protocol: DNS | T1071.004 | https://attack.mitre.org/techniques/T1071/004/ |
| Protocol Tunneling | T1572 | https://attack.mitre.org/techniques/T1572/ |
| Adversary-in-the-Middle | T1557 | https://attack.mitre.org/techniques/T1557/ |
| Dynamic Resolution: DGA | T1568.002 | https://attack.mitre.org/techniques/T1568/002/ |
| Compromise Infrastructure: DNS Server | T1584.002 | https://attack.mitre.org/techniques/T1584/002/ |

---

## Tools Reference

| Tool | Install (macOS) | Used In |
|------|-----------------|---------|
| dig (BIND) | `brew install bind` | Labs 1–4, 7 |
| Graphviz | `brew install graphviz` | Lab 1 |
| Wireshark / tshark | `brew install --cask wireshark` | Labs 3, 6, 9 |
| dnspython | `pip3 install dnspython` | Labs 2, 7 |
| nmap | `brew install nmap` | Lab 4 |
| Splunk Free | https://www.splunk.com/en_us/download/ | Labs 5, 6, 12 |
| scikit-learn | `pip3 install scikit-learn` | Lab 8 |
| Sigma | `pip3 install sigma-cli` | Labs 5, 6, 12 |
| BIND9 | Docker/VM | Lab 10 |
| Unbound | `brew install unbound` | Lab 10 |
