# 🌐 DNS Hierarchy Mapper

**Lab 1 — DNS Mastery Study Plan**

> Traces the full DNS delegation chain from root to authoritative nameserver and generates visual output.

Part of a [12-week DNS curriculum](../README.md) designed for security practitioners. This tool demonstrates hands-on understanding of DNS delegation, the namespace tree, root servers, TLD infrastructure, and authoritative resolution.

---

## What It Does

Given any domain, this tool:

1. Runs `dig +trace` to follow the delegation path from the **root zone (.)** down to the domain's **authoritative nameservers**
2. Parses each delegation hop — capturing NS records, glue records, and TTLs
3. Generates two output formats:
   - **ASCII tree** — color-coded terminal output showing the full chain
   - **Graphviz diagram** — visual PNG/SVG showing delegation flow
4. Exports structured JSON with complete delegation metadata

## Why This Matters (for Security Practitioners)

DNS delegation is the backbone of internet trust. Understanding the chain from root → TLD → authoritative NS is critical for:

- **Threat hunting** — Identifying anomalous delegation (e.g., newly changed NS records, suspicious registrars)
- **Incident response** — Tracing DNS hijacking and cache poisoning attacks
- **Detection engineering** — Writing rules that flag delegation changes in monitored domains
- **Red team awareness** — Understanding what attackers see during reconnaissance (passive DNS, zone enumeration)

---

## Prerequisites

### macOS (Homebrew)

```bash
# dig is included with macOS, but install latest BIND tools for best results
brew install bind

# Graphviz for visual output
brew install graphviz
```

### Python

- **Python 3.10+** required (uses modern type hints and dataclasses)
- **No pip dependencies** — uses only the standard library + system tools

### Verify Setup

```bash
dig -v           # Should show DiG version
dot -V           # Should show graphviz version
python3 --version  # Should be 3.10+
```

---

## Usage

### Trace a Single Domain

```bash
python3 dns_hierarchy_mapper.py example.com
```

### Trace Multiple Domains

```bash
python3 dns_hierarchy_mapper.py -d nasa.gov mit.edu google.com bbc.co.uk cloudflare.com
```

### Run the Default Sample Set

The default set covers 5 diverse domain types (`.gov`, `.edu`, `.com`, `.co.uk`):

```bash
python3 dns_hierarchy_mapper.py --defaults
```

### All Options

```
usage: dns_hierarchy_mapper [-h] [-d DOMAIN [DOMAIN ...]] [--defaults]
                            [-o OUTPUT_DIR] [-f {ascii,graphviz,both}]
                            [--server IP] [--no-color] [-v]
                            [domain]

Options:
  domain                  Single domain to trace
  -d, --domains           One or more domains to trace
  --defaults              Use the 5 default sample domains
  -o, --output-dir        Output directory (default: ./output)
  -f, --format            Output format: ascii, graphviz, or both (default: both)
  --server IP             DNS server for initial query (e.g., 8.8.8.8)
  --no-color              Disable ANSI color in terminal
  -v, --verbose           Debug logging
```

---

## Sample Output

### ASCII Tree

```
DNS Delegation Chain: nasa.gov
────────────────────────────────────────────────────────

  ├── . (Root)
  │   ├─ NS: a.root-servers.net
  │   ├─ NS: b.root-servers.net
  │   ├─ NS: c.root-servers.net
  │   └─ NS: d.root-servers.net
  │      TTL: 518400s
  │
  ├── gov. (TLD)
  │   ├─ NS: a.gov-servers.net
  │   ├─ NS: b.gov-servers.net
  │   └─ NS: c.gov-servers.net
  │      TTL: 172800s
  │
  └── nasa.gov.
      ├─ NS: ns1.nasa.gov
      └─ NS: ns2.nasa.gov
         TTL: 3600s

  ✓ Answer: nasa.gov → A 52.0.14.116

  Authoritative NS: ns1.nasa.gov, ns2.nasa.gov
```

### Graphviz Diagram

After running, check `output/` for:
- `nasa_gov.dot` — Graphviz source (editable)
- `nasa_gov.png` — Raster image
- `nasa_gov.svg` — Vector image (scales cleanly for presentations)

### JSON Summary

```json
{
  "generated": "2026-02-28T19:00:00+00:00",
  "tool": "DNS Hierarchy Mapper — Lab 1",
  "domains": [
    {
      "domain": "nasa.gov",
      "valid": true,
      "hop_count": 3,
      "authoritative_ns": ["ns1.nasa.gov", "ns2.nasa.gov"],
      "final_answer": "A 52.0.14.116",
      "hops": [
        { "zone": ".", "nameservers": ["a.root-servers.net", "..."], "ttl": 518400 },
        { "zone": "gov", "nameservers": ["a.gov-servers.net", "..."], "ttl": 172800 },
        { "zone": "nasa.gov", "nameservers": ["ns1.nasa.gov", "ns2.nasa.gov"], "ttl": 3600 }
      ]
    }
  ]
}
```

---

## Output Files

```
output/
├── nasa_gov.dot           # Graphviz source
├── nasa_gov.png           # Visual diagram
├── nasa_gov.svg           # Vector diagram
├── nasa_gov_tree.txt      # ASCII tree (plain text)
├── mit_edu.dot
├── mit_edu.png
├── ...
└── summary.json           # Combined metadata for all domains
```

---

## Architecture & Design Decisions

| Decision | Rationale |
|----------|-----------|
| `dig +trace` over `dnspython` | Mirrors real-world troubleshooting workflows; shows tool proficiency |
| Dataclass models | Clean separation of data and rendering; easy to extend |
| Dual output (ASCII + Graphviz) | Terminal-friendly for daily use; Graphviz for portfolio/presentations |
| JSON summary | Machine-readable output for integration with other tools/labs |
| No external Python deps | Reduces friction; demonstrates stdlib proficiency |

---

## MITRE ATT&CK Mapping

This lab builds foundational skills for detecting:

| Technique | ID | Relevance |
|-----------|-----|-----------|
| Gather Victim Network Information: DNS | T1590.002 | Understanding what delegation data reveals to attackers |
| Domain Trust Discovery | T1482 | How trust is established through the NS chain |
| DNS Server (Resource Development) | T1584.002 | Recognizing when attackers set up their own NS infrastructure |

---

## Extending This Tool

Ideas for future iterations:

- **DNSSEC validation chain** — Add DS/DNSIG record tracking at each hop (leads into Lab 7)
- **Historical comparison** — Cache previous traces and diff for delegation changes
- **Bulk scanning** — Feed Alexa Top 1000 and generate delegation statistics
- **Anomaly detection** — Flag domains with unusual delegation patterns (single NS, no glue, etc.)
- **Integration with Lab 5** — Feed delegation data into the C2 Detector

---

## References

- **DNS and BIND, 5th Edition** — Cricket Liu & Paul Albitz (O'Reilly) — Chapters 1-4
- **The Hidden Potential of DNS in Security** — Joshua Kuo & Ross Gibson (Infoblox)
- **RFC 1034** — Domain Names: Concepts and Facilities
- **RFC 1035** — Domain Names: Implementation and Specification
- **Cloudflare Learning Center** — https://cloudflare.com/learning/dns/

---

## License

MIT License — See [LICENSE](LICENSE) for details.
