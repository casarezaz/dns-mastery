# Lab 3: DNS Cache Analyzer

> **DNS Mastery Curriculum** — Week 3: Caching & TTL Deep Dive

## Overview

A DNS caching behavior analysis tool that probes resolvers repeatedly to track TTL countdown, measure cache hit/miss rates, and compare caching performance across multiple public resolvers. Visualizes TTL decay over time with ASCII charts and interactive HTML reports.

## What This Tool Does

Given a domain, the analyzer:
1. Sends repeated DNS probes at configurable intervals
2. Tracks TTL countdown to observe cache decay in real-time
3. Distinguishes cache hits from misses based on TTL patterns and query timing
4. Compares caching behavior across multiple resolvers (Google, Cloudflare, Quad9, OpenDNS)
5. Calculates cache hit rates, speedup factors, and performance metrics
6. Generates ASCII terminal charts and interactive HTML reports with Chart.js

## Key Concepts Demonstrated

- **TTL (Time To Live)**: How DNS records expire in cache and the implications for propagation
- **Cache Hit vs Miss**: Identifying cached responses by TTL decay patterns and query latency
- **Resolver Behavior**: How different public resolvers cache differently (TTL clamping, minimum TTL, prefetching)
- **DNS Propagation**: Why TTL matters when making DNS changes
- **Performance Impact**: Quantifying the speed difference between cached and uncached queries
- **Anycast Effects**: How resolver anycast networks affect cache consistency

## Quick Start

### Prerequisites

```bash
# macOS
brew install bind    # provides dig
```

### Usage

```bash
# Basic: Track TTL decay on your system resolver
python3 dns_cache_analyzer.py google.com

# Compare across major public resolvers
python3 dns_cache_analyzer.py google.com --all-resolvers

# Specific resolvers
python3 dns_cache_analyzer.py github.com -r system google-primary cloudflare-primary

# More probes, shorter interval (more granular TTL tracking)
python3 dns_cache_analyzer.py nasa.gov --probes 20 --interval 1

# Quick comparison of all default domains
python3 dns_cache_analyzer.py --defaults --all-resolvers --probes 5

# All options
python3 dns_cache_analyzer.py --help
```

### Available Resolvers

| Name | Address | Provider |
|------|---------|----------|
| system | (default) | Your local/ISP resolver |
| google-primary | 8.8.8.8 | Google Public DNS |
| google-secondary | 8.8.4.4 | Google Public DNS |
| cloudflare-primary | 1.1.1.1 | Cloudflare DNS |
| cloudflare-secondary | 1.0.0.1 | Cloudflare DNS |
| quad9 | 9.9.9.9 | Quad9 (security-focused) |
| opendns | 208.67.222.222 | OpenDNS (Cisco) |

### Output

Each analysis produces:
- **Terminal**: ASCII TTL decay bars, cache hit/miss indicators, resolver comparison tables
- **JSON**: `output/<domain>_cache.json` — full probe data for programmatic analysis
- **HTML**: `output/<domain>_cache.html` — interactive Chart.js TTL decay visualization

## Architecture

```
dns_cache_analyzer.py
├── CacheProbeEngine      # Sends dig queries, extracts TTL + timing
├── TerminalRenderer      # ASCII TTL bars, stats, resolver tables
├── JSONExporter          # Structured JSON export
├── HTMLExporter          # Chart.js interactive HTML reports
└── DNSCacheAnalyzer      # Main orchestrator
```

### Design Decisions

- **dig probing**: Direct `dig` calls with `+noall +answer +stats` give precise TTL and query time. No library abstraction hiding the mechanics.
- **Cache detection heuristic**: Compares observed TTL to expected (previous TTL minus interval). If TTL decrements as expected, it's a cache hit. If TTL resets near original, it's a miss.
- **Resolver comparison**: Running the same probe series across resolvers reveals different caching strategies — some clamp minimum TTLs, some prefetch, some use larger shared caches.

## What to Look For

When you run the tool, observe these patterns:

1. **TTL Staircase**: Cached responses show TTL counting down like a staircase. Each probe should show TTL ~2s less than the previous (at default interval).

2. **Query Time Gap**: First query (cache miss) is typically 20-100ms. Subsequent cached queries drop to 1-10ms. The speedup factor quantifies this.

3. **Resolver Differences**:
   - Google (8.8.8.8) often returns slightly different TTLs due to anycast
   - Cloudflare (1.1.1.1) is typically fastest for cached queries
   - Quad9 adds security filtering overhead
   - Your system resolver behavior depends on your ISP/router

4. **TTL Reset Points**: When a TTL hits 0, the resolver must re-query the authoritative server. Watch for the TTL jumping back to the original value — that's a cache refresh.

## Security Relevance

Understanding DNS caching is critical for:

| Scenario | Relevance |
|----------|-----------|
| DNS poisoning attacks | Attackers target cache entries; understanding TTL helps assess exposure windows |
| Incident response | Knowing cache TTLs tells you how long a malicious DNS change persists |
| DNS change propagation | When remediating a compromise, low TTLs mean faster cutover |
| Reconnaissance detection | Anomalous query patterns to your DNS can indicate cache probing |

## MITRE ATT&CK Mapping

| Technique | Connection |
|-----------|------------|
| T1071.004 - DNS | Understanding normal cache behavior helps detect C2 over DNS |
| T1557.004 - DNS Spoofing | Cache poisoning exploits TTL windows |
| T1584.002 - DNS Server | Compromised resolvers affect cache integrity |

## Connections to Other Labs

- **Lab 1 (Hierarchy Mapper)**: Delegation chain determines which authoritative servers get cached
- **Lab 2 (Record Analyzer)**: TTL values from record analysis predict caching duration
- **Lab 6 (Tunneling Detector)**: Abnormal cache patterns can indicate DNS tunneling
- **Lab 11 (Performance Benchmarker)**: Cache metrics feed into performance analysis

## Reading Assignment

- *DNS and BIND*, Ch. 5: DNS Caching & Negative Caching
- *DNS and BIND*, Ch. 6: How DNS Works (resolver algorithms)
- *The Hidden Potential of DNS in Security*, Ch. 2: DNS Infrastructure

## License

MIT
