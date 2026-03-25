# Sample Data Manifest

This directory contains generated DNS logs with embedded C2 patterns.

## Embedded C2 Profiles

| Profile | Domain | Interval | Jitter | Src IP | Type | Style |
|---------|--------|----------|--------|--------|------|-------|
| beacon-low | update-service.badactor.xyz | 60s | 5% | 10.1.1.50 | A | short |
| beacon-high | cdn-check.malware-c2.net | 300s | 8% | 10.1.1.75 | TXT | encoded |
| exfil | ns1.data-exfil.evil | 10s | 30% | 10.1.1.100 | A | hex |
| dga | None | 5s | 50% | 10.1.1.200 | A | dga |
| txt-tunnel | t.dns-tunnel.cc | 2s | 15% | 10.1.1.150 | TXT | base64 |

## Statistics

- Total queries: 13238
- Time span: 4 hours
- Benign domains: 50
- C2 profiles: 5
