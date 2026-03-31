#!/usr/bin/env python3
"""
RPZ Policy Builder — Lab 10 of the DNS Mastery Study Plan
==========================================================
Automated threat intelligence to Response Policy Zone pipeline.
Integrates threat intelligence feeds (abuse.ch, PhishTank, Hagezi format)
into BIND9 and Unbound resolver configurations.

Parses multiple feed formats:
  - abuse.ch URLhaus CSV
  - abuse.ch domain blocklist
  - PhishTank CSV
  - hosts-file format (Hagezi, StevenBlack)
  - plain domain lists

Generates RPZ zone files (BIND9 format) with:
  - SOA and NS records
  - NXDOMAIN (block), NODATA (empty response), PASSTHRU (whitelist), redirect actions
  - RPZ trigger syntax (qname, ip, nsdname, nsip)
  - Serial number management (YYYYMMDDNN format)

Also generates Unbound local-zone configuration.

MITRE ATT&CK Mapping:
    T1583.001 — Acquire Infrastructure: Domains
    T1071.004 — Application Layer Protocol: DNS
    T1568     — Dynamic Resolution

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import textwrap
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional, Set, Dict, List, Tuple

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Constants & Enumerations
# ---------------------------------------------------------------------------

class PolicyAction(Enum):
    """RPZ policy actions."""
    NXDOMAIN = "nxdomain"      # Block with NXDOMAIN response
    NODATA = "nodata"          # Block with empty response (NODATA)
    PASSTHRU = "passthru"      # Whitelist: pass through to upstream
    REDIRECT = "redirect"      # Redirect to walled garden IP


class FeedFormat(Enum):
    """Feed file formats."""
    ABUSE_CH_DOMAINS = "abuse-ch-domains"    # abuse.ch domain blocklist
    ABUSE_CH_URLHAUS = "abuse-ch-urlhaus"    # abuse.ch URLhaus CSV
    PHISHTANK_CSV = "phishtank-csv"          # PhishTank CSV
    HOSTS_FILE = "hosts-file"                 # hosts file format (Hagezi)
    PLAIN_DOMAINS = "plain-domains"          # Plain domain list (one per line)


class RPZTriggerType(Enum):
    """RPZ trigger types."""
    QNAME = "qname"             # Query name (domain)
    IP = "ip"                   # Client IP address
    NSDNAME = "nsdname"         # Nameserver domain name
    NSIP = "nsip"               # Nameserver IP address


DEFAULT_SOA_SERIAL_BASE = 2024032700  # YYYYMMDDNN format
DEFAULT_WALLED_GARDEN_IP = "0.0.0.0"
DEFAULT_RPZ_ZONE_NAME = "rpz.local"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class FeedEntry:
    """A single entry from a threat intel feed."""
    domain: str                 # FQDN to block
    source_feed: str           # Feed name it came from
    feed_format: FeedFormat    # Feed format type
    description: str = ""      # Optional description
    confidence: float = 1.0    # 0.0-1.0 confidence score
    timestamp: str = ""        # When discovered
    metadata: Dict = field(default_factory=dict)  # Extra metadata

    def __post_init__(self):
        """Normalize domain to lowercase."""
        self.domain = self.domain.lower().strip()

    def __hash__(self):
        """Hash for deduplication."""
        return hash(self.domain)

    def __eq__(self, other):
        """Equality for deduplication."""
        if not isinstance(other, FeedEntry):
            return False
        return self.domain == other.domain


@dataclass
class FeedSource:
    """A threat intelligence feed source."""
    name: str                   # Feed name (e.g., "abuse-ch-domains")
    feed_format: FeedFormat    # Format type
    file_path: Path            # Path to feed file
    description: str = ""      # Feed description
    enabled: bool = True       # Whether to include in policy


@dataclass
class RPZPolicy:
    """An RPZ policy rule."""
    domain: str                 # Domain to apply policy to
    action: PolicyAction       # Block action
    trigger_type: RPZTriggerType = RPZTriggerType.QNAME
    redirect_ip: str = ""      # For REDIRECT action
    comment: str = ""          # Optional comment
    source_feeds: Set[str] = field(default_factory=set)


@dataclass
class RPZZone:
    """A generated RPZ zone."""
    zone_name: str
    policies: Dict[str, RPZPolicy] = field(default_factory=dict)  # domain -> policy
    serial: int = DEFAULT_SOA_SERIAL_BASE
    whitelist: Set[str] = field(default_factory=set)  # Domains to never block

    def add_policy(self, domain: str, policy: RPZPolicy):
        """Add or update a policy."""
        if domain not in self.whitelist:
            self.policies[domain] = policy

    def remove_policy(self, domain: str):
        """Remove a policy."""
        self.policies.pop(domain, None)

    def add_whitelist(self, domain: str):
        """Add domain to whitelist and remove any existing policy."""
        self.whitelist.add(domain.lower().strip())
        self.remove_policy(domain)


@dataclass
class ZoneStats:
    """Statistics about an RPZ zone."""
    total_domains: int = 0
    blocked_nxdomain: int = 0
    blocked_nodata: int = 0
    redirected: int = 0
    passthru: int = 0
    entries_per_feed: Dict[str, int] = field(default_factory=dict)
    duplicate_entries: int = 0
    unique_entries: int = 0
    feed_overlap: Dict[str, int] = field(default_factory=dict)  # domain -> count


# ---------------------------------------------------------------------------
# Feed Parsing Functions
# ---------------------------------------------------------------------------

def parse_abuse_ch_domains(feed_path: Path) -> List[FeedEntry]:
    """Parse abuse.ch domain blocklist format (plain text, one domain per line)."""
    entries = []
    try:
        with open(feed_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                domain = line.lower()
                if domain:
                    entries.append(FeedEntry(
                        domain=domain,
                        source_feed=feed_path.stem,
                        feed_format=FeedFormat.ABUSE_CH_DOMAINS,
                        description=f"abuse.ch domain blocklist entry"
                    ))
    except Exception as e:
        print(f"Error parsing abuse.ch domains from {feed_path}: {e}", file=sys.stderr)
    return entries


def parse_abuse_ch_urlhaus(feed_path: Path) -> List[FeedEntry]:
    """Parse abuse.ch URLhaus CSV format."""
    entries = []
    try:
        with open(feed_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row or not row.get('domain'):
                    continue
                domain = row['domain'].lower().strip()
                if domain:
                    entries.append(FeedEntry(
                        domain=domain,
                        source_feed=feed_path.stem,
                        feed_format=FeedFormat.ABUSE_CH_URLHAUS,
                        description=row.get('url', ''),
                        timestamp=row.get('date_added', '')
                    ))
    except Exception as e:
        print(f"Error parsing abuse.ch URLhaus from {feed_path}: {e}", file=sys.stderr)
    return entries


def parse_phishtank_csv(feed_path: Path) -> List[FeedEntry]:
    """Parse PhishTank CSV format."""
    entries = []
    try:
        with open(feed_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row or not row.get('Domain'):
                    continue
                domain = row['Domain'].lower().strip()
                if domain:
                    entries.append(FeedEntry(
                        domain=domain,
                        source_feed=feed_path.stem,
                        feed_format=FeedFormat.PHISHTANK_CSV,
                        description="PhishTank phishing domain",
                        timestamp=row.get('First Seen', '')
                    ))
    except Exception as e:
        print(f"Error parsing PhishTank CSV from {feed_path}: {e}", file=sys.stderr)
    return entries


def parse_hosts_file(feed_path: Path) -> List[FeedEntry]:
    """Parse hosts file format (Hagezi, StevenBlack, etc.)."""
    entries = []
    try:
        with open(feed_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    domain = parts[1].lower()
                    if domain:
                        entries.append(FeedEntry(
                            domain=domain,
                            source_feed=feed_path.stem,
                            feed_format=FeedFormat.HOSTS_FILE,
                            description=f"Hosts file entry (IP: {ip})"
                        ))
    except Exception as e:
        print(f"Error parsing hosts file from {feed_path}: {e}", file=sys.stderr)
    return entries


def parse_plain_domains(feed_path: Path) -> List[FeedEntry]:
    """Parse plain domain list (one domain per line)."""
    entries = []
    try:
        with open(feed_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                domain = line.lower()
                if domain:
                    entries.append(FeedEntry(
                        domain=domain,
                        source_feed=feed_path.stem,
                        feed_format=FeedFormat.PLAIN_DOMAINS,
                        description="Custom blocklist entry"
                    ))
    except Exception as e:
        print(f"Error parsing plain domains from {feed_path}: {e}", file=sys.stderr)
    return entries


def parse_feed(feed_source: FeedSource) -> List[FeedEntry]:
    """Parse a feed file based on its format."""
    if not feed_source.enabled or not feed_source.file_path.exists():
        return []

    parsers = {
        FeedFormat.ABUSE_CH_DOMAINS: parse_abuse_ch_domains,
        FeedFormat.ABUSE_CH_URLHAUS: parse_abuse_ch_urlhaus,
        FeedFormat.PHISHTANK_CSV: parse_phishtank_csv,
        FeedFormat.HOSTS_FILE: parse_hosts_file,
        FeedFormat.PLAIN_DOMAINS: parse_plain_domains,
    }

    parser = parsers.get(feed_source.feed_format)
    if parser:
        return parser(feed_source.file_path)
    return []


# ---------------------------------------------------------------------------
# RPZ Zone Generation
# ---------------------------------------------------------------------------

def generate_bind_zone_file(
    zone: RPZZone,
    action: PolicyAction,
    redirect_ip: str = DEFAULT_WALLED_GARDEN_IP
) -> str:
    """Generate BIND9 RPZ zone file format."""
    lines = []

    # Zone header and SOA record
    lines.append(f"$ORIGIN {zone.zone_name}.")
    lines.append("")

    # SOA record
    lines.append("; SOA record")
    lines.append(f"@  3600  IN  SOA  ns1.{zone.zone_name}. hostmaster.{zone.zone_name}. (")
    lines.append(f"    {zone.serial}  ; serial")
    lines.append(f"    3600           ; refresh")
    lines.append(f"    1800           ; retry")
    lines.append(f"    604800         ; expire")
    lines.append(f"    3600 )         ; minimum")
    lines.append("")

    # NS record
    lines.append("; Nameserver records")
    lines.append(f"@  3600  IN  NS  ns1.{zone.zone_name}.")
    lines.append(f"ns1.{zone.zone_name}.  3600  IN  A  127.0.0.1")
    lines.append("")

    # Policy entries
    lines.append(f"; RPZ Policy Records ({action.value})")
    lines.append("")

    for domain in sorted(zone.policies.keys()):
        policy = zone.policies[domain]

        # RPZ response policy syntax
        if action == PolicyAction.NXDOMAIN:
            lines.append(f"{domain}.  3600  IN  CNAME  .")
        elif action == PolicyAction.NODATA:
            lines.append(f"{domain}.  3600  IN  CNAME  *.")
        elif action == PolicyAction.PASSTHRU:
            lines.append(f"{domain}.  3600  IN  CNAME  rpz-passthru.")
        elif action == PolicyAction.REDIRECT:
            ip = policy.redirect_ip or redirect_ip
            lines.append(f"{domain}.  3600  IN  CNAME  {ip}.rpz-ip.")

    lines.append("")
    return "\n".join(lines)


def generate_unbound_config(
    zone: RPZZone,
    action: PolicyAction,
    redirect_ip: str = DEFAULT_WALLED_GARDEN_IP
) -> str:
    """Generate Unbound local-zone configuration."""
    lines = []

    lines.append("# Unbound RPZ Policy Configuration")
    lines.append(f"# Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"# Zone: {zone.zone_name}")
    lines.append(f"# Serial: {zone.serial}")
    lines.append("")

    for domain in sorted(zone.policies.keys()):
        policy = zone.policies[domain]

        if action == PolicyAction.NXDOMAIN:
            lines.append(f'local-zone: "{domain}" always_nxdomain')
        elif action == PolicyAction.NODATA:
            lines.append(f'local-zone: "{domain}" always_nodata')
        elif action == PolicyAction.PASSTHRU:
            lines.append(f'local-zone: "{domain}" transparent')
        elif action == PolicyAction.REDIRECT:
            ip = policy.redirect_ip or redirect_ip
            lines.append(f'local-zone: "{domain}" redirect')
            lines.append(f'local-data: "{domain} 3600 IN A {ip}"')

    lines.append("")
    return "\n".join(lines)


def generate_json_output(zone: RPZZone, action: PolicyAction) -> str:
    """Generate JSON output."""
    policies_dict = {}
    for domain, policy in sorted(zone.policies.items()):
        policies_dict[domain] = {
            "action": action.value,
            "trigger_type": policy.trigger_type.value,
            "redirect_ip": policy.redirect_ip,
            "sources": list(policy.source_feeds),
            "comment": policy.comment
        }

    output = {
        "zone_name": zone.zone_name,
        "serial": zone.serial,
        "action": action.value,
        "generated": datetime.now(timezone.utc).isoformat(),
        "statistics": {
            "total_domains": len(zone.policies),
            "whitelist_size": len(zone.whitelist)
        },
        "policies": policies_dict
    }
    return json.dumps(output, indent=2)


# ---------------------------------------------------------------------------
# Zone Validation & Statistics
# ---------------------------------------------------------------------------

def validate_zone(zone: RPZZone) -> Tuple[bool, List[str]]:
    """Validate zone file format and content."""
    errors = []

    # Check zone name
    if not zone.zone_name or not zone.zone_name.strip():
        errors.append("Zone name is empty")

    # Check serial format (YYYYMMDDNN)
    serial_str = str(zone.serial)
    if len(serial_str) < 10:
        errors.append(f"Serial {zone.serial} doesn't follow YYYYMMDDNN format")

    # Check for invalid domains
    for domain in zone.policies.keys():
        if not domain or not isinstance(domain, str):
            errors.append(f"Invalid domain: {domain}")
        # Basic FQDN validation
        if '..' in domain or domain.startswith('.') or domain.endswith('.'):
            errors.append(f"Invalid domain format: {domain}")

    return len(errors) == 0, errors


def compute_statistics(
    zone: RPZZone,
    all_entries: Dict[str, FeedEntry],
    feeds_processed: List[str]
) -> ZoneStats:
    """Compute statistics about the zone."""
    stats = ZoneStats()

    # Count policies by action type
    for domain, policy in zone.policies.items():
        if policy.action == PolicyAction.NXDOMAIN:
            stats.blocked_nxdomain += 1
        elif policy.action == PolicyAction.NODATA:
            stats.blocked_nodata += 1
        elif policy.action == PolicyAction.REDIRECT:
            stats.redirected += 1
        elif policy.action == PolicyAction.PASSTHRU:
            stats.passthru += 1

    stats.total_domains = len(zone.policies)
    stats.unique_entries = len(set(e.domain for e in all_entries.values()))

    # Count entries per feed
    for domain, entry in all_entries.items():
        feed_name = entry.source_feed
        stats.entries_per_feed[feed_name] = stats.entries_per_feed.get(feed_name, 0) + 1

        # Track feed overlap
        if domain in zone.policies:
            stats.feed_overlap[domain] = stats.feed_overlap.get(domain, 0) + 1

    stats.duplicate_entries = len(all_entries) - stats.unique_entries

    return stats


def increment_serial(base_serial: int) -> int:
    """Increment serial in YYYYMMDDNN format."""
    serial_str = str(base_serial)
    if len(serial_str) < 10:
        return base_serial + 1

    # Extract components: YYYYMMDDNN
    date_part = int(serial_str[:8])
    counter = int(serial_str[8:])

    # Check if we've exceeded 99 for today
    if counter >= 99:
        # Would need to increment date, but we'll just increment counter
        return base_serial + 1
    else:
        return int(serial_str[:8] + str(counter + 1).zfill(2))


# ---------------------------------------------------------------------------
# Main Policy Builder
# ---------------------------------------------------------------------------

class RPZPolicyBuilder:
    """Main RPZ policy builder orchestrator."""

    def __init__(
        self,
        zone_name: str = DEFAULT_RPZ_ZONE_NAME,
        base_serial: int = DEFAULT_SOA_SERIAL_BASE,
        walled_garden_ip: str = DEFAULT_WALLED_GARDEN_IP
    ):
        self.zone_name = zone_name
        self.base_serial = base_serial
        self.walled_garden_ip = walled_garden_ip
        self.feeds: List[FeedSource] = []
        self.zone = RPZZone(zone_name=zone_name, serial=base_serial)
        self.all_entries: Dict[str, FeedEntry] = {}

    def add_feed(self, feed_source: FeedSource):
        """Add a feed source."""
        self.feeds.append(feed_source)

    def add_whitelist(self, whitelist_file: Path):
        """Load and add whitelist from file."""
        if not whitelist_file.exists():
            return

        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith('#'):
                        self.zone.add_whitelist(domain)
        except Exception as e:
            print(f"Error loading whitelist: {e}", file=sys.stderr)

    def build_policy(
        self,
        action: PolicyAction = PolicyAction.NXDOMAIN,
        redirect_ip: str = ""
    ) -> RPZZone:
        """Build RPZ policy from feeds."""
        # Parse all feeds
        for feed in self.feeds:
            entries = parse_feed(feed)
            for entry in entries:
                if entry.domain not in self.all_entries:
                    self.all_entries[entry.domain] = entry
                # Track which feeds contain this domain
                self.all_entries[entry.domain].metadata['feeds'] = \
                    self.all_entries[entry.domain].metadata.get('feeds', set())
                self.all_entries[entry.domain].metadata['feeds'].add(feed.name)

        # Create policies for non-whitelisted entries
        for domain, entry in self.all_entries.items():
            if domain not in self.zone.whitelist:
                policy = RPZPolicy(
                    domain=domain,
                    action=action,
                    redirect_ip=redirect_ip or self.walled_garden_ip,
                    source_feeds=entry.metadata.get('feeds', set())
                )
                self.zone.add_policy(domain, policy)

        return self.zone

    def get_statistics(self) -> ZoneStats:
        """Get zone statistics."""
        return compute_statistics(self.zone, self.all_entries, [f.name for f in self.feeds])

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate the zone."""
        return validate_zone(self.zone)

    def export_bind(self) -> str:
        """Export as BIND9 zone file."""
        return generate_bind_zone_file(
            self.zone,
            PolicyAction.NXDOMAIN,
            self.walled_garden_ip
        )

    def export_unbound(self) -> str:
        """Export as Unbound config."""
        return generate_unbound_config(
            self.zone,
            PolicyAction.NXDOMAIN,
            self.walled_garden_ip
        )

    def export_json(self) -> str:
        """Export as JSON."""
        return generate_json_output(self.zone, PolicyAction.NXDOMAIN)


# ---------------------------------------------------------------------------
# CLI Interface
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="RPZ Policy Builder - Automated threat intelligence to RPZ pipeline"
    )

    parser.add_argument('feeds', nargs='*', help='Feed files to process')
    parser.add_argument('--zone-name', default=DEFAULT_RPZ_ZONE_NAME,
                        help='RPZ zone name (default: %(default)s)')
    parser.add_argument('--action', choices=['nxdomain', 'nodata', 'passthru', 'redirect'],
                        default='nxdomain', help='Policy action (default: %(default)s)')
    parser.add_argument('--redirect-ip', default=DEFAULT_WALLED_GARDEN_IP,
                        help='IP for redirect action (default: %(default)s)')
    parser.add_argument('--whitelist', type=Path, help='Whitelist file (one domain per line)')
    parser.add_argument('--output', '-o', type=Path, help='Output file (default: stdout)')
    parser.add_argument('--format', '-f', choices=['bind', 'unbound', 'json'],
                        default='bind', help='Output format (default: %(default)s)')
    parser.add_argument('--validate', action='store_true',
                        help='Validate zone file only')
    parser.add_argument('--stats', action='store_true',
                        help='Print statistics and exit')
    parser.add_argument('--serial', type=int, default=DEFAULT_SOA_SERIAL_BASE,
                        help='SOA serial number (default: %(default)s)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')

    args = parser.parse_args()

    # Initialize builder
    builder = RPZPolicyBuilder(
        zone_name=args.zone_name,
        base_serial=args.serial
    )

    # Detect feed formats and add feeds
    for feed_file in args.feeds:
        feed_path = Path(feed_file)
        if not feed_path.exists():
            print(f"Warning: Feed file not found: {feed_path}", file=sys.stderr)
            continue

        # Auto-detect format based on filename
        stem = feed_path.stem.lower()
        if 'urlhaus' in stem:
            fmt = FeedFormat.ABUSE_CH_URLHAUS
        elif 'phish' in stem or 'phishtank' in stem:
            fmt = FeedFormat.PHISHTANK_CSV
        elif 'hosts' in stem or 'hagezi' in stem or 'steven' in stem:
            fmt = FeedFormat.HOSTS_FILE
        elif 'abuse' in stem or 'domain' in stem:
            fmt = FeedFormat.ABUSE_CH_DOMAINS
        else:
            fmt = FeedFormat.PLAIN_DOMAINS

        feed_source = FeedSource(
            name=feed_path.stem,
            feed_format=fmt,
            file_path=feed_path,
            description=f"Feed from {feed_file}"
        )
        builder.add_feed(feed_source)

        if args.verbose:
            print(f"Added feed: {feed_path.stem} ({fmt.value})", file=sys.stderr)

    # Load whitelist if provided
    if args.whitelist:
        builder.add_whitelist(args.whitelist)
        if args.verbose:
            print(f"Loaded whitelist: {args.whitelist}", file=sys.stderr)

    # Build policy
    action_map = {
        'nxdomain': PolicyAction.NXDOMAIN,
        'nodata': PolicyAction.NODATA,
        'passthru': PolicyAction.PASSTHRU,
        'redirect': PolicyAction.REDIRECT,
    }
    action = action_map.get(args.action, PolicyAction.NXDOMAIN)

    zone = builder.build_policy(action, args.redirect_ip)

    if args.verbose:
        print(f"Built policy with {len(zone.policies)} domains", file=sys.stderr)

    # Validate
    valid, errors = builder.validate()
    if not valid:
        print("Zone validation failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(1)

    # Output statistics if requested
    if args.stats:
        stats = builder.get_statistics()
        print("RPZ Zone Statistics:")
        print(f"  Total domains: {stats.total_domains}")
        print(f"  NXDOMAIN blocks: {stats.blocked_nxdomain}")
        print(f"  NODATA blocks: {stats.blocked_nodata}")
        print(f"  Redirects: {stats.redirected}")
        print(f"  Passthroughs: {stats.passthru}")
        print(f"  Entries per feed:")
        for feed_name, count in sorted(stats.entries_per_feed.items()):
            print(f"    {feed_name}: {count}")
        sys.exit(0)

    # Generate output
    if args.format == 'bind':
        output = generate_bind_zone_file(zone, action, args.redirect_ip)
    elif args.format == 'unbound':
        output = generate_unbound_config(zone, action, args.redirect_ip)
    else:  # json
        output = generate_json_output(zone, action)

    # Write output
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            if args.verbose:
                print(f"Wrote output to: {args.output}", file=sys.stderr)
        except Exception as e:
            print(f"Error writing output: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(output)


if __name__ == '__main__':
    main()
