#!/usr/bin/env python3
"""
Unit tests for rpz_policy_builder.py
Comprehensive test suite for RPZ policy generation, feed parsing, and validation.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from rpz_policy_builder import (
    FeedEntry,
    FeedSource,
    FeedFormat,
    PolicyAction,
    RPZTriggerType,
    RPZPolicy,
    RPZZone,
    ZoneStats,
    RPZPolicyBuilder,
    parse_abuse_ch_domains,
    parse_abuse_ch_urlhaus,
    parse_phishtank_csv,
    parse_hosts_file,
    parse_plain_domains,
    generate_bind_zone_file,
    generate_unbound_config,
    generate_json_output,
    validate_zone,
    compute_statistics,
    increment_serial,
)


class TestFeedEntry(unittest.TestCase):
    """Test FeedEntry data structure."""

    def test_domain_normalization(self):
        """Domains should be normalized to lowercase."""
        entry = FeedEntry(
            domain="EXAMPLE.COM",
            source_feed="test",
            feed_format=FeedFormat.PLAIN_DOMAINS
        )
        self.assertEqual(entry.domain, "example.com")

    def test_domain_strip_whitespace(self):
        """Domains should have whitespace stripped."""
        entry = FeedEntry(
            domain="  example.com  ",
            source_feed="test",
            feed_format=FeedFormat.PLAIN_DOMAINS
        )
        self.assertEqual(entry.domain, "example.com")

    def test_hash_for_deduplication(self):
        """Entries with same domain should hash the same."""
        entry1 = FeedEntry(
            domain="example.com",
            source_feed="feed1",
            feed_format=FeedFormat.PLAIN_DOMAINS
        )
        entry2 = FeedEntry(
            domain="example.com",
            source_feed="feed2",
            feed_format=FeedFormat.HOSTS_FILE
        )
        self.assertEqual(hash(entry1), hash(entry2))

    def test_equality_for_deduplication(self):
        """Entries with same domain should be equal."""
        entry1 = FeedEntry(
            domain="example.com",
            source_feed="feed1",
            feed_format=FeedFormat.PLAIN_DOMAINS
        )
        entry2 = FeedEntry(
            domain="example.com",
            source_feed="feed2",
            feed_format=FeedFormat.HOSTS_FILE
        )
        self.assertEqual(entry1, entry2)


class TestFeedParsers(unittest.TestCase):
    """Test feed parsing functions."""

    def setUp(self):
        """Create temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_parse_plain_domains(self):
        """Parse plain domain list format."""
        feed_file = Path(self.temp_dir) / "domains.txt"
        with open(feed_file, 'w') as f:
            f.write("# Comment\n")
            f.write("example.com\n")
            f.write("EVIL.ORG\n")
            f.write("\n")
            f.write("badsite.net\n")

        entries = parse_plain_domains(feed_file)

        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0].domain, "example.com")
        self.assertEqual(entries[1].domain, "evil.org")
        self.assertEqual(entries[2].domain, "badsite.net")

    def test_parse_hosts_file(self):
        """Parse hosts file format (Hagezi, StevenBlack)."""
        feed_file = Path(self.temp_dir) / "hosts.txt"
        with open(feed_file, 'w') as f:
            f.write("# Hosts format\n")
            f.write("0.0.0.0 example.com\n")
            f.write("127.0.0.1 evil.org\n")
            f.write("0.0.0.0 malware.net\n")

        entries = parse_hosts_file(feed_file)

        self.assertEqual(len(entries), 3)
        domains = {e.domain for e in entries}
        self.assertIn("example.com", domains)
        self.assertIn("evil.org", domains)
        self.assertIn("malware.net", domains)

    def test_parse_phishtank_csv(self):
        """Parse PhishTank CSV format."""
        feed_file = Path(self.temp_dir) / "phishtank.csv"
        with open(feed_file, 'w') as f:
            f.write("Domain,First Seen\n")
            f.write("phishing1.com,2024-01-01\n")
            f.write("phishing2.net,2024-01-02\n")

        entries = parse_phishtank_csv(feed_file)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].domain, "phishing1.com")
        self.assertEqual(entries[1].domain, "phishing2.net")

    def test_parse_abuse_ch_urlhaus(self):
        """Parse abuse.ch URLhaus CSV format."""
        feed_file = Path(self.temp_dir) / "urlhaus.csv"
        with open(feed_file, 'w') as f:
            f.write("domain,url,date_added\n")
            f.write("badsite.com,http://badsite.com/malware,2024-01-01\n")
            f.write("evilhost.org,http://evilhost.org/phish,2024-01-02\n")

        entries = parse_abuse_ch_urlhaus(feed_file)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].domain, "badsite.com")
        self.assertEqual(entries[1].domain, "evilhost.org")

    def test_parse_abuse_ch_domains(self):
        """Parse abuse.ch domain blocklist format."""
        feed_file = Path(self.temp_dir) / "abuse_ch.txt"
        with open(feed_file, 'w') as f:
            f.write("# abuse.ch domains\n")
            f.write("badactor.com\n")
            f.write("malicious.org\n")

        entries = parse_abuse_ch_domains(feed_file)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].domain, "badactor.com")
        self.assertEqual(entries[1].domain, "malicious.org")

    def test_parse_empty_file(self):
        """Parsing empty file should return empty list."""
        feed_file = Path(self.temp_dir) / "empty.txt"
        feed_file.write_text("")

        entries = parse_plain_domains(feed_file)
        self.assertEqual(len(entries), 0)

    def test_parse_nonexistent_file(self):
        """Parsing nonexistent file should handle gracefully."""
        feed_file = Path(self.temp_dir) / "nonexistent.txt"
        entries = parse_plain_domains(feed_file)
        self.assertEqual(len(entries), 0)


class TestRPZZone(unittest.TestCase):
    """Test RPZZone data structure."""

    def test_zone_creation(self):
        """Create basic RPZ zone."""
        zone = RPZZone(zone_name="rpz.local")
        self.assertEqual(zone.zone_name, "rpz.local")
        self.assertEqual(len(zone.policies), 0)

    def test_add_policy(self):
        """Add policy to zone."""
        zone = RPZZone(zone_name="rpz.local")
        policy = RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        )
        zone.add_policy("example.com", policy)

        self.assertEqual(len(zone.policies), 1)
        self.assertIn("example.com", zone.policies)

    def test_remove_policy(self):
        """Remove policy from zone."""
        zone = RPZZone(zone_name="rpz.local")
        policy = RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        )
        zone.add_policy("example.com", policy)
        zone.remove_policy("example.com")

        self.assertEqual(len(zone.policies), 0)

    def test_whitelist_prevents_policy(self):
        """Whitelisted domains should not accept policies."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_whitelist("example.com")

        policy = RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        )
        zone.add_policy("example.com", policy)

        self.assertEqual(len(zone.policies), 0)

    def test_whitelist_removes_existing_policy(self):
        """Whitelisting should remove existing policy."""
        zone = RPZZone(zone_name="rpz.local")
        policy = RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        )
        zone.add_policy("example.com", policy)
        self.assertEqual(len(zone.policies), 1)

        zone.add_whitelist("example.com")

        self.assertEqual(len(zone.policies), 0)
        self.assertIn("example.com", zone.whitelist)


class TestZoneGeneration(unittest.TestCase):
    """Test RPZ zone file generation."""

    def test_generate_bind_zone_nxdomain(self):
        """Generate BIND zone with NXDOMAIN action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("example.com", RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        ))
        zone.add_policy("evil.org", RPZPolicy(
            domain="evil.org",
            action=PolicyAction.NXDOMAIN
        ))

        zone_file = generate_bind_zone_file(zone, PolicyAction.NXDOMAIN)

        # Verify structure
        self.assertIn("$ORIGIN rpz.local.", zone_file)
        self.assertIn("SOA", zone_file)
        self.assertIn("NS", zone_file)
        self.assertIn("example.com.", zone_file)
        self.assertIn("evil.org.", zone_file)
        self.assertIn("CNAME  .", zone_file)  # NXDOMAIN syntax

    def test_generate_bind_zone_nodata(self):
        """Generate BIND zone with NODATA action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("example.com", RPZPolicy(
            domain="example.com",
            action=PolicyAction.NODATA
        ))

        zone_file = generate_bind_zone_file(zone, PolicyAction.NODATA)

        self.assertIn("example.com.", zone_file)
        self.assertIn("CNAME  *.", zone_file)  # NODATA syntax

    def test_generate_bind_zone_passthru(self):
        """Generate BIND zone with PASSTHRU action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("safe.com", RPZPolicy(
            domain="safe.com",
            action=PolicyAction.PASSTHRU
        ))

        zone_file = generate_bind_zone_file(zone, PolicyAction.PASSTHRU)

        self.assertIn("safe.com.", zone_file)
        self.assertIn("rpz-passthru", zone_file)

    def test_generate_bind_zone_redirect(self):
        """Generate BIND zone with REDIRECT action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("malware.net", RPZPolicy(
            domain="malware.net",
            action=PolicyAction.REDIRECT,
            redirect_ip="192.0.2.1"
        ))

        zone_file = generate_bind_zone_file(zone, PolicyAction.REDIRECT, "192.0.2.1")

        self.assertIn("malware.net.", zone_file)
        self.assertIn("rpz-ip", zone_file)

    def test_generate_unbound_config_nxdomain(self):
        """Generate Unbound config with NXDOMAIN action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("example.com", RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        ))

        config = generate_unbound_config(zone, PolicyAction.NXDOMAIN)

        self.assertIn('local-zone: "example.com" always_nxdomain', config)

    def test_generate_unbound_config_redirect(self):
        """Generate Unbound config with REDIRECT action."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("malware.net", RPZPolicy(
            domain="malware.net",
            action=PolicyAction.REDIRECT,
            redirect_ip="192.0.2.1"
        ))

        config = generate_unbound_config(zone, PolicyAction.REDIRECT, "192.0.2.1")

        self.assertIn('local-zone: "malware.net" redirect', config)
        self.assertIn('local-data: "malware.net 3600 IN A 192.0.2.1"', config)

    def test_generate_json_output(self):
        """Generate JSON output."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("example.com", RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN,
            source_feeds={"feed1", "feed2"}
        ))

        json_output = generate_json_output(zone, PolicyAction.NXDOMAIN)
        data = json.loads(json_output)

        self.assertEqual(data["zone_name"], "rpz.local")
        self.assertEqual(data["action"], "nxdomain")
        self.assertEqual(data["statistics"]["total_domains"], 1)
        self.assertIn("example.com", data["policies"])


class TestZoneValidation(unittest.TestCase):
    """Test RPZ zone validation."""

    def test_valid_zone(self):
        """Valid zone should pass validation."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("example.com", RPZPolicy(
            domain="example.com",
            action=PolicyAction.NXDOMAIN
        ))

        valid, errors = validate_zone(zone)

        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

    def test_invalid_empty_zone_name(self):
        """Empty zone name should fail validation."""
        zone = RPZZone(zone_name="")

        valid, errors = validate_zone(zone)

        self.assertFalse(valid)
        self.assertTrue(any("zone name" in e.lower() for e in errors))

    def test_invalid_serial_format(self):
        """Invalid serial format should fail validation."""
        zone = RPZZone(zone_name="rpz.local")
        zone.serial = 123  # Too short

        valid, errors = validate_zone(zone)

        self.assertFalse(valid)
        self.assertTrue(any("serial" in e.lower() for e in errors))

    def test_invalid_domain_format(self):
        """Invalid domain format should fail validation."""
        zone = RPZZone(zone_name="rpz.local")
        zone.policies["..invalid"] = RPZPolicy(
            domain="..invalid",
            action=PolicyAction.NXDOMAIN
        )

        valid, errors = validate_zone(zone)

        self.assertFalse(valid)


class TestStatistics(unittest.TestCase):
    """Test statistics computation."""

    def test_compute_statistics(self):
        """Compute zone statistics."""
        zone = RPZZone(zone_name="rpz.local")
        zone.add_policy("ex1.com", RPZPolicy(
            domain="ex1.com",
            action=PolicyAction.NXDOMAIN
        ))
        zone.add_policy("ex2.com", RPZPolicy(
            domain="ex2.com",
            action=PolicyAction.NODATA
        ))
        zone.add_policy("ex3.com", RPZPolicy(
            domain="ex3.com",
            action=PolicyAction.REDIRECT
        ))

        all_entries = {
            "ex1.com": FeedEntry(
                domain="ex1.com",
                source_feed="feed1",
                feed_format=FeedFormat.PLAIN_DOMAINS,
                metadata={"feeds": {"feed1"}}
            ),
            "ex2.com": FeedEntry(
                domain="ex2.com",
                source_feed="feed2",
                feed_format=FeedFormat.PLAIN_DOMAINS,
                metadata={"feeds": {"feed2"}}
            ),
            "ex3.com": FeedEntry(
                domain="ex3.com",
                source_feed="feed1",
                feed_format=FeedFormat.PLAIN_DOMAINS,
                metadata={"feeds": {"feed1"}}
            ),
        }

        stats = compute_statistics(zone, all_entries, ["feed1", "feed2"])

        self.assertEqual(stats.total_domains, 3)
        self.assertEqual(stats.blocked_nxdomain, 1)
        self.assertEqual(stats.blocked_nodata, 1)
        self.assertEqual(stats.redirected, 1)


class TestSerialNumberManagement(unittest.TestCase):
    """Test serial number increment logic."""

    def test_increment_serial_basic(self):
        """Increment serial number."""
        serial = 2024032700
        new_serial = increment_serial(serial)
        self.assertEqual(new_serial, 2024032701)

    def test_increment_serial_multiple(self):
        """Increment serial multiple times."""
        serial = 2024032700
        for _ in range(5):
            serial = increment_serial(serial)
        self.assertEqual(serial, 2024032705)

    def test_increment_serial_short(self):
        """Handle short serial numbers."""
        serial = 100
        new_serial = increment_serial(serial)
        self.assertEqual(new_serial, 101)


class TestRPZPolicyBuilder(unittest.TestCase):
    """Test RPZPolicyBuilder orchestrator."""

    def setUp(self):
        """Create temporary directory for test feeds."""
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        import shutil
        shutil.rmtree(self.temp_dir)

    def test_builder_initialization(self):
        """Initialize builder."""
        builder = RPZPolicyBuilder(zone_name="test.rpz")
        self.assertEqual(builder.zone_name, "test.rpz")
        self.assertEqual(len(builder.feeds), 0)

    def test_add_feed(self):
        """Add feed to builder."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\n")

        feed_source = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed_source)

        self.assertEqual(len(builder.feeds), 1)

    def test_build_policy_single_feed(self):
        """Build policy from single feed."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\nevil.org\n")

        feed_source = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed_source)

        zone = builder.build_policy()

        self.assertEqual(len(zone.policies), 2)
        self.assertIn("example.com", zone.policies)
        self.assertIn("evil.org", zone.policies)

    def test_build_policy_multiple_feeds(self):
        """Build policy from multiple feeds."""
        builder = RPZPolicyBuilder()

        # Feed 1
        feed1_path = Path(self.temp_dir) / "feed1.txt"
        feed1_path.write_text("example.com\n")

        # Feed 2
        feed2_path = Path(self.temp_dir) / "feed2.txt"
        feed2_path.write_text("evil.org\n")

        feed1 = FeedSource(
            name="feed1",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed1_path
        )
        feed2 = FeedSource(
            name="feed2",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed2_path
        )

        builder.add_feed(feed1)
        builder.add_feed(feed2)

        zone = builder.build_policy()

        self.assertEqual(len(zone.policies), 2)

    def test_build_policy_with_whitelist(self):
        """Build policy respecting whitelist."""
        builder = RPZPolicyBuilder()

        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\nevil.org\nsafe.com\n")

        whitelist_path = Path(self.temp_dir) / "whitelist.txt"
        whitelist_path.write_text("safe.com\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )

        builder.add_feed(feed)
        builder.add_whitelist(whitelist_path)

        zone = builder.build_policy()

        self.assertEqual(len(zone.policies), 2)
        self.assertIn("example.com", zone.policies)
        self.assertIn("evil.org", zone.policies)
        self.assertNotIn("safe.com", zone.policies)
        self.assertIn("safe.com", zone.whitelist)

    def test_deduplication_across_feeds(self):
        """Duplicate domains across feeds should be deduplicated."""
        builder = RPZPolicyBuilder()

        # Feed 1
        feed1_path = Path(self.temp_dir) / "feed1.txt"
        feed1_path.write_text("example.com\n")

        # Feed 2 with same domain
        feed2_path = Path(self.temp_dir) / "feed2.txt"
        feed2_path.write_text("example.com\nevil.org\n")

        feed1 = FeedSource(
            name="feed1",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed1_path
        )
        feed2 = FeedSource(
            name="feed2",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed2_path
        )

        builder.add_feed(feed1)
        builder.add_feed(feed2)

        zone = builder.build_policy()

        # Should have 2 unique domains, not 3
        self.assertEqual(len(zone.policies), 2)

    def test_validate_zone(self):
        """Validate zone through builder."""
        builder = RPZPolicyBuilder(zone_name="rpz.local")
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed)
        builder.build_policy()

        valid, errors = builder.validate()

        self.assertTrue(valid)

    def test_get_statistics(self):
        """Get statistics from builder."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\nevil.org\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed)
        builder.build_policy()

        stats = builder.get_statistics()

        self.assertEqual(stats.total_domains, 2)

    def test_export_bind(self):
        """Export zone as BIND format."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed)
        builder.build_policy()

        bind_zone = builder.export_bind()

        self.assertIn("$ORIGIN", bind_zone)
        self.assertIn("SOA", bind_zone)
        self.assertIn("example.com.", bind_zone)

    def test_export_unbound(self):
        """Export zone as Unbound format."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed)
        builder.build_policy()

        unbound_config = builder.export_unbound()

        self.assertIn("local-zone", unbound_config)
        self.assertIn("example.com", unbound_config)

    def test_export_json(self):
        """Export zone as JSON format."""
        builder = RPZPolicyBuilder()
        feed_path = Path(self.temp_dir) / "test.txt"
        feed_path.write_text("example.com\n")

        feed = FeedSource(
            name="test",
            feed_format=FeedFormat.PLAIN_DOMAINS,
            file_path=feed_path
        )
        builder.add_feed(feed)
        builder.build_policy()

        json_output = builder.export_json()

        data = json.loads(json_output)
        self.assertIn("policies", data)
        self.assertIn("example.com", data["policies"])


if __name__ == '__main__':
    unittest.main()
