#!/usr/bin/env python3
"""
Unit tests for zone_transfer_auditor.py
Validates DNS wire protocol encoding/decoding, zone analysis, risk scoring,
and report formatting using simulated zone data.
"""

import json
import struct
import sys
import unittest

from zone_transfer_auditor import (
    _encode_name,
    _decode_name,
    _build_axfr_query,
    _build_ns_query,
    _parse_response_records,
    ZoneAnalyzer,
    compute_risk_score,
    format_text_report,
    format_json_report,
    format_csv_records,
    AuditReport,
    Finding,
    run_audit,
)


# ---- Simulated zone data (modeled on zonetransfer.me) ----
SIMULATED_ZONE = [
    {"name": "zonetransfer.me", "type": "SOA", "rdtype": 6, "ttl": 7200,
     "rdata": "nsztm1.digi.ninja robin.digi.ninja 2019100801 172800 900 1209600 3600"},
    {"name": "zonetransfer.me", "type": "NS", "rdtype": 2, "ttl": 300,
     "rdata": "nsztm1.digi.ninja"},
    {"name": "zonetransfer.me", "type": "NS", "rdtype": 2, "ttl": 300,
     "rdata": "nsztm2.digi.ninja"},
    {"name": "zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "5.196.105.14"},
    {"name": "zonetransfer.me", "type": "MX", "rdtype": 15, "ttl": 300,
     "rdata": "0 ASPMX.L.GOOGLE.COM"},
    {"name": "zonetransfer.me", "type": "MX", "rdtype": 15, "ttl": 300,
     "rdata": "10 ALT1.ASPMX.L.GOOGLE.COM"},
    {"name": "zonetransfer.me", "type": "TXT", "rdtype": 16, "ttl": 300,
     "rdata": "v=spf1 ip4:5.196.105.14 include:_spf.google.com ~all"},
    {"name": "zonetransfer.me", "type": "TXT", "rdtype": 16, "ttl": 300,
     "rdata": "google-site-verification=tyP28J7JAUHA9fw2sHXMgcCC0I6XBmmoVi04VlMewxA"},
    {"name": "staging.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "192.168.1.100"},
    {"name": "dev.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "10.0.0.50"},
    {"name": "admin.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "5.196.105.15"},
    {"name": "vpn.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "172.16.0.1"},
    {"name": "jenkins.zonetransfer.me", "type": "CNAME", "rdtype": 5, "ttl": 300,
     "rdata": "ci.internal.zonetransfer.me"},
    {"name": "mail.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "5.196.105.14"},
    {"name": "_sip._tcp.zonetransfer.me", "type": "SRV", "rdtype": 33, "ttl": 300,
     "rdata": "0 0 5060 sip.zonetransfer.me"},
    {"name": "_ldap._tcp.zonetransfer.me", "type": "SRV", "rdtype": 33, "ttl": 300,
     "rdata": "0 0 389 ldap.zonetransfer.me"},
    {"name": "zonetransfer.me", "type": "AAAA", "rdtype": 28, "ttl": 300,
     "rdata": "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
    {"name": "*.zonetransfer.me", "type": "A", "rdtype": 1, "ttl": 300,
     "rdata": "5.196.105.14"},
    {"name": "secret-api.zonetransfer.me", "type": "TXT", "rdtype": 16, "ttl": 60,
     "rdata": "api-key=sk-1234567890abcdef"},
    {"name": "zonetransfer.me", "type": "SOA", "rdtype": 6, "ttl": 7200,
     "rdata": "nsztm1.digi.ninja robin.digi.ninja 2019100801 172800 900 1209600 3600"},
]


class TestDNSWireProtocol(unittest.TestCase):
    """Test DNS wire format encoding/decoding."""

    def test_encode_name_simple(self):
        encoded = _encode_name("example.com")
        # \x07example\x03com\x00
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_encode_name_subdomain(self):
        encoded = _encode_name("sub.example.com")
        self.assertEqual(encoded, b"\x03sub\x07example\x03com\x00")

    def test_encode_name_trailing_dot(self):
        # Should handle trailing dot gracefully
        encoded = _encode_name("example.com.")
        self.assertEqual(encoded, b"\x07example\x03com\x00")

    def test_decode_name_roundtrip(self):
        original = "test.example.com"
        encoded = _encode_name(original)
        decoded, _ = _decode_name(encoded, 0)
        self.assertEqual(decoded, original)

    def test_decode_name_compression(self):
        # Build a message with a compressed name
        # First name at offset 0: example.com
        msg = _encode_name("example.com")
        # Second name: pointer to offset 0
        msg += b"\xc0\x00"
        name, offset = _decode_name(msg, len(msg) - 2)
        self.assertEqual(name, "example.com")

    def test_build_axfr_query(self):
        query = _build_axfr_query("example.com", txn_id=0x1234)
        # Check header
        txn_id = struct.unpack("!H", query[:2])[0]
        self.assertEqual(txn_id, 0x1234)
        # Check QDCOUNT = 1
        qdcount = struct.unpack("!H", query[4:6])[0]
        self.assertEqual(qdcount, 1)
        # Check QTYPE = 252 (AXFR) at end of question
        qtype = struct.unpack("!H", query[-4:-2])[0]
        self.assertEqual(qtype, 252)

    def test_build_ns_query(self):
        query = _build_ns_query("example.com", txn_id=0xABCD)
        txn_id = struct.unpack("!H", query[:2])[0]
        self.assertEqual(txn_id, 0xABCD)
        # QTYPE = 2 (NS)
        qtype = struct.unpack("!H", query[-4:-2])[0]
        self.assertEqual(qtype, 2)


class TestZoneAnalyzer(unittest.TestCase):
    """Test zone data analysis modules."""

    def setUp(self):
        self.analyzer = ZoneAnalyzer("zonetransfer.me", SIMULATED_ZONE)

    def test_record_type_counts(self):
        counts = self.analyzer.get_record_type_counts()
        self.assertEqual(counts["A"], 7)  # Including wildcard
        self.assertEqual(counts["SOA"], 2)
        self.assertEqual(counts["NS"], 2)
        self.assertEqual(counts["MX"], 2)
        self.assertEqual(counts["TXT"], 3)
        self.assertEqual(counts["SRV"], 2)
        self.assertEqual(counts["AAAA"], 1)
        self.assertEqual(counts["CNAME"], 1)

    def test_unique_hostnames(self):
        hostnames = self.analyzer.get_unique_hostnames()
        self.assertIn("staging.zonetransfer.me", hostnames)
        self.assertIn("dev.zonetransfer.me", hostnames)
        self.assertIn("admin.zonetransfer.me", hostnames)
        self.assertIn("nsztm1.digi.ninja", hostnames)  # From NS rdata

    def test_unique_ips(self):
        ips = self.analyzer.get_unique_ips()
        self.assertIn("5.196.105.14", ips)
        self.assertIn("192.168.1.100", ips)
        self.assertIn("10.0.0.50", ips)
        self.assertIn("172.16.0.1", ips)

    def test_findings_include_private_ips(self):
        findings = self.analyzer.analyze_all()
        private_ip_findings = [
            f for f in findings
            if f.category == "Internal Exposure" and "RFC 1918" in f.title
        ]
        # Should find 192.168.1.100, 10.0.0.50, and 172.16.0.1
        leaked_ips = [f.title for f in private_ip_findings]
        self.assertTrue(any("192.168.1.100" in t for t in leaked_ips))
        self.assertTrue(any("10.0.0.50" in t for t in leaked_ips))
        self.assertTrue(any("172.16.0.1" in t for t in leaked_ips))

    def test_findings_include_internal_hostnames(self):
        findings = self.analyzer.analyze_all()
        internal_findings = [
            f for f in findings
            if f.category == "Internal Exposure" and "hostname" in f.title.lower()
        ]
        names = " ".join(f.title for f in internal_findings)
        self.assertIn("staging", names)
        self.assertIn("dev", names)
        self.assertIn("admin", names)
        self.assertIn("vpn", names)
        self.assertIn("jenkins", names)

    def test_findings_include_spf(self):
        findings = self.analyzer.analyze_all()
        spf_findings = [f for f in findings if "SPF" in f.title]
        self.assertTrue(len(spf_findings) > 0)

    def test_findings_include_api_key(self):
        findings = self.analyzer.analyze_all()
        api_findings = [f for f in findings if "API" in f.title or "key" in f.title.lower()]
        self.assertTrue(len(api_findings) > 0)
        # API key findings should be HIGH severity
        self.assertTrue(any(f.severity == "HIGH" for f in api_findings))

    def test_findings_include_srv_services(self):
        findings = self.analyzer.analyze_all()
        srv_findings = [f for f in findings if f.category == "Service Enumeration"]
        self.assertTrue(len(srv_findings) > 0)
        self.assertIn("sip", srv_findings[0].detail.lower())

    def test_findings_include_mx(self):
        findings = self.analyzer.analyze_all()
        mx_findings = [f for f in findings if f.category == "Mail Infrastructure"]
        self.assertTrue(len(mx_findings) > 0)

    def test_findings_include_wildcard(self):
        findings = self.analyzer.analyze_all()
        wildcard_findings = [f for f in findings if "wildcard" in f.title.lower()]
        self.assertTrue(len(wildcard_findings) > 0)

    def test_findings_include_no_caa(self):
        findings = self.analyzer.analyze_all()
        caa_findings = [f for f in findings if "CAA" in f.title]
        self.assertTrue(len(caa_findings) > 0)

    def test_mitre_mapping(self):
        findings = self.analyzer.analyze_all()
        mitre_techniques = set(f.mitre_technique for f in findings if f.mitre_technique)
        self.assertIn("T1590.002", mitre_techniques)
        self.assertIn("T1018", mitre_techniques)
        self.assertIn("T1526", mitre_techniques)


class TestRiskScoring(unittest.TestCase):
    """Test risk score computation."""

    def test_no_transfers_no_findings(self):
        score, rating = compute_risk_score([], [{"transfer_allowed": False}])
        self.assertEqual(score, 0)
        self.assertEqual(rating, "PASS")

    def test_transfer_allowed_base_penalty(self):
        score, rating = compute_risk_score(
            [],
            [{"transfer_allowed": True}]
        )
        self.assertGreaterEqual(score, 30)

    def test_all_servers_vulnerable(self):
        score, rating = compute_risk_score(
            [],
            [{"transfer_allowed": True}, {"transfer_allowed": True}]
        )
        self.assertGreaterEqual(score, 45)  # 30 base + 15 all-vulnerable

    def test_critical_findings_push_score_high(self):
        findings = [
            Finding("CRITICAL", "Test", "Test critical", "detail"),
            Finding("HIGH", "Test", "Test high", "detail"),
        ]
        score, rating = compute_risk_score(
            findings,
            [{"transfer_allowed": True}]
        )
        self.assertGreaterEqual(score, 70)
        self.assertEqual(rating, "CRITICAL")

    def test_score_capped_at_100(self):
        findings = [Finding("CRITICAL", "T", "T", "d") for _ in range(10)]
        score, _ = compute_risk_score(findings, [{"transfer_allowed": True}])
        self.assertLessEqual(score, 100)


class TestReportFormatting(unittest.TestCase):
    """Test report output formatting."""

    def _make_report(self):
        analyzer = ZoneAnalyzer("zonetransfer.me", SIMULATED_ZONE)
        findings = analyzer.analyze_all()
        score, rating = compute_risk_score(
            findings,
            [{"transfer_allowed": True, "record_count": len(SIMULATED_ZONE)}]
        )
        return AuditReport(
            domain="zonetransfer.me",
            timestamp="2026-03-25T12:00:00Z",
            servers_tested=[{"name": "nsztm1.digi.ninja", "ip": "81.4.108.41"}],
            transfer_results=[{
                "server_name": "nsztm1.digi.ninja",
                "server_ip": "81.4.108.41",
                "transfer_allowed": True,
                "record_count": len(SIMULATED_ZONE),
                "elapsed_ms": 245.3,
                "error": None,
                "records": SIMULATED_ZONE,
            }],
            findings=findings,
            record_type_distribution=analyzer.get_record_type_counts(),
            unique_hostnames=analyzer.get_unique_hostnames(),
            unique_ips=analyzer.get_unique_ips(),
            risk_score=score,
            risk_rating=rating,
        )

    def test_text_report_contains_key_sections(self):
        report = self._make_report()
        text = format_text_report(report)
        self.assertIn("ZONE TRANSFER AUDIT REPORT", text)
        self.assertIn("SERVER RESULTS", text)
        self.assertIn("ZONE STATISTICS", text)
        self.assertIn("FINDINGS", text)
        self.assertIn("MITRE ATT&CK MAPPING", text)
        self.assertIn("REMEDIATION", text)
        self.assertIn("zonetransfer.me", text)
        self.assertIn("T1590.002", text)

    def test_text_report_shows_allowed(self):
        report = self._make_report()
        text = format_text_report(report)
        self.assertIn("ALLOWED", text)

    def test_json_report_valid(self):
        report = self._make_report()
        json_str = format_json_report(report)
        data = json.loads(json_str)
        self.assertEqual(data["domain"], "zonetransfer.me")
        self.assertIn("findings", data)
        self.assertIn("risk_score", data)
        self.assertGreater(data["risk_score"], 0)

    def test_csv_export(self):
        csv_str = format_csv_records(SIMULATED_ZONE)
        lines = [l.rstrip("\r") for l in csv_str.strip().split("\n")]
        self.assertEqual(lines[0], "name,type,ttl,rdata")
        self.assertEqual(len(lines), len(SIMULATED_ZONE) + 1)  # +1 for header


class TestDeniedTransfer(unittest.TestCase):
    """Test behavior when all transfers are denied."""

    def test_denied_report(self):
        report = AuditReport(
            domain="secure-example.com",
            timestamp="2026-03-25T12:00:00Z",
            servers_tested=[{"name": "ns1.secure.com", "ip": "1.2.3.4"}],
            transfer_results=[{
                "server_name": "ns1.secure.com",
                "server_ip": "1.2.3.4",
                "transfer_allowed": False,
                "record_count": 0,
                "elapsed_ms": 50.0,
                "error": "Transfer refused (RCODE=REFUSED)",
                "records": [],
            }],
            findings=[Finding(
                "INFO", "Zone Transfer",
                "All tested servers denied zone transfers",
                "No zone data was obtained",
            )],
            risk_score=0,
            risk_rating="PASS",
        )
        text = format_text_report(report)
        self.assertIn("DENIED", text)
        self.assertIn("PASS", text)
        self.assertNotIn("REMEDIATION", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
