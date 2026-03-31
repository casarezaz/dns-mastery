#!/usr/bin/env python3
"""
Unit tests for encrypted_dns_analyzer.py
Validates protocol detection, bypass detection, and reporting modules.
"""

import json
import tempfile
import unittest
from pathlib import Path

from encrypted_dns_analyzer import (
    ProtocolType,
    BypassSeverity,
    ConnectionRecord,
    ProtocolDetection,
    BypassAlert,
    EncryptionReport,
    detect_protocol,
    detect_bypass,
    analyze_connections,
    generate_protocol_comparison_matrix,
    format_text_report,
    format_json_report,
    format_csv_report,
    load_connections_from_json,
    load_connections_from_csv,
    load_connections,
    _is_internal_ip,
    _is_doh_provider,
)


class TestInternalIPDetection(unittest.TestCase):
    """Test private/internal IP detection."""

    def test_rfc1918_ips(self):
        """Test RFC 1918 private IP ranges."""
        # Class A
        self.assertTrue(_is_internal_ip("10.0.0.1"))
        self.assertTrue(_is_internal_ip("10.255.255.255"))

        # Class B
        self.assertTrue(_is_internal_ip("172.16.0.0"))
        self.assertTrue(_is_internal_ip("172.31.255.255"))

        # Class C
        self.assertTrue(_is_internal_ip("192.168.0.1"))
        self.assertTrue(_is_internal_ip("192.168.255.255"))

    def test_public_ips(self):
        """Test public IP addresses."""
        self.assertFalse(_is_internal_ip("8.8.8.8"))
        self.assertFalse(_is_internal_ip("1.1.1.1"))
        self.assertFalse(_is_internal_ip("9.9.9.9"))

    def test_invalid_ip(self):
        """Test invalid IP addresses."""
        self.assertFalse(_is_internal_ip("invalid"))
        self.assertFalse(_is_internal_ip(""))


class TestDoHProviderDetection(unittest.TestCase):
    """Test DoH provider identification."""

    def test_google_dns_domain(self):
        """Test Google DNS domain recognition."""
        is_provider, name = _is_doh_provider("dns.google.com", "1.2.3.4")
        self.assertTrue(is_provider)
        self.assertEqual(name, "Google DNS")

    def test_google_dns_ip(self):
        """Test Google DNS IP recognition."""
        is_provider, name = _is_doh_provider("example.com", "8.8.8.8")
        self.assertTrue(is_provider)
        self.assertEqual(name, "Google DNS")

    def test_cloudflare_dns(self):
        """Test Cloudflare DNS recognition."""
        is_provider, name = _is_doh_provider("one.one.one.one", "1.1.1.1")
        self.assertTrue(is_provider)
        self.assertEqual(name, "Cloudflare DNS")

    def test_quad9_dns(self):
        """Test Quad9 DNS recognition."""
        is_provider, name = _is_doh_provider("dns.quad9.net", "9.9.9.9")
        self.assertTrue(is_provider)
        self.assertEqual(name, "Quad9 DNS")

    def test_unknown_provider(self):
        """Test unknown provider."""
        is_provider, name = _is_doh_provider("example.com", "2.3.4.5")
        self.assertFalse(is_provider)
        self.assertEqual(name, "")


class TestProtocolDetection(unittest.TestCase):
    """Test DNS protocol detection from connection metadata."""

    def test_detect_plaintext_dns_udp(self):
        """Detect plaintext DNS over UDP port 53."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="10.0.0.1",
            server_port=53,
            protocol="UDP",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.PLAINTEXT)
        self.assertGreaterEqual(det.confidence, 0.95)

    def test_detect_plaintext_dns_tcp(self):
        """Detect plaintext DNS over TCP port 53."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="10.0.0.1",
            server_port=53,
            protocol="TCP",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.PLAINTEXT)

    def test_detect_dot_tls(self):
        """Detect DoT (DNS over TLS) on port 853."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=853,
            protocol="TLS",
            tls_version="TLS 1.3",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.DOT)
        self.assertGreaterEqual(det.confidence, 0.95)

    def test_detect_doq_quic(self):
        """Detect DoQ (DNS over QUIC) on port 853."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=853,
            protocol="QUIC",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.DOQ)
        self.assertGreaterEqual(det.confidence, 0.95)

    def test_detect_doh_with_dns_query_path(self):
        """Detect DoH with /dns-query path."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=443,
            protocol="HTTPS",
            domain="dns.google.com",
            path="/dns-query?dns=...",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.DOH)
        self.assertGreaterEqual(det.confidence, 0.99)

    def test_detect_doh_known_provider(self):
        """Detect DoH by known provider IP."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="1.1.1.1",
            server_port=443,
            protocol="HTTPS",
            domain="one.one.one.one",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.DOH)
        self.assertTrue(det.is_doh_provider)
        self.assertEqual(det.provider_name, "Cloudflare DNS")

    def test_detect_unknown_protocol(self):
        """Detect unknown protocol."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="10.0.0.1",
            server_port=9999,
            protocol="CUSTOM",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.UNKNOWN)


class TestBypassDetection(unittest.TestCase):
    """Test DoH bypass detection."""

    def test_detect_doh_bypass(self):
        """Detect client using external DoH provider."""
        # Create detections showing bypass
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=443,
            protocol="HTTPS",
            domain="dns.google.com",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.DOH)
        self.assertTrue(det.is_doh_provider)

        # Detect bypass
        detections = [det]
        alerts = detect_bypass(detections)
        self.assertTrue(len(alerts) > 0)
        self.assertEqual(alerts[0].client_ip, "192.168.1.100")
        self.assertEqual(alerts[0].provider_name, "Google DNS")

    def test_no_bypass_for_internal_resolver(self):
        """Don't flag internal resolver usage as bypass."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="10.0.0.1",
            server_port=443,
            protocol="HTTPS",
            domain="internal-resolver.local",
        )
        det = detect_protocol(conn)
        detections = [det]
        alerts = detect_bypass(detections)
        # Should not generate bypass alert for internal resolver
        self.assertEqual(len(alerts), 0)

    def test_no_bypass_for_plaintext(self):
        """Don't flag plaintext DNS as bypass."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=53,
            protocol="UDP",
        )
        det = detect_protocol(conn)
        detections = [det]
        alerts = detect_bypass(detections)
        self.assertEqual(len(alerts), 0)


class TestAnalysisAndReporting(unittest.TestCase):
    """Test batch analysis and reporting functions."""

    def setUp(self):
        """Create sample connection data."""
        self.connections = [
            ConnectionRecord(
                timestamp="2024-01-01T00:00:00Z",
                client_ip="192.168.1.100",
                server_ip="10.0.0.1",
                server_port=53,
                protocol="UDP",
            ),
            ConnectionRecord(
                timestamp="2024-01-01T00:00:01Z",
                client_ip="192.168.1.100",
                server_ip="8.8.8.8",
                server_port=443,
                protocol="HTTPS",
                domain="dns.google.com",
                path="/dns-query",
            ),
            ConnectionRecord(
                timestamp="2024-01-01T00:00:02Z",
                client_ip="192.168.1.101",
                server_ip="8.8.8.8",
                server_port=853,
                protocol="TLS",
            ),
            ConnectionRecord(
                timestamp="2024-01-01T00:00:03Z",
                client_ip="192.168.1.102",
                server_ip="1.1.1.1",
                server_port=853,
                protocol="QUIC",
            ),
        ]

    def test_analyze_mixed_protocols(self):
        """Analyze mixed protocol connections."""
        detections, report = analyze_connections(self.connections)

        self.assertEqual(report.total_connections, 4)
        self.assertEqual(report.plaintext_count, 1)
        self.assertEqual(report.doh_count, 1)
        self.assertEqual(report.dot_count, 1)
        self.assertEqual(report.doq_count, 1)

    def test_encryption_coverage_calculation(self):
        """Test encryption coverage percentage."""
        detections, report = analyze_connections(self.connections)

        # 3 encrypted + 1 plaintext = 75% coverage
        self.assertAlmostEqual(report.encryption_coverage, 0.75, places=2)
        self.assertAlmostEqual(report.plaintext_percentage, 0.25, places=2)

    def test_protocol_distribution(self):
        """Test protocol distribution dictionary."""
        detections, report = analyze_connections(self.connections)

        self.assertEqual(report.protocol_distribution["plaintext"], 1)
        self.assertEqual(report.protocol_distribution["DoH"], 1)
        self.assertEqual(report.protocol_distribution["DoT"], 1)
        self.assertEqual(report.protocol_distribution["DoQ"], 1)

    def test_per_client_protocol_usage(self):
        """Test per-client protocol tracking."""
        detections, report = analyze_connections(self.connections)

        # Client 100 should have plaintext and DoH
        client_100_protocols = report.clients_per_protocol.get("192.168.1.100", {})
        self.assertIn(ProtocolType.PLAINTEXT, client_100_protocols)
        self.assertIn(ProtocolType.DOH, client_100_protocols)

    def test_top_providers_extraction(self):
        """Test top DoH providers extraction."""
        detections, report = analyze_connections(self.connections)

        # Should extract Google and Cloudflare
        provider_names = [name for name, _ in report.top_providers]
        self.assertIn("Google DNS", provider_names)

    def test_unencrypted_clients_identification(self):
        """Test identification of clients using plaintext DNS."""
        detections, report = analyze_connections(self.connections)

        # Only 192.168.1.100 uses plaintext
        self.assertIn("192.168.1.100", report.unencrypted_clients)


class TestReportFormatting(unittest.TestCase):
    """Test report formatting functions."""

    def setUp(self):
        """Create sample analysis results."""
        self.connections = [
            ConnectionRecord(
                timestamp="2024-01-01T00:00:00Z",
                client_ip="192.168.1.100",
                server_ip="10.0.0.1",
                server_port=53,
                protocol="UDP",
            ),
            ConnectionRecord(
                timestamp="2024-01-01T00:00:01Z",
                client_ip="192.168.1.100",
                server_ip="8.8.8.8",
                server_port=443,
                protocol="HTTPS",
                domain="dns.google.com",
                path="/dns-query",
            ),
        ]
        self.detections, self.report = analyze_connections(self.connections)

    def test_text_report_generation(self):
        """Test human-readable text report."""
        report_text = format_text_report(self.detections, self.report)
        self.assertIn("ENCRYPTED DNS ANALYZER", report_text)
        self.assertIn("ENCRYPTION COVERAGE SUMMARY", report_text)
        self.assertIn("PROTOCOL DISTRIBUTION", report_text)
        self.assertIn("PLAINTEXT", report_text)
        self.assertIn("DoH", report_text)

    def test_text_report_verbose(self):
        """Test verbose text report with per-client details."""
        report_text = format_text_report(self.detections, self.report, verbose=True)
        self.assertIn("PER-CLIENT PROTOCOL USAGE", report_text)

    def test_json_report_generation(self):
        """Test JSON report generation."""
        report_json = format_json_report(self.detections, self.report)
        data = json.loads(report_json)

        self.assertIn("analysis_timestamp", data)
        self.assertIn("summary", data)
        self.assertIn("protocol_counts", data)
        self.assertEqual(data["summary"]["total_connections"], 2)

    def test_csv_report_generation(self):
        """Test CSV report generation."""
        report_csv = format_csv_report(self.detections)

        lines = report_csv.split("\n")
        self.assertGreater(len(lines), 1)  # Header + data
        self.assertIn("client_ip,server_ip", lines[0])


class TestProtocolComparison(unittest.TestCase):
    """Test protocol comparison matrix generation."""

    def test_comparison_matrix_structure(self):
        """Test comparison matrix contains all protocols."""
        matrix = generate_protocol_comparison_matrix()

        self.assertIn("protocols", matrix)
        self.assertIn("feature_comparison", matrix)

        protocols = matrix["protocols"]
        self.assertIn("DoH", protocols)
        self.assertIn("DoT", protocols)
        self.assertIn("DoQ", protocols)
        self.assertIn("Plaintext", protocols)

    def test_doh_details(self):
        """Test DoH protocol details."""
        matrix = generate_protocol_comparison_matrix()
        doh = matrix["protocols"]["DoH"]

        self.assertEqual(doh["port"], 443)
        self.assertEqual(doh["transport"], "HTTPS/TLS")
        self.assertIn("advantages", doh)
        self.assertIn("disadvantages", doh)

    def test_dot_details(self):
        """Test DoT protocol details."""
        matrix = generate_protocol_comparison_matrix()
        dot = matrix["protocols"]["DoT"]

        self.assertEqual(dot["port"], 853)
        self.assertEqual(dot["rfc"], "RFC 7858")

    def test_doq_details(self):
        """Test DoQ protocol details."""
        matrix = generate_protocol_comparison_matrix()
        doq = matrix["protocols"]["DoQ"]

        self.assertEqual(doq["port"], 853)
        self.assertEqual(doq["rfc"], "RFC 9250")

    def test_feature_comparison_table(self):
        """Test feature comparison table."""
        matrix = generate_protocol_comparison_matrix()
        features = matrix["feature_comparison"]

        self.assertIn("Encryption", features)
        self.assertIn("Authentication", features)
        self.assertIn("Firewall Friendly", features)

        # Verify all protocols are in feature comparisons
        for feature, values in features.items():
            for proto in ["DoH", "DoT", "DoQ", "Plaintext"]:
                self.assertIn(proto, values)


class TestFileLoading(unittest.TestCase):
    """Test loading connections from various file formats."""

    def test_load_json_connections(self):
        """Test loading connections from JSON."""
        data = [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "client_ip": "192.168.1.100",
                "server_ip": "8.8.8.8",
                "server_port": 443,
                "protocol": "HTTPS",
                "domain": "dns.google.com",
                "path": "/dns-query",
            }
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            temp_file = f.name

        try:
            connections = load_connections_from_json(temp_file)
            self.assertEqual(len(connections), 1)
            self.assertEqual(connections[0].client_ip, "192.168.1.100")
        finally:
            Path(temp_file).unlink()

    def test_load_csv_connections(self):
        """Test loading connections from CSV."""
        csv_content = (
            "timestamp,client_ip,server_ip,server_port,protocol,domain,path\n"
            "2024-01-01T00:00:00Z,192.168.1.100,8.8.8.8,443,HTTPS,dns.google.com,/dns-query\n"
        )

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".csv", delete=False
        ) as f:
            f.write(csv_content)
            temp_file = f.name

        try:
            connections = load_connections_from_csv(temp_file)
            self.assertEqual(len(connections), 1)
            self.assertEqual(connections[0].client_ip, "192.168.1.100")
        finally:
            Path(temp_file).unlink()

    def test_load_connections_auto_json(self):
        """Test auto-detection of JSON format."""
        data = [
            {
                "timestamp": "2024-01-01T00:00:00Z",
                "client_ip": "192.168.1.100",
                "server_ip": "8.8.8.8",
                "server_port": 53,
                "protocol": "UDP",
            }
        ]

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(data, f)
            temp_file = f.name

        try:
            connections = load_connections(temp_file)
            self.assertEqual(len(connections), 1)
        finally:
            Path(temp_file).unlink()


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""

    def test_empty_connection_list(self):
        """Test analysis with empty connection list."""
        detections, report = analyze_connections([])

        self.assertEqual(report.total_connections, 0)
        self.assertEqual(report.encryption_coverage, 0.0)

    def test_single_connection(self):
        """Test analysis with single connection."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=53,
            protocol="UDP",
        )
        detections, report = analyze_connections([conn])

        self.assertEqual(report.total_connections, 1)
        self.assertEqual(report.plaintext_count, 1)
        self.assertAlmostEqual(report.encryption_coverage, 0.0)

    def test_malformed_port(self):
        """Test handling of malformed port numbers."""
        conn = ConnectionRecord(
            timestamp="2024-01-01T00:00:00Z",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=999999,
            protocol="TCP",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.UNKNOWN)

    def test_missing_optional_fields(self):
        """Test protocol detection with missing optional fields."""
        conn = ConnectionRecord(
            timestamp="",
            client_ip="192.168.1.100",
            server_ip="8.8.8.8",
            server_port=53,
            protocol="UDP",
            domain="",
            path="",
        )
        det = detect_protocol(conn)
        self.assertEqual(det.detected_protocol, ProtocolType.PLAINTEXT)


if __name__ == "__main__":
    unittest.main()
