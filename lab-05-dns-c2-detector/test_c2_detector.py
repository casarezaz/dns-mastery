#!/usr/bin/env python3
"""
Unit tests for dns_c2_detector.py
Validates all detection modules using controlled synthetic data.
"""

import json
import math
import os
import statistics
import sys
import tempfile
import unittest

from dns_c2_detector import (
    shannon_entropy,
    label_entropy,
    extract_base_domain,
    DNSQuery,
    DomainProfile,
    Detection,
    build_domain_profiles,
    detect_beaconing,
    detect_high_entropy,
    detect_encoded_labels,
    detect_long_labels,
    detect_txt_abuse,
    detect_nxdomain_flood,
    detect_volume_anomaly,
    compute_threat_score,
    analyze,
    auto_parse,
    format_text_report,
    format_json_report,
    DEFAULT_THRESHOLDS,
)


class TestShannonEntropy(unittest.TestCase):
    """Test Shannon entropy calculation."""

    def test_empty_string(self):
        self.assertEqual(shannon_entropy(""), 0.0)

    def test_single_char(self):
        self.assertEqual(shannon_entropy("aaaa"), 0.0)

    def test_two_chars_equal(self):
        # "ab" repeated = exactly 1 bit
        self.assertAlmostEqual(shannon_entropy("abababab"), 1.0, places=5)

    def test_high_entropy(self):
        # All unique chars = high entropy
        text = "abcdefghijklmnop"
        ent = shannon_entropy(text)
        self.assertEqual(ent, math.log2(16))

    def test_random_hex_is_high(self):
        # Hex-encoded data should have entropy ~4.0
        import os
        hex_str = os.urandom(32).hex()
        ent = shannon_entropy(hex_str)
        self.assertGreater(ent, 3.0)

    def test_normal_word_is_low(self):
        ent = shannon_entropy("www")
        self.assertLess(ent, 2.0)


class TestLabelEntropy(unittest.TestCase):
    """Test subdomain entropy extraction."""

    def test_bare_domain(self):
        ent, sub = label_entropy("example.com", "example.com")
        self.assertEqual(ent, 0.0)
        self.assertEqual(sub, "")

    def test_simple_subdomain(self):
        ent, sub = label_entropy("www.example.com", "example.com")
        self.assertEqual(sub, "www")
        self.assertLess(ent, 2.0)

    def test_encoded_subdomain(self):
        encoded = "a1b2c3d4e5f6a7b8c9d0e1f2"
        ent, sub = label_entropy(f"{encoded}.evil.com", "evil.com")
        self.assertEqual(sub, encoded)
        self.assertGreater(ent, 3.0)


class TestExtractBaseDomain(unittest.TestCase):
    """Test base domain extraction."""

    def test_simple(self):
        self.assertEqual(extract_base_domain("www.example.com"), "example.com")

    def test_deep_subdomain(self):
        self.assertEqual(extract_base_domain("a.b.c.example.com"), "example.com")

    def test_bare_domain(self):
        self.assertEqual(extract_base_domain("example.com"), "example.com")

    def test_co_uk(self):
        self.assertEqual(extract_base_domain("www.example.co.uk"), "example.co.uk")

    def test_trailing_dot(self):
        self.assertEqual(extract_base_domain("www.example.com."), "example.com")


class TestBeaconDetection(unittest.TestCase):
    """Test beacon interval detection."""

    def _make_profile(self, domain, interval, jitter_pct, count):
        """Create a profile with regular beacon intervals."""
        import random
        random.seed(99)
        queries = []
        ts = 1000.0
        for i in range(count):
            jitter = random.gauss(0, interval * jitter_pct)
            actual_interval = max(0.5, interval + jitter)
            queries.append(DNSQuery(
                timestamp=ts,
                src_ip="10.1.1.50",
                query_name=f"check{i}.{domain}",
                query_type="A",
            ))
            ts += actual_interval

        profile = DomainProfile(domain=domain, total_queries=count)
        profile.queries = queries
        profile.src_ips = {"10.1.1.50"}
        timestamps = [q.timestamp for q in queries]
        profile.intervals = [timestamps[i+1] - timestamps[i]
                             for i in range(len(timestamps) - 1)]
        return profile

    def test_regular_beacon_detected(self):
        # 60s interval, 5% jitter — should be detected
        profile = self._make_profile("beacon.evil.com", 60, 0.05, 50)
        result = detect_beaconing(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)
        self.assertIn(result.severity, ("CRITICAL", "HIGH"))
        self.assertGreater(result.confidence, 0.5)

    def test_irregular_traffic_not_detected(self):
        # Highly irregular intervals — should NOT be detected
        import random
        random.seed(42)
        profile = DomainProfile(domain="legit.com", total_queries=50)
        profile.intervals = [random.uniform(1, 3600) for _ in range(49)]
        profile.src_ips = {"10.1.1.10"}
        profile.queries = [DNSQuery(timestamp=0, src_ip="10.1.1.10",
                                     query_name="legit.com", query_type="A")]
        result = detect_beaconing(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)

    def test_too_few_queries(self):
        profile = self._make_profile("few.evil.com", 60, 0.05, 3)
        result = detect_beaconing(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)


class TestHighEntropyDetection(unittest.TestCase):
    """Test subdomain entropy detection."""

    def _make_profile(self, domain, subdomains):
        profile = DomainProfile(domain=domain, total_queries=len(subdomains))
        profile.src_ips = {"10.1.1.50"}
        for sub in subdomains:
            ent, _ = label_entropy(f"{sub}.{domain}", domain)
            profile.subdomains.append(sub)
            profile.subdomain_entropies.append(ent)
        return profile

    def test_high_entropy_detected(self):
        # Hex-encoded subdomains
        subs = [os.urandom(16).hex() for _ in range(20)]
        profile = self._make_profile("evil.com", subs)
        result = detect_high_entropy(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)
        self.assertIn(result.severity, ("CRITICAL", "HIGH", "MEDIUM"))

    def test_low_entropy_not_detected(self):
        subs = ["www", "mail", "api", "cdn", "static", "login", "app",
                "blog", "docs", "help"]
        profile = self._make_profile("legit.com", subs)
        result = detect_high_entropy(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)

    def test_benign_prefixes_skipped(self):
        subs = ["_dmarc", "_domainkey.selector1", "_spf", "_acme-challenge.token123"]
        profile = self._make_profile("legit.com", subs)
        result = detect_high_entropy(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)


class TestEncodedLabelDetection(unittest.TestCase):
    """Test encoded label detection."""

    def test_hex_labels_detected(self):
        profile = DomainProfile(domain="evil.com")
        profile.subdomains = [os.urandom(20).hex() for _ in range(15)]
        profile.src_ips = {"10.1.1.50"}
        result = detect_encoded_labels(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)
        self.assertIn("hex", result.evidence["encoding_types"])

    def test_base32_labels_detected(self):
        import base64
        profile = DomainProfile(domain="evil.com")
        profile.subdomains = [
            base64.b32encode(os.urandom(15)).decode().rstrip("=")
            for _ in range(15)
        ]
        profile.src_ips = {"10.1.1.50"}
        result = detect_encoded_labels(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)

    def test_short_labels_not_detected(self):
        profile = DomainProfile(domain="legit.com")
        profile.subdomains = ["www", "mail", "api", "cdn", "login"]
        result = detect_encoded_labels(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)


class TestTxtAbuseDetection(unittest.TestCase):
    """Test TXT record abuse detection."""

    def test_high_txt_ratio_detected(self):
        profile = DomainProfile(domain="evil.com", total_queries=100)
        profile.query_types["TXT"] = 90
        profile.query_types["A"] = 10
        profile.src_ips = {"10.1.1.50"}
        result = detect_txt_abuse(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)

    def test_low_txt_ratio_not_detected(self):
        profile = DomainProfile(domain="legit.com", total_queries=100)
        profile.query_types["TXT"] = 3
        profile.query_types["A"] = 97
        result = detect_txt_abuse(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)


class TestNxdomainDetection(unittest.TestCase):
    """Test NXDOMAIN flood / DGA detection."""

    def test_high_nxdomain_detected(self):
        profile = DomainProfile(domain="dga.evil.com",
                                total_queries=100, nxdomain_count=85)
        profile.src_ips = {"10.1.1.50"}
        result = detect_nxdomain_flood(profile, DEFAULT_THRESHOLDS)
        self.assertIsNotNone(result)
        self.assertEqual(result.mitre_technique, "T1568.002")

    def test_normal_nxdomain_not_detected(self):
        profile = DomainProfile(domain="legit.com",
                                total_queries=100, nxdomain_count=5)
        result = detect_nxdomain_flood(profile, DEFAULT_THRESHOLDS)
        self.assertIsNone(result)


class TestVolumeAnomaly(unittest.TestCase):
    """Test volume anomaly detection."""

    def test_anomalous_volume_detected(self):
        profiles = {}
        # Normal domains: ~20 queries each
        for i in range(20):
            p = DomainProfile(domain=f"normal{i}.com", total_queries=20)
            p.src_ips = {f"10.1.1.{i}"}
            profiles[p.domain] = p
        # One anomalous domain: 500 queries
        p = DomainProfile(domain="suspicious.evil.com", total_queries=500)
        p.src_ips = {"10.1.1.200"}
        profiles[p.domain] = p

        results = detect_volume_anomaly(profiles, DEFAULT_THRESHOLDS)
        self.assertTrue(len(results) > 0)
        self.assertEqual(results[0].domain, "suspicious.evil.com")


class TestCompositeThreatScore(unittest.TestCase):
    """Test composite threat scoring."""

    def test_no_detections_clean(self):
        score, rating = compute_threat_score([])
        self.assertEqual(score, 0)
        self.assertEqual(rating, "CLEAN")

    def test_single_high_detection(self):
        dets = [Detection("HIGH", "test", "evil.com", "ind", "det", 0.8)]
        score, rating = compute_threat_score(dets)
        self.assertGreater(score, 0)

    def test_multi_technique_bonus(self):
        dets = [
            Detection("HIGH", "Beacon", "evil.com", "i", "d", 0.8, mitre_technique="T1071.004"),
            Detection("HIGH", "Entropy", "evil.com", "i", "d", 0.8, mitre_technique="T1071.004"),
            Detection("MEDIUM", "Labels", "evil.com", "i", "d", 0.7, mitre_technique="T1572"),
        ]
        score_multi, _ = compute_threat_score(dets)

        # Single detection
        score_single, _ = compute_threat_score([dets[0]])

        self.assertGreater(score_multi, score_single + 20)


class TestIntegration(unittest.TestCase):
    """Integration test using sample data files."""

    def test_csv_parsing_and_analysis(self):
        sample_csv = os.path.join(os.path.dirname(__file__),
                                  "sample_data", "sample_dns.csv")
        if not os.path.exists(sample_csv):
            self.skipTest("Sample data not generated yet")

        queries = auto_parse(sample_csv)
        self.assertGreater(len(queries), 100)

        results = analyze(queries)
        self.assertGreater(results["summary"]["total_detections"], 0)

        # Should detect the known C2 domains
        detected_domains = set(results["detections_by_domain"].keys())
        # At least some of our C2 profiles should be caught
        known_c2 = {"badactor.xyz", "malware-c2.net", "data-exfil.evil", "dns-tunnel.cc"}
        overlap = detected_domains & known_c2
        self.assertGreater(len(overlap), 0,
                           f"Expected to detect some of {known_c2}, got {detected_domains}")

    def test_zeek_parsing_and_analysis(self):
        sample_log = os.path.join(os.path.dirname(__file__),
                                  "sample_data", "sample_dns.log")
        if not os.path.exists(sample_log):
            self.skipTest("Sample data not generated yet")

        queries = auto_parse(sample_log)
        self.assertGreater(len(queries), 100)

        results = analyze(queries)
        self.assertGreater(results["summary"]["domains_with_detections"], 0)

    def test_text_report_format(self):
        results = {
            "summary": {
                "total_queries_analyzed": 100,
                "unique_domains_profiled": 10,
                "domains_with_detections": 1,
                "total_detections": 2,
                "timestamp": "2026-03-25T12:00:00Z",
            },
            "detections_by_domain": {
                "evil.com": {
                    "threat_score": 75,
                    "threat_rating": "HIGH",
                    "detection_count": 2,
                    "techniques_triggered": ["Beacon", "Entropy"],
                    "src_ips": ["10.1.1.50"],
                    "detections": [
                        {
                            "severity": "HIGH",
                            "technique": "Beacon Interval Analysis",
                            "indicator": "Mean interval: 60s",
                            "detail": "Periodic beaconing detected",
                            "confidence": 0.85,
                            "mitre_technique": "T1071.004",
                            "evidence": {},
                            "sample_queries": ["check.evil.com"],
                        }
                    ],
                }
            },
            "thresholds_used": DEFAULT_THRESHOLDS,
        }

        text = format_text_report(results)
        self.assertIn("DNS C2 DETECTION REPORT", text)
        self.assertIn("evil.com", text)
        self.assertIn("T1071.004", text)

    def test_json_report_valid(self):
        results = {
            "summary": {"total_queries_analyzed": 0, "unique_domains_profiled": 0,
                        "domains_with_detections": 0, "total_detections": 0,
                        "timestamp": "now"},
            "detections_by_domain": {},
            "thresholds_used": DEFAULT_THRESHOLDS,
        }
        json_str = format_json_report(results)
        data = json.loads(json_str)
        self.assertIn("summary", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
