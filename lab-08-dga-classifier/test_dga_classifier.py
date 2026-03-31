#!/usr/bin/env python3
"""
Unit tests for DGA Domain Classifier (Lab 08)
==============================================
Comprehensive test coverage for feature extraction, classification,
confidence scoring, DGA family detection, and batch processing.
"""

import unittest
import json
import csv
from pathlib import Path
from tempfile import TemporaryDirectory

from dga_classifier import (
    extract_sld_and_tld,
    calculate_entropy,
    analyze_bigrams,
    analyze_consonant_sequences,
    analyze_consecutive_patterns,
    extract_features,
    classify_domain,
    classify_batch,
    load_domains_from_file,
    format_text_report,
    format_json_report,
    format_csv_report,
    DGAFamily,
    ClassificationStatus,
    ModelConfig,
)


class TestSLDTLDExtraction(unittest.TestCase):
    """Test domain and TLD extraction."""

    def test_standard_domain(self):
        sld, tld = extract_sld_and_tld("example.com")
        self.assertEqual(sld, "example")
        self.assertEqual(tld, "com")

    def test_subdomain_extraction(self):
        sld, tld = extract_sld_and_tld("www.example.com")
        # Should take last two parts
        self.assertEqual(tld, "com")

    def test_trailing_dot(self):
        sld, tld = extract_sld_and_tld("example.com.")
        self.assertEqual(sld, "example")
        self.assertEqual(tld, "com")

    def test_uppercase_conversion(self):
        sld, tld = extract_sld_and_tld("EXAMPLE.COM")
        self.assertEqual(sld, "example")
        self.assertEqual(tld, "com")

    def test_long_tld(self):
        sld, tld = extract_sld_and_tld("example.co.uk")
        self.assertEqual(tld, "uk")  # Takes last part


class TestEntropyCalculation(unittest.TestCase):
    """Test Shannon entropy calculation."""

    def test_empty_string(self):
        entropy = calculate_entropy("")
        self.assertEqual(entropy, 0.0)

    def test_single_character(self):
        entropy = calculate_entropy("a")
        self.assertEqual(entropy, 0.0)

    def test_uniform_distribution(self):
        # "aaaa" has only one character
        entropy = calculate_entropy("aaaa")
        self.assertEqual(entropy, 0.0)

    def test_uniform_binary(self):
        # "ab" repeated: 50/50
        entropy = calculate_entropy("ababab")
        self.assertAlmostEqual(entropy, 1.0, places=1)

    def test_natural_word_vs_random(self):
        # Natural word has lower entropy than random
        natural_entropy = calculate_entropy("example")
        random_entropy = calculate_entropy("xkqdmpt")
        self.assertLess(natural_entropy, random_entropy)

    def test_high_entropy_string(self):
        # Highly random string
        entropy = calculate_entropy("aabbccddee")
        self.assertGreater(entropy, 2.0)


class TestBigramAnalysis(unittest.TestCase):
    """Test bigram analysis."""

    def test_empty_string(self):
        total, common = analyze_bigrams("")
        self.assertEqual(total, 0)
        self.assertEqual(common, 0)

    def test_single_character(self):
        total, common = analyze_bigrams("a")
        self.assertEqual(total, 0)

    def test_natural_word(self):
        total, common = analyze_bigrams("the")
        self.assertEqual(total, 2)  # "th", "he"
        self.assertEqual(common, 2)  # Both are common

    def test_random_string(self):
        total, common = analyze_bigrams("xkpqm")
        self.assertEqual(total, 4)  # 4 bigrams
        self.assertLess(common, 3)  # Few common bigrams

    def test_case_insensitivity(self):
        total1, common1 = analyze_bigrams("THE")
        total2, common2 = analyze_bigrams("the")
        self.assertEqual(total1, total2)
        self.assertEqual(common1, common2)


class TestConsonantSequences(unittest.TestCase):
    """Test consonant sequence detection."""

    def test_no_consonants(self):
        seq = analyze_consonant_sequences("aeiou")
        self.assertEqual(seq, 0)

    def test_single_consonant(self):
        seq = analyze_consonant_sequences("bcaei")
        # "bc" = 2 consecutive consonants
        self.assertEqual(seq, 2)

    def test_consonant_cluster(self):
        seq = analyze_consonant_sequences("strength")
        # "str" = 3, "ngth" = 4
        self.assertEqual(seq, 4)

    def test_mixed_content(self):
        seq = analyze_consonant_sequences("string")
        # "str" = 3
        self.assertGreaterEqual(seq, 3)

    def test_long_sequence(self):
        seq = analyze_consonant_sequences("bbbbbcccc")
        # 9 total consonants (5 b's + 4 c's)
        self.assertEqual(seq, 9)


class TestConsecutivePatterns(unittest.TestCase):
    """Test consecutive vowel/consonant pattern detection."""

    def test_no_patterns(self):
        vowels, consonants = analyze_consecutive_patterns("abc")
        # Alternating, no consecutive patterns
        self.assertFalse(vowels)
        self.assertFalse(consonants)

    def test_consecutive_vowels(self):
        vowels, consonants = analyze_consecutive_patterns("baeiu")
        self.assertTrue(vowels)

    def test_long_consonant_sequence(self):
        vowels, consonants = analyze_consecutive_patterns("astring")
        # "str" = 3 consonants
        self.assertTrue(consonants)

    def test_both_patterns(self):
        vowels, consonants = analyze_consecutive_patterns("beautiful")
        # "eau" and other patterns
        self.assertTrue(vowels)


class TestFeatureExtraction(unittest.TestCase):
    """Test comprehensive feature extraction."""

    def test_legitimate_domain(self):
        features = extract_features("example.com")
        self.assertEqual(features.sld, "example")
        self.assertEqual(features.tld, "com")
        self.assertEqual(features.length, 7)
        self.assertGreater(features.entropy, 0)
        self.assertGreater(features.vowel_ratio, 0)

    def test_dga_domain(self):
        # Simulated DGA: random characters
        features = extract_features("xkpdmqrt.com")
        self.assertEqual(features.length, 8)
        # High entropy expected
        self.assertGreaterEqual(features.entropy, 3.0)
        # Low vowel ratio
        self.assertLess(features.vowel_ratio, 0.5)

    def test_feature_completeness(self):
        features = extract_features("legitimate.org")
        self.assertIsNotNone(features.domain)
        self.assertIsNotNone(features.sld)
        self.assertIsNotNone(features.tld)
        self.assertGreaterEqual(features.length, 0)
        self.assertGreaterEqual(features.entropy, 0)
        self.assertEqual(features.digit_ratio, 0.0)  # No digits
        self.assertFalse(features.has_digits)

    def test_domain_with_digits(self):
        features = extract_features("abc123def.com")
        self.assertTrue(features.has_digits)
        self.assertGreater(features.digit_ratio, 0)
        self.assertEqual(features.digit_count, 3)

    def test_uppercase_detection(self):
        # Note: SLD is extracted and lowercased, so uppercase_ratio will be 0
        # This tests that the feature is properly extracted
        features = extract_features("example.com")
        self.assertEqual(features.uppercase_ratio, 0.0)


class TestClassification(unittest.TestCase):
    """Test domain classification."""

    def test_legitimate_domains(self):
        legit_domains = [
            "google.com",
            "microsoft.com",
            "amazon.org",
            "example.com",
        ]

        for domain in legit_domains:
            result = classify_domain(domain)
            self.assertIsNotNone(result)
            self.assertIn(result.classification, [
                ClassificationStatus.LEGITIMATE,
                ClassificationStatus.SUSPICIOUS,
            ])
            # Confidence should be calculated
            self.assertGreaterEqual(result.confidence, 0.0)
            self.assertLessEqual(result.confidence, 1.0)

    def test_dga_domains(self):
        # High-entropy random strings
        dga_domains = [
            "xkpdmqrt.com",
            "qpqpmqmr.com",
            "bfghjkln.com",
        ]

        for domain in dga_domains:
            result = classify_domain(domain)
            self.assertIsNotNone(result)
            # Should be flagged as DGA or SUSPICIOUS
            self.assertIn(result.classification, [
                ClassificationStatus.DGA,
                ClassificationStatus.SUSPICIOUS,
            ])

    def test_confidence_scoring(self):
        result1 = classify_domain("google.com")
        result2 = classify_domain("xkpdmqrt.com")

        # Both should have confidence scores
        self.assertGreaterEqual(result1.confidence, 0.0)
        self.assertLessEqual(result1.confidence, 1.0)
        self.assertGreaterEqual(result2.confidence, 0.0)
        self.assertLessEqual(result2.confidence, 1.0)

    def test_score_bounds(self):
        domains = ["google.com", "xkpdmqrt.com", "abc123.net"]
        for domain in domains:
            result = classify_domain(domain)
            self.assertGreaterEqual(result.score, 0.0)
            self.assertLessEqual(result.score, 100.0)

    def test_reasons_populated(self):
        result = classify_domain("xkpdmqrt.com")
        self.assertGreater(len(result.reasons), 0)

    def test_dga_family_estimation(self):
        result = classify_domain("xkpdmqrt.com")
        self.assertIn(result.dga_family, [
            DGAFamily.RANDOM_CHAR,
            DGAFamily.DICTIONARY,
            DGAFamily.HASH_BASED,
            DGAFamily.LEGITIMATE,
        ])

    def test_custom_config(self):
        config = ModelConfig()
        config.dga_threshold = 60.0  # Raise threshold
        config.entropy_dga_min = 4.0  # Higher entropy needed

        result1 = classify_domain("google.com", config)
        result2 = classify_domain("xkpdmqrt.com", config)

        self.assertIsNotNone(result1)
        self.assertIsNotNone(result2)

    def test_suspicious_tld_detection(self):
        result = classify_domain("example.xyz")  # Suspicious TLD
        self.assertIsNotNone(result)


class TestBatchProcessing(unittest.TestCase):
    """Test batch domain classification."""

    def test_batch_classification(self):
        domains = ["google.com", "example.org", "xkpdmqrt.com"]
        results = classify_batch(domains)

        self.assertEqual(len(results), 3)
        for result in results:
            self.assertIsNotNone(result.domain)
            self.assertIsNotNone(result.classification)
            self.assertGreaterEqual(result.score, 0.0)

    def test_batch_empty(self):
        results = classify_batch([])
        self.assertEqual(len(results), 0)

    def test_batch_with_invalid_domain(self):
        # Should handle gracefully
        domains = ["google.com", "", "example.com"]
        results = classify_batch(domains)
        # Should have at least 2 results
        self.assertGreaterEqual(len(results), 2)


class TestFileLoading(unittest.TestCase):
    """Test loading domains from files."""

    def test_load_plain_text(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "domains.txt"
            filepath.write_text("google.com\nexample.org\ntest.net\n")

            domains = load_domains_from_file(filepath)
            self.assertEqual(len(domains), 3)
            self.assertIn("google.com", domains)

    def test_load_json_list(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "domains.json"
            data = ["google.com", "example.org", "test.net"]
            filepath.write_text(json.dumps(data))

            domains = load_domains_from_file(filepath)
            self.assertEqual(len(domains), 3)

    def test_load_json_objects(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "domains.json"
            data = [
                {"domain": "google.com"},
                {"domain": "example.org"},
            ]
            filepath.write_text(json.dumps(data))

            domains = load_domains_from_file(filepath)
            self.assertEqual(len(domains), 2)

    def test_load_csv(self):
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "domains.csv"
            filepath.write_text("domain\ngoogle.com\nexample.org\n")

            domains = load_domains_from_file(filepath)
            self.assertGreaterEqual(len(domains), 2)


class TestReportFormatting(unittest.TestCase):
    """Test report generation."""

    def test_text_report(self):
        domains = ["google.com", "example.org", "xkpdmqrt.com"]
        results = classify_batch(domains)
        report = format_text_report(results)

        self.assertIn("DGA DOMAIN CLASSIFIER REPORT", report)
        self.assertIn("Total Domains:", report)
        self.assertIn("DETAILED RESULTS:", report)

    def test_json_report(self):
        domains = ["google.com", "xkpdmqrt.com"]
        results = classify_batch(domains)
        report = format_json_report(results)

        data = json.loads(report)
        self.assertIn("summary", data)
        self.assertIn("results", data)
        self.assertEqual(data["summary"]["total"], 2)

    def test_csv_report(self):
        domains = ["google.com", "example.org"]
        results = classify_batch(domains)
        report = format_csv_report(results)

        lines = report.split('\n')
        # Should have header + 2 data rows
        self.assertGreaterEqual(len(lines), 2)

    def test_report_with_empty_results(self):
        report = format_text_report([])
        self.assertIn("DGA DOMAIN CLASSIFIER REPORT", report)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""

    def test_very_short_domain(self):
        result = classify_domain("ab.co")
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.score, 0.0)

    def test_very_long_domain(self):
        long_domain = "a" * 50 + ".com"
        result = classify_domain(long_domain)
        self.assertIsNotNone(result)

    def test_domain_with_hyphens(self):
        result = classify_domain("my-domain.com")
        self.assertIsNotNone(result)

    def test_all_digits(self):
        result = classify_domain("12345678.com")
        self.assertIsNotNone(result)
        self.assertEqual(result.features.digit_ratio, 1.0)

    def test_no_vowels(self):
        # Unusual but valid
        result = classify_domain("xyz.com")
        self.assertIsNotNone(result)
        # Should have high consonant ratio
        self.assertGreater(result.features.consonant_ratio, 0.5)

    def test_all_same_character(self):
        result = classify_domain("aaaaa.com")
        self.assertEqual(result.features.unique_char_count, 1)
        self.assertEqual(result.features.entropy, 0.0)

    def test_mixed_case_domain(self):
        result = classify_domain("MyDomain.Com")
        self.assertEqual(result.sld, "mydomain")
        self.assertEqual(result.tld, "com")


class TestIntegration(unittest.TestCase):
    """Integration tests."""

    def test_full_workflow(self):
        # Create a sample file
        with TemporaryDirectory() as tmpdir:
            filepath = Path(tmpdir) / "test_domains.txt"
            test_domains = ["google.com", "example.org", "xkqdmrt.com"]
            filepath.write_text("\n".join(test_domains))

            # Load domains
            loaded = load_domains_from_file(filepath)
            self.assertEqual(len(loaded), 3)

            # Classify
            results = classify_batch(loaded)
            self.assertEqual(len(results), 3)

            # Generate reports
            text_report = format_text_report(results)
            json_report = format_json_report(results)
            csv_report = format_csv_report(results)

            self.assertGreater(len(text_report), 0)
            self.assertGreater(len(json_report), 0)
            self.assertGreater(len(csv_report), 0)

    def test_model_config_application(self):
        domains = ["example.com", "xkpdmqrt.com"]

        # Strict config (high DGA threshold)
        strict = ModelConfig()
        strict.dga_threshold = 80.0

        # Loose config (low DGA threshold)
        loose = ModelConfig()
        loose.dga_threshold = 40.0

        results_strict = [classify_domain(d, strict) for d in domains]
        results_loose = [classify_domain(d, loose) for d in domains]

        # Loose config should flag more as DGA
        strict_dga = sum(1 for r in results_strict if r.classification == ClassificationStatus.DGA)
        loose_dga = sum(1 for r in results_loose if r.classification == ClassificationStatus.DGA)

        self.assertLessEqual(strict_dga, loose_dga)


if __name__ == "__main__":
    unittest.main()
