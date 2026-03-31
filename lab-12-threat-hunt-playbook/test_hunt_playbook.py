#!/usr/bin/env python3
"""
Unit tests for threat_hunt_playbook.py
Validates all hunt definitions, queries, and playbook functionality.
"""

import json
import unittest
from datetime import datetime, timezone

from threat_hunt_playbook import (
    Severity,
    DataSource,
    Hunt,
    HuntQuery,
    HuntFinding,
    CoverageMatrix,
    DNSThreatHuntPlaybook,
    build_hunt_library,
    __version__,
)


class TestHuntLibraryCompleteness(unittest.TestCase):
    """Verify all 10 hunts are present."""

    def setUp(self):
        self.hunts = build_hunt_library()

    def test_total_hunts(self):
        """Should have exactly 10 hunts."""
        self.assertEqual(len(self.hunts), 10)

    def test_all_hunt_ids_present(self):
        """All hunt IDs H001-H010 should be present."""
        expected_ids = [f"H{i:03d}" for i in range(1, 11)]
        actual_ids = [hunt.hunt_id for hunt in self.hunts]
        self.assertEqual(sorted(actual_ids), sorted(expected_ids))

    def test_hunt_names_not_empty(self):
        """All hunts should have non-empty names."""
        for hunt in self.hunts:
            self.assertTrue(hunt.name)
            self.assertGreater(len(hunt.name), 0)

    def test_hunt_hypotheses_not_empty(self):
        """All hunts should have hypotheses."""
        for hunt in self.hunts:
            self.assertTrue(hunt.hypothesis)
            self.assertGreater(len(hunt.hypothesis), 10)

    def test_all_hunts_have_severity(self):
        """All hunts should have severity."""
        for hunt in self.hunts:
            self.assertIsNotNone(hunt.severity)
            self.assertIn(hunt.severity, [Severity.INFO, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])

    def test_all_hunts_have_mitre_ids(self):
        """All hunts should have MITRE technique IDs."""
        for hunt in self.hunts:
            self.assertGreater(len(hunt.mitre_ids), 0)
            for mitre_id in hunt.mitre_ids:
                self.assertTrue(mitre_id.startswith("T"))

    def test_all_hunts_have_data_sources(self):
        """All hunts should have data sources."""
        for hunt in self.hunts:
            self.assertGreater(len(hunt.data_sources), 0)
            for ds in hunt.data_sources:
                self.assertIsInstance(ds, DataSource)

    def test_all_hunts_have_queries(self):
        """All hunts should have at least one query."""
        for hunt in self.hunts:
            self.assertGreater(len(hunt.queries), 0)

    def test_all_hunts_have_detection_logic(self):
        """All hunts should have detection logic."""
        for hunt in self.hunts:
            self.assertTrue(hunt.detection_logic)
            self.assertGreater(len(hunt.detection_logic), 20)

    def test_all_hunts_have_iocs(self):
        """All hunts should have indicators of compromise."""
        for hunt in self.hunts:
            self.assertGreater(len(hunt.indicators_of_compromise), 0)

    def test_all_hunts_have_response_procedure(self):
        """All hunts should have response procedures."""
        for hunt in self.hunts:
            self.assertTrue(hunt.response_procedure)
            self.assertGreater(len(hunt.response_procedure), 20)

    def test_all_hunts_have_false_positive_mitigation(self):
        """All hunts should have false positive mitigation."""
        for hunt in self.hunts:
            self.assertTrue(hunt.false_positive_mitigation)
            self.assertGreater(len(hunt.false_positive_mitigation), 10)


class TestQueryGeneration(unittest.TestCase):
    """Verify queries for all hunts."""

    def setUp(self):
        self.hunts = build_hunt_library()

    def test_all_hunts_have_splunk_query(self):
        """All hunts should have at least one Splunk SPL query."""
        for hunt in self.hunts:
            splunk_queries = [q for q in hunt.queries if q.query_type == "splunk_spl"]
            self.assertGreater(len(splunk_queries), 0, f"Hunt {hunt.hunt_id} missing Splunk query")

    def test_all_queries_have_description(self):
        """All queries should have descriptions."""
        for hunt in self.hunts:
            for query in hunt.queries:
                self.assertTrue(query.description)
                self.assertGreater(len(query.description), 5)

    def test_all_queries_have_content(self):
        """All queries should have non-empty content."""
        for hunt in self.hunts:
            for query in hunt.queries:
                self.assertTrue(query.query)
                self.assertGreater(len(query.query), 0)

    def test_query_types_valid(self):
        """Query types should be valid."""
        valid_types = ["splunk_spl", "kql", "sigma"]
        for hunt in self.hunts:
            for query in hunt.queries:
                self.assertIn(query.query_type, valid_types)


class TestMITRECoverageMatrix(unittest.TestCase):
    """Test MITRE ATT&CK coverage."""

    def setUp(self):
        self.playbook = DNSThreatHuntPlaybook()

    def test_coverage_matrix_populated(self):
        """Coverage matrix should be populated."""
        matrix = self.playbook.coverage.to_dict()
        self.assertGreater(len(matrix), 0)

    def test_all_hunt_mitre_ids_in_matrix(self):
        """All hunt MITRE IDs should be in the matrix."""
        matrix = self.playbook.coverage.to_dict()
        all_mitre_ids = set()
        for hunt in self.playbook.hunts:
            all_mitre_ids.update(hunt.mitre_ids)
        self.assertEqual(set(matrix.keys()), all_mitre_ids)

    def test_matrix_contains_correct_hunt_ids(self):
        """Matrix should map MITRE techniques to hunts correctly."""
        matrix = self.playbook.coverage.to_dict()
        for hunt in self.playbook.hunts:
            for technique in hunt.mitre_ids:
                self.assertIn(hunt.hunt_id, matrix[technique])

    def test_required_mitre_techniques_covered(self):
        """All required MITRE techniques should be in coverage."""
        required_techniques = [
            "T1071.004",  # Application Layer Protocol: DNS
            "T1572",      # Protocol Tunneling
            "T1568.002",  # Dynamic Resolution: DGA
            "T1048.003",  # Exfiltration Over Alternative Protocol
            "T1583.001",  # Acquire Infrastructure: Domains
            "T1557.004",  # Adversary-in-the-Middle: DNS Spoofing
            "T1590.002",  # Gather Victim Network Information: DNS
        ]
        matrix = self.playbook.coverage.to_dict()
        for technique in required_techniques:
            self.assertIn(technique, matrix, f"Missing coverage for {technique}")


class TestHuntFiltering(unittest.TestCase):
    """Test hunt filtering functionality."""

    def setUp(self):
        self.playbook = DNSThreatHuntPlaybook()

    def test_filter_by_severity_critical(self):
        """Should filter by CRITICAL severity."""
        critical = self.playbook.list_hunts(severity=Severity.CRITICAL)
        self.assertGreater(len(critical), 0)
        for hunt in critical:
            self.assertEqual(hunt.severity, Severity.CRITICAL)

    def test_filter_by_severity_high(self):
        """Should filter by HIGH severity."""
        high = self.playbook.list_hunts(severity=Severity.HIGH)
        self.assertGreater(len(high), 0)
        for hunt in high:
            self.assertEqual(hunt.severity, Severity.HIGH)

    def test_filter_by_data_source(self):
        """Should filter by data source."""
        dns_logs = self.playbook.list_hunts(data_source=DataSource.DNS_LOGS)
        self.assertGreater(len(dns_logs), 0)
        for hunt in dns_logs:
            self.assertIn(DataSource.DNS_LOGS, hunt.data_sources)

    def test_filter_by_mitre_technique(self):
        """Should filter by MITRE technique."""
        t1572 = self.playbook.list_hunts(mitre_technique="T1572")
        self.assertGreater(len(t1572), 0)
        for hunt in t1572:
            self.assertIn("T1572", hunt.mitre_ids)

    def test_filter_empty_result(self):
        """Filter should return empty list if no matches."""
        none_found = self.playbook.list_hunts(mitre_technique="T9999.999")
        self.assertEqual(len(none_found), 0)


class TestPlaybookExport(unittest.TestCase):
    """Test playbook export functionality."""

    def setUp(self):
        self.playbook = DNSThreatHuntPlaybook()

    def test_export_text_format(self):
        """Should export as text."""
        output = self.playbook.export_playbook(format_type="text")
        self.assertIsInstance(output, str)
        self.assertIn("DNS THREAT HUNT PLAYBOOK", output)
        self.assertIn("H001", output)
        self.assertIn("MITRE", output)

    def test_export_json_format(self):
        """Should export as JSON."""
        output = self.playbook.export_playbook(format_type="json")
        self.assertIsInstance(output, str)
        data = json.loads(output)
        self.assertIn("title", data)
        self.assertIn("hunts", data)
        self.assertIn("coverage_matrix", data)
        self.assertEqual(len(data["hunts"]), 10)

    def test_export_markdown_format(self):
        """Should export as Markdown."""
        output = self.playbook.export_playbook(format_type="markdown")
        self.assertIsInstance(output, str)
        self.assertIn("# DNS Threat Hunt Playbook", output)
        self.assertIn("H001", output)

    def test_export_includes_all_hunts(self):
        """Export should include all 10 hunts."""
        json_output = self.playbook.export_playbook(format_type="json")
        data = json.loads(json_output)
        self.assertEqual(len(data["hunts"]), 10)

    def test_export_json_structure(self):
        """JSON export should have correct structure."""
        json_output = self.playbook.export_playbook(format_type="json")
        data = json.loads(json_output)
        self.assertIn("title", data)
        self.assertIn("generated_at", data)
        self.assertIn("version", data)
        self.assertIn("total_hunts", data)
        self.assertEqual(data["total_hunts"], 10)


class TestHuntQueries(unittest.TestCase):
    """Test query retrieval."""

    def setUp(self):
        self.playbook = DNSThreatHuntPlaybook()

    def test_get_hunt_by_id(self):
        """Should retrieve hunt by ID."""
        hunt = self.playbook.get_hunt("H001")
        self.assertIsNotNone(hunt)
        self.assertEqual(hunt.hunt_id, "H001")

    def test_get_nonexistent_hunt(self):
        """Should return None for nonexistent hunt."""
        hunt = self.playbook.get_hunt("H999")
        self.assertIsNone(hunt)

    def test_get_queries_for_hunt(self):
        """Should retrieve queries for a hunt."""
        queries = self.playbook.get_queries_for_hunt("H001")
        self.assertGreater(len(queries), 0)

    def test_get_queries_by_type(self):
        """Should filter queries by type."""
        splunk_queries = self.playbook.get_queries_for_hunt("H001", query_type="splunk_spl")
        self.assertGreater(len(splunk_queries), 0)
        for query in splunk_queries:
            self.assertEqual(query.query_type, "splunk_spl")

    def test_get_queries_nonexistent_hunt(self):
        """Should return empty list for nonexistent hunt."""
        queries = self.playbook.get_queries_for_hunt("H999")
        self.assertEqual(len(queries), 0)


class TestPlaybookStatistics(unittest.TestCase):
    """Test playbook statistics."""

    def setUp(self):
        self.playbook = DNSThreatHuntPlaybook()

    def test_coverage_stats_structure(self):
        """Should return valid coverage stats."""
        stats = self.playbook.get_coverage_stats()
        self.assertIn("total_hunts", stats)
        self.assertIn("total_mitre_techniques", stats)
        self.assertIn("hunts_by_severity", stats)
        self.assertIn("mitre_techniques", stats)

    def test_coverage_stats_counts(self):
        """Stats should reflect actual hunt counts."""
        stats = self.playbook.get_coverage_stats()
        total = (
            stats["hunts_by_severity"]["CRITICAL"]
            + stats["hunts_by_severity"]["HIGH"]
            + stats["hunts_by_severity"]["MEDIUM"]
            + stats["hunts_by_severity"]["INFO"]
        )
        self.assertEqual(total, stats["total_hunts"])

    def test_mitre_techniques_count(self):
        """Should count MITRE techniques."""
        stats = self.playbook.get_coverage_stats()
        self.assertGreater(stats["total_mitre_techniques"], 0)


class TestHuntDataStructures(unittest.TestCase):
    """Test Hunt dataclass and related structures."""

    def test_hunt_to_dict(self):
        """Hunt should convert to dict."""
        hunt_lib = build_hunt_library()
        hunt = hunt_lib[0]
        hunt_dict = hunt.to_dict()
        self.assertIsInstance(hunt_dict, dict)
        self.assertEqual(hunt_dict["hunt_id"], hunt.hunt_id)
        self.assertEqual(hunt_dict["name"], hunt.name)

    def test_hunt_finding_creation(self):
        """Should create HuntFinding instances."""
        finding = HuntFinding(
            hunt_id="H001",
            hunt_name="Test Hunt",
            severity=Severity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            indicator="test.domain.com",
            details="Test detection",
            suggested_response="Block domain",
        )
        self.assertEqual(finding.hunt_id, "H001")
        self.assertEqual(finding.severity, Severity.HIGH)

    def test_coverage_matrix_operations(self):
        """CoverageMatrix should add and retrieve techniques."""
        matrix = CoverageMatrix()
        matrix.add("T1572", "H001")
        matrix.add("T1572", "H002")
        matrix.add("T1071.004", "H001")

        matrix_dict = matrix.to_dict()
        self.assertEqual(len(matrix_dict["T1572"]), 2)
        self.assertIn("H001", matrix_dict["T1572"])
        self.assertIn("H001", matrix_dict["T1071.004"])


class TestSpecificHunts(unittest.TestCase):
    """Test specific hunt configurations."""

    def setUp(self):
        self.hunts = build_hunt_library()

    def test_h001_dns_tunneling(self):
        """H001 should be DNS Tunneling."""
        h001 = next(h for h in self.hunts if h.hunt_id == "H001")
        self.assertIn("T1572", h001.mitre_ids)
        self.assertIn("T1048.003", h001.mitre_ids)
        self.assertGreater(len(h001.indicators_of_compromise), 0)

    def test_h002_c2_over_dns(self):
        """H002 should be C2 over DNS."""
        h002 = next(h for h in self.hunts if h.hunt_id == "H002")
        self.assertEqual(h002.severity, Severity.CRITICAL)
        self.assertIn("T1071.004", h002.mitre_ids)

    def test_h003_dga_detection(self):
        """H003 should be DGA Detection."""
        h003 = next(h for h in self.hunts if h.hunt_id == "H003")
        self.assertIn("T1568.002", h003.mitre_ids)

    def test_h004_cache_poisoning(self):
        """H004 should be DNS Cache Poisoning."""
        h004 = next(h for h in self.hunts if h.hunt_id == "H004")
        self.assertEqual(h004.severity, Severity.CRITICAL)
        self.assertIn("T1557.004", h004.mitre_ids)

    def test_h005_zone_transfer(self):
        """H005 should be Zone Transfer Abuse."""
        h005 = next(h for h in self.hunts if h.hunt_id == "H005")
        self.assertIn("T1590.002", h005.mitre_ids)

    def test_h006_dnssec(self):
        """H006 should be DNSSEC Validation."""
        h006 = next(h for h in self.hunts if h.hunt_id == "H006")
        self.assertIn("T1557.004", h006.mitre_ids)

    def test_h007_amplification(self):
        """H007 should be DNS Amplification."""
        h007 = next(h for h in self.hunts if h.hunt_id == "H007")
        self.assertIn("T1048.003", h007.mitre_ids)

    def test_h008_doh_bypass(self):
        """H008 should be DoH Bypass."""
        h008 = next(h for h in self.hunts if h.hunt_id == "H008")
        self.assertIn("T1071.004", h008.mitre_ids)

    def test_h009_fast_flux(self):
        """H009 should be Fast-Flux Detection."""
        h009 = next(h for h in self.hunts if h.hunt_id == "H009")
        self.assertIn("T1583.001", h009.mitre_ids)

    def test_h010_data_exfiltration(self):
        """H010 should be DNS Data Exfiltration."""
        h010 = next(h for h in self.hunts if h.hunt_id == "H010")
        self.assertIn("T1048.003", h010.mitre_ids)


if __name__ == "__main__":
    unittest.main()
