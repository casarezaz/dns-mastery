#!/usr/bin/env python3
"""Unit tests for dns_threat_model.py"""
import json, unittest, tempfile
from dns_threat_model import (
    DNSArchitecture, Threat, ThreatName, ResolverType, EncryptionType,
    RiskAssessment, IncidentEvent, IncidentSeverity, Timeline,
    ThreatAssessmentEngine, HardeningEngine, ArchitectureComparator,
    TimelineBuilder, DiagramGenerator
)

class TestDNSArchitectureDataclass(unittest.TestCase):
    def test_create_basic_architecture(self):
        arch = DNSArchitecture(
            name="Test", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.NONE, dnssec_validation=False
        )
        self.assertEqual(arch.name, "Test")
        self.assertEqual(arch.resolver_type, ResolverType.RECURSIVE)

    def test_enum_string_normalization(self):
        arch = DNSArchitecture(
            name="Test", resolver_type="recursive",
            encryption="doh", dnssec_validation=True
        )
        self.assertEqual(arch.resolver_type, ResolverType.RECURSIVE)
        self.assertEqual(arch.encryption, EncryptionType.DOH)

    def test_to_dict_serialization(self):
        arch = DNSArchitecture(
            name="Test", resolver_type=ResolverType.FORWARDING,
            encryption=EncryptionType.DOT, dnssec_validation=True,
            upstream_providers=["8.8.8.8"]
        )
        d = arch.to_dict()
        self.assertEqual(d["name"], "Test")
        self.assertEqual(d["resolver_type"], "forwarding")

class TestThreatDataclass(unittest.TestCase):
    def test_create_threat(self):
        threat = Threat(
            name=ThreatName.SPOOFING, description="Test",
            likelihood=7, impact=9
        )
        self.assertEqual(threat.name, ThreatName.SPOOFING)

    def test_threat_risk_score(self):
        threat = Threat(
            name=ThreatName.SPOOFING, description="Test",
            likelihood=7, impact=9
        )
        self.assertEqual(threat.risk_score(), 63)

    def test_risk_score_capped_at_100(self):
        threat = Threat(
            name=ThreatName.SPOOFING, description="Test",
            likelihood=10, impact=10
        )
        self.assertEqual(threat.risk_score(), 100)

class TestIncidentEventAndTimeline(unittest.TestCase):
    def test_create_incident_event(self):
        event = IncidentEvent(
            timestamp="2026-03-27T10:00:00Z", event_type="DNS Query",
            description="Test query", severity=IncidentSeverity.CRITICAL
        )
        self.assertEqual(event.event_type, "DNS Query")

    def test_timeline_creation(self):
        timeline = Timeline(
            incident_name="DGA Attack", start_time="2026-03-27T10:00:00Z",
            end_time="2026-03-27T12:00:00Z"
        )
        self.assertEqual(timeline.incident_name, "DGA Attack")
        self.assertEqual(len(timeline.events), 0)

    def test_timeline_add_event(self):
        timeline = Timeline(
            incident_name="Test", start_time="2026-03-27T10:00:00Z",
            end_time="2026-03-27T12:00:00Z"
        )
        event = IncidentEvent(
            timestamp="2026-03-27T10:30:00Z", event_type="Alert",
            description="DGA detected"
        )
        timeline.add_event(event)
        self.assertEqual(len(timeline.events), 1)

class TestThreatAssessmentEngine(unittest.TestCase):
    def test_engine_initialization(self):
        arch = DNSArchitecture(
            name="Test", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.NONE, dnssec_validation=False
        )
        engine = ThreatAssessmentEngine(arch)
        self.assertEqual(engine.architecture, arch)

    def test_assess_all_threats(self):
        arch = DNSArchitecture(
            name="Test", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.DOT, dnssec_validation=True
        )
        engine = ThreatAssessmentEngine(arch)
        assessments = engine.assess_all_threats()
        self.assertEqual(len(assessments), 7)

class TestHardeningEngine(unittest.TestCase):
    def test_generate_recommendations_empty(self):
        assessment = RiskAssessment(
            threat=Threat(name=ThreatName.SPOOFING, description="Test", likelihood=2, impact=2),
            risk_score=4, severity="LOW", vulnerable=False
        )
        recommendations = HardeningEngine.generate_recommendations([assessment])
        self.assertEqual(len(recommendations), 0)

class TestArchitectureComparator(unittest.TestCase):
    def test_compare_plaintext_to_encrypted(self):
        plaintext = DNSArchitecture(
            name="Plaintext", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.NONE, dnssec_validation=False,
            rpz_blocklists=[], logging_level="none", rate_limiting=False
        )
        encrypted = DNSArchitecture(
            name="Encrypted", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.DOH, dnssec_validation=True,
            rpz_blocklists=["abuse.ch"], logging_level="detailed", rate_limiting=True
        )
        comparison = ArchitectureComparator.compare(plaintext, encrypted)
        self.assertGreater(len(comparison["improvements"]), 0)

class TestTimelineBuilder(unittest.TestCase):
    def test_build_timeline_from_events(self):
        events_data = [
            {"timestamp": "2026-03-27T10:00:00Z", "event_type": "Alert", "description": "Test"},
            {"timestamp": "2026-03-27T10:30:00Z", "event_type": "Response", "description": "Test2"}
        ]
        timeline = TimelineBuilder.build_timeline("Test", events_data)
        self.assertEqual(timeline.incident_name, "Test")
        self.assertEqual(len(timeline.events), 2)

    def test_timeline_event_sorting(self):
        events_data = [
            {"timestamp": "2026-03-27T10:30:00Z", "event_type": "Alert", "description": "Second"},
            {"timestamp": "2026-03-27T10:00:00Z", "event_type": "Alert", "description": "First"}
        ]
        timeline = TimelineBuilder.build_timeline("Test", events_data)
        self.assertEqual(timeline.events[0].description, "First")

class TestDiagramGenerator(unittest.TestCase):
    def test_generate_basic_diagram(self):
        arch = DNSArchitecture(
            name="Test", resolver_type=ResolverType.RECURSIVE,
            encryption=EncryptionType.DOT, dnssec_validation=True,
            upstream_providers=["8.8.8.8"]
        )
        diagram = DiagramGenerator.generate_diagram(arch)
        self.assertIn("Test", diagram)
        self.assertIn("RECURSIVE", diagram)

if __name__ == "__main__":
    unittest.main()
