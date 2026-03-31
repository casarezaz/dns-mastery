#!/usr/bin/env python3
"""DNS Threat Model & Architecture Analyzer — Lab 11"""
from __future__ import annotations
import argparse, json, sys, textwrap
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Literal, Any
from enum import Enum

__version__ = "1.0.0"

class ResolverType(Enum):
    RECURSIVE = "recursive"
    FORWARDING = "forwarding"
    STUB = "stub"

class EncryptionType(Enum):
    NONE = "none"
    DOT = "dot"
    DOH = "doh"
    DOQ = "doq"

class ThreatName(Enum):
    SPOOFING = "DNS Spoofing"
    HIJACKING = "DNS Hijacking"
    TUNNELING = "DNS Tunneling"
    EXFILTRATION = "Data Exfiltration over DNS"
    DGA = "DGA Detection (Domain Generation Algorithm)"
    CACHE_POISONING = "Cache Poisoning"
    AMPLIFICATION = "DNS Amplification Attack"

class IncidentSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"

@dataclass
class DNSArchitecture:
    name: str
    resolver_type: ResolverType | str
    encryption: EncryptionType | str
    dnssec_validation: bool
    upstream_providers: list[str] = field(default_factory=list)
    rpz_blocklists: list[str] = field(default_factory=list)
    logging_level: Literal["none", "basic", "detailed"] = "basic"
    caching_enabled: bool = True
    rate_limiting: bool = False
    description: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        if isinstance(self.resolver_type, str):
            try:
                self.resolver_type = ResolverType(self.resolver_type)
            except ValueError:
                self.resolver_type = ResolverType.RECURSIVE
        if isinstance(self.encryption, str):
            try:
                self.encryption = EncryptionType(self.encryption)
            except ValueError:
                self.encryption = EncryptionType.NONE

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["resolver_type"] = self.resolver_type.value
        d["encryption"] = self.encryption.value
        return d

@dataclass
class Threat:
    name: ThreatName | str
    description: str
    likelihood: int
    impact: int
    affected_components: list[str] = field(default_factory=list)
    mitre_technique: str = ""

    def __post_init__(self):
        if isinstance(self.name, str):
            try:
                self.name = ThreatName(self.name)
            except ValueError:
                self.name = ThreatName.SPOOFING

    def risk_score(self) -> int:
        return min(100, max(1, self.likelihood * self.impact))

@dataclass
class RiskAssessment:
    threat: Threat
    risk_score: int
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    vulnerable: bool
    rationale: str = ""

@dataclass
class HardeningRecommendation:
    threat_name: str
    recommendation: str
    priority: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    implementation_effort: Literal["EASY", "MODERATE", "COMPLEX"]
    expected_impact: str

@dataclass
class IncidentEvent:
    timestamp: str
    event_type: str
    description: str
    source_ip: str = ""
    target_domain: str = ""
    severity: IncidentSeverity | str = IncidentSeverity.INFO

    def __post_init__(self):
        if isinstance(self.severity, str):
            try:
                self.severity = IncidentSeverity(self.severity)
            except ValueError:
                self.severity = IncidentSeverity.INFO

@dataclass
class Timeline:
    incident_name: str
    start_time: str
    end_time: str
    events: list[IncidentEvent] = field(default_factory=list)
    affected_domains: list[str] = field(default_factory=list)
    root_cause: str = ""
    impact_summary: str = ""

    def add_event(self, event: IncidentEvent) -> None:
        self.events.append(event)

    def get_events_by_severity(self, severity: IncidentSeverity) -> list[IncidentEvent]:
        return [e for e in self.events if e.severity == severity]

class ThreatAssessmentEngine:
    THREAT_CATALOG = [
        Threat(name=ThreatName.SPOOFING, description="Attacker responds with forged DNS answers", likelihood=8, impact=9, mitre_technique="T1557.004"),
        Threat(name=ThreatName.HIJACKING, description="Attacker redirects DNS queries", likelihood=7, impact=10, mitre_technique="T1557.004"),
        Threat(name=ThreatName.TUNNELING, description="Attacker uses DNS for covert channel", likelihood=6, impact=8, mitre_technique="T1071.004"),
        Threat(name=ThreatName.EXFILTRATION, description="Data encoded in DNS queries", likelihood=6, impact=9, mitre_technique="T1071.004"),
        Threat(name=ThreatName.DGA, description="DGA domain contact attempts", likelihood=5, impact=7, mitre_technique="T1590.002"),
        Threat(name=ThreatName.CACHE_POISONING, description="False records injected into cache", likelihood=4, impact=9, mitre_technique="T1557.004"),
        Threat(name=ThreatName.AMPLIFICATION, description="DNS amplification DDoS", likelihood=3, impact=8, mitre_technique="T1071.004"),
    ]

    def __init__(self, architecture: DNSArchitecture):
        self.architecture = architecture

    def assess_threat(self, threat: Threat) -> RiskAssessment:
        adjusted_likelihood = threat.likelihood
        adjusted_impact = threat.impact

        if threat.name in [ThreatName.SPOOFING, ThreatName.HIJACKING]:
            if self.architecture.encryption != EncryptionType.NONE:
                adjusted_likelihood = max(1, adjusted_likelihood - 3)
        if threat.name in [ThreatName.SPOOFING, ThreatName.CACHE_POISONING]:
            if self.architecture.dnssec_validation:
                adjusted_likelihood = max(1, adjusted_likelihood - 2)
        if threat.name == ThreatName.DGA:
            if self.architecture.rpz_blocklists:
                adjusted_likelihood = max(1, adjusted_likelihood - 2)
        if threat.name in [ThreatName.EXFILTRATION, ThreatName.TUNNELING]:
            if self.architecture.logging_level == "detailed":
                adjusted_impact = max(1, adjusted_impact - 2)
        if threat.name == ThreatName.AMPLIFICATION:
            if self.architecture.rate_limiting:
                adjusted_likelihood = max(1, adjusted_likelihood - 2)
                adjusted_impact = max(1, adjusted_impact - 2)

        risk_score = min(100, max(1, adjusted_likelihood * adjusted_impact))
        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        vulnerable = risk_score >= 50
        return RiskAssessment(threat=threat, risk_score=risk_score, severity=severity, vulnerable=vulnerable)

    def assess_all_threats(self) -> list[RiskAssessment]:
        return [self.assess_threat(threat) for threat in self.THREAT_CATALOG]

class HardeningEngine:
    @staticmethod
    def generate_recommendations(assessments: list[RiskAssessment]) -> list[HardeningRecommendation]:
        recommendations = []
        for assessment in assessments:
            if not assessment.vulnerable:
                continue
            threat = assessment.threat
            threat_name = threat.name.value if isinstance(threat.name, ThreatName) else str(threat.name)
            recommendations.append(HardeningRecommendation(
                threat_name=threat_name,
                recommendation="Implement hardening measure",
                priority="HIGH",
                implementation_effort="MODERATE",
                expected_impact="Improves security posture"
            ))
        return recommendations

class ArchitectureComparator:
    @staticmethod
    def compare(before: DNSArchitecture, after: DNSArchitecture) -> dict[str, Any]:
        comparison = {
            "before": before.to_dict(),
            "after": after.to_dict(),
            "improvements": [],
            "security_posture_change": "NO CHANGE",
        }

        if before.encryption.value != after.encryption.value:
            comparison["improvements"].append(f"Encryption: {before.encryption.value} → {after.encryption.value}")
        if (not before.dnssec_validation) and after.dnssec_validation:
            comparison["improvements"].append("DNSSEC: disabled → enabled")
        if len(before.rpz_blocklists) < len(after.rpz_blocklists):
            comparison["improvements"].append(f"Blocklists: {len(before.rpz_blocklists)} → {len(after.rpz_blocklists)}")

        if comparison["improvements"]:
            comparison["security_posture_change"] = "SIGNIFICANT IMPROVEMENT"

        engine_before = ThreatAssessmentEngine(before)
        engine_after = ThreatAssessmentEngine(after)
        assessments_before = engine_before.assess_all_threats()
        assessments_after = engine_after.assess_all_threats()
        
        vuln_before = sum(1 for a in assessments_before if a.vulnerable)
        vuln_after = sum(1 for a in assessments_after if a.vulnerable)
        avg_risk_before = sum(a.risk_score for a in assessments_before) / len(assessments_before)
        avg_risk_after = sum(a.risk_score for a in assessments_after) / len(assessments_after)

        comparison["vulnerability_reduction"] = {"before_vulnerable": vuln_before, "after_vulnerable": vuln_after}
        comparison["risk_score_improvement"] = {"average_risk_before": round(avg_risk_before, 2), "average_risk_after": round(avg_risk_after, 2), "improvement": round(avg_risk_before - avg_risk_after, 2)}
        return comparison

class DiagramGenerator:
    @staticmethod
    def generate_diagram(architecture: DNSArchitecture) -> str:
        lines = ["=" * 70, f"DNS Architecture: {architecture.name}".center(70), "=" * 70, ""]
        lines.append("┌─────────────────────────────────────────────────────────┐")
        lines.append("│  CLIENT APPLICATIONS                                    │")
        lines.append("└──────────────────────┬──────────────────────────────────┘")
        lines.append("                       ▼")
        encryption_label = "(" + architecture.encryption.value.upper() + ")"
        lines.append(f"┌─────────────────────────────────────────────────────────┐")
        lines.append(f"│  {architecture.resolver_type.value.upper()} RESOLVER {encryption_label}      │")
        lines.append("└─────────────────────────────────────────────────────────┘")
        return "\n".join(lines)

class TimelineBuilder:
    @staticmethod
    def build_timeline(name: str, events_data: list[dict[str, Any]]) -> Timeline:
        timeline = Timeline(incident_name=name, start_time="", end_time="", events=[], affected_domains=[])
        if not events_data:
            return timeline
        parsed_events = [IncidentEvent(**ed) for ed in events_data]
        parsed_events.sort(key=lambda e: e.timestamp)
        timeline.events = parsed_events
        if parsed_events:
            timeline.start_time = parsed_events[0].timestamp
            timeline.end_time = parsed_events[-1].timestamp
        affected = set(e.target_domain for e in timeline.events if e.target_domain)
        timeline.affected_domains = sorted(list(affected))
        return timeline

    @staticmethod
    def timeline_narrative(timeline: Timeline) -> str:
        return f"Incident: {timeline.incident_name}\nStart: {timeline.start_time}\nEnd: {timeline.end_time}\nEvents: {len(timeline.events)}"

def format_threat_report(architecture: DNSArchitecture, assessments: list[RiskAssessment]) -> str:
    return f"Threat Assessment for {architecture.name}\nThreats analyzed: {len(assessments)}"

def format_recommendations_report(recommendations: list[HardeningRecommendation]) -> str:
    return f"Recommendations: {len(recommendations)} items"

def format_comparison_report(comparison: dict[str, Any]) -> str:
    return f"Comparison: {comparison['security_posture_change']}"

def main():
    parser = argparse.ArgumentParser(description="DNS Threat Model Analyzer")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    subparsers = parser.add_subparsers(dest="command")
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("config", type=str)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("before", type=str)
    compare_parser.add_argument("after", type=str)
    timeline_parser = subparsers.add_parser("timeline")
    timeline_parser.add_argument("events", type=str)
    diagram_parser = subparsers.add_parser("diagram")
    diagram_parser.add_argument("config", type=str)
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == "analyze":
            with open(args.config) as f:
                arch_data = json.load(f)
            architecture = DNSArchitecture(**arch_data)
            engine = ThreatAssessmentEngine(architecture)
            assessments = engine.assess_all_threats()
            recommendations = HardeningEngine.generate_recommendations(assessments)
            print(format_threat_report(architecture, assessments))
        elif args.command == "compare":
            with open(args.before) as f:
                before_data = json.load(f)
            with open(args.after) as f:
                after_data = json.load(f)
            before = DNSArchitecture(**before_data)
            after = DNSArchitecture(**after_data)
            comparison = ArchitectureComparator.compare(before, after)
            print(format_comparison_report(comparison))
        elif args.command == "timeline":
            with open(args.events) as f:
                events_data = json.load(f)
            timeline = TimelineBuilder.build_timeline("Incident", events_data)
            print(TimelineBuilder.timeline_narrative(timeline))
        elif args.command == "diagram":
            with open(args.config) as f:
                arch_data = json.load(f)
            architecture = DNSArchitecture(**arch_data)
            print(DiagramGenerator.generate_diagram(architecture))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
