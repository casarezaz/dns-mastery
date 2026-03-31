#!/usr/bin/env python3
"""
DGA Domain Classifier — Lab 08 of the DNS Mastery Study Plan
==============================================================
An ML-based domain classifier that distinguishes DGA-generated domains from legitimate ones.
Uses purely Python standard library with rule-based scoring for real-time classification.

Features analyzed:
  - Character frequency analysis (letter distribution)
  - Bigram frequency (consecutive letter pairs)
  - Shannon entropy (randomness measure)
  - Domain length profiling
  - Vowel/consonant ratio
  - Digit ratio and distribution
  - Unique character count
  - Longest consonant sequence
  - TLD analysis (legitimate vs suspicious TLDs)

DGA Families Detected:
  - Random Character (Conficker, Necurs-style)
  - Dictionary-based (Pykspa, Murofet, Redyms)
  - Hash-based (Cryptolocker, DGA.cc, Tinba)
  - Legitimate domains

MITRE ATT&CK Mapping:
    T1568.002 — Dynamic Resolution: Domain Generation Algorithms
    T1071.004 — Application Layer Protocol: DNS
    T1583.001 — Acquire Infrastructure: Domains

Author : Angie Casarez (casarezaz)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Tuple, Dict, List
from enum import Enum

__version__ = "1.0.0"


# ---------------------------------------------------------------------------
# Constants & Enumerations
# ---------------------------------------------------------------------------
class DGAFamily(Enum):
    """Suspected DGA family classification."""
    RANDOM_CHAR = "random_char"      # Random character generation
    DICTIONARY = "dictionary"         # Dictionary-based DGA
    HASH_BASED = "hash_based"        # Hash-based DGA (seeded)
    LEGITIMATE = "legitimate"         # Legitimate domain


class ClassificationStatus(Enum):
    """Overall classification result."""
    DGA = "DGA"
    LEGITIMATE = "LEGITIMATE"
    SUSPICIOUS = "SUSPICIOUS"


# Legitimate common TLDs
LEGITIMATE_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "co", "uk", "de", "fr", "es", "it", "nl", "be", "au", "ca", "jp", "cn", "in",
    "br", "mx", "ru", "se", "no", "ch", "at", "nz", "ie", "kr", "hk", "sg",
    "info", "biz", "us", "tv", "cc", "io", "mobi", "name", "asia", "travel",
    "app", "dev", "cloud", "ai", "tech", "online", "site", "shop", "blog",
}

# Suspicious TLDs sometimes used in DGA
SUSPICIOUS_TLDS = {
    "xyz", "click", "download", "racing", "stream", "gdn", "work", "gg",
    "pw", "tk", "ml", "ga", "cf", "ws",
}

# Common vowels and consonants
VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

# Expected bigram frequencies in English (top bigrams)
COMMON_ENGLISH_BIGRAMS = {
    "th", "he", "in", "er", "an", "re", "ed", "on", "en", "at",
    "es", "or", "te", "ar", "nd", "to", "it", "is", "st", "le",
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class DomainFeatures:
    """Extracted features from a domain name."""
    domain: str
    sld: str                          # Second-level domain (before TLD)
    tld: str                          # Top-level domain
    length: int                        # Domain length (excluding TLD)
    entropy: float                     # Shannon entropy of SLD
    char_frequency: Dict[str, float]   # Letter frequency as %
    bigram_count: int                  # Number of bigrams in SLD
    common_bigrams: int                # Count of common English bigrams
    vowel_ratio: float                 # Percentage of vowels
    consonant_ratio: float             # Percentage of consonants
    digit_ratio: float                 # Percentage of digits
    unique_char_count: int             # Distinct characters
    longest_consonant_seq: int         # Length of longest consonant run
    has_digits: bool                   # True if domain contains digits
    digit_count: int                   # Number of digits
    uppercase_ratio: float             # Ratio of uppercase letters
    has_consecutive_vowels: bool       # True if 2+ consecutive vowels
    has_consecutive_consonants: bool   # True if 3+ consecutive consonants

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/CSV export."""
        d = asdict(self)
        d.pop('char_frequency', None)  # Remove nested dict for export
        return d


@dataclass
class ClassificationResult:
    """Result of domain classification."""
    domain: str
    sld: str
    tld: str
    classification: ClassificationStatus
    dga_family: DGAFamily
    confidence: float                  # 0.0 - 1.0
    score: float                       # 0.0 - 100.0
    features: DomainFeatures           # Features used
    reasons: List[str] = field(default_factory=list)  # Why classified as DGA

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/CSV export."""
        return {
            "domain": self.domain,
            "sld": self.sld,
            "tld": self.tld,
            "classification": self.classification.value,
            "dga_family": self.dga_family.value,
            "confidence": round(self.confidence, 3),
            "score": round(self.score, 1),
            "reasons": "; ".join(self.reasons),
        }


@dataclass
class ModelConfig:
    """Configuration parameters for the classifier model."""
    # Entropy thresholds
    entropy_dga_min: float = 3.6      # Min entropy for DGA
    entropy_legit_max: float = 3.0    # Max entropy for legitimate

    # Character distribution thresholds
    unique_char_threshold: float = 0.65  # Min unique char ratio for DGA
    digit_ratio_threshold: float = 0.15  # Min digit ratio for DGA

    # Consonant sequence threshold
    consonant_seq_threshold: int = 4   # Min consonant run for DGA

    # Vowel ratio thresholds
    vowel_ratio_dga_max: float = 0.30  # Max vowel ratio for DGA
    vowel_ratio_legit_min: float = 0.25  # Min vowel ratio for legitimate

    # Common bigram threshold
    common_bigram_ratio_legit: float = 0.35  # Min common bigrams ratio for legit

    # Overall DGA score threshold
    dga_threshold: float = 55.0        # Score above this = DGA
    legit_threshold: float = 35.0      # Score below this = LEGITIMATE

    # TLD analysis
    penalize_suspicious_tld: float = 15.0  # Points for suspicious TLD
    reward_legit_tld: float = -20.0   # Points for legitimate TLD


# ---------------------------------------------------------------------------
# Feature Extraction Functions
# ---------------------------------------------------------------------------
def extract_sld_and_tld(domain: str) -> Tuple[str, str]:
    """
    Extract SLD (second-level domain) and TLD from domain name.

    Args:
        domain: Full domain name (e.g., "example.com")

    Returns:
        Tuple of (sld, tld) - always lowercase
    """
    domain = domain.lower().strip()

    # Remove trailing dot if present
    if domain.endswith('.'):
        domain = domain[:-1]

    parts = domain.rsplit('.', 1)
    if len(parts) == 1:
        return parts[0], ""

    sld, tld = parts
    return sld, tld


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.

    Args:
        text: Input string

    Returns:
        Entropy in bits per character (0.0 - ~5.7 for ASCII)
    """
    if not text:
        return 0.0

    # Count character frequencies
    freqs = Counter(text)
    text_len = len(text)

    # Calculate entropy
    entropy = 0.0
    for count in freqs.values():
        p = count / text_len
        entropy -= p * math.log2(p)

    return entropy


def analyze_bigrams(text: str) -> Tuple[int, int]:
    """
    Analyze bigrams (consecutive letter pairs) in text.

    Args:
        text: Input string

    Returns:
        Tuple of (total_bigrams, common_english_bigrams)
    """
    text_lower = text.lower()
    bigrams = [text_lower[i:i+2] for i in range(len(text_lower) - 1)]

    if not bigrams:
        return 0, 0

    common_count = sum(1 for bg in bigrams if bg in COMMON_ENGLISH_BIGRAMS)
    return len(bigrams), common_count


def analyze_consonant_sequences(text: str) -> int:
    """
    Find longest sequence of consecutive consonants.

    Args:
        text: Input string

    Returns:
        Length of longest consonant sequence
    """
    text_lower = text.lower()
    max_seq = 0
    current_seq = 0

    for char in text_lower:
        if char in CONSONANTS:
            current_seq += 1
            max_seq = max(max_seq, current_seq)
        else:
            current_seq = 0

    return max_seq


def analyze_consecutive_patterns(text: str) -> Tuple[bool, bool]:
    """
    Analyze for consecutive vowels (2+) and consonants (3+).

    Args:
        text: Input string

    Returns:
        Tuple of (has_consecutive_vowels, has_consecutive_consonants)
    """
    text_lower = text.lower()
    vowel_seq = 0
    consonant_seq = 0
    has_consec_vowels = False
    has_consec_consonants = False

    for char in text_lower:
        if char in VOWELS:
            vowel_seq += 1
            consonant_seq = 0
            if vowel_seq >= 2:
                has_consec_vowels = True
        elif char in CONSONANTS:
            consonant_seq += 1
            vowel_seq = 0
            if consonant_seq >= 3:
                has_consec_consonants = True
        else:
            vowel_seq = 0
            consonant_seq = 0

    return has_consec_vowels, has_consec_consonants


def extract_features(domain: str) -> DomainFeatures:
    """
    Extract all features from a domain name.

    Args:
        domain: Full domain name

    Returns:
        DomainFeatures object
    """
    sld, tld = extract_sld_and_tld(domain)
    sld_lower = sld.lower()

    # Basic measurements
    length = len(sld)
    entropy = calculate_entropy(sld_lower)

    # Character frequency analysis
    char_counts = Counter(c for c in sld_lower if c.isalpha())
    total_letters = sum(char_counts.values())
    char_frequency = {
        ch: (count / total_letters * 100) if total_letters > 0 else 0
        for ch, count in char_counts.items()
    }

    # Bigram analysis
    bigram_total, bigram_common = analyze_bigrams(sld)

    # Vowel and consonant analysis
    vowel_count = sum(1 for c in sld_lower if c in VOWELS)
    consonant_count = sum(1 for c in sld_lower if c in CONSONANTS)
    vowel_ratio = (vowel_count / total_letters) if total_letters > 0 else 0.0
    consonant_ratio = (consonant_count / total_letters) if total_letters > 0 else 0.0

    # Digit analysis
    digit_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = (digit_count / length) if length > 0 else 0.0

    # Unique characters
    unique_char_count = len(set(sld_lower))
    unique_char_ratio = (unique_char_count / length) if length > 0 else 0.0

    # Consonant sequences
    longest_consonant_seq = analyze_consonant_sequences(sld)

    # Uppercase ratio
    uppercase_count = sum(1 for c in sld if c.isupper())
    uppercase_ratio = (uppercase_count / length) if length > 0 else 0.0

    # Consecutive patterns
    has_consec_vowels, has_consec_consonants = analyze_consecutive_patterns(sld)

    return DomainFeatures(
        domain=domain,
        sld=sld,
        tld=tld,
        length=length,
        entropy=entropy,
        char_frequency=char_frequency,
        bigram_count=bigram_total,
        common_bigrams=bigram_common,
        vowel_ratio=vowel_ratio,
        consonant_ratio=consonant_ratio,
        digit_ratio=digit_ratio,
        unique_char_count=unique_char_count,
        longest_consonant_seq=longest_consonant_seq,
        has_digits=(digit_count > 0),
        digit_count=digit_count,
        uppercase_ratio=uppercase_ratio,
        has_consecutive_vowels=has_consec_vowels,
        has_consecutive_consonants=has_consec_consonants,
    )


# ---------------------------------------------------------------------------
# Classification Functions
# ---------------------------------------------------------------------------
def estimate_dga_family(features: DomainFeatures, score: float) -> DGAFamily:
    """
    Estimate the DGA family based on characteristics.

    Args:
        features: Extracted features
        score: DGA likelihood score

    Returns:
        Estimated DGAFamily
    """
    if score < 40.0:
        return DGAFamily.LEGITIMATE

    # High entropy + many unique chars = random character DGA
    if features.entropy > 4.2 and features.unique_char_count >= (features.length * 0.75):
        return DGAFamily.RANDOM_CHAR

    # High digit ratio + moderate entropy = hash-based DGA
    if features.digit_ratio > 0.15 and features.entropy > 3.5:
        return DGAFamily.HASH_BASED

    # Moderate entropy + vowel-consonant patterns = dictionary-based
    if features.entropy > 3.0 and features.entropy <= 3.8:
        return DGAFamily.DICTIONARY

    # Default to random char if high DGA score
    if score > 70.0:
        return DGAFamily.RANDOM_CHAR

    return DGAFamily.DICTIONARY


def classify_domain(domain: str, config: ModelConfig = None) -> ClassificationResult:
    """
    Classify a single domain as DGA or legitimate.

    Args:
        domain: Domain name to classify
        config: ModelConfig with classification parameters

    Returns:
        ClassificationResult object
    """
    if config is None:
        config = ModelConfig()

    # Extract features
    features = extract_features(domain)
    sld, tld = features.sld, features.tld

    # Initialize scoring
    score = 0.0
    reasons = []

    # Rule 1: Entropy analysis
    if features.entropy > config.entropy_dga_min:
        entropy_contrib = (features.entropy - config.entropy_dga_min) * 8
        score += min(entropy_contrib, 25)
        reasons.append(f"High entropy: {features.entropy:.2f}")
    elif features.entropy > config.entropy_legit_max:
        score += 10
        reasons.append(f"Moderate entropy: {features.entropy:.2f}")

    # Rule 2: Unique character count
    unique_char_ratio = features.unique_char_count / features.length if features.length > 0 else 0
    if unique_char_ratio > config.unique_char_threshold:
        score += 20
        reasons.append(f"High unique char ratio: {unique_char_ratio:.2%}")

    # Rule 3: Vowel ratio (low vowel = suspicious)
    if features.vowel_ratio < config.vowel_ratio_dga_max:
        score += 15
        reasons.append(f"Low vowel ratio: {features.vowel_ratio:.2%}")
    elif features.vowel_ratio > config.vowel_ratio_legit_min:
        score -= 5
        reasons.append(f"Natural vowel ratio: {features.vowel_ratio:.2%}")

    # Rule 4: Digit ratio
    if features.digit_ratio > config.digit_ratio_threshold:
        score += 12
        reasons.append(f"High digit ratio: {features.digit_ratio:.2%}")

    # Rule 5: Consonant sequences (long runs are unnatural)
    if features.longest_consonant_seq >= config.consonant_seq_threshold:
        seq_contrib = (features.longest_consonant_seq - 3) * 4
        score += min(seq_contrib, 15)
        reasons.append(f"Long consonant sequence: {features.longest_consonant_seq}")

    # Rule 6: Common bigrams (few = suspicious)
    if features.bigram_count > 0:
        common_ratio = features.common_bigrams / features.bigram_count
        if common_ratio < config.common_bigram_ratio_legit:
            score += 12
            reasons.append(f"Few common bigrams: {common_ratio:.2%}")
        else:
            score -= 8
            reasons.append(f"Natural bigram pattern: {common_ratio:.2%}")

    # Rule 7: Domain length (very short or very long is suspicious)
    if features.length < 5 or features.length > 20:
        score += 8
        reasons.append(f"Atypical length: {features.length}")

    # Rule 8: TLD analysis
    if tld.lower() in SUSPICIOUS_TLDS:
        score += config.penalize_suspicious_tld
        reasons.append(f"Suspicious TLD: {tld}")
    elif tld.lower() in LEGITIMATE_TLDS:
        score += config.reward_legit_tld  # Negative = reduces score
        reasons.append(f"Legitimate TLD: {tld}")

    # Rule 9: Consecutive patterns
    if features.has_consecutive_consonants:
        score += 10
        reasons.append("Unnatural consonant clusters")

    # Rule 10: Mostly consonants
    if features.consonant_ratio > 0.75:
        score += 12
        reasons.append(f"Very high consonant ratio: {features.consonant_ratio:.2%}")

    # Clamp score to 0-100
    score = max(0.0, min(100.0, score))

    # Determine classification and confidence
    if score >= config.dga_threshold:
        classification = ClassificationStatus.DGA
        confidence = min(1.0, (score - config.dga_threshold) / 50.0)
    elif score <= config.legit_threshold:
        classification = ClassificationStatus.LEGITIMATE
        confidence = 1.0 - (score / config.legit_threshold)
    else:
        classification = ClassificationStatus.SUSPICIOUS
        confidence = 0.5

    # Estimate DGA family
    dga_family = estimate_dga_family(features, score)

    return ClassificationResult(
        domain=domain,
        sld=sld,
        tld=tld,
        classification=classification,
        dga_family=dga_family,
        confidence=confidence,
        score=score,
        features=features,
        reasons=reasons,
    )


# ---------------------------------------------------------------------------
# Batch Processing
# ---------------------------------------------------------------------------
def load_domains_from_file(filepath: Path) -> List[str]:
    """
    Load domains from various file formats.

    Supports:
    - Plain text (one domain per line)
    - CSV (expects 'domain' column)
    - JSON (list of domains or list of objects with 'domain' key)

    Args:
        filepath: Path to domain file

    Returns:
        List of domain names
    """
    domains = []
    content = filepath.read_text().strip()

    # Try JSON first
    if content.startswith('[') or content.startswith('{'):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        domains.append(item)
                    elif isinstance(item, dict) and 'domain' in item:
                        domains.append(item['domain'])
            return domains
        except (json.JSONDecodeError, KeyError):
            pass

    # Try CSV
    if ',' in content[:100]:
        try:
            lines = content.split('\n')
            reader = csv.DictReader(lines)
            for row in reader:
                if row and 'domain' in row:
                    domains.append(row['domain'].strip())
            if domains:
                return domains
        except (KeyError, ValueError):
            pass

    # Default to plain text (one per line)
    domains = [line.strip() for line in content.split('\n') if line.strip()]

    return domains


def classify_batch(domains: List[str], config: ModelConfig = None) -> List[ClassificationResult]:
    """
    Classify multiple domains.

    Args:
        domains: List of domain names
        config: ModelConfig

    Returns:
        List of ClassificationResult objects
    """
    if config is None:
        config = ModelConfig()

    results = []
    for domain in domains:
        try:
            result = classify_domain(domain, config)
            results.append(result)
        except Exception as e:
            print(f"Error classifying {domain}: {e}", file=sys.stderr)

    return results


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def format_text_report(results: List[ClassificationResult]) -> str:
    """Generate human-readable text report."""
    lines = []
    lines.append("=" * 80)
    lines.append("DGA DOMAIN CLASSIFIER REPORT")
    lines.append("=" * 80)
    lines.append("")

    # Summary statistics
    dga_count = sum(1 for r in results if r.classification == ClassificationStatus.DGA)
    legit_count = sum(1 for r in results if r.classification == ClassificationStatus.LEGITIMATE)
    susp_count = sum(1 for r in results if r.classification == ClassificationStatus.SUSPICIOUS)

    lines.append(f"Total Domains: {len(results)}")
    if len(results) > 0:
        lines.append(f"  DGA:        {dga_count} ({dga_count/len(results)*100:.1f}%)")
        lines.append(f"  Legitimate: {legit_count} ({legit_count/len(results)*100:.1f}%)")
        lines.append(f"  Suspicious: {susp_count} ({susp_count/len(results)*100:.1f}%)")
    else:
        lines.append(f"  DGA:        0 (0.0%)")
        lines.append(f"  Legitimate: 0 (0.0%)")
        lines.append(f"  Suspicious: 0 (0.0%)")
    lines.append("")

    # DGA Family breakdown
    families = Counter(r.dga_family for r in results if r.classification == ClassificationStatus.DGA)
    if families:
        lines.append("DGA Families Detected:")
        for family, count in sorted(families.items(), key=lambda x: -x[1]):
            lines.append(f"  {family.value}: {count}")
        lines.append("")

    # Detailed results
    lines.append("DETAILED RESULTS:")
    lines.append("-" * 80)

    for result in sorted(results, key=lambda r: -r.score):
        lines.append(f"Domain: {result.domain}")
        lines.append(f"  Classification: {result.classification.value}")
        lines.append(f"  Score: {result.score:.1f}/100 | Confidence: {result.confidence:.1%}")
        lines.append(f"  DGA Family: {result.dga_family.value}")

        if result.reasons:
            lines.append(f"  Reasons:")
            for reason in result.reasons:
                lines.append(f"    - {reason}")

        lines.append(f"  Features: entropy={result.features.entropy:.2f}, "
                    f"vowel_ratio={result.features.vowel_ratio:.2%}, "
                    f"digit_ratio={result.features.digit_ratio:.2%}, "
                    f"length={result.features.length}, "
                    f"unique_chars={result.features.unique_char_count}")
        lines.append("")

    return "\n".join(lines)


def format_json_report(results: List[ClassificationResult]) -> str:
    """Generate JSON report."""
    data = {
        "summary": {
            "total": len(results),
            "dga": sum(1 for r in results if r.classification == ClassificationStatus.DGA),
            "legitimate": sum(1 for r in results if r.classification == ClassificationStatus.LEGITIMATE),
            "suspicious": sum(1 for r in results if r.classification == ClassificationStatus.SUSPICIOUS),
        },
        "results": [r.to_dict() for r in results],
    }
    return json.dumps(data, indent=2)


def format_csv_report(results: List[ClassificationResult]) -> str:
    """Generate CSV report."""
    if not results:
        return ""

    fieldnames = list(results[0].to_dict().keys())

    lines = []
    # Manual CSV generation
    lines.append(",".join(fieldnames))
    for result in results:
        row = result.to_dict()
        values = []
        for field in fieldnames:
            val = row.get(field, "")
            if isinstance(val, str) and ("," in val or '"' in val):
                val = f'"{val.replace(chr(34), chr(34)+chr(34))}"'
            values.append(str(val))
        lines.append(",".join(values))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    """Command-line interface."""
    parser = argparse.ArgumentParser(
        description="DGA Domain Classifier — Detect DGA-generated domains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Classify a single domain
  python3 dga_classifier.py example.com

  # Classify domains from a file
  python3 dga_classifier.py domains.txt

  # JSON output
  python3 dga_classifier.py --format json domains.txt

  # Tune DGA threshold
  python3 dga_classifier.py --dga-threshold 60 domains.txt

  # Only show DGA domains
  python3 dga_classifier.py --min-score 55 domains.txt
        """
    )

    parser.add_argument("domain", nargs="*", help="Domain(s) to classify (or file path)")
    parser.add_argument("--file", "-f", help="Input file (domains or CSV)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--format", "-F", choices=["text", "json", "csv"], default="text",
                       help="Output format (default: text)")
    parser.add_argument("--dga-threshold", type=float, default=55.0,
                       help="Score threshold for DGA classification (default: 55)")
    parser.add_argument("--legit-threshold", type=float, default=35.0,
                       help="Score threshold for LEGITIMATE classification (default: 35)")
    parser.add_argument("--min-score", type=float,
                       help="Only report domains with score >= N")
    parser.add_argument("--entropy-threshold", type=float,
                       help="Entropy threshold for DGA (default: 3.6)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--version", "-V", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Collect domains
    domains = []

    if args.file:
        filepath = Path(args.file)
        if filepath.exists():
            domains = load_domains_from_file(filepath)
            if args.verbose:
                print(f"[*] Loaded {len(domains)} domains from {args.file}", file=sys.stderr)

    if args.domain:
        # Check if it's a file path
        potential_file = Path(args.domain[0])
        if potential_file.exists() and potential_file.is_file():
            domains = load_domains_from_file(potential_file)
            if args.verbose:
                print(f"[*] Loaded {len(domains)} domains from {args.domain[0]}", file=sys.stderr)
        else:
            domains.extend(args.domain)

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Configure model
    config = ModelConfig()
    config.dga_threshold = args.dga_threshold
    config.legit_threshold = args.legit_threshold
    if args.entropy_threshold:
        config.entropy_dga_min = args.entropy_threshold

    # Classify
    if args.verbose:
        print(f"[*] Classifying {len(domains)} domains...", file=sys.stderr)

    results = classify_batch(domains, config)

    # Filter by min score if specified
    if args.min_score is not None:
        results = [r for r in results if r.score >= args.min_score]

    # Format output
    if args.format == "json":
        output = format_json_report(results)
    elif args.format == "csv":
        output = format_csv_report(results)
    else:
        output = format_text_report(results)

    # Write output
    if args.output:
        Path(args.output).write_text(output)
        if args.verbose:
            print(f"[*] Report written to {args.output}", file=sys.stderr)
    else:
        print(output)

    # Exit code: 0 if no DGA, 1 if DGA detected
    dga_count = sum(1 for r in results if r.classification == ClassificationStatus.DGA)
    sys.exit(1 if dga_count > 0 else 0)


if __name__ == "__main__":
    main()
