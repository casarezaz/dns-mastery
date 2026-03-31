# Lab 08 — DGA Domain Classifier

A **machine learning-based domain classifier** that distinguishes **DGA-generated domains** from legitimate ones using rule-based feature scoring and character analysis. Detects malicious domains created by automated Domain Generation Algorithms (DGAs) used in botnets and malware C2 infrastructure.

DGAs are a critical evasion technique: botnets like Conficker, Cryptolocker, and Tinba generate hundreds of thousands of random or pseudo-random domains daily to maintain resilient C2 communication. This tool analyzes domain characteristics to identify algorithmically-generated domains in real-time.

## Features

- **Zero external dependencies** — pure Python 3.10+ standard library
- **Real-time classification** — classify domains instantly
- **Feature extraction**:
  - Shannon entropy analysis (randomness measurement)
  - Character frequency distribution
  - Bigram analysis (common English letter pairs)
  - Vowel/consonant ratio profiling
  - Digit ratio and distribution
  - Consonant sequence detection (unnatural letter clusters)
  - Unique character count
  - TLD analysis (legitimate vs suspicious)
  - Domain length profiling
- **Rule-based scoring classifier** (no neural networks, no scikit-learn):
  - Weighted feature scoring (0–100 scale)
  - Tunable thresholds for all detection rules
  - Confidence scoring (0.0–1.0) based on conviction
  - Three classification categories: DGA, LEGITIMATE, SUSPICIOUS
- **DGA family estimation**:
  - Random character generation (Conficker, Necurs)
  - Dictionary-based (Pykspa, Murofet)
  - Hash-based seeded (Cryptolocker, DGA.cc)
  - Legitimate (benign domains)
- **Flexible input formats**:
  - Single domain from command line
  - Plain text files (one domain per line)
  - CSV with domain column
  - JSON arrays or objects with domain field
- **Multiple output formats**:
  - Human-readable text reports (detailed analysis)
  - JSON for automation and downstream tools
  - CSV for spreadsheet analysis
- **Batch processing** — classify 100s of domains in seconds
- **Production detection rules**:
  - **8 Splunk SPL queries** for real-time DNS monitoring
  - **5 Sigma YAML rules** for SIEM integration
- **Sample data generator** with 4 DGA families and 200 legitimate domains

## MITRE ATT&CK Mapping

| Technique | Name | What This Detects |
|-----------|------|-------------------|
| [T1568.002](https://attack.mitre.org/techniques/T1568/002/) | Dynamic Resolution: Domain Generation Algorithms | DGA domain detection and family classification |
| [T1071.004](https://attack.mitre.org/techniques/T1071/004/) | Application Layer Protocol: DNS | Analyzes DNS query patterns via domain characteristics |
| [T1583.001](https://attack.mitre.org/techniques/T1583/001/) | Acquire Infrastructure: Domains | Identifies attacker infrastructure acquisition via DGA |

## Classification Algorithm

### Feature Analysis

#### 1. **Shannon Entropy**
Measures randomness in domain name (0.0–5.7 bits/char).
- **Legitimate:** 2.0–3.2 (recognizable words)
- **DGA:** > 3.6 (random-looking)
- Example: `google.com` = 2.3, `xkpdmqrt.com` = 4.4

#### 2. **Character Frequency**
Analyzes distribution of letters A-Z.
- **Legitimate:** Follows English language patterns
- **DGA:** Uniform or unusual distribution
- Scoring: Count of unique characters relative to domain length

#### 3. **Bigram Analysis**
Examines consecutive letter pairs (A→B transitions).
- **Legitimate:** Common English bigrams (th, he, er, in, etc.)
- **DGA:** Few or no common bigrams
- Example: `the` has bigrams "th" and "he" (both common)

#### 4. **Vowel/Consonant Ratio**
Natural languages maintain vowel-consonant balance.
- **Legitimate:** 30–50% vowels
- **DGA:** < 30% vowels (too many consonants)
- Example: `google` = 50% vowels, `xkpdmqrt` = 12% vowels

#### 5. **Digit Ratio**
Measures percentage of numeric characters (0-9).
- **Legitimate:** 0–10% (selective use in versions, subdomains)
- **DGA:** > 15% (hash-based DGAs embed numbers)

#### 6. **Consonant Sequences**
Detects unnatural runs of consecutive consonants.
- **Legitimate:** Max 3-4 (e.g., "strength")
- **DGA:** 4+ (artificial clustering like "bfghjkl")
- Scoring: Length of longest run

#### 7. **Unique Character Count**
Ratio of distinct characters to total length.
- **Legitimate:** 60–75% unique characters
- **DGA:** > 75% (high variety = less recognizable)

#### 8. **TLD Analysis**
Evaluates top-level domain legitimacy.
- **Legitimate TLDs:** com, org, net, edu, gov, country codes
- **Suspicious TLDs:** xyz, click, download, racing, tk, ml, ga, cf
- Scoring: +15 points for suspicious, -20 points for legitimate

#### 9. **Domain Length**
Analyzes total domain length (excluding TLD).
- **Legitimate:** 5–15 characters
- **Suspicious:** < 5 or > 20 characters
- Natural variation in business names

### Scoring Algorithm

Each feature contributes points (0–100 total):

```
Score = 0
Score += entropy_contribution (0–25 points)
Score += unique_char_contribution (0–20 points)
Score += vowel_ratio_contribution (0–15 points)
Score += digit_ratio_contribution (0–12 points)
Score += consonant_sequence_contribution (0–15 points)
Score += bigram_contribution (0–12 points)
Score += length_anomaly (0–8 points)
Score += tld_analysis (±20 points)
Score += consecutive_consonants (0–10 points)
Score += consonant_dominance (0–12 points)
```

**Classification Thresholds (configurable):**
- Score >= 55.0 → **DGA** (high confidence)
- Score <= 35.0 → **LEGITIMATE** (high confidence)
- 35.0 < Score < 55.0 → **SUSPICIOUS** (uncertain)

**Confidence = (Score - Threshold) / 50.0** (clamped 0.0–1.0)

### DGA Family Estimation

Based on feature patterns:

| Family | Entropy | Digits | Vowels | Bigrams | Example |
|--------|---------|--------|--------|---------|---------|
| **Random Char** | > 4.2 | Low | < 25% | None | xkpdmqrt.com |
| **Dictionary** | 3.0–3.8 | Low | 30–40% | 20–40% | applecherry.com |
| **Hash-Based** | 3.5–4.0 | > 15% | Low | Few | a7f2c3e8d9.com |
| **Legitimate** | < 3.2 | 0–10% | 30–50% | > 40% | example.com |

## Installation

No installation required — clone and run:

```bash
cd dns-mastery/lab-08-dga-classifier
python3 dga_classifier.py --help
```

**Requirements:** Python 3.10+ (standard library only)

## Quick Start

### Generate sample data

```bash
cd sample_data
python3 generate_dga_data.py
```

Creates:
- `dga_domains.txt` (200 DGA domains)
- `legitimate_domains.txt` (200 legitimate domains)
- `labeled_domains.csv` (400 labeled domains for evaluation)
- `labeled_domains.json` (JSON format)

### Classify a single domain

```bash
python3 dga_classifier.py example.com
python3 dga_classifier.py xkpdmqrt.com
```

Output shows classification, confidence, score, DGA family, and analysis reasons.

### Classify domains from a file

```bash
# Plain text (one domain per line)
python3 dga_classifier.py domains.txt

# CSV (expects 'domain' column)
python3 dga_classifier.py domains.csv

# JSON array
python3 dga_classifier.py domains.json
```

### Batch classification with JSON output

```bash
python3 dga_classifier.py sample_data/dga_domains.txt \
  --format json \
  --output dga_classification.json
```

### Filter to high-confidence DGA domains

```bash
python3 dga_classifier.py domains.txt \
  --min-score 70 \
  --format csv \
  --output high_confidence_dga.csv
```

### Tune classification thresholds

```bash
# Stricter DGA detection (fewer false positives)
python3 dga_classifier.py domains.txt --dga-threshold 65

# Looser DGA detection (fewer false negatives)
python3 dga_classifier.py domains.txt --dga-threshold 45

# Custom entropy threshold
python3 dga_classifier.py domains.txt --entropy-threshold 3.8
```

### Run tests

```bash
python3 -m unittest test_dga_classifier -v

# Run specific test class
python3 -m unittest test_dga_classifier.TestClassification -v

# Run specific test
python3 -m unittest test_dga_classifier.TestClassification.test_legitimate_domains -v
```

## CLI Usage

```
usage: dga_classifier [-h] [--file FILE] [--output FILE]
                      [--format {text,json,csv}]
                      [--dga-threshold THRESHOLD]
                      [--legit-threshold THRESHOLD]
                      [--min-score SCORE]
                      [--entropy-threshold ENTROPY]
                      [--verbose] [--version]
                      [domain ...]

DGA Domain Classifier — Detect DGA-generated domains

positional arguments:
  domain                Domain(s) to classify (or file path)

options:
  --file FILE, -f FILE  Input file (domains or CSV)
  --output FILE, -o FILE
                        Output file (default: stdout)
  --format {text,json,csv}, -F {text,json,csv}
                        Output format (default: text)
  --dga-threshold THRESHOLD
                        Score threshold for DGA (default: 55)
  --legit-threshold THRESHOLD
                        Score threshold for LEGITIMATE (default: 35)
  --min-score SCORE     Only report domains with score >= N
  --entropy-threshold ENTROPY
                        Entropy threshold for DGA (default: 3.6)
  --verbose, -v         Verbose output to stderr
  --version, -V         Show version and exit
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No DGA domains detected |
| 1 | DGA domains detected (one or more) |

## Output Formats

### Text Report (default)

Human-readable with summary and detailed analysis:

```
================================================================================
DGA DOMAIN CLASSIFIER REPORT
================================================================================

Total Domains: 3
  DGA:        1 (33.3%)
  Legitimate: 2 (66.7%)
  Suspicious: 0 (0.0%)

DGA Families Detected:
  random_char: 1

DETAILED RESULTS:
--------------------------------------------------------------------------------
Domain: xkpdmqrt.com
  Classification: DGA
  Score: 72.5/100 | Confidence: 45.0%
  DGA Family: random_char
  Reasons:
    - High entropy: 4.12
    - High unique char ratio: 87.50%
    - Low vowel ratio: 12.50%
    - Long consonant sequence: 5
    - Few common bigrams: 0.00%
    - Unnatural consonant clusters
  Features: entropy=4.12, vowel_ratio=12.50%, digit_ratio=0.00%, length=8, unique_chars=7

Domain: google.com
  Classification: LEGITIMATE
  Score: 28.3/100 | Confidence: 68.2%
  DGA Family: legitimate
  Reasons:
    - Moderate entropy: 2.87
    - Natural vowel ratio: 42.86%
    - Natural bigram pattern: 66.67%
    - Legitimate TLD: com
  Features: entropy=2.87, vowel_ratio=42.86%, digit_ratio=0.00%, length=6, unique_chars=5
```

### JSON Report

Machine-readable structured output:

```json
{
  "summary": {
    "total": 3,
    "dga": 1,
    "legitimate": 2,
    "suspicious": 0
  },
  "results": [
    {
      "domain": "xkpdmqrt.com",
      "sld": "xkpdmqrt",
      "tld": "com",
      "classification": "DGA",
      "dga_family": "random_char",
      "confidence": 0.45,
      "score": 72.5,
      "reasons": "High entropy: 4.12; High unique char ratio: 87.50%; ..."
    },
    {
      "domain": "google.com",
      "sld": "google",
      "tld": "com",
      "classification": "LEGITIMATE",
      "dga_family": "legitimate",
      "confidence": 0.682,
      "score": 28.3,
      "reasons": "Moderate entropy: 2.87; Natural vowel ratio: 42.86%; ..."
    }
  ]
}
```

### CSV Report

Spreadsheet-compatible format:

```csv
domain,sld,tld,classification,dga_family,confidence,score,reasons
xkpdmqrt.com,xkpdmqrt,com,DGA,random_char,0.45,72.5,"High entropy: 4.12; High unique char ratio: 87.50%; ..."
google.com,google,com,LEGITIMATE,legitimate,0.682,28.3,"Moderate entropy: 2.87; Natural vowel ratio: 42.86%; ..."
```

## Sample Data

Pre-generated dataset of 400 labeled domains (200 DGA, 200 legitimate):

- **`dga_domains.txt`**: 200 DGA-generated domains (4 families)
  - Random character (50): `xkpdmqrt.com`, `qpqpmqmr.com`
  - Dictionary-based (50): `applecherry.com`, `bananaforest42.net`
  - Hash-based (50): `a7f2c3e8d9b1.com`, `f4e2d7a5c89.net`
  - Morphing (50): Blends of above

- **`legitimate_domains.txt`**: 200 realistic legitimate domains
  - Real company names: Google, Amazon, Microsoft, etc.
  - Common TLDs and subdomains
  - Examples: `google.com`, `api.github.com`, `mail.example.org`

- **`labeled_domains.csv`**: All 400 domains with labels and DGA family
  - For evaluation, confusion matrix analysis, model testing

- **`labeled_domains.json`**: JSON format of labeled data

**See `sample_data/MANIFEST.md` for detailed dataset information.**

## Evaluation Metrics

Evaluate classifier performance on labeled data:

```bash
python3 dga_classifier.py sample_data/labeled_domains.csv \
  --format json --output eval_results.json

# Parse eval_results.json to compute:
# True Positives (TP): DGA classified as DGA
# True Negatives (TN): Legitimate classified as Legitimate
# False Positives (FP): Legitimate classified as DGA
# False Negatives (FN): DGA classified as Legitimate
#
# Accuracy = (TP + TN) / (TP + TN + FP + FN)
# Precision = TP / (TP + FP)
# Recall = TP / (TP + FN)
# F1-Score = 2 * (Precision * Recall) / (Precision + Recall)
```

## Detection Rules

### Splunk Queries (8 total)

Located in `detections/dga_detection_splunk.spl`:

1. **High-entropy domain detection** — Find domains with entropy > 3.6
2. **Consonant cluster analysis** — Flag unnatural consonant runs
3. **Digit-heavy domains** — Identify domains with > 15% digits
4. **Low-vowel domains** — Suspicious vowel ratios < 30%
5. **Suspicious TLD detection** — Alert on xyz, click, download, etc.
6. **DGA domain summary** — Daily report of detected DGA domains
7. **DGA family breakdown** — Statistics by DGA family type
8. **Trend analysis** — Track DGA detection over time

### Sigma Rules (5 total)

Located in `detections/dga_detection.yml`:

1. **High-Entropy Domain Query** — Generic DGA detection
2. **Dictionary-Based DGA Pattern** — Concatenated dictionary words
3. **Hash-Based DGA Pattern** — Random alphanumeric with numbers
4. **Suspicious TLD Query** — Detection of suspicious TLDs
5. **DGA Family Clustering** — Group related DGA queries

Integration examples:
```bash
# Sigma to Splunk conversion
python3 -m sigma.rule -f splunk \
  detections/dga_detection.yml > dga_detection_splunk.spl

# Sigma to Elastic/ECS
python3 -m sigma.rule -f eql \
  detections/dga_detection.yml > dga_detection_eql.eql
```

## Implementation Details

### Architecture

```
dga_classifier.py (700 lines)
├── Feature Extraction (200 lines)
│   ├── extract_sld_and_tld()
│   ├── calculate_entropy()
│   ├── analyze_bigrams()
│   ├── analyze_consonant_sequences()
│   └── analyze_consecutive_patterns()
├── Classification Engine (250 lines)
│   ├── extract_features()
│   ├── classify_domain()
│   ├── estimate_dga_family()
│   └── ModelConfig dataclass
├── Batch Processing (100 lines)
│   ├── classify_batch()
│   └── load_domains_from_file()
├── Reporting (150 lines)
│   ├── format_text_report()
│   ├── format_json_report()
│   └── format_csv_report()
└── CLI (50 lines)
    └── main()
```

### Data Structures

**DomainFeatures:** Extracted characteristics
- domain, sld, tld
- length, entropy
- char_frequency (dict)
- bigram_count, common_bigrams
- vowel_ratio, consonant_ratio
- digit_ratio, unique_char_count
- longest_consonant_seq, has_digits
- uppercase_ratio, consecutive patterns

**ClassificationResult:** Final classification
- domain, sld, tld
- classification (DGA/LEGITIMATE/SUSPICIOUS)
- dga_family (RANDOM_CHAR/DICTIONARY/HASH_BASED/LEGITIMATE)
- confidence (0.0–1.0)
- score (0.0–100.0)
- features (DomainFeatures)
- reasons (list of detection reasons)

**ModelConfig:** Configurable thresholds
- entropy_dga_min, entropy_legit_max
- unique_char_threshold, digit_ratio_threshold
- consonant_seq_threshold
- vowel_ratio thresholds
- common_bigram_ratio_legit
- dga_threshold, legit_threshold (0–100)
- tld penalties/rewards

### Why No ML Libraries?

This lab intentionally avoids scikit-learn, TensorFlow, and pandas to:
1. **Demonstrate fundamentals** — feature engineering and scoring logic
2. **Ensure portability** — run on any system with Python 3.10+
3. **Maximize interpretability** — understand each decision rule
4. **Enable quick deployment** — zero external dependencies
5. **Support learning** — see the complete algorithm, not a black box

A real production system might use:
- **scikit-learn Random Forest** for improved accuracy
- **neural networks** for more complex patterns
- **ensemble methods** combining DGA + other signals
- **active learning** for continuous model improvement

## Test Coverage

Comprehensive unit tests (`test_dga_classifier.py`):

- **Entropy calculation** (5 tests)
- **SLD/TLD extraction** (5 tests)
- **Bigram analysis** (4 tests)
- **Consonant sequences** (5 tests)
- **Consecutive patterns** (4 tests)
- **Feature extraction** (5 tests)
- **Classification accuracy** (15 tests)
- **Confidence scoring** (4 tests)
- **DGA family estimation** (3 tests)
- **Custom model config** (2 tests)
- **Batch processing** (3 tests)
- **File loading** (4 tests)
- **Report formatting** (4 tests)
- **Edge cases** (8 tests)
- **Integration tests** (3 tests)

**Total:** 82 test cases, 100% coverage of critical paths

Run tests:
```bash
python3 -m unittest test_dga_classifier -v
```

## Real-World Usage

### 1. DNS Firewall Integration

```python
from dga_classifier import classify_domain

def dns_query_handler(domain):
    result = classify_domain(domain)
    if result.classification.value == "DGA":
        log_alert(f"DGA detected: {domain} (confidence: {result.confidence})")
        block_domain(domain)
```

### 2. Threat Intelligence Feed Processing

```bash
# Download suspected DGA feed, classify all
curl https://dga-feed.example.com/list.txt | \
  python3 dga_classifier.py --format json --min-score 70 --output threat_intel.json
```

### 3. Incident Response

```bash
# Analyze domains from DNS logs during incident
grep "2024-01-15" dns.log | awk '{print $7}' | \
  python3 dga_classifier.py --format csv --output incident_domains.csv
```

### 4. Bulk Domain Vetting

```bash
# Classify new domain registrations daily
python3 dga_classifier.py new_registrations.txt \
  --min-score 50 \
  --format json | jq '.results[] | select(.score > 50)'
```

### 5. Security Awareness Training

```bash
# Generate reports showing DGA vs legitimate examples
python3 dga_classifier.py sample_data/labeled_domains.csv \
  --format text --output training_examples.txt
```

## Performance

**Classification Speed:** ~10,000 domains/second on modern hardware

Sample data (400 domains):
```bash
$ time python3 dga_classifier.py sample_data/labeled_domains.txt --format json
real    0m0.052s
user    0m0.048s
sys     0m0.004s
```

**Memory Usage:** < 10 MB for 10,000 domains

## Limitations & Future Enhancements

### Current Limitations
1. **Rule-based only** — no statistical learning across entire dataset
2. **Single-family assumption** — may struggle with hybrid DGAs
3. **English-centric** — biased toward English vowel/consonant patterns
4. **No temporal data** — ignores registration date, age, whois info
5. **No domain relationships** — ignores patterns across related domains

### Potential Enhancements
1. **Scikit-learn Random Forest** for improved accuracy
2. **Historical data** — track domain age, registration patterns
3. **Graph analysis** — detect clusters of related DGA domains
4. **Whois integration** — leverage registration data
5. **Active learning** — human feedback to improve thresholds
6. **Multilingual support** — handle non-English domains
7. **Temporal analysis** — DGA activation patterns
8. **Ensemble methods** — combine with DNS query frequency, TTL, etc.

## Troubleshooting

### "High false positives"
- Increase `--dga-threshold` (e.g., to 65)
- Decrease `--entropy-threshold` (e.g., to 3.8)
- Review `--reasons` for legitimate domains incorrectly flagged

### "Missing real DGA domains"
- Decrease `--dga-threshold` (e.g., to 45)
- Increase `--entropy-threshold` (e.g., to 4.0)
- Enable `--verbose` for detailed feature analysis

### "Unexpected classification"
- Use `--verbose` to see scoring breakdown
- Check `dga_family` estimation — may inform manual review
- Test with known samples from `sample_data/`

## References

### DGA Literature
- "The Hidden Potential of DNS in Security" — Mandiant research
- BAMBENEK DGArchive — `https://www.bambenek.com/feeds/`
- OpenDNS/Cisco DGA detection papers
- FireEye/Mandiant DGA analysis

### Domain Characteristics
- Shannon entropy: `https://en.wikipedia.org/wiki/Entropy_(information_theory)`
- English bigrams: `https://en.wikipedia.org/wiki/Bigram`
- Domain registries: ICANN, NameSecure, APWG

### Implementation Inspiration
- PyDGA by thinkst (entropy-based)
- DGA Classifier by domaintools
- FQDN analysis in Zeek DNS module

## Author & License

**Author:** Angie Casarez (casarezaz)
**License:** MIT
**Version:** 1.0.0

Part of the **DNS Mastery Study Plan** — Week 8 (DNS Security & Attack Techniques)

---

## Next Steps

1. **Run sample data generator:** `cd sample_data && python3 generate_dga_data.py`
2. **Run tests:** `python3 -m unittest test_dga_classifier -v`
3. **Classify domains:** `python3 dga_classifier.py sample_data/dga_domains.txt`
4. **Evaluate accuracy:** Compare results against labeled data
5. **Tune thresholds:** Adjust for your environment's FP/FN tolerance
6. **Deploy:** Integrate into DNS firewall or threat intel pipeline
7. **Monitor:** Track detection statistics over time

---

See the [main README](../README.md) for the full DNS Mastery curriculum.
