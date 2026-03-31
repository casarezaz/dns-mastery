# Lab 08 Sample Data — DGA Domain Classifier

**Generated:** By `generate_dga_data.py`

## Overview

Sample dataset for training and testing the DGA domain classifier. Contains 400 labeled domains: 200 DGA-generated and 200 legitimate.

## Files

### `dga_domains.txt`
- **Format:** Plain text, one domain per line
- **Content:** 200 DGA-generated domains
- **Families:** Random character, dictionary-based, hash-based, morphing
- **Purpose:** Testing DGA detection accuracy

### `legitimate_domains.txt`
- **Format:** Plain text, one domain per line
- **Content:** 200 realistic legitimate domains
- **Examples:** google.com, example.org, amazon.com variants
- **Purpose:** Testing false positive rate, classifier specificity

### `labeled_domains.csv`
- **Format:** CSV with headers
- **Columns:** domain, label (dga/legitimate), dga_family
- **Content:** All 400 domains with labels and DGA family classification
- **Purpose:** Evaluation, training, confusion matrix analysis
- **Usage:** `python3 dga_classifier.py labeled_domains.csv --format csv --output report.csv`

### `labeled_domains.json`
- **Format:** JSON array of objects
- **Schema:** `{"domain": "...", "label": "dga|legitimate", "dga_family": "..."}`
- **Content:** All 400 domains in machine-readable format
- **Purpose:** API/scripting workflows, downstream processing
- **Usage:** `python3 dga_classifier.py labeled_domains.json --format json --output report.json`

### `generate_dga_data.py`
- **Purpose:** Regenerate sample data with consistent random seeds
- **Usage:** `python3 generate_dga_data.py` (creates all files above)
- **Reproducibility:** Uses fixed seeds (seed 42 for legit, family name hashes for DGA)

## Data Characteristics

### DGA Domains (200 total)

#### Random Character Family (50)
- **Algorithm:** Pure random alphanumeric strings
- **Characteristics:**
  - Length: 8-16 characters
  - High Shannon entropy (> 4.0)
  - Low vowel ratio (< 30%)
  - Many unique characters (70%+ of length)
  - No common English bigrams
  - Resembles: Conficker, Necurs, Kraken
- **Examples:**
  ```
  xkpdmqrt.com
  qpqpmqmr.com
  bfghjkln.com
  ```

#### Dictionary-Based Family (50)
- **Algorithm:** Concatenated dictionary words, sometimes with numbers
- **Characteristics:**
  - Moderate entropy (3.0-3.5)
  - Natural vowel patterns (30-40%)
  - Some common bigrams (20-40%)
  - 1-3 words from a word list
  - May contain digits or hyphens
  - Resembles: Pykspa, Murofet, Redyms
- **Examples:**
  ```
  applecherrydragon.com
  bananaforest42.net
  quietriver.org
  ```

#### Hash-Based Family (50)
- **Algorithm:** MD5 hash seeded by index, truncated and possibly encoded
- **Characteristics:**
  - High entropy (3.5-4.0)
  - Random-looking alphanumeric
  - Often contains digits (15-30%)
  - Few common bigrams
  - Deterministic but unpredictable-looking
  - Resembles: Cryptolocker, DGA.cc, Tinba
- **Examples:**
  ```
  a7f2c3e8d9b1.com
  f4e2d7a5c89.net
  b3f1c8e2a47.org
  ```

#### Morphing Family (50)
- **Algorithm:** Mix of random, dictionary, and hash characteristics
- **Characteristics:**
  - Variable entropy (3.0-4.0)
  - Blends characteristics of other families
  - Realistic variation (hard to classify by family)
- **Examples:**
  ```
  eagleforest123.com
  kxtymnd.net
  junglequiet99.org
  ```

### Legitimate Domains (200)

- **Names:** 46 common company/service names (Google, Amazon, Microsoft, etc.)
  - Sometimes with subdomains (www, api, mail, admin, app, cdn)
  - Sometimes with suffixes (prod, staging, dev, v2)
- **TLDs:** 36 legitimate TLDs (com, org, net, edu, gov, country codes, new TLDs)
- **Characteristics:**
  - Natural entropy (2.0-3.2)
  - Good vowel ratio (30-50%)
  - Common English bigrams (40-70%)
  - Pronounceable patterns
  - Familiar brand/word structure
- **Examples:**
  ```
  google.com
  aws.amazon.com
  github.com
  api.stripe.com
  admin-backup.example.net
  ```

## Usage Examples

### Test classifier on DGA domains
```bash
python3 dga_classifier.py dga_domains.txt
```

### Test classifier on legitimate domains
```bash
python3 dga_classifier.py legitimate_domains.txt
```

### Evaluate performance on labeled data
```bash
python3 dga_classifier.py labeled_domains.csv --format json --output evaluation.json

# Then parse evaluation to compute:
# - True Positives (DGA classified as DGA)
# - True Negatives (Legitimate classified as Legitimate)
# - False Positives (Legitimate classified as DGA)
# - False Negatives (DGA classified as Legitimate)
```

### Tune classifier parameters for labeled data
```bash
# Try stricter threshold
python3 dga_classifier.py labeled_domains.csv --dga-threshold 65

# Try different entropy threshold
python3 dga_classifier.py labeled_domains.csv --entropy-threshold 3.8
```

### Batch processing with custom format
```bash
# CSV output with only DGA scores >= 70
python3 dga_classifier.py labeled_domains.csv \
  --format csv \
  --min-score 70 \
  --output high_confidence_dga.csv
```

## Dataset Properties

| Property | Value |
|----------|-------|
| Total domains | 400 |
| DGA domains | 200 (50%) |
| Legitimate domains | 200 (50%) |
| DGA families | 4 (random, dictionary, hash-based, morphing) |
| TLDs represented | ~60 |
| Min domain length | 3 chars |
| Max domain length | ~30 chars |
| Reproducible | Yes (fixed random seeds) |

## Quality Notes

1. **Balance:** Equal DGA/legitimate ratio (50/50) for unbiased testing
2. **Realism:** Legitimate domains use actual company names and common TLDs
3. **Diversity:** DGA families represent real-world algorithms
4. **Reproducibility:** Generated with fixed seeds for consistency across runs
5. **Deterministic:** Running `generate_dga_data.py` produces identical files

## Regenerating Data

To create fresh sample data with new random DGA domains:

```bash
cd sample_data
python3 generate_dga_data.py
```

The script uses fixed random seeds internally for reproducibility:
- Legitimate domains: seed 42
- Random char DGA: hash of "random_char"
- Dictionary DGA: hash of "dictionary"
- Hash-based DGA: hash of "hash_based"
- Morphing DGA: seed 999

## References

- **DGA Research:**
  - Conficker DGA: `http://en.wikipedia.org/wiki/Conficker`
  - Pykspa: `https://securelist.com/the-evolution-of-the-pykspa-botnets/`
  - Cryptolocker: `https://en.wikipedia.org/wiki/Cryptolocker`

- **Sample generation inspired by:**
  - BAMBENEK DGArchive
  - OpenDNS DGA detection research
  - FireEye/Mandiant DGA analysis papers

## Author

Generated for DNS Mastery Lab 08 — DGA Domain Classifier
Author: Angie Casarez (casarezaz)
