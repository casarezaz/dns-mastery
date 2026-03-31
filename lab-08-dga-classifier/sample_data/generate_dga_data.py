#!/usr/bin/env python3
"""
DGA Sample Data Generator — Lab 08
===================================
Generates synthetic DGA domains and legitimate domains for testing and training
the DGA classifier.

Output:
  - dga_domains.txt: One domain per line (all DGA domains)
  - legitimate_domains.txt: One domain per line (legitimate domains)
  - labeled_domains.csv: CSV with domain and label (dga/legitimate)
  - labeled_domains.json: JSON array of objects with domain and label
"""

import random
import json
import csv
import string
import hashlib
from collections import defaultdict


# ============================================================================
# Legitimate Domain Data
# ============================================================================
LEGITIMATE_NAMES = [
    "google", "facebook", "amazon", "microsoft", "apple", "netflix", "twitter",
    "instagram", "linkedin", "github", "stackoverflow", "medium", "airbnb",
    "uber", "slack", "zoom", "stripe", "shopify", "squarespace", "wix",
    "wordpress", "wikipedia", "reddit", "quora", "yelp", "booking",
    "alibaba", "baidu", "tencent", "JD", "weibo", "tiktok",
    "example", "test", "sample", "demo", "localhost", "production",
    "staging", "development", "api", "admin", "mail", "support",
    "sales", "marketing", "engineering", "finance", "hr", "legal",
]

LEGITIMATE_TLDS = [
    "com", "org", "net", "edu", "gov", "co.uk", "de", "fr", "it", "es",
    "nl", "be", "ch", "at", "au", "ca", "jp", "cn", "in", "br",
    "ru", "kr", "hk", "sg", "se", "no", "dk", "fi", "ie", "nz",
    "io", "app", "dev", "cloud", "ai", "tech",
]

# Dictionary words for dictionary-based DGA
DICTIONARY_WORDS = [
    "apple", "banana", "cherry", "dragon", "eagle", "forest", "guitar",
    "happy", "island", "jungle", "kitchen", "library", "mountain",
    "network", "ocean", "palace", "quiet", "river", "sunset",
    "tiger", "umbrella", "volcano", "water", "xray", "yellow",
    "zebra", "account", "bitcoin", "crypto", "database", "email",
    "finance", "global", "hidden", "internet", "kernel", "leader",
    "memory", "network", "operation", "process", "quantum", "random",
    "secure", "trusted", "update", "virus", "wallet", "xchange",
]


# ============================================================================
# DGA Generators
# ============================================================================
class DGAGenerator:
    """Base class for DGA generators."""

    def generate(self, seed: int, count: int) -> list:
        """Generate DGA domains."""
        raise NotImplementedError


class RandomCharDGA(DGAGenerator):
    """
    Random character DGA (like Conficker, Necurs, Kraken).
    Simply generates random alphanumeric strings.
    """

    def generate(self, seed: int, count: int) -> list:
        random.seed(seed)
        domains = []
        for _ in range(count):
            length = random.randint(8, 16)
            # Random alphanumeric
            domain = ''.join(random.choice(string.ascii_lowercase + string.digits)
                           for _ in range(length))
            domains.append(domain + ".com")
        return domains


class DictionaryDGA(DGAGenerator):
    """
    Dictionary-based DGA (like Pykspa, Murofet, Redyms).
    Concatenates words from a dictionary, sometimes with separators.
    """

    def generate(self, seed: int, count: int) -> list:
        random.seed(seed)
        domains = []
        tlds = ["com", "net", "org", "info", "biz"]

        for _ in range(count):
            # 1-3 words from dictionary
            word_count = random.randint(1, 3)
            words = [random.choice(DICTIONARY_WORDS) for _ in range(word_count)]

            # Maybe add separator
            if random.random() > 0.7:
                sep = random.choice(["-", ""])
                domain = sep.join(words)
            else:
                domain = "".join(words)

            # Add digits occasionally
            if random.random() > 0.7:
                domain += str(random.randint(0, 999))

            tld = random.choice(tlds)
            domains.append(domain + "." + tld)

        return domains


class HashBasedDGA(DGAGenerator):
    """
    Hash-based DGA (like Cryptolocker, DGA.cc, Tinba).
    Uses hash of date/time or seed to generate domains.
    Often produces domains with high entropy.
    """

    def generate(self, seed: int, count: int) -> list:
        domains = []

        for i in range(count):
            # Create seed from index
            data = f"{seed:08d}{i:08d}{random.randint(0, 999999):06d}".encode()
            hash_digest = hashlib.md5(data).hexdigest()

            # Take first 10-14 chars of hash, encode in various ways
            encoding_choice = random.choice(['hex', 'base32'])

            if encoding_choice == 'hex':
                # Use hex directly
                domain = hash_digest[:random.randint(10, 14)]
            else:
                # Create a pseudo-base32 from hex
                domain = ''.join(random.choice(string.ascii_lowercase + string.digits)
                               for _ in range(random.randint(10, 14)))

            # Maybe add a few digits
            if random.random() > 0.6:
                domain += str(random.randint(0, 99))

            tld = random.choice(["com", "net", "org", "info"])
            domains.append(domain + "." + tld)

        return domains


class MorphingDGA(DGAGenerator):
    """
    Morphing DGA with elements of multiple types.
    Combines characteristics of random, dictionary, and hash-based.
    """

    def generate(self, seed: int, count: int) -> list:
        random.seed(seed)
        domains = []

        for _ in range(count):
            choice = random.random()

            if choice < 0.3:
                # More dictionary-like
                words = [random.choice(DICTIONARY_WORDS[:5]) for _ in range(random.randint(1, 2))]
                domain = "".join(words)
            elif choice < 0.6:
                # More random
                length = random.randint(8, 14)
                domain = ''.join(random.choice(string.ascii_lowercase)
                               for _ in range(length))
            else:
                # Mix of random and numbers
                length = random.randint(6, 10)
                domain = ''.join(random.choice(string.ascii_lowercase + string.digits)
                               for _ in range(length))

            # Add digits
            if random.random() > 0.5:
                domain += str(random.randint(10, 999))

            tld = random.choice(["com", "net", "org", "cc", "info"])
            domains.append(domain + "." + tld)

        return domains


# ============================================================================
# Data Generation
# ============================================================================
def generate_legitimate_domains(count: int) -> list:
    """Generate realistic legitimate domains."""
    domains = []
    random.seed(42)  # Reproducible

    for _ in range(count):
        name = random.choice(LEGITIMATE_NAMES)

        # Sometimes add prefix
        if random.random() > 0.6:
            prefix = random.choice(["www", "api", "mail", "admin", "app", "cdn", "test"])
            name = prefix + "." + name

        # Sometimes add suffix
        if random.random() > 0.7:
            suffix = random.choice(["api", "v2", "prod", "staging", "dev", "backup"])
            name = name + "-" + suffix

        tld = random.choice(LEGITIMATE_TLDS)
        domains.append(name + "." + tld)

    return domains


def generate_dga_domains(count: int) -> dict:
    """
    Generate DGA domains from multiple families.

    Returns:
        Dictionary with family names as keys and domain lists as values.
    """
    per_family = count // 3

    generators = {
        "random_char": RandomCharDGA(),
        "dictionary": DictionaryDGA(),
        "hash_based": HashBasedDGA(),
    }

    dga_domains = {}

    for family, generator in generators.items():
        seed = hash(family) % 2**31
        dga_domains[family] = generator.generate(seed, per_family)

    # Add morphing as well
    morphing_gen = MorphingDGA()
    dga_domains["morphing"] = morphing_gen.generate(999, count - 3 * per_family)

    return dga_domains


# ============================================================================
# Main
# ============================================================================
def main():
    """Generate sample data files."""

    print("[*] DGA Domain Classifier - Sample Data Generator")
    print("[*] Generating sample data...")

    # Generate domains
    legit_domains = generate_legitimate_domains(200)
    dga_dict = generate_dga_domains(200)

    # Flatten DGA domains
    dga_domains_flat = []
    dga_family_map = {}
    for family, domains in dga_dict.items():
        dga_domains_flat.extend(domains)
        for domain in domains:
            dga_family_map[domain] = family

    print(f"[+] Generated {len(legit_domains)} legitimate domains")
    print(f"[+] Generated {len(dga_domains_flat)} DGA domains")
    print(f"    - Random char: {len(dga_dict.get('random_char', []))}")
    print(f"    - Dictionary:  {len(dga_dict.get('dictionary', []))}")
    print(f"    - Hash-based:  {len(dga_dict.get('hash_based', []))}")
    print(f"    - Morphing:    {len(dga_dict.get('morphing', []))}")

    # ========================================================================
    # Write individual domain files
    # ========================================================================
    with open("dga_domains.txt", "w") as f:
        for domain in dga_domains_flat:
            f.write(domain + "\n")
    print("[+] Wrote dga_domains.txt")

    with open("legitimate_domains.txt", "w") as f:
        for domain in legit_domains:
            f.write(domain + "\n")
    print("[+] Wrote legitimate_domains.txt")

    # ========================================================================
    # Write labeled CSV
    # ========================================================================
    with open("labeled_domains.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["domain", "label", "dga_family"])
        writer.writeheader()

        for domain in dga_domains_flat:
            family = dga_family_map.get(domain, "unknown")
            writer.writerow({"domain": domain, "label": "dga", "dga_family": family})

        for domain in legit_domains:
            writer.writerow({"domain": domain, "label": "legitimate", "dga_family": "n/a"})

    print("[+] Wrote labeled_domains.csv (400 domains)")

    # ========================================================================
    # Write labeled JSON
    # ========================================================================
    labeled_data = []

    for domain in dga_domains_flat:
        family = dga_family_map.get(domain, "unknown")
        labeled_data.append({
            "domain": domain,
            "label": "dga",
            "dga_family": family,
        })

    for domain in legit_domains:
        labeled_data.append({
            "domain": domain,
            "label": "legitimate",
            "dga_family": "n/a",
        })

    with open("labeled_domains.json", "w") as f:
        json.dump(labeled_data, f, indent=2)

    print("[+] Wrote labeled_domains.json (400 domains)")

    # ========================================================================
    # Sample statistics
    # ========================================================================
    print("\n[*] Sample Statistics:")
    print(f"    Total domains: {len(legit_domains) + len(dga_domains_flat)}")
    print(f"    DGA ratio: {len(dga_domains_flat) / (len(legit_domains) + len(dga_domains_flat)) * 100:.1f}%")

    # Show examples
    print("\n[*] Sample Legitimate Domains:")
    for domain in legit_domains[:5]:
        print(f"    {domain}")

    print("\n[*] Sample DGA Domains (Random Char):")
    for domain in dga_dict["random_char"][:5]:
        print(f"    {domain}")

    print("\n[*] Sample DGA Domains (Dictionary):")
    for domain in dga_dict["dictionary"][:5]:
        print(f"    {domain}")

    print("\n[*] Sample DGA Domains (Hash-Based):")
    for domain in dga_dict["hash_based"][:5]:
        print(f"    {domain}")

    print("\n[+] Done! Sample data ready for classifier training/testing.")


if __name__ == "__main__":
    main()
