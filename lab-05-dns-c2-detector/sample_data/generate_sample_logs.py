#!/usr/bin/env python3
"""
Generate realistic DNS log samples with embedded C2 patterns.
Creates both benign traffic and known-bad C2 patterns for testing.

Output formats: Zeek TSV dns.log and CSV.
"""

import csv
import hashlib
import math
import os
import random
import string
import sys
import time

random.seed(42)  # Reproducible

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
START_TIME = 1711360000.0  # ~2024-03-25 12:00:00 UTC
DURATION = 3600 * 4        # 4 hours of traffic
NUM_BENIGN_DOMAINS = 50
BENIGN_QUERIES_PER_DOMAIN = (5, 50)

# C2 profiles
C2_PROFILES = {
    "beacon-low": {
        "domain": "update-service.badactor.xyz",
        "interval": 60,       # 60-second beacon
        "jitter": 0.05,       # 5% jitter
        "src_ip": "10.1.1.50",
        "query_type": "A",
        "subdomain_style": "short",  # Short random subdomains
    },
    "beacon-high": {
        "domain": "cdn-check.malware-c2.net",
        "interval": 300,      # 5-minute beacon
        "jitter": 0.08,       # 8% jitter
        "src_ip": "10.1.1.75",
        "query_type": "TXT",
        "subdomain_style": "encoded",  # Base32 encoded data
    },
    "exfil": {
        "domain": "ns1.data-exfil.evil",
        "interval": 10,       # Fast exfil
        "jitter": 0.30,       # Higher jitter (batched sends)
        "src_ip": "10.1.1.100",
        "query_type": "A",
        "subdomain_style": "hex",  # Hex-encoded data
    },
    "dga": {
        "domain": None,  # Randomly generated domains
        "interval": 5,
        "jitter": 0.50,
        "src_ip": "10.1.1.200",
        "query_type": "A",
        "subdomain_style": "dga",
        "nxdomain_rate": 0.85,
    },
    "txt-tunnel": {
        "domain": "t.dns-tunnel.cc",
        "interval": 2,
        "jitter": 0.15,
        "src_ip": "10.1.1.150",
        "query_type": "TXT",
        "subdomain_style": "base64",
    },
}

# Benign domain pool
BENIGN_DOMAINS_POOL = [
    "google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com",
    "netflix.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "reddit.com", "twitter.com", "linkedin.com", "youtube.com", "yahoo.com",
    "cloudflare.com", "fastly.net", "akamaiedge.net", "office365.com",
    "zoom.us", "slack.com", "dropbox.com", "salesforce.com", "adobe.com",
    "mozilla.org", "python.org", "npmjs.com", "docker.com", "aws.amazon.com",
    "azure.microsoft.com", "gcp.google.com", "outlook.com", "gmail.com",
    "icloud.com", "spotify.com", "twitch.tv", "pinterest.com", "tumblr.com",
    "medium.com", "wordpress.com", "shopify.com", "stripe.com", "paypal.com",
    "ebay.com", "walmart.com", "target.com", "bestbuy.com", "costco.com",
    "cnn.com", "bbc.com", "nytimes.com", "washingtonpost.com", "reuters.com",
]

BENIGN_SUBDOMAINS = [
    "www", "mail", "api", "cdn", "static", "img", "assets", "login",
    "app", "m", "mobile", "docs", "help", "support", "blog", "dev",
    "staging", "prod", "us-east-1", "eu-west-1",
]

INTERNAL_IPS = [f"10.1.1.{i}" for i in range(10, 250)]
DNS_SERVERS = ["10.0.0.1", "10.0.0.2"]


def random_subdomain(style: str, seq: int = 0) -> str:
    """Generate a subdomain based on C2 style."""
    if style == "short":
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
    elif style == "encoded":
        # Base32-like
        data = os.urandom(random.randint(10, 25))
        import base64
        return base64.b32encode(data).decode().rstrip("=").lower()
    elif style == "hex":
        return os.urandom(random.randint(16, 32)).hex()
    elif style == "base64":
        data = os.urandom(random.randint(12, 30))
        import base64
        return base64.b64encode(data).decode().rstrip("=").replace("+", "-").replace("/", "_")
    elif style == "dga":
        # DGA-style random domain
        seed = hashlib.md5(f"{seq}".encode()).hexdigest()
        length = random.randint(8, 15)
        tlds = [".com", ".net", ".org", ".info", ".xyz", ".top"]
        return seed[:length] + random.choice(tlds)
    return "check"


def generate_benign_queries(start: float, end: float) -> list[dict]:
    """Generate realistic benign DNS traffic."""
    queries = []
    domains = random.sample(BENIGN_DOMAINS_POOL, min(NUM_BENIGN_DOMAINS, len(BENIGN_DOMAINS_POOL)))

    for domain in domains:
        num_queries = random.randint(*BENIGN_QUERIES_PER_DOMAIN)
        src_ip = random.choice(INTERNAL_IPS)

        for _ in range(num_queries):
            ts = random.uniform(start, end)
            subdomain = random.choice(BENIGN_SUBDOMAINS) if random.random() < 0.6 else ""
            qname = f"{subdomain}.{domain}" if subdomain else domain
            qtype = random.choices(["A", "AAAA", "MX", "TXT", "CNAME"],
                                   weights=[60, 15, 5, 10, 10])[0]
            rcode = "NOERROR" if random.random() < 0.95 else "NXDOMAIN"

            queries.append({
                "ts": ts,
                "src_ip": src_ip,
                "dst_ip": random.choice(DNS_SERVERS),
                "query": qname,
                "qtype": qtype,
                "rcode": rcode,
            })

    return queries


def generate_c2_queries(profile: dict, name: str,
                        start: float, end: float) -> list[dict]:
    """Generate C2 beacon traffic based on a profile."""
    queries = []
    ts = start + random.uniform(0, profile["interval"])
    seq = 0

    while ts < end:
        jitter = random.gauss(0, profile["interval"] * profile["jitter"])
        interval = max(0.5, profile["interval"] + jitter)

        if profile["subdomain_style"] == "dga":
            qname = random_subdomain("dga", seq)
            rcode = "NXDOMAIN" if random.random() < profile.get("nxdomain_rate", 0) else "NOERROR"
        else:
            sub = random_subdomain(profile["subdomain_style"], seq)
            qname = f"{sub}.{profile['domain']}"
            rcode = "NOERROR"

        queries.append({
            "ts": ts,
            "src_ip": profile["src_ip"],
            "dst_ip": random.choice(DNS_SERVERS),
            "query": qname,
            "qtype": profile["query_type"],
            "rcode": rcode,
        })

        ts += interval
        seq += 1

    return queries


def write_zeek_tsv(queries: list[dict], filepath: str):
    """Write queries in Zeek dns.log TSV format."""
    queries.sort(key=lambda q: q["ts"])

    with open(filepath, "w") as f:
        f.write("#separator \\x09\n")
        f.write("#set_separator\t,\n")
        f.write("#empty_field\t(empty)\n")
        f.write("#unset_field\t-\n")
        f.write("#path\tdns\n")
        f.write(f"#open\t{time.strftime('%Y-%m-%d-%H-%M-%S')}\n")
        f.write("#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t"
                "proto\ttrans_id\trtt\tquery\tqclass\tqclass_name\tqtype\tqtype_name\t"
                "rcode\trcode_name\tAA\tTC\tRD\tRA\tZ\tanswers\tTTLs\trejected\n")
        f.write("#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tcount\t"
                "interval\tstring\tcount\tstring\tcount\tstring\tcount\tstring\t"
                "bool\tbool\tbool\tbool\tcount\tvector[string]\tvector[interval]\tbool\n")

        qtype_map = {"A": "1", "AAAA": "28", "MX": "15", "TXT": "16",
                      "CNAME": "5", "NS": "2", "SOA": "6", "SRV": "33"}
        rcode_map = {"NOERROR": "0", "NXDOMAIN": "3", "SERVFAIL": "2", "REFUSED": "5"}

        for i, q in enumerate(queries):
            uid = f"C{hashlib.md5(f'{i}'.encode()).hexdigest()[:16]}"
            qtype_num = qtype_map.get(q["qtype"], "1")
            rcode_num = rcode_map.get(q["rcode"], "0")
            rtt = f"{random.uniform(0.001, 0.1):.6f}" if q["rcode"] == "NOERROR" else "-"
            answer = "1.2.3.4" if q["rcode"] == "NOERROR" and q["qtype"] == "A" else "-"
            ttl = "300.000000" if answer != "-" else "-"
            src_port = str(random.randint(1024, 65535))

            f.write(f"{q['ts']:.6f}\t{uid}\t{q['src_ip']}\t{src_port}\t"
                    f"{q['dst_ip']}\t53\tudp\t{random.randint(1, 65535)}\t{rtt}\t"
                    f"{q['query']}\t1\tC_INTERNET\t{qtype_num}\t{q['qtype']}\t"
                    f"{rcode_num}\t{q['rcode']}\tF\tF\tT\tT\t0\t{answer}\t{ttl}\tF\n")

        f.write(f"#close\t{time.strftime('%Y-%m-%d-%H-%M-%S')}\n")


def write_csv(queries: list[dict], filepath: str):
    """Write queries in simple CSV format."""
    queries.sort(key=lambda q: q["ts"])

    with open(filepath, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "src_ip", "server_ip",
                                                "query", "query_type", "response_code"])
        writer.writeheader()
        for q in queries:
            writer.writerow({
                "timestamp": f"{q['ts']:.6f}",
                "src_ip": q["src_ip"],
                "server_ip": q["dst_ip"],
                "query": q["query"],
                "query_type": q["qtype"],
                "response_code": q["rcode"],
            })


def main():
    end_time = START_TIME + DURATION

    print("[*] Generating benign DNS traffic...")
    all_queries = generate_benign_queries(START_TIME, end_time)
    print(f"    Generated {len(all_queries)} benign queries")

    print("[*] Generating C2 traffic patterns...")
    for name, profile in C2_PROFILES.items():
        c2_queries = generate_c2_queries(profile, name, START_TIME, end_time)
        print(f"    {name}: {len(c2_queries)} queries → {profile.get('domain', 'DGA domains')}")
        all_queries.extend(c2_queries)

    print(f"[*] Total queries: {len(all_queries)}")

    # Write outputs
    script_dir = os.path.dirname(os.path.abspath(__file__))

    zeek_path = os.path.join(script_dir, "sample_dns.log")
    write_zeek_tsv(all_queries, zeek_path)
    print(f"[*] Wrote Zeek TSV: {zeek_path}")

    csv_path = os.path.join(script_dir, "sample_dns.csv")
    write_csv(all_queries, csv_path)
    print(f"[*] Wrote CSV: {csv_path}")

    # Write a manifest describing the embedded C2 patterns
    manifest_path = os.path.join(script_dir, "MANIFEST.md")
    with open(manifest_path, "w") as f:
        f.write("# Sample Data Manifest\n\n")
        f.write("This directory contains generated DNS logs with embedded C2 patterns.\n\n")
        f.write("## Embedded C2 Profiles\n\n")
        f.write("| Profile | Domain | Interval | Jitter | Src IP | Type | Style |\n")
        f.write("|---------|--------|----------|--------|--------|------|-------|\n")
        for name, p in C2_PROFILES.items():
            domain = p.get("domain", "DGA-generated")
            f.write(f"| {name} | {domain} | {p['interval']}s | "
                    f"{p['jitter']:.0%} | {p['src_ip']} | "
                    f"{p['query_type']} | {p['subdomain_style']} |\n")
        f.write(f"\n## Statistics\n\n")
        f.write(f"- Total queries: {len(all_queries)}\n")
        f.write(f"- Time span: {DURATION / 3600:.0f} hours\n")
        f.write(f"- Benign domains: {NUM_BENIGN_DOMAINS}\n")
        f.write(f"- C2 profiles: {len(C2_PROFILES)}\n")

    print(f"[*] Wrote manifest: {manifest_path}")
    print("[*] Done!")


if __name__ == "__main__":
    main()
