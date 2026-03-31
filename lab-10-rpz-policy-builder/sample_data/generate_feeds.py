#!/usr/bin/env python3
"""
Generate sample threat intelligence feeds for testing RPZ Policy Builder.
Creates realistic threat intel feed samples in multiple formats.
"""

import csv
from pathlib import Path
from datetime import datetime, timedelta

# Get the script directory
SCRIPT_DIR = Path(__file__).parent

# Sample malicious domains and URLs
MALWARE_DOMAINS = [
    "malware-c2.com",
    "botnet-control.net",
    "ransomware-gateway.org",
    "trojan-delivery.ru",
    "rootkit-command.cc",
    "adware-loader.info",
    "worm-distribution.tk",
    "spyware-beacon.xyz",
    "backdoor-tunnel.pw",
    "exploit-kit.tv",
]

PHISHING_DOMAINS = [
    "paypal-login-verify.com",
    "amazon-account-confirm.org",
    "microsoft-office365-update.net",
    "apple-id-security.xyz",
    "bank-credentials-check.ru",
    "ebay-billing-update.info",
    "linkedin-verification.tk",
    "google-account-recovery.cc",
    "facebook-security-alert.pw",
    "netflix-billing-verify.tv",
]

BOTNET_DOMAINS = [
    "dga-seed1.net",
    "dga-seed2.com",
    "fast-flux1.org",
    "fast-flux2.ru",
    "peer-to-peer-control.cc",
    "zombie-network.xyz",
    "commandcontrol1.tv",
    "commandcontrol2.pw",
    "shadowserver-node.info",
    "infrastructure-hub.tk",
]

RANSOMWARE_DOMAINS = [
    "locky-decryption.com",
    "wannacry-payment.org",
    "petya-ransom.net",
    "cryptowall-gate.ru",
    "cerber-recovery.cc",
    "sodinokibi-demand.xyz",
    "darkside-marketplace.tv",
    "conti-leak-site.pw",
    "revil-payment.info",
    "lhc-extortion.tk",
]

PHISHING_URLS = [
    ("bank.phishing-site.ru", "https://bank.phishing-site.ru/login.php"),
    ("office-365.login-verify.com", "https://office-365.login-verify.com/authenticate"),
    ("paypal-update.credential-checker.org", "https://paypal-update.credential-checker.org"),
    ("amazon.verify-account.net", "https://amazon.verify-account.net/account/login"),
]

# Safe/benign domains for whitelist
SAFE_DOMAINS = [
    "google.com",
    "facebook.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
]


def generate_abuse_ch_domains():
    """Generate abuse.ch domain blocklist format."""
    output_file = SCRIPT_DIR / "abuse_ch_domains.txt"

    with open(output_file, 'w') as f:
        f.write("# abuse.ch Domain Blocklist\n")
        f.write("# Format: plain domain list\n")
        f.write("# Generated: {}\n".format(datetime.now().isoformat()))
        f.write("#\n")

        for domain in MALWARE_DOMAINS + BOTNET_DOMAINS + RANSOMWARE_DOMAINS:
            f.write(f"{domain}\n")

    print(f"Generated: {output_file}")
    return output_file


def generate_phishtank_csv():
    """Generate PhishTank CSV format."""
    output_file = SCRIPT_DIR / "phishtank_sample.csv"

    with open(output_file, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['Domain', 'First Seen', 'Last Seen', 'Status'])
        writer.writeheader()

        now = datetime.now()
        for i, domain in enumerate(PHISHING_DOMAINS):
            first_seen = (now - timedelta(days=30+i)).isoformat()
            last_seen = (now - timedelta(days=i)).isoformat()
            writer.writerow({
                'Domain': domain,
                'First Seen': first_seen,
                'Last Seen': last_seen,
                'Status': 'online' if i % 3 == 0 else 'offline'
            })

    print(f"Generated: {output_file}")
    return output_file


def generate_hagezi_hosts():
    """Generate hosts file format (Hagezi/StevenBlack style)."""
    output_file = SCRIPT_DIR / "hagezi_hosts.txt"

    with open(output_file, 'w') as f:
        f.write("# Hagezi hosts file format\n")
        f.write("# Generated: {}\n".format(datetime.now().isoformat()))
        f.write("#\n")

        # Add some entries with multiple variants (www., mail., etc.)
        redirect_ips = ["0.0.0.0", "127.0.0.1", "192.0.2.1"]

        for i, domain in enumerate(MALWARE_DOMAINS + PHISHING_DOMAINS):
            ip = redirect_ips[i % len(redirect_ips)]
            f.write(f"{ip} {domain}\n")

            # Add some common subdomains
            if i % 3 == 0:
                f.write(f"{ip} www.{domain}\n")
                f.write(f"{ip} mail.{domain}\n")

    print(f"Generated: {output_file}")
    return output_file


def generate_custom_blocklist():
    """Generate custom domain blocklist."""
    output_file = SCRIPT_DIR / "custom_blocklist.txt"

    with open(output_file, 'w') as f:
        f.write("# Custom blocklist\n")
        f.write("# Format: one domain per line\n")
        f.write("# Generated: {}\n".format(datetime.now().isoformat()))
        f.write("#\n")

        for domain in BOTNET_DOMAINS + RANSOMWARE_DOMAINS:
            f.write(f"{domain}\n")

    print(f"Generated: {output_file}")
    return output_file


def generate_whitelist():
    """Generate whitelist of safe domains."""
    output_file = SCRIPT_DIR / "whitelist.txt"

    with open(output_file, 'w') as f:
        f.write("# Whitelist - domains that should never be blocked\n")
        f.write("# Format: one domain per line\n")
        f.write("# Generated: {}\n".format(datetime.now().isoformat()))
        f.write("#\n")

        for domain in SAFE_DOMAINS:
            f.write(f"{domain}\n")

    print(f"Generated: {output_file}")
    return output_file


def main():
    """Generate all sample feeds."""
    print("Generating sample threat intelligence feeds...")
    print()

    generate_abuse_ch_domains()
    generate_phishtank_csv()
    generate_hagezi_hosts()
    generate_custom_blocklist()
    generate_whitelist()

    print()
    print("Sample data generation complete!")


if __name__ == '__main__':
    main()
