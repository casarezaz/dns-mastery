#!/usr/bin/env python3
"""
DNS Hierarchy Mapper
====================
Maps the full DNS delegation chain from root to authoritative nameserver
for any given domain. Uses `dig +trace` to capture each hop and generates
both ASCII tree and Graphviz visual outputs.

Part of the DNS Mastery Study Plan — Lab 1
Author: Angie Casarez
License: MIT

Usage:
    python dns_hierarchy_mapper.py example.com
    python dns_hierarchy_mapper.py -d nasa.gov mit.edu google.com bbc.co.uk -o output/
    python dns_hierarchy_mapper.py -d cloudflare.com --format both --verbose
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class DelegationHop:
    """Represents a single hop in the DNS delegation chain."""
    zone: str
    record_type: str
    nameservers: list[str]
    ip_addresses: list[str] = field(default_factory=list)
    ttl: Optional[int] = None
    raw_records: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        ns_str = ", ".join(self.nameservers[:3])
        if len(self.nameservers) > 3:
            ns_str += f" (+{len(self.nameservers) - 3} more)"
        return f"{self.zone} → {ns_str}"

@dataclass
class DelegationChain:
    """Complete delegation chain for a domain."""
    domain: str
    hops: list[DelegationHop] = field(default_factory=list)
    authoritative_ns: list[str] = field(default_factory=list)
    final_answer: Optional[str] = None
    query_time: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_valid(self) -> bool:
        return len(self.hops) > 0 and self.error is None


# ---------------------------------------------------------------------------
# Core: dig +trace Parser
# ---------------------------------------------------------------------------

class DigTraceParser:
    """Parses the output of `dig +trace` into structured delegation hops."""

    # Patterns for parsing dig output
    RE_SECTION_HEADER = re.compile(r"^;;\s*(.*?)\s*$")
    RE_NS_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+NS\s+(\S+)\s*$", re.MULTILINE
    )
    RE_A_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+A\s+(\S+)\s*$", re.MULTILINE
    )
    RE_AAAA_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+AAAA\s+(\S+)\s*$", re.MULTILINE
    )
    RE_DS_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+DS\s+(.+)$", re.MULTILINE
    )
    RE_RRSIG_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+RRSIG\s+(.+)$", re.MULTILINE
    )
    RE_SOA_RECORD = re.compile(
        r"^(\S+)\s+(\d+)\s+IN\s+SOA\s+(\S+)\s+(\S+)\s+(.+)$", re.MULTILINE
    )
    RE_FROM_SERVER = re.compile(
        r"^;;\s+Received\s+\d+\s+bytes\s+from\s+(\S+)#\d+\((\S+)\)",
        re.MULTILINE
    )

    def parse(self, raw_output: str, domain: str) -> DelegationChain:
        """Parse dig +trace output into a DelegationChain."""
        chain = DelegationChain(domain=domain)

        # Split into sections by the ";; Received ... from" lines
        sections = re.split(r"(?=;;\s+Received\s+\d+\s+bytes\s+from)", raw_output)

        for section in sections:
            if not section.strip():
                continue
            hop = self._parse_section(section)
            if hop:
                chain.hops.append(hop)

        # Identify the authoritative nameservers (last NS hop)
        ns_hops = [h for h in chain.hops if h.record_type == "NS"]
        if ns_hops:
            chain.authoritative_ns = ns_hops[-1].nameservers

        # Check for final answer records (A, AAAA, CNAME)
        final = self._extract_final_answer(raw_output, domain)
        if final:
            chain.final_answer = final

        chain.query_time = datetime.now(timezone.utc).isoformat()

        return chain

    def _parse_section(self, section: str) -> Optional[DelegationHop]:
        """Parse a single section of dig +trace output."""
        ns_matches = self.RE_NS_RECORD.findall(section)
        from_match = self.RE_FROM_SERVER.search(section)

        if not ns_matches:
            return None

        zone = ns_matches[0][0]  # The zone being delegated
        ttl = int(ns_matches[0][1])
        nameservers = list(dict.fromkeys(m[2].rstrip(".") for m in ns_matches))

        # Collect glue A records
        a_matches = self.RE_A_RECORD.findall(section)
        ip_addresses = [m[2] for m in a_matches]

        # Check for DNSSEC records
        has_ds = bool(self.RE_DS_RECORD.search(section))
        has_rrsig = bool(self.RE_RRSIG_RECORD.search(section))

        raw_records = [line.strip() for line in section.split("\n")
                       if line.strip() and not line.startswith(";;")]

        return DelegationHop(
            zone=zone.rstrip(".") or ".",
            record_type="NS",
            nameservers=nameservers,
            ip_addresses=ip_addresses,
            ttl=ttl,
            raw_records=raw_records,
        )

    def _extract_final_answer(self, raw_output: str, domain: str) -> Optional[str]:
        """Extract the final A/AAAA/CNAME answer if present."""
        pattern = re.compile(
            rf"^{re.escape(domain)}\.?\s+\d+\s+IN\s+(A|AAAA|CNAME)\s+(\S+)",
            re.MULTILINE,
        )
        match = pattern.search(raw_output)
        if match:
            return f"{match.group(1)} {match.group(2)}"
        return None


# ---------------------------------------------------------------------------
# Output: ASCII Tree
# ---------------------------------------------------------------------------

class ASCIITreeRenderer:
    """Renders a delegation chain as a colored ASCII tree."""

    # ANSI color codes
    COLORS = {
        "root":   "\033[93m",   # Yellow
        "tld":    "\033[96m",   # Cyan
        "domain": "\033[92m",   # Green
        "ns":     "\033[37m",   # White/gray
        "ip":     "\033[90m",   # Dark gray
        "answer": "\033[95m",   # Magenta
        "bold":   "\033[1m",
        "reset":  "\033[0m",
        "dim":    "\033[2m",
    }

    def render(self, chain: DelegationChain, use_color: bool = True) -> str:
        """Render the delegation chain as an ASCII tree."""
        if not use_color:
            self.COLORS = {k: "" for k in self.COLORS}

        lines = []
        c = self.COLORS

        # Header
        lines.append("")
        lines.append(f"{c['bold']}DNS Delegation Chain: {chain.domain}{c['reset']}")
        lines.append(f"{c['dim']}{'─' * 60}{c['reset']}")
        lines.append("")

        if not chain.is_valid:
            lines.append(f"  ⚠  Error: {chain.error or 'No delegation data found'}")
            return "\n".join(lines)

        for i, hop in enumerate(chain.hops):
            is_last_hop = (i == len(chain.hops) - 1)
            connector = "└── " if is_last_hop else "├── "
            continuation = "    " if is_last_hop else "│   "

            # Determine the color based on position in chain
            if hop.zone == ".":
                zone_color = c["root"]
                label = ". (Root)"
            elif hop.zone.count(".") == 0:
                zone_color = c["tld"]
                label = f"{hop.zone}. (TLD)"
            else:
                zone_color = c["domain"]
                label = f"{hop.zone}."

            lines.append(f"  {connector}{zone_color}{c['bold']}{label}{c['reset']}")

            # Show nameservers (up to 4)
            display_ns = hop.nameservers[:4]
            for j, ns in enumerate(display_ns):
                is_last_ns = (j == len(display_ns) - 1) and (len(hop.nameservers) <= 4)
                ns_connector = "└─ " if is_last_ns else "├─ "
                lines.append(
                    f"  {continuation}{ns_connector}{c['ns']}NS: {ns}{c['reset']}"
                )

            if len(hop.nameservers) > 4:
                remaining = len(hop.nameservers) - 4
                lines.append(
                    f"  {continuation}└─ {c['dim']}(+{remaining} more nameservers){c['reset']}"
                )

            # Show TTL
            if hop.ttl is not None:
                lines.append(
                    f"  {continuation}   {c['dim']}TTL: {hop.ttl}s{c['reset']}"
                )

            lines.append(f"  {'│' if not is_last_hop else ' '}")

        # Final answer
        if chain.final_answer:
            lines.append(
                f"  {c['answer']}{c['bold']}✓ Answer: {chain.domain} → "
                f"{chain.final_answer}{c['reset']}"
            )
            lines.append("")

        # Authoritative NS summary
        if chain.authoritative_ns:
            lines.append(
                f"  {c['dim']}Authoritative NS: "
                f"{', '.join(chain.authoritative_ns)}{c['reset']}"
            )

        lines.append(f"  {c['dim']}Query time: {chain.query_time}{c['reset']}")
        lines.append("")

        return "\n".join(lines)

    def render_to_file(self, chain: DelegationChain, filepath: Path) -> None:
        """Render to a plain text file (no ANSI colors)."""
        output = self.render(chain, use_color=False)
        filepath.write_text(output, encoding="utf-8")
        logging.info(f"ASCII tree saved to {filepath}")


# ---------------------------------------------------------------------------
# Output: Graphviz
# ---------------------------------------------------------------------------

class GraphvizRenderer:
    """Renders a delegation chain as a Graphviz DOT diagram."""

    # Color scheme
    PALETTE = {
        "root_fill":   "#2D2D2D",
        "root_font":   "#FFD700",
        "tld_fill":    "#1A3A5C",
        "tld_font":    "#87CEEB",
        "domain_fill": "#1A4D2E",
        "domain_font": "#90EE90",
        "ns_fill":     "#3D3D3D",
        "ns_font":     "#CCCCCC",
        "answer_fill": "#4A1A5C",
        "answer_font": "#DDA0DD",
        "edge_color":  "#666666",
        "bg_color":    "#1E1E1E",
    }

    def render_dot(self, chain: DelegationChain) -> str:
        """Generate DOT source for the delegation chain."""
        p = self.PALETTE

        lines = [
            "digraph dns_delegation {",
            '  rankdir=TB;',
            f'  bgcolor="{p["bg_color"]}";',
            '  node [shape=box, style="filled,rounded", fontname="Helvetica"];',
            f'  edge [color="{p["edge_color"]}", penwidth=1.5, arrowsize=0.8];',
            "",
            "  // Title",
            f'  labelloc="t";',
            f'  label=<<B><FONT POINT-SIZE="18" COLOR="#FFFFFF">'
            f'DNS Delegation: {chain.domain}</FONT></B>>;',
            "",
        ]

        if not chain.is_valid:
            lines.append(f'  error [label="Error: {chain.error}", '
                        f'fillcolor="#8B0000", fontcolor="#FFFFFF"];')
            lines.append("}")
            return "\n".join(lines)

        prev_node = None
        for i, hop in enumerate(chain.hops):
            node_id = f"hop_{i}"

            # Determine style
            if hop.zone == "." or hop.zone == "":
                fill = p["root_fill"]
                font = p["root_font"]
                label = ". (Root Zone)"
            elif hop.zone.count(".") == 0:
                fill = p["tld_fill"]
                font = p["tld_font"]
                label = f"{hop.zone}. (TLD)"
            else:
                fill = p["domain_fill"]
                font = p["domain_font"]
                label = f"{hop.zone}."

            # Build label with nameservers
            ns_display = hop.nameservers[:3]
            ns_lines = "\\n".join(f"NS: {ns}" for ns in ns_display)
            if len(hop.nameservers) > 3:
                ns_lines += f"\\n(+{len(hop.nameservers) - 3} more)"

            full_label = f"{label}\\n\\n{ns_lines}"
            if hop.ttl is not None:
                full_label += f"\\n\\nTTL: {hop.ttl}s"

            lines.append(
                f'  {node_id} [label="{full_label}", '
                f'fillcolor="{fill}", fontcolor="{font}", fontsize=10];'
            )

            if prev_node:
                lines.append(f'  {prev_node} -> {node_id};')
            prev_node = node_id

        # Final answer node
        if chain.final_answer:
            lines.append("")
            lines.append(
                f'  answer [label="{chain.domain}\\n{chain.final_answer}", '
                f'fillcolor="{p["answer_fill"]}", fontcolor="{p["answer_font"]}", '
                f'fontsize=11, style="filled,rounded,bold"];'
            )
            if prev_node:
                lines.append(
                    f'  {prev_node} -> answer '
                    f'[style=dashed, color="{p["answer_font"]}"];'
                )

        lines.append("}")
        return "\n".join(lines)

    def render_to_file(
        self, chain: DelegationChain, output_dir: Path,
        formats: list[str] = None,
    ) -> list[Path]:
        """Render to DOT file and optionally compile to PNG/SVG."""
        if formats is None:
            formats = ["png", "svg"]

        output_dir.mkdir(parents=True, exist_ok=True)
        safe_name = chain.domain.replace(".", "_")

        # Write DOT source
        dot_path = output_dir / f"{safe_name}.dot"
        dot_source = self.render_dot(chain)
        dot_path.write_text(dot_source, encoding="utf-8")
        logging.info(f"DOT source saved to {dot_path}")

        output_files = [dot_path]

        # Compile with graphviz if available
        for fmt in formats:
            out_path = output_dir / f"{safe_name}.{fmt}"
            try:
                result = subprocess.run(
                    ["dot", f"-T{fmt}", str(dot_path), "-o", str(out_path)],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    logging.info(f"Graphviz {fmt.upper()} saved to {out_path}")
                    output_files.append(out_path)
                else:
                    logging.warning(
                        f"Graphviz failed for {fmt}: {result.stderr.strip()}"
                    )
            except FileNotFoundError:
                logging.warning(
                    "Graphviz `dot` not found. Install with: brew install graphviz"
                )
                logging.info(
                    f"DOT source saved — render manually: "
                    f"dot -Tpng {dot_path} -o {out_path}"
                )
                break
            except subprocess.TimeoutExpired:
                logging.warning(f"Graphviz timed out rendering {fmt}")

        return output_files


# ---------------------------------------------------------------------------
# Core: DNS Hierarchy Mapper
# ---------------------------------------------------------------------------

class DNSHierarchyMapper:
    """Orchestrates DNS delegation chain mapping."""

    def __init__(self, dns_server: Optional[str] = None):
        self.dns_server = dns_server
        self.parser = DigTraceParser()
        self.ascii_renderer = ASCIITreeRenderer()
        self.graphviz_renderer = GraphvizRenderer()

    def trace_domain(self, domain: str) -> DelegationChain:
        """Run dig +trace and parse the results."""
        logging.info(f"Tracing delegation chain for: {domain}")

        # Validate domain format
        if not self._validate_domain(domain):
            chain = DelegationChain(domain=domain)
            chain.error = f"Invalid domain format: {domain}"
            return chain

        # Build dig command
        cmd = ["dig", "+trace", "+nodnssec", "+additional", domain]
        if self.dns_server:
            cmd.append(f"@{self.dns_server}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                chain = DelegationChain(domain=domain)
                chain.error = f"dig failed (exit {result.returncode}): {result.stderr.strip()}"
                return chain

            raw_output = result.stdout
            logging.debug(f"Raw dig output:\n{raw_output}")

            chain = self.parser.parse(raw_output, domain)

            if not chain.hops:
                chain.error = "No delegation hops found in dig output"

            return chain

        except FileNotFoundError:
            chain = DelegationChain(domain=domain)
            chain.error = (
                "`dig` command not found. Install with: brew install bind"
            )
            return chain
        except subprocess.TimeoutExpired:
            chain = DelegationChain(domain=domain)
            chain.error = "dig +trace timed out after 30 seconds"
            return chain
        except Exception as e:
            chain = DelegationChain(domain=domain)
            chain.error = f"Unexpected error: {e}"
            return chain

    def map_domains(
        self,
        domains: list[str],
        output_dir: Path,
        output_format: str = "both",
        use_color: bool = True,
    ) -> list[DelegationChain]:
        """Map multiple domains and generate all outputs."""
        output_dir.mkdir(parents=True, exist_ok=True)
        chains = []

        for domain in domains:
            chain = self.trace_domain(domain)
            chains.append(chain)

            # ASCII output (always print to console)
            ascii_output = self.ascii_renderer.render(chain, use_color=use_color)
            print(ascii_output)

            # Save ASCII to file
            if output_format in ("ascii", "both"):
                safe_name = domain.replace(".", "_")
                txt_path = output_dir / f"{safe_name}_tree.txt"
                self.ascii_renderer.render_to_file(chain, txt_path)

            # Graphviz output
            if output_format in ("graphviz", "both"):
                self.graphviz_renderer.render_to_file(chain, output_dir)

        # Generate combined summary
        self._save_summary(chains, output_dir)

        return chains

    def _validate_domain(self, domain: str) -> bool:
        """Basic domain format validation."""
        pattern = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
        )
        return bool(pattern.match(domain))

    def _save_summary(self, chains: list[DelegationChain], output_dir: Path) -> None:
        """Save a JSON summary of all traced domains."""
        summary = {
            "generated": datetime.now(timezone.utc).isoformat(),
            "tool": "DNS Hierarchy Mapper — Lab 1",
            "domains": [],
        }

        for chain in chains:
            entry = {
                "domain": chain.domain,
                "valid": chain.is_valid,
                "hop_count": len(chain.hops),
                "authoritative_ns": chain.authoritative_ns,
                "final_answer": chain.final_answer,
                "hops": [
                    {
                        "zone": h.zone,
                        "nameservers": h.nameservers,
                        "ttl": h.ttl,
                    }
                    for h in chain.hops
                ],
            }
            if chain.error:
                entry["error"] = chain.error
            summary["domains"].append(entry)

        summary_path = output_dir / "summary.json"
        summary_path.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        logging.info(f"Summary saved to {summary_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

DEFAULT_DOMAINS = [
    "nasa.gov",        # .gov — US government
    "mit.edu",         # .edu — academic
    "google.com",      # .com — commercial (massive delegation)
    "bbc.co.uk",       # .co.uk — country-code second-level
    "cloudflare.com",  # .com — DNS infrastructure provider
]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns_hierarchy_mapper",
        description=(
            "DNS Hierarchy Mapper — traces the full delegation chain from root "
            "to authoritative nameserver and generates visual outputs."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s example.com\n"
            "  %(prog)s -d nasa.gov mit.edu google.com bbc.co.uk\n"
            "  %(prog)s --defaults --format both -o output/\n"
            "  %(prog)s -d cloudflare.com --server 8.8.8.8 --verbose\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "domain",
        nargs="?",
        help="Single domain to trace",
    )
    parser.add_argument(
        "-d", "--domains",
        nargs="+",
        metavar="DOMAIN",
        help="One or more domains to trace",
    )
    parser.add_argument(
        "--defaults",
        action="store_true",
        help=f"Use the default sample domains: {', '.join(DEFAULT_DOMAINS)}",
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("output"),
        help="Output directory for generated files (default: ./output)",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["ascii", "graphviz", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--server",
        metavar="IP",
        help="DNS server to use for initial query (e.g., 8.8.8.8)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output in terminal",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Determine domains to trace
    domains = []
    if args.defaults:
        domains = DEFAULT_DOMAINS
    elif args.domains:
        domains = args.domains
    elif args.domain:
        domains = [args.domain]
    else:
        parser.print_help()
        print("\n⚠  Provide at least one domain, use -d, or use --defaults")
        return 1

    # Run the mapper
    mapper = DNSHierarchyMapper(dns_server=args.server)

    try:
        chains = mapper.map_domains(
            domains=domains,
            output_dir=args.output_dir,
            output_format=args.format,
            use_color=not args.no_color,
        )
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        return 130

    # Summary
    valid = sum(1 for c in chains if c.is_valid)
    total = len(chains)
    print(f"\n{'─' * 60}")
    print(f"✓ Traced {valid}/{total} domains successfully")
    print(f"  Output directory: {args.output_dir.resolve()}")

    if args.format in ("graphviz", "both"):
        print(f"  Graphviz files: *.dot, *.png, *.svg")
    if args.format in ("ascii", "both"):
        print(f"  ASCII trees:    *_tree.txt")
    print(f"  Summary:        summary.json")
    print()

    return 0 if valid == total else 1


if __name__ == "__main__":
    sys.exit(main())
