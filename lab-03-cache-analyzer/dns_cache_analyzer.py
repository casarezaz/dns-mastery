#!/usr/bin/env python3
"""
DNS Cache Analyzer
Lab 3 - DNS Mastery Curriculum

Analyzes DNS caching behavior by querying domains repeatedly and tracking
TTL countdown. Measures resolver cache hit/miss rates, compares caching
across different resolvers, and visualizes TTL decay over time.

Author: Angie Casarez
License: MIT
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ─── Configuration ────────────────────────────────────────────────────────────

VERSION = "1.0.0"

# Well-known public resolvers
RESOLVERS = {
    "system": None,  # Use system default
    "google-primary": "8.8.8.8",
    "google-secondary": "8.8.4.4",
    "cloudflare-primary": "1.1.1.1",
    "cloudflare-secondary": "1.0.0.1",
    "quad9": "9.9.9.9",
    "opendns": "208.67.222.222",
}

DEFAULT_TEST_DOMAINS = [
    "google.com",
    "github.com",
    "nasa.gov",
    "bbc.co.uk",
    "cloudflare.com",
]

# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

    @classmethod
    def disable(cls):
        for attr in dir(cls):
            if attr.isupper() and not attr.startswith("_"):
                setattr(cls, attr, "")


# ─── Data Models ──────────────────────────────────────────────────────────────

@dataclass
class CacheProbe:
    """A single cache probe result."""
    timestamp: str
    probe_number: int
    ttl: int
    query_time_ms: float
    server: str
    answer: str
    is_cached: bool = False  # Inferred from query time and TTL pattern


@dataclass
class TTLDecayTrack:
    """Tracks TTL decay over successive queries."""
    domain: str
    record_type: str
    resolver: str
    resolver_name: str
    original_ttl: int = 0
    probes: list = field(default_factory=list)
    cache_hit_count: int = 0
    cache_miss_count: int = 0
    avg_cached_query_ms: float = 0.0
    avg_uncached_query_ms: float = 0.0


@dataclass
class ResolverComparison:
    """Comparison of caching behavior across resolvers."""
    domain: str
    record_type: str
    resolver_results: dict = field(default_factory=dict)


@dataclass
class CacheAnalysis:
    """Complete cache analysis results."""
    domain: str
    timestamp: str = ""
    ttl_tracks: list = field(default_factory=list)
    resolver_comparison: Optional[dict] = None
    summary: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ─── Cache Probe Engine ──────────────────────────────────────────────────────

class CacheProbeEngine:
    """Probes DNS caches using dig."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.logger = logging.getLogger("CacheProbeEngine")

    def probe(self, domain: str, record_type: str = "A",
              nameserver: Optional[str] = None) -> CacheProbe:
        """Send a single probe query and capture TTL + timing."""
        cmd = ["dig", "+noall", "+answer", "+stats",
               f"+time={self.timeout}", "+tries=1"]

        if nameserver:
            cmd.append(f"@{nameserver}")

        cmd.extend([domain, record_type])

        try:
            start = time.monotonic()
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self.timeout + 3
            )
            elapsed = (time.monotonic() - start) * 1000

            output = proc.stdout.strip()

            ttl = self._extract_ttl(output)
            query_time = self._extract_query_time(output) or elapsed
            server = self._extract_server(output) or (nameserver or "system")
            answer = self._extract_answer(output, record_type)

            return CacheProbe(
                timestamp=datetime.now(timezone.utc).isoformat(),
                probe_number=0,
                ttl=ttl,
                query_time_ms=query_time,
                server=server,
                answer=answer
            )

        except subprocess.TimeoutExpired:
            return CacheProbe(
                timestamp=datetime.now(timezone.utc).isoformat(),
                probe_number=0,
                ttl=-1,
                query_time_ms=-1,
                server=nameserver or "system",
                answer="TIMEOUT"
            )
        except Exception as e:
            self.logger.error(f"Probe failed: {e}")
            return CacheProbe(
                timestamp=datetime.now(timezone.utc).isoformat(),
                probe_number=0,
                ttl=-1,
                query_time_ms=-1,
                server=nameserver or "system",
                answer=f"ERROR: {e}"
            )

    def probe_series(self, domain: str, record_type: str = "A",
                     nameserver: Optional[str] = None,
                     count: int = 10, interval: float = 2.0,
                     resolver_name: str = "system") -> TTLDecayTrack:
        """Run a series of probes to track TTL decay."""
        track = TTLDecayTrack(
            domain=domain,
            record_type=record_type,
            resolver=nameserver or "system",
            resolver_name=resolver_name
        )

        self.logger.info(
            f"Starting {count} probes for {domain}/{record_type} "
            f"via {resolver_name} (interval: {interval}s)"
        )

        for i in range(count):
            probe = self.probe(domain, record_type, nameserver)
            probe.probe_number = i + 1

            # Determine if cached based on TTL pattern
            if i == 0:
                track.original_ttl = probe.ttl
                probe.is_cached = False  # First query establishes baseline
            else:
                prev_probe = track.probes[-1]
                if prev_probe.ttl > 0 and probe.ttl > 0:
                    # If TTL decreased roughly by the interval, it's cached
                    expected_ttl = prev_probe.ttl - int(interval)
                    # Allow some tolerance (±2 seconds)
                    if abs(probe.ttl - expected_ttl) <= 3:
                        probe.is_cached = True
                    elif probe.ttl >= track.original_ttl - 2:
                        # TTL reset - cache miss or refresh
                        probe.is_cached = False
                    else:
                        probe.is_cached = True

            track.probes.append(probe)

            if i < count - 1:
                time.sleep(interval)

        # Calculate stats
        cached_probes = [p for p in track.probes if p.is_cached]
        uncached_probes = [p for p in track.probes if not p.is_cached]

        track.cache_hit_count = len(cached_probes)
        track.cache_miss_count = len(uncached_probes)

        if cached_probes:
            track.avg_cached_query_ms = sum(
                p.query_time_ms for p in cached_probes
            ) / len(cached_probes)

        if uncached_probes:
            track.avg_uncached_query_ms = sum(
                p.query_time_ms for p in uncached_probes
            ) / len(uncached_probes)

        return track

    def _extract_ttl(self, output: str) -> int:
        """Extract TTL from dig answer section."""
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                try:
                    return int(parts[1])
                except (ValueError, IndexError):
                    continue
        return -1

    def _extract_query_time(self, output: str) -> Optional[float]:
        """Extract query time from dig stats."""
        match = re.search(r";; Query time: (\d+) msec", output)
        return float(match.group(1)) if match else None

    def _extract_server(self, output: str) -> Optional[str]:
        """Extract responding server."""
        match = re.search(r";; SERVER: (.+?)#", output)
        return match.group(1) if match else None

    def _extract_answer(self, output: str, record_type: str) -> str:
        """Extract the answer value."""
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith(";"):
                continue
            parts = line.split(None, 4)
            if len(parts) >= 5 and parts[3] == record_type:
                return parts[4]
        return "NO ANSWER"


# ─── Terminal Renderer ────────────────────────────────────────────────────────

class TerminalRenderer:
    """Renders cache analysis to terminal."""

    def render_ttl_track(self, track: TTLDecayTrack):
        """Render a TTL decay track with ASCII chart."""
        c = Colors

        print(f"\n{c.BOLD}{c.CYAN}TTL Decay: {track.domain} ({track.record_type}){c.RESET}")
        print(f"{c.DIM}Resolver: {track.resolver_name} ({track.resolver}){c.RESET}")
        print(f"{c.DIM}Original TTL: {track.original_ttl}s{c.RESET}")
        print(f"{c.DIM}{'─' * 60}{c.RESET}")

        if not track.probes:
            print(f"  {c.YELLOW}No probes collected{c.RESET}")
            return

        # ASCII TTL decay chart
        max_ttl = max(p.ttl for p in track.probes if p.ttl > 0) if any(
            p.ttl > 0 for p in track.probes
        ) else 1
        chart_width = 40

        print(f"\n  {'Probe':>6}  {'TTL':>6}  {'Time':>7}  {'Cache':>5}  TTL Bar")
        print(f"  {'─' * 6}  {'─' * 6}  {'─' * 7}  {'─' * 5}  {'─' * chart_width}")

        for probe in track.probes:
            if probe.ttl < 0:
                bar = f"{c.RED}ERROR{c.RESET}"
                ttl_str = "  ERR"
            else:
                bar_len = int((probe.ttl / max_ttl) * chart_width) if max_ttl > 0 else 0
                bar_char = "█"

                if probe.is_cached:
                    bar = f"{c.GREEN}{bar_char * bar_len}{c.RESET}"
                    cache_str = f"{c.GREEN}HIT{c.RESET}"
                else:
                    bar = f"{c.YELLOW}{bar_char * bar_len}{c.RESET}"
                    cache_str = f"{c.YELLOW}MISS{c.RESET}"

                ttl_str = f"{probe.ttl:>5}s"

            time_str = f"{probe.query_time_ms:>5.0f}ms" if probe.query_time_ms >= 0 else "  ERR"

            if probe.ttl >= 0:
                print(f"  {probe.probe_number:>6}  {ttl_str}  {time_str}  "
                      f"{cache_str:>14}  {bar}")
            else:
                print(f"  {probe.probe_number:>6}  {'ERR':>6}  {time_str}  "
                      f"{c.RED}{'ERR':>5}{c.RESET}  {bar}")

        # Stats
        print(f"\n  {c.BOLD}Cache Stats:{c.RESET}")
        total = track.cache_hit_count + track.cache_miss_count
        hit_rate = (track.cache_hit_count / total * 100) if total > 0 else 0

        print(f"    Hits: {c.GREEN}{track.cache_hit_count}{c.RESET} / "
              f"Misses: {c.YELLOW}{track.cache_miss_count}{c.RESET} / "
              f"Rate: {c.BOLD}{hit_rate:.0f}%{c.RESET}")

        if track.avg_cached_query_ms > 0:
            print(f"    Avg cached query:   {c.GREEN}{track.avg_cached_query_ms:.1f}ms{c.RESET}")
        if track.avg_uncached_query_ms > 0:
            print(f"    Avg uncached query: {c.YELLOW}{track.avg_uncached_query_ms:.1f}ms{c.RESET}")

        speedup = (
            track.avg_uncached_query_ms / track.avg_cached_query_ms
            if track.avg_cached_query_ms > 0 and track.avg_uncached_query_ms > 0
            else 0
        )
        if speedup > 0:
            print(f"    Cache speedup:      {c.CYAN}{speedup:.1f}x{c.RESET}")
        print()

    def render_resolver_comparison(self, comparison: ResolverComparison):
        """Render resolver comparison table."""
        c = Colors

        print(f"\n{c.BOLD}{c.MAGENTA}Resolver Comparison: {comparison.domain}{c.RESET}")
        print(f"{c.DIM}{'─' * 70}{c.RESET}")

        # Header
        print(f"\n  {'Resolver':<20} {'Orig TTL':>9} {'Hit Rate':>9} "
              f"{'Cached':>8} {'Uncached':>10} {'Speedup':>8}")
        print(f"  {'─' * 20} {'─' * 9} {'─' * 9} {'─' * 8} {'─' * 10} {'─' * 8}")

        for name, track in comparison.resolver_results.items():
            total = track.cache_hit_count + track.cache_miss_count
            hit_rate = (track.cache_hit_count / total * 100) if total > 0 else 0

            speedup = (
                track.avg_uncached_query_ms / track.avg_cached_query_ms
                if track.avg_cached_query_ms > 0 and track.avg_uncached_query_ms > 0
                else 0
            )

            hit_color = c.GREEN if hit_rate > 70 else (c.YELLOW if hit_rate > 30 else c.RED)

            print(f"  {name:<20} {track.original_ttl:>8}s "
                  f"{hit_color}{hit_rate:>8.0f}%{c.RESET} "
                  f"{track.avg_cached_query_ms:>7.1f}ms "
                  f"{track.avg_uncached_query_ms:>9.1f}ms "
                  f"{speedup:>7.1f}x")

        print()

    def render_analysis(self, analysis: CacheAnalysis):
        """Render complete analysis."""
        c = Colors

        print(f"\n{c.BOLD}{'═' * 60}{c.RESET}")
        print(f"{c.BOLD}{c.CYAN}  DNS Cache Analysis: {analysis.domain}{c.RESET}")
        print(f"{c.BOLD}{'═' * 60}{c.RESET}")

        for track in analysis.ttl_tracks:
            self.render_ttl_track(track)

        if analysis.resolver_comparison:
            comp = ResolverComparison(
                domain=analysis.domain,
                record_type="A",
                resolver_results=analysis.resolver_comparison
            )
            self.render_resolver_comparison(comp)

        # Summary
        print(f"{c.DIM}{'─' * 60}{c.RESET}")
        s = analysis.summary
        print(f"  {c.BOLD}Analysis Summary:{c.RESET}")
        print(f"    Domain:          {analysis.domain}")
        print(f"    Resolvers tested: {s.get('resolvers_tested', 0)}")
        print(f"    Total probes:    {s.get('total_probes', 0)}")
        print(f"    Overall hit rate: {s.get('overall_hit_rate', 0):.0f}%")
        print(f"    Best resolver:   {s.get('best_resolver', 'N/A')} "
              f"({s.get('best_hit_rate', 0):.0f}% hit rate)")
        print(f"    Fastest cached:  {s.get('fastest_cached_resolver', 'N/A')} "
              f"({s.get('fastest_cached_ms', 0):.1f}ms)")
        print()


# ─── File Exporters ───────────────────────────────────────────────────────────

class JSONExporter:
    """Export cache analysis to JSON."""

    def export(self, analysis: CacheAnalysis, filepath: str):
        """Export to JSON file."""
        data = {
            "domain": analysis.domain,
            "timestamp": analysis.timestamp,
            "ttl_tracks": [],
            "resolver_comparison": {},
            "summary": analysis.summary
        }

        for track in analysis.ttl_tracks:
            track_data = {
                "domain": track.domain,
                "record_type": track.record_type,
                "resolver": track.resolver,
                "resolver_name": track.resolver_name,
                "original_ttl": track.original_ttl,
                "cache_hit_count": track.cache_hit_count,
                "cache_miss_count": track.cache_miss_count,
                "avg_cached_query_ms": track.avg_cached_query_ms,
                "avg_uncached_query_ms": track.avg_uncached_query_ms,
                "probes": [asdict(p) for p in track.probes]
            }
            data["ttl_tracks"].append(track_data)

        if analysis.resolver_comparison:
            for name, track in analysis.resolver_comparison.items():
                data["resolver_comparison"][name] = {
                    "resolver": track.resolver,
                    "original_ttl": track.original_ttl,
                    "cache_hit_count": track.cache_hit_count,
                    "cache_miss_count": track.cache_miss_count,
                    "avg_cached_query_ms": track.avg_cached_query_ms,
                    "avg_uncached_query_ms": track.avg_uncached_query_ms,
                    "probes": [asdict(p) for p in track.probes]
                }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)


class HTMLExporter:
    """Export cache analysis to HTML report."""

    def export(self, analysis: CacheAnalysis, filepath: str):
        """Export to styled HTML report."""
        tracks_html = ""
        for track in analysis.ttl_tracks:
            tracks_html += self._render_track_html(track)

        comparison_html = ""
        if analysis.resolver_comparison:
            comparison_html = self._render_comparison_html(analysis)

        chart_data = self._build_chart_data(analysis)
        summary = analysis.summary

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Cache Analysis: {analysis.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'SF Mono', 'Fira Code', monospace; background: #1a1a2e; color: #e0e0e0; padding: 2rem; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #00d4ff; margin-bottom: 0.5rem; }}
        h2 {{ color: #ffd700; margin: 2rem 0 1rem; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
        .meta {{ color: #888; font-size: 0.85rem; margin-bottom: 2rem; }}
        .track {{ background: #16213e; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
        .track-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }}
        .track-title {{ color: #00d4ff; font-weight: bold; font-size: 1.1rem; }}
        .track-meta {{ color: #888; font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }}
        th {{ text-align: left; padding: 0.5rem; color: #888; border-bottom: 1px solid #333; }}
        td {{ padding: 0.5rem; border-bottom: 1px solid #1a1a2e; }}
        .hit {{ color: #00ff88; }}
        .miss {{ color: #ffaa00; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 1rem 0; }}
        .stat {{ background: #0f3460; padding: 1rem; border-radius: 6px; text-align: center; }}
        .stat-value {{ font-size: 1.5rem; font-weight: bold; color: #00d4ff; }}
        .stat-label {{ font-size: 0.75rem; color: #888; margin-top: 0.3rem; }}
        .bar {{ display: inline-block; height: 14px; border-radius: 2px; }}
        .bar-hit {{ background: #00ff88; }}
        .bar-miss {{ background: #ffaa00; }}
        .chart-container {{ background: #16213e; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
        canvas {{ width: 100%; max-height: 300px; }}
        .comparison-table {{ width: 100%; }}
        .comparison-table th {{ background: #0f3460; }}
        .summary {{ background: #16213e; padding: 1.5rem; border-radius: 8px; margin-top: 2rem; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Cache Analysis</h1>
        <p class="meta">{analysis.domain} &mdash; {analysis.timestamp}</p>

        <h2>TTL Decay Tracking</h2>
        {tracks_html}

        <h2>TTL Decay Chart</h2>
        <div class="chart-container">
            <canvas id="ttlChart"></canvas>
        </div>

        {comparison_html}

        <div class="summary">
            <h2 style="margin-top:0; border:none;">Summary</h2>
            <div class="stat-grid">
                <div class="stat">
                    <div class="stat-value">{summary.get('resolvers_tested', 0)}</div>
                    <div class="stat-label">Resolvers Tested</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('total_probes', 0)}</div>
                    <div class="stat-label">Total Probes</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('overall_hit_rate', 0):.0f}%</div>
                    <div class="stat-label">Overall Hit Rate</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{summary.get('fastest_cached_ms', 0):.0f}ms</div>
                    <div class="stat-label">Fastest Cached</div>
                </div>
            </div>
        </div>

        <p class="meta" style="margin-top: 2rem; text-align: center;">
            Generated by DNS Cache Analyzer v{VERSION} &mdash; DNS Mastery Lab 3
        </p>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <script>
    const chartData = {chart_data};
    if (chartData.datasets.length > 0) {{
        const ctx = document.getElementById('ttlChart').getContext('2d');
        new Chart(ctx, {{
            type: 'line',
            data: chartData,
            options: {{
                responsive: true,
                plugins: {{
                    title: {{ display: true, text: 'TTL Decay Over Time', color: '#e0e0e0' }},
                    legend: {{ labels: {{ color: '#e0e0e0' }} }}
                }},
                scales: {{
                    x: {{
                        title: {{ display: true, text: 'Probe #', color: '#888' }},
                        ticks: {{ color: '#888' }},
                        grid: {{ color: '#333' }}
                    }},
                    y: {{
                        title: {{ display: true, text: 'TTL (seconds)', color: '#888' }},
                        ticks: {{ color: '#888' }},
                        grid: {{ color: '#333' }}
                    }}
                }}
            }}
        }});
    }}
    </script>
</body>
</html>"""

        with open(filepath, "w") as f:
            f.write(html)

    def _render_track_html(self, track: TTLDecayTrack) -> str:
        """Render a single TTL decay track."""
        total = track.cache_hit_count + track.cache_miss_count
        hit_rate = (track.cache_hit_count / total * 100) if total > 0 else 0

        rows = ""
        max_ttl = max(p.ttl for p in track.probes if p.ttl > 0) if any(
            p.ttl > 0 for p in track.probes
        ) else 1

        for probe in track.probes:
            cache_class = "hit" if probe.is_cached else "miss"
            cache_label = "HIT" if probe.is_cached else "MISS"
            bar_width = int((probe.ttl / max_ttl) * 200) if probe.ttl > 0 and max_ttl > 0 else 0
            bar_class = "bar-hit" if probe.is_cached else "bar-miss"

            rows += f"""
            <tr>
                <td>{probe.probe_number}</td>
                <td>{probe.ttl}s</td>
                <td>{probe.query_time_ms:.0f}ms</td>
                <td class="{cache_class}">{cache_label}</td>
                <td><span class="bar {bar_class}" style="width: {bar_width}px;"></span></td>
            </tr>"""

        speedup = (
            track.avg_uncached_query_ms / track.avg_cached_query_ms
            if track.avg_cached_query_ms > 0 and track.avg_uncached_query_ms > 0
            else 0
        )

        return f"""
        <div class="track">
            <div class="track-header">
                <span class="track-title">{track.resolver_name} ({track.resolver})</span>
                <span class="track-meta">Original TTL: {track.original_ttl}s</span>
            </div>
            <div class="stat-grid">
                <div class="stat">
                    <div class="stat-value" style="color: #00ff88;">{hit_rate:.0f}%</div>
                    <div class="stat-label">Cache Hit Rate</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{track.avg_cached_query_ms:.1f}ms</div>
                    <div class="stat-label">Avg Cached</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{track.avg_uncached_query_ms:.1f}ms</div>
                    <div class="stat-label">Avg Uncached</div>
                </div>
                <div class="stat">
                    <div class="stat-value">{speedup:.1f}x</div>
                    <div class="stat-label">Speedup</div>
                </div>
            </div>
            <table>
                <thead>
                    <tr><th>#</th><th>TTL</th><th>Query Time</th><th>Cache</th><th>TTL Bar</th></tr>
                </thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    def _render_comparison_html(self, analysis: CacheAnalysis) -> str:
        """Render resolver comparison table."""
        if not analysis.resolver_comparison:
            return ""

        rows = ""
        for name, track in analysis.resolver_comparison.items():
            total = track.cache_hit_count + track.cache_miss_count
            hit_rate = (track.cache_hit_count / total * 100) if total > 0 else 0
            speedup = (
                track.avg_uncached_query_ms / track.avg_cached_query_ms
                if track.avg_cached_query_ms > 0 and track.avg_uncached_query_ms > 0
                else 0
            )

            rows += f"""
            <tr>
                <td>{name}</td>
                <td>{track.resolver}</td>
                <td>{track.original_ttl}s</td>
                <td>{hit_rate:.0f}%</td>
                <td>{track.avg_cached_query_ms:.1f}ms</td>
                <td>{track.avg_uncached_query_ms:.1f}ms</td>
                <td>{speedup:.1f}x</td>
            </tr>"""

        return f"""
        <h2>Resolver Comparison</h2>
        <table class="comparison-table">
            <thead>
                <tr>
                    <th>Resolver</th><th>Address</th><th>Orig TTL</th>
                    <th>Hit Rate</th><th>Cached</th><th>Uncached</th><th>Speedup</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    def _build_chart_data(self, analysis: CacheAnalysis) -> str:
        """Build Chart.js data for TTL decay visualization."""
        colors = ["#00d4ff", "#00ff88", "#ff88ff", "#ffaa00", "#ff4444", "#4488ff"]
        datasets = []

        for i, track in enumerate(analysis.ttl_tracks):
            color = colors[i % len(colors)]
            data_points = [p.ttl for p in track.probes if p.ttl >= 0]
            labels = list(range(1, len(data_points) + 1))

            datasets.append({
                "label": track.resolver_name,
                "data": data_points,
                "borderColor": color,
                "backgroundColor": color + "33",
                "tension": 0.1,
                "fill": False
            })

        max_probes = max(len(t.probes) for t in analysis.ttl_tracks) if analysis.ttl_tracks else 0
        labels = list(range(1, max_probes + 1))

        return json.dumps({"labels": labels, "datasets": datasets})


# ─── Main Analyzer ────────────────────────────────────────────────────────────

class DNSCacheAnalyzer:
    """Main orchestrator for DNS cache analysis."""

    def __init__(self, timeout: int = 5, output_dir: str = "output",
                 probe_count: int = 10, interval: float = 2.0):
        self.engine = CacheProbeEngine(timeout=timeout)
        self.renderer = TerminalRenderer()
        self.json_exporter = JSONExporter()
        self.html_exporter = HTMLExporter()
        self.output_dir = output_dir
        self.probe_count = probe_count
        self.interval = interval
        self.logger = logging.getLogger("DNSCacheAnalyzer")

        os.makedirs(output_dir, exist_ok=True)

    def analyze_single(self, domain: str, resolvers: dict = None,
                       record_type: str = "A",
                       no_color: bool = False) -> CacheAnalysis:
        """Analyze caching for a domain across specified resolvers."""
        if no_color:
            Colors.disable()

        if resolvers is None:
            resolvers = {"system": None}

        analysis = CacheAnalysis(domain=domain)

        for name, server in resolvers.items():
            self.logger.info(f"Probing {domain} via {name}")
            track = self.engine.probe_series(
                domain=domain,
                record_type=record_type,
                nameserver=server,
                count=self.probe_count,
                interval=self.interval,
                resolver_name=name
            )
            analysis.ttl_tracks.append(track)

        # Build resolver comparison if multiple resolvers
        if len(resolvers) > 1:
            analysis.resolver_comparison = {
                track.resolver_name: track for track in analysis.ttl_tracks
            }

        # Build summary
        total_probes = sum(len(t.probes) for t in analysis.ttl_tracks)
        total_hits = sum(t.cache_hit_count for t in analysis.ttl_tracks)
        total_total = sum(
            t.cache_hit_count + t.cache_miss_count for t in analysis.ttl_tracks
        )
        overall_hit_rate = (total_hits / total_total * 100) if total_total > 0 else 0

        # Find best resolver
        best_track = max(
            analysis.ttl_tracks,
            key=lambda t: (
                t.cache_hit_count / (t.cache_hit_count + t.cache_miss_count)
                if (t.cache_hit_count + t.cache_miss_count) > 0 else 0
            )
        )
        best_total = best_track.cache_hit_count + best_track.cache_miss_count
        best_hit_rate = (
            best_track.cache_hit_count / best_total * 100
        ) if best_total > 0 else 0

        # Find fastest cached resolver
        cached_resolvers = [
            t for t in analysis.ttl_tracks if t.avg_cached_query_ms > 0
        ]
        fastest = min(
            cached_resolvers, key=lambda t: t.avg_cached_query_ms
        ) if cached_resolvers else None

        analysis.summary = {
            "resolvers_tested": len(resolvers),
            "total_probes": total_probes,
            "overall_hit_rate": overall_hit_rate,
            "best_resolver": best_track.resolver_name,
            "best_hit_rate": best_hit_rate,
            "fastest_cached_resolver": fastest.resolver_name if fastest else "N/A",
            "fastest_cached_ms": fastest.avg_cached_query_ms if fastest else 0,
        }

        return analysis

    def run(self, domain: str, resolvers: dict = None,
            record_type: str = "A", no_color: bool = False,
            no_html: bool = False) -> CacheAnalysis:
        """Run full analysis with rendering and export."""
        analysis = self.analyze_single(
            domain, resolvers, record_type, no_color
        )

        # Render
        self.renderer.render_analysis(analysis)

        # Export
        safe_domain = domain.replace(".", "_")

        json_path = os.path.join(self.output_dir, f"{safe_domain}_cache.json")
        self.json_exporter.export(analysis, json_path)
        self.logger.info(f"JSON saved to {json_path}")

        if not no_html:
            html_path = os.path.join(self.output_dir, f"{safe_domain}_cache.html")
            self.html_exporter.export(analysis, html_path)
            self.logger.info(f"HTML report saved to {html_path}")

        return analysis


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dns_cache_analyzer",
        description="DNS Cache Analyzer - Track TTL decay, measure cache hit rates, "
                    "and compare resolver caching behavior.",
        epilog="Part of the DNS Mastery curriculum - Lab 3"
    )

    parser.add_argument(
        "domains",
        nargs="*",
        help="Domain(s) to analyze"
    )

    parser.add_argument(
        "--defaults",
        action="store_true",
        help="Analyze default sample domains"
    )

    parser.add_argument(
        "--resolvers", "-r",
        nargs="+",
        choices=list(RESOLVERS.keys()),
        default=["system"],
        help="Resolvers to test (default: system)"
    )

    parser.add_argument(
        "--all-resolvers",
        action="store_true",
        help="Test all known resolvers"
    )

    parser.add_argument(
        "--probes", "-p",
        type=int,
        default=10,
        help="Number of probes per resolver (default: 10)"
    )

    parser.add_argument(
        "--interval", "-i",
        type=float,
        default=2.0,
        help="Seconds between probes (default: 2.0)"
    )

    parser.add_argument(
        "--record-type", "-t",
        default="A",
        help="Record type to query (default: A)"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Query timeout in seconds (default: 5)"
    )

    parser.add_argument(
        "--output-dir", "-o",
        default="output",
        help="Output directory (default: output)"
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )

    parser.add_argument(
        "--no-html",
        action="store_true",
        help="Skip HTML report generation"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    domains = list(args.domains) if args.domains else []
    if args.defaults:
        domains = DEFAULT_TEST_DOMAINS

    if not domains:
        parser.print_help()
        sys.exit(1)

    # Build resolver dict
    if args.all_resolvers:
        resolvers = dict(RESOLVERS)
    else:
        resolvers = {name: RESOLVERS[name] for name in args.resolvers}

    analyzer = DNSCacheAnalyzer(
        timeout=args.timeout,
        output_dir=args.output_dir,
        probe_count=args.probes,
        interval=args.interval
    )

    for domain in domains:
        analyzer.run(
            domain=domain,
            resolvers=resolvers,
            record_type=args.record_type,
            no_color=args.no_color,
            no_html=args.no_html
        )


if __name__ == "__main__":
    main()
