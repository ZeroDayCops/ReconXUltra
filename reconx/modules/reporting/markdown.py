#!/usr/bin/env python3
"""
============================================================================
ReconX Ultra — Markdown Report Generator
============================================================================
Generates a comprehensive markdown report from all reconnaissance data.
============================================================================
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    print("Usage: markdown.py <domain>")
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN


def count_lines(filepath):
    """Count lines in a file, return 0 if missing."""
    try:
        with open(filepath) as f:
            return sum(1 for line in f if line.strip())
    except (FileNotFoundError, PermissionError):
        return 0


def read_lines(filepath, limit=None):
    """Read lines from a file."""
    try:
        with open(filepath) as f:
            lines = [l.strip() for l in f if l.strip()]
            return lines[:limit] if limit else lines
    except (FileNotFoundError, PermissionError):
        return []


def load_json(filepath):
    """Load JSON file."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, PermissionError):
        return None


def main():
    report_path = OUTPUT_DIR / "reports" / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # Gather statistics
    stats = {
        "subdomains": count_lines(OUTPUT_DIR / "subs/all_subdomains.txt"),
        "passive_subs": count_lines(OUTPUT_DIR / "subs/passive_all.txt"),
        "active_subs": count_lines(OUTPUT_DIR / "subs/active_all.txt"),
        "resolved": count_lines(OUTPUT_DIR / "resolved/resolved_subdomains.txt"),
        "unique_ips": count_lines(OUTPUT_DIR / "resolved/unique_ips.txt"),
        "live_hosts": count_lines(OUTPUT_DIR / "live/live_hosts.txt"),
        "status_200": count_lines(OUTPUT_DIR / "live/status_200.txt"),
        "status_403": count_lines(OUTPUT_DIR / "live/status_403.txt"),
        "interesting_titles": count_lines(OUTPUT_DIR / "live/interesting_titles.txt"),
        "total_urls": count_lines(OUTPUT_DIR / "urls/all_urls.txt"),
        "api_endpoints": count_lines(OUTPUT_DIR / "urls/api_endpoints.txt"),
        "js_urls": count_lines(OUTPUT_DIR / "js/js_urls.txt"),
        "xss_candidates": count_lines(OUTPUT_DIR / "urls/xss_candidates.txt"),
        "lfi_candidates": count_lines(OUTPUT_DIR / "urls/lfi_candidates.txt"),
        "ssrf_candidates": count_lines(OUTPUT_DIR / "urls/ssrf_candidates.txt"),
        "sqli_candidates": count_lines(OUTPUT_DIR / "urls/sqli_candidates.txt"),
        "redirect_candidates": count_lines(OUTPUT_DIR / "urls/redirect_candidates.txt"),
        "nuclei_findings": count_lines(OUTPUT_DIR / "scans/nuclei_all_summary.txt"),
        "open_ports": count_lines(OUTPUT_DIR / "scans/open_ports.txt"),
        "takeover_findings": count_lines(OUTPUT_DIR / "takeover/all_takeover_findings.txt"),
    }

    # Load secrets report
    secrets_report = load_json(OUTPUT_DIR / "secrets/js_secrets_report.json")
    secrets_count = secrets_report.get("total_findings", 0) if secrets_report else 0

    with open(report_path, 'w') as f:
        # Header
        f.write(f"# 🔍 ReconX Ultra — Reconnaissance Report\n\n")
        f.write(f"**Target:** `{DOMAIN}`  \n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
        f.write(f"**Framework:** ReconX Ultra v2.0.0  \n\n")
        f.write(f"---\n\n")

        # Executive Summary
        f.write(f"## 📊 Executive Summary\n\n")
        f.write(f"| Metric | Count |\n")
        f.write(f"|--------|-------|\n")
        f.write(f"| Total Subdomains | **{stats['subdomains']}** |\n")
        f.write(f"| Live Hosts | **{stats['live_hosts']}** |\n")
        f.write(f"| Total URLs | **{stats['total_urls']}** |\n")
        f.write(f"| JavaScript Files | **{stats['js_urls']}** |\n")
        f.write(f"| Nuclei Findings | **{stats['nuclei_findings']}** |\n")
        f.write(f"| Open Ports | **{stats['open_ports']}** |\n")
        f.write(f"| JS Secrets | **{secrets_count}** |\n")
        f.write(f"| Takeover Candidates | **{stats['takeover_findings']}** |\n\n")

        # Subdomains
        f.write(f"## 🌐 Subdomain Enumeration\n\n")
        f.write(f"- **Total unique subdomains:** {stats['subdomains']}\n")
        f.write(f"- **Passive sources:** {stats['passive_subs']}\n")
        f.write(f"- **Active discovery:** {stats['active_subs']}\n")
        f.write(f"- **Resolved to IP:** {stats['resolved']}\n")
        f.write(f"- **Unique IPs:** {stats['unique_ips']}\n\n")

        # Live Hosts
        f.write(f"## 🖥️ Live Hosts\n\n")
        f.write(f"- **Live hosts:** {stats['live_hosts']}\n")
        f.write(f"- **200 OK:** {stats['status_200']}\n")
        f.write(f"- **403 Forbidden:** {stats['status_403']}\n\n")

        # Interesting titles
        interesting = read_lines(OUTPUT_DIR / "live/interesting_titles.txt", 20)
        if interesting:
            f.write(f"### 🎯 Interesting Titles ({stats['interesting_titles']} total)\n\n")
            for title in interesting:
                f.write(f"- `{title}`\n")
            f.write(f"\n")

        # Technologies
        tech_summary = read_lines(OUTPUT_DIR / "live/tech_summary.txt", 20)
        if tech_summary:
            f.write(f"### 🔧 Technology Stack\n\n")
            f.write(f"| Count | Technology |\n")
            f.write(f"|-------|------------|\n")
            for line in tech_summary:
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    f.write(f"| {parts[0]} | {parts[1]} |\n")
            f.write(f"\n")

        # URLs
        f.write(f"## 🔗 URL Intelligence\n\n")
        f.write(f"- **Total URLs:** {stats['total_urls']}\n")
        f.write(f"- **API endpoints:** {stats['api_endpoints']}\n")
        f.write(f"- **JavaScript files:** {stats['js_urls']}\n\n")

        # Vulnerability Candidates
        f.write(f"## ⚡ Vulnerability Candidates\n\n")
        f.write(f"| Category | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| XSS | {stats['xss_candidates']} |\n")
        f.write(f"| LFI | {stats['lfi_candidates']} |\n")
        f.write(f"| SSRF | {stats['ssrf_candidates']} |\n")
        f.write(f"| SQLi | {stats['sqli_candidates']} |\n")
        f.write(f"| Open Redirect | {stats['redirect_candidates']} |\n\n")

        # Nuclei Findings
        nuclei_findings = read_lines(OUTPUT_DIR / "scans/nuclei_all_summary.txt", 30)
        if nuclei_findings:
            f.write(f"## 🛡️ Nuclei Findings ({stats['nuclei_findings']} total)\n\n")
            f.write(f"| Severity | Template | Host | Name |\n")
            f.write(f"|----------|----------|------|------|\n")
            for finding in nuclei_findings:
                parts = finding.split(" | ")
                if len(parts) >= 4:
                    f.write(f"| {parts[0]} | {parts[1]} | {parts[2]} | {parts[3]} |\n")
            f.write(f"\n")

        # Secrets
        if secrets_report and secrets_count > 0:
            f.write(f"## 🔑 JavaScript Secrets ({secrets_count} findings)\n\n")
            for finding in secrets_report.get("findings", [])[:20]:
                severity = finding.get("severity", "info").upper()
                f.write(f"- **[{severity}]** {finding.get('pattern', 'Unknown')}: ")
                f.write(f"`{finding.get('match', '')[:80]}...`\n")
            f.write(f"\n")

        # Takeover
        takeover = read_lines(OUTPUT_DIR / "takeover/all_takeover_findings.txt", 20)
        if takeover:
            f.write(f"## 🚨 Subdomain Takeover Candidates\n\n")
            for entry in takeover:
                f.write(f"- `{entry}`\n")
            f.write(f"\n")

        # Footer
        f.write(f"\n---\n\n")
        f.write(f"*Generated by ReconX Ultra v2.0.0 — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n")

    print(f"  ✅ Markdown report saved: {report_path}")


if __name__ == "__main__":
    main()
