#!/usr/bin/env python3
"""
============================================================================
ReconX Ultra — JavaScript Secret Extraction
============================================================================
Analyzes downloaded JavaScript files for secrets, API keys, tokens,
Firebase configs, hidden endpoints, GraphQL paths, and admin routes
using regex patterns and Shannon entropy analysis.
============================================================================
"""

import os
import re
import sys
import json
import math
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Configuration ────────────────────────────────────────────────────────────

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    print("Usage: secrets.py <domain>")
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
JS_DIR = OUTPUT_DIR / "js"
JS_FILES_DIR = JS_DIR / "files"
SECRETS_DIR = OUTPUT_DIR / "secrets"
SECRETS_DIR.mkdir(parents=True, exist_ok=True)

# ── Entropy Calculation ─────────────────────────────────────────────────────

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for char in data:
        freq[char] += 1
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)

# ── Secret Patterns ─────────────────────────────────────────────────────────

SECRET_PATTERNS = {
    # API Keys & Tokens
    "AWS Access Key": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
    "AWS Secret Key": r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Google Cloud Key": r"(?:GOOG|goog)[A-Za-z0-9_\-]{20,}",
    "Firebase Config": r"(?:apiKey|authDomain|databaseURL|storageBucket|messagingSenderId|appId|measurementId)\s*[:=]\s*['\"]([^'\"]+)['\"]",
    "Firebase URL": r"https?://[a-z0-9-]+\.firebaseio\.com[^\s'\"]*",
    "Slack Token": r"xox[bposa]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "GitHub Token": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "GitHub OAuth": r"(?:github|gh)[_\-]?(?:token|key|secret|oauth)[_\-]?\s*[=:]\s*['\"]?([a-f0-9]{40})['\"]?",
    "Stripe Secret": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Publishable": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\-_]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twilio Account SID": r"AC[a-z0-9]{32}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Mailchimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "SendGrid API Key": r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
    "Generic API Key": r"(?:api[_\-]?key|apikey|api[_\-]?secret|api[_\-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?",
    "Generic Secret": r"(?:secret|password|passwd|token|auth[_\-]?token|access[_\-]?token|bearer)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-/+=]{8,128})['\"]?",
    "Private Key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "Basic Auth": r"(?:basic\s+)([A-Za-z0-9+/=]{20,})",
    "Bearer Token": r"(?:bearer\s+)([A-Za-z0-9_\-\.]+)",

    # Cloud & Infrastructure
    "Azure Storage": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+",
    "Azure Connection String": r"(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=]+",
    "S3 Bucket": r"(?:s3://|s3\.amazonaws\.com/|s3-[a-z0-9-]+\.amazonaws\.com/)[a-zA-Z0-9._-]+",
    "CloudFront URL": r"https?://[a-z0-9]+\.cloudfront\.net[^\s'\"]*",

    # Database
    "MongoDB URI": r"mongodb(?:\+srv)?://[^\s'\"]+",
    "PostgreSQL URI": r"postgres(?:ql)?://[^\s'\"]+",
    "MySQL URI": r"mysql://[^\s'\"]+",
    "Redis URI": r"redis://[^\s'\"]+",

    # Communication
    "Telegram Bot Token": r"[0-9]+:AA[A-Za-z0-9_-]{33}",
    "Discord Webhook": r"https://(?:discord|discordapp)\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}",
}

# ── Endpoint Patterns ───────────────────────────────────────────────────────

ENDPOINT_PATTERNS = {
    "Absolute URL": r"""(?:['"])(https?://[^\s'"<>]+)(?:['"])""",
    "Relative Path": r"""(?:['"])(\/[a-zA-Z0-9_\-./]+(?:\?[^\s'"]*)?['"])""",
    "API Route": r"""(?:['"])(\/(?:api|v[0-9]+|rest|graphql|auth|admin|internal|private|debug)[^\s'"<>]*)(?:['"])""",
    "GraphQL Endpoint": r"""(?:['"])(\/(?:graphql|gql|query|mutation|subscription)[^\s'"<>]*)(?:['"])""",
    "Admin Route": r"""(?:['"])(\/(?:admin|dashboard|panel|console|manage|control|backoffice|backend|internal)[^\s'"<>]*)(?:['"])""",
    "Debug Route": r"""(?:['"])(\/(?:debug|test|dev|staging|_debug|_internal|_status|_health|healthcheck|actuator)[^\s'"<>]*)(?:['"])""",
    "WebSocket URL": r"""(?:['"])(wss?://[^\s'"<>]+)(?:['"])""",
}

# ── Analysis Functions ──────────────────────────────────────────────────────

class Finding:
    def __init__(self, pattern_name, match, file_path, line_number, entropy=0.0, severity="info"):
        self.pattern_name = pattern_name
        self.match = match[:200]  # Truncate long matches
        self.file_path = str(file_path)
        self.line_number = line_number
        self.entropy = entropy
        self.severity = severity
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "pattern": self.pattern_name,
            "match": self.match,
            "file": self.file_path,
            "line": self.line_number,
            "entropy": self.entropy,
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


def classify_severity(pattern_name, entropy):
    """Classify finding severity based on pattern and entropy."""
    critical_patterns = ["AWS Access Key", "AWS Secret Key", "Private Key", "Stripe Secret",
                         "MongoDB URI", "PostgreSQL URI", "JWT Token", "Generic Secret"]
    high_patterns = ["Google API Key", "GitHub Token", "Slack Token", "SendGrid API Key",
                     "Firebase URL", "Azure Storage", "Discord Bot Token", "Telegram Bot Token"]

    if pattern_name in critical_patterns or entropy > 4.5:
        return "critical"
    elif pattern_name in high_patterns or entropy > 4.0:
        return "high"
    elif entropy > 3.5:
        return "medium"
    return "low"


def analyze_file(file_path):
    """Analyze a single JS file for secrets and endpoints."""
    findings = []
    endpoints = []

    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
            lines = content.split('\n')
    except Exception:
        return findings, endpoints

    # Secret scanning
    for pattern_name, pattern in SECRET_PATTERNS.items():
        try:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                matched_text = match.group(0)
                # Find line number
                pos = match.start()
                line_num = content[:pos].count('\n') + 1
                entropy = shannon_entropy(matched_text)
                severity = classify_severity(pattern_name, entropy)

                # Filter low-confidence matches
                if len(matched_text) < 8:
                    continue
                if entropy < 2.0 and severity == "low":
                    continue

                findings.append(Finding(
                    pattern_name=pattern_name,
                    match=matched_text,
                    file_path=file_path,
                    line_number=line_num,
                    entropy=entropy,
                    severity=severity,
                ))
        except re.error:
            continue

    # Endpoint scanning
    for ep_name, ep_pattern in ENDPOINT_PATTERNS.items():
        try:
            for match in re.finditer(ep_pattern, content, re.IGNORECASE):
                matched_text = match.group(1) if match.groups() else match.group(0)
                # Clean up the match
                matched_text = matched_text.strip("'\"")
                if len(matched_text) > 5:
                    endpoints.append({
                        "type": ep_name,
                        "endpoint": matched_text,
                        "file": str(file_path),
                    })
        except re.error:
            continue

    return findings, endpoints


def high_entropy_strings(content, min_length=20, min_entropy=4.0):
    """Find high-entropy strings that might be secrets."""
    findings = []
    # Match quoted strings
    for match in re.finditer(r"""['"]([A-Za-z0-9+/=_\-]{20,})['"]""", content):
        candidate = match.group(1)
        ent = shannon_entropy(candidate)
        if ent >= min_entropy and len(candidate) >= min_length:
            pos = match.start()
            line_num = content[:pos].count('\n') + 1
            findings.append(Finding(
                pattern_name="High Entropy String",
                match=candidate,
                file_path="",
                line_number=line_num,
                entropy=ent,
                severity="medium" if ent < 4.5 else "high",
            ))
    return findings


# ── Main Execution ──────────────────────────────────────────────────────────

def main():
    print(f"\n  🔍 JavaScript Secret Analysis for: {DOMAIN}")
    print(f"  {'─' * 50}")

    all_findings = []
    all_endpoints = []
    files_analyzed = 0

    # Analyze downloaded JS files
    if JS_FILES_DIR.exists():
        js_files = list(JS_FILES_DIR.glob("*.js"))
        total_files = len(js_files)
        print(f"  ℹ️  Analyzing {total_files} JavaScript files...")

        for i, js_file in enumerate(js_files, 1):
            findings, endpoints = analyze_file(js_file)
            all_findings.extend(findings)
            all_endpoints.extend(endpoints)
            files_analyzed += 1

            # Also do high-entropy analysis
            try:
                with open(js_file, 'r', errors='ignore') as f:
                    content = f.read()
                he_findings = high_entropy_strings(content)
                for f_item in he_findings:
                    f_item.file_path = str(js_file)
                all_findings.extend(he_findings)
            except Exception:
                pass

    # Deduplicate findings
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = f"{f.pattern_name}:{f.match}"
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # Deduplicate endpoints
    seen_ep = set()
    unique_endpoints = []
    for ep in all_endpoints:
        key = ep["endpoint"]
        if key not in seen_ep:
            seen_ep.add(key)
            unique_endpoints.append(ep)

    # ── Save Results ─────────────────────────────────────────────────────────

    # JSON report
    report = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "files_analyzed": files_analyzed,
        "total_findings": len(unique_findings),
        "total_endpoints": len(unique_endpoints),
        "findings": [f.to_dict() for f in unique_findings],
        "endpoints": unique_endpoints,
    }

    report_path = SECRETS_DIR / "js_secrets_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)

    # Text summary
    summary_path = SECRETS_DIR / "js_secrets_summary.txt"
    with open(summary_path, 'w') as f:
        f.write(f"# ReconX Ultra — JavaScript Secret Analysis\n")
        f.write(f"# Domain: {DOMAIN}\n")
        f.write(f"# Date: {datetime.now().isoformat()}\n")
        f.write(f"# Files analyzed: {files_analyzed}\n")
        f.write(f"# {'=' * 60}\n\n")

        # Group by severity
        for severity in ["critical", "high", "medium", "low"]:
            sev_findings = [fi for fi in unique_findings if fi.severity == severity]
            if sev_findings:
                f.write(f"\n## [{severity.upper()}] ({len(sev_findings)} findings)\n")
                f.write(f"{'─' * 60}\n")
                for fi in sev_findings:
                    f.write(f"  Pattern:  {fi.pattern_name}\n")
                    f.write(f"  Match:    {fi.match}\n")
                    f.write(f"  File:     {fi.file_path}\n")
                    f.write(f"  Line:     {fi.line_number}\n")
                    f.write(f"  Entropy:  {fi.entropy}\n")
                    f.write(f"\n")

    # Save endpoints
    endpoints_path = JS_DIR / "extracted_endpoints.txt"
    with open(endpoints_path, 'w') as f:
        for ep in unique_endpoints:
            f.write(f"{ep['endpoint']}\n")

    # Save categorized endpoints
    for ep_type in set(ep["type"] for ep in unique_endpoints):
        type_eps = [ep["endpoint"] for ep in unique_endpoints if ep["type"] == ep_type]
        type_file = JS_DIR / f"endpoints_{ep_type.lower().replace(' ', '_')}.txt"
        with open(type_file, 'w') as f:
            f.write('\n'.join(sorted(set(type_eps))))

    # ── Print Summary ────────────────────────────────────────────────────────
    severity_counts = defaultdict(int)
    for f_item in unique_findings:
        severity_counts[f_item.severity] += 1

    print(f"\n  {'─' * 50}")
    print(f"  📊 Analysis Results:")
    print(f"    ├─ Files analyzed:    {files_analyzed}")
    print(f"    ├─ Total findings:    {len(unique_findings)}")
    if severity_counts.get("critical", 0) > 0:
        print(f"    ├─ 🚨 Critical:      {severity_counts['critical']}")
    if severity_counts.get("high", 0) > 0:
        print(f"    ├─ ⚠️  High:          {severity_counts['high']}")
    if severity_counts.get("medium", 0) > 0:
        print(f"    ├─ 📌 Medium:        {severity_counts['medium']}")
    if severity_counts.get("low", 0) > 0:
        print(f"    ├─ ℹ️  Low:           {severity_counts['low']}")
    print(f"    ├─ Endpoints:        {len(unique_endpoints)}")

    # Count endpoint types
    ep_type_counts = defaultdict(int)
    for ep in unique_endpoints:
        ep_type_counts[ep["type"]] += 1
    for ep_type, count in sorted(ep_type_counts.items()):
        print(f"    │  └─ {ep_type}: {count}")

    print(f"    └─ Report saved:     {report_path}")
    print()


if __name__ == "__main__":
    main()
