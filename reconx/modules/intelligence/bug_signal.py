#!/usr/bin/env python3
"""
ReconX Ultra — Bug Signal & Vulnerability Intelligence Engine
=============================================================
Aggregates all recon data, scores risk, classifies endpoints,
extracts JS intelligence, and generates prioritized findings.

Outputs:
  - prioritized_targets.json
  - suspicious_endpoints.txt
  - api_inventory.json
  - endpoint_scores.txt
"""

import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: bug_signal.py <domain>", file=sys.stderr)
    sys.exit(1)

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
RECONX_ROOT = SCRIPT_DIR.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_URLS = OUTPUT_DIR / "urls"
OUT_JS = OUTPUT_DIR / "js"
OUT_PARAMS = OUTPUT_DIR / "params"
OUT_LIVE = OUTPUT_DIR / "live"
OUT_CONTENT = OUTPUT_DIR / "content"
OUT_SECRETS = OUTPUT_DIR / "secrets"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_SCANS = OUTPUT_DIR / "scans"

OUT_INTEL.mkdir(parents=True, exist_ok=True)

# ── Risk Scoring Constants ───────────────────────────────────────────────────
CRITICAL_KEYWORDS = {
    "admin", "internal", "debug", "graphql", "upload", "proxy", "webhook",
    "callback", "import", "export", "backup", "config", "setup", "install",
    "console", "actuator", "management", "swagger", "api-docs", "phpinfo",
    "server-status", "elmah", "trace", "profiler", "metrics", "health",
}

HIGH_KEYWORDS = {
    "login", "auth", "token", "oauth", "sso", "saml", "jwt", "session",
    "password", "reset", "register", "signup", "api", "graphiql", "fetch",
    "redirect", "file", "download", "pdf", "render", "template",
}

MEDIUM_KEYWORDS = {
    "search", "query", "filter", "sort", "page", "view", "display",
    "preview", "share", "embed", "comment", "message", "contact",
    "feedback", "form", "submit", "process", "action",
}

# ── Secret Patterns ──────────────────────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase": r"(?i)firebase[a-z0-9_.-]*\.com",
    "Slack Token": r"xox[bpoas]-[0-9]{10,}-[0-9a-zA-Z]{10,}",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "JWT Token": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
    "Private Key": r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----",
    "Bearer Token": r"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*",
    "Basic Auth": r"(?i)basic\s+[A-Za-z0-9+/=]{10,}",
    "Heroku API Key": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Mailgun Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio SID": r"AC[a-zA-Z0-9_]{32}",
    "Stripe Key": r"(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    "Square Token": r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}",
    "SendGrid Key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
    "Telegram Bot": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
    "Password Field": r"""(?i)['"]?password['"]?\s*[:=]\s*['"][^'"]{4,}['"]""",
    "API Key Generic": r"""(?i)['"]?api[_-]?key['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]""",
    "Secret Generic": r"""(?i)['"]?secret['"]?\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]""",
}

# ── Endpoint Extraction Patterns ────────────────────────────────────────────
ENDPOINT_PATTERNS = [
    r'["\']/(api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|webhook|callback|debug|config|actuator|swagger|health|metrics|status)[/\w.-]*["\']',
    r'["\']https?://[^"\']+["\']',
    r'fetch\s*\(\s*["\'][^"\']+["\']',
    r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\'][^"\']+["\']',
    r'axios\.(get|post|put|delete|patch)\s*\(\s*["\'][^"\']+["\']',
    r'XMLHttpRequest[^;]+open\s*\([^)]+["\'][^"\']+["\']',
]

# ═══════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═══════════════════════════════════════════════════════════════════════════

def read_lines(filepath):
    """Read non-empty lines from a file."""
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []

def read_files_in_dir(dirpath, ext=None):
    """Read all file contents in a directory."""
    contents = {}
    dirpath = Path(dirpath)
    if not dirpath.exists():
        return contents
    for f in dirpath.iterdir():
        if f.is_file() and (ext is None or f.suffix == ext):
            try:
                contents[str(f)] = f.read_text(errors='ignore')
            except Exception:
                pass
    return contents

def score_url(url):
    """Score a URL based on keyword presence."""
    url_lower = url.lower()
    score = 0
    reasons = []

    for kw in CRITICAL_KEYWORDS:
        if kw in url_lower:
            score += 30
            reasons.append(f"critical:{kw}")

    for kw in HIGH_KEYWORDS:
        if kw in url_lower:
            score += 15
            reasons.append(f"high:{kw}")

    for kw in MEDIUM_KEYWORDS:
        if kw in url_lower:
            score += 5
            reasons.append(f"medium:{kw}")

    # Bonus for parameters
    if '?' in url:
        score += 5
        param_count = url.count('&') + 1
        score += min(param_count * 2, 10)

    # Bonus for non-standard ports
    if re.search(r':\d{4,5}/', url):
        score += 10
        reasons.append("non-standard-port")

    # Bonus for API paths
    if re.search(r'/api/|/v[0-9]+/', url_lower):
        score += 10
        reasons.append("api-path")

    return min(score, 100), reasons

# ═══════════════════════════════════════════════════════════════════════════
# Intelligence Engines
# ═══════════════════════════════════════════════════════════════════════════

def analyze_js_files():
    """Scan JS files for secrets, endpoints, and intelligence."""
    print("[*] Analyzing JavaScript files for intelligence...")
    js_dir = OUT_JS / "files"
    secrets_found = []
    endpoints_found = set()
    admin_routes = set()

    js_files = read_files_in_dir(js_dir, ".js")
    if not js_files:
        # Also try JS URLs list
        js_urls_file = OUT_JS / "js_urls.txt"
        print(f"    No local JS files found ({js_dir})")
        return secrets_found, endpoints_found, admin_routes

    print(f"    Scanning {len(js_files)} JS files...")

    for filepath, content in js_files.items():
        fname = Path(filepath).name

        # Secret detection
        for secret_name, pattern in SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, content)
                for match in matches[:5]:  # Cap per pattern per file
                    match_str = match if isinstance(match, str) else str(match)
                    if len(match_str) > 200:
                        match_str = match_str[:200] + "..."
                    secrets_found.append({
                        "type": secret_name,
                        "file": fname,
                        "match": match_str,
                        "severity": "CRITICAL" if "key" in secret_name.lower() or "private" in secret_name.lower() else "HIGH"
                    })
            except re.error:
                pass

        # Endpoint extraction
        for pattern in ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, content)
                for match in matches:
                    cleaned = re.sub(r'^["\']|["\']$', '', match.strip())
                    if len(cleaned) > 5 and not cleaned.startswith('//'):
                        endpoints_found.add(cleaned)
            except re.error:
                pass

        # Admin route detection
        admin_pattern = r'["\']/(admin|internal|dashboard|management|console|staff|superuser|moderator|backoffice|cms|panel)[/\w.-]*["\']'
        for match in re.findall(admin_pattern, content, re.IGNORECASE):
            admin_routes.add(match)

    return secrets_found, endpoints_found, admin_routes


def build_api_inventory():
    """Build an API inventory from all discovered data."""
    print("[*] Building API inventory...")
    inventory = {
        "graphql_endpoints": [],
        "swagger_specs": [],
        "rest_apis": [],
        "websocket_endpoints": [],
        "undocumented_apis": []
    }

    # GraphQL
    graphql_file = OUT_INTEL / "graphql_targets.txt"
    if not graphql_file.exists():
        graphql_file = OUTPUT_DIR / "scans" / "graphql_endpoints.txt"
    inventory["graphql_endpoints"] = read_lines(graphql_file)

    # Swagger
    swagger_file = OUTPUT_DIR / "scans" / "swagger_specs.txt"
    inventory["swagger_specs"] = read_lines(swagger_file)

    # Detect API endpoints from URLs
    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    for url in all_urls:
        url_lower = url.lower()
        if re.search(r'/api/|/v[0-9]+/', url_lower):
            inventory["rest_apis"].append(url)
        if 'ws://' in url_lower or 'wss://' in url_lower:
            inventory["websocket_endpoints"].append(url)

    # Deduplicate
    for key in inventory:
        inventory[key] = list(set(inventory[key]))[:500]

    return inventory


def generate_suspicious_endpoints():
    """Identify suspicious endpoints from all URL data."""
    print("[*] Identifying suspicious endpoints...")
    suspicious = []
    all_urls = read_lines(OUT_URLS / "all_urls.txt")

    suspicious_patterns = [
        (r'/(admin|internal|debug|console|management|staff)', "ADMIN_ROUTE", "HIGH"),
        (r'/(upload|import|export|backup|dump|migrate)', "FILE_OPERATION", "HIGH"),
        (r'/(proxy|fetch|request|forward|gateway|relay)', "PROXY_ENDPOINT", "HIGH"),
        (r'/(webhook|callback|hook|notify|event)', "WEBHOOK", "HIGH"),
        (r'/(graphql|graphiql|playground)', "GRAPHQL", "HIGH"),
        (r'/(swagger|api-docs|openapi|redoc)', "API_DOCS", "MEDIUM"),
        (r'/(login|auth|oauth|sso|saml|cas)', "AUTH_ENDPOINT", "MEDIUM"),
        (r'/(config|setup|install|init|env)', "CONFIG_EXPOSED", "CRITICAL"),
        (r'/(actuator|health|metrics|status|info|beans)', "ACTUATOR", "HIGH"),
        (r'/\.(git|svn|hg|env|DS_Store)', "SCM_EXPOSED", "CRITICAL"),
        (r'/(phpinfo|server-status|server-info|elmah)', "INFO_DISCLOSURE", "CRITICAL"),
        (r'/(cgi-bin|wp-content|wp-includes)', "LEGACY_PATH", "MEDIUM"),
    ]

    for url in all_urls:
        for pattern, category, severity in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious.append({
                    "url": url,
                    "category": category,
                    "severity": severity
                })
                break  # One category per URL

    return suspicious


def score_and_prioritize():
    """Score all endpoints and generate prioritized list."""
    print("[*] Scoring and prioritizing targets...")
    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    live_hosts = read_lines(OUT_LIVE / "live_hosts.txt")

    scored_targets = []

    # Score URLs
    for url in all_urls:
        score, reasons = score_url(url)
        if score >= 10:
            scored_targets.append({
                "url": url,
                "score": score,
                "reasons": reasons[:5],
                "type": "url"
            })

    # Score live hosts
    for host in live_hosts:
        score, reasons = score_url(host)
        if score >= 10:
            scored_targets.append({
                "url": host,
                "score": score,
                "reasons": reasons[:5],
                "type": "host"
            })

    # Sort by score descending
    scored_targets.sort(key=lambda x: x["score"], reverse=True)
    return scored_targets[:1000]  # Top 1000


# ═══════════════════════════════════════════════════════════════════════════
# Main Execution
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print(f"  Bug Signal Intelligence Engine — {DOMAIN}")
    print(f"{'='*60}\n")

    # 1. JavaScript Intelligence
    js_secrets, js_endpoints, admin_routes = analyze_js_files()

    if js_secrets:
        secrets_file = OUT_INTEL / "js_secrets.json"
        with open(secrets_file, 'w') as f:
            json.dump(js_secrets, f, indent=2)
        print(f"    [!] {len(js_secrets)} secrets found in JS files")

    if js_endpoints:
        ep_file = OUT_INTEL / "js_endpoints.txt"
        with open(ep_file, 'w') as f:
            f.write('\n'.join(sorted(js_endpoints)))
        print(f"    [+] {len(js_endpoints)} API endpoints extracted from JS")

    if admin_routes:
        ar_file = OUT_INTEL / "admin_routes.txt"
        with open(ar_file, 'w') as f:
            f.write('\n'.join(sorted(admin_routes)))
        print(f"    [!] {len(admin_routes)} admin routes found in JS")

    # 2. API Inventory
    api_inv = build_api_inventory()
    api_file = OUT_INTEL / "api_inventory.json"
    with open(api_file, 'w') as f:
        json.dump(api_inv, f, indent=2)
    total_apis = sum(len(v) for v in api_inv.values())
    print(f"    [+] API inventory: {total_apis} endpoints catalogued")

    # 3. Suspicious Endpoints
    suspicious = generate_suspicious_endpoints()
    susp_file = OUT_INTEL / "suspicious_endpoints.txt"
    with open(susp_file, 'w') as f:
        for s in suspicious:
            f.write(f"[{s['severity']}] [{s['category']}] {s['url']}\n")
    print(f"    [!] {len(suspicious)} suspicious endpoints identified")

    # 4. Prioritized Targets
    prioritized = score_and_prioritize()
    prio_file = OUT_INTEL / "prioritized_targets.json"
    with open(prio_file, 'w') as f:
        json.dump(prioritized, f, indent=2)

    # Also write a human-readable version
    scores_file = OUT_INTEL / "endpoint_scores.txt"
    with open(scores_file, 'w') as f:
        f.write(f"# ReconX Ultra — Endpoint Risk Scores for {DOMAIN}\n")
        f.write(f"# Score range: 0-100 (higher = more interesting)\n\n")
        for t in prioritized[:200]:
            reasons_str = ", ".join(t["reasons"][:3])
            f.write(f"[{t['score']:3d}] {t['url']}  ({reasons_str})\n")
    print(f"    [+] {len(prioritized)} targets scored and prioritized")

    # 5. Summary statistics
    print(f"\n{'─'*60}")
    print(f"  Intelligence Summary:")
    print(f"{'─'*60}")
    print(f"    JS Secrets:          {len(js_secrets)}")
    print(f"    JS Endpoints:        {len(js_endpoints)}")
    print(f"    Admin Routes:        {len(admin_routes)}")
    print(f"    API Inventory:       {total_apis}")
    print(f"    Suspicious URLs:     {len(suspicious)}")
    print(f"    Prioritized Targets: {len(prioritized)}")
    crit = len([s for s in suspicious if s['severity'] == 'CRITICAL'])
    high = len([s for s in suspicious if s['severity'] == 'HIGH'])
    if crit > 0:
        print(f"    \033[1;31m⚠  {crit} CRITICAL findings require immediate attention\033[0m")
    if high > 0:
        print(f"    \033[1;33m⚠  {high} HIGH findings should be investigated\033[0m")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
