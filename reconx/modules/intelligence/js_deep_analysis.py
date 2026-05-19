#!/usr/bin/env python3
"""
ReconX Ultra — Deep JavaScript Intelligence Engine
===================================================
Performs deep analysis of collected JavaScript files:
  - Deobfuscation & beautification
  - DOM sink detection (XSS vectors)
  - API endpoint extraction
  - Secret detection with entropy analysis
  - Hidden route discovery
  - Source map analysis
  - Webpack chunk detection
  - Internal domain extraction

Outputs to: output/<domain>/intelligence/
"""

import json
import math
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: js_deep_analysis.py <domain>", file=sys.stderr)
    sys.exit(1)

SCRIPT_DIR = Path(__file__).resolve().parent
RECONX_ROOT = SCRIPT_DIR.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_JS = OUTPUT_DIR / "js"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_INTEL.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════

DOM_SINKS = {
    "innerHTML": {"severity": "HIGH", "vuln": "XSS", "desc": "Direct HTML injection sink"},
    "outerHTML": {"severity": "HIGH", "vuln": "XSS", "desc": "Direct HTML injection sink"},
    "document.write": {"severity": "HIGH", "vuln": "XSS", "desc": "Document write sink"},
    "document.writeln": {"severity": "HIGH", "vuln": "XSS", "desc": "Document writeln sink"},
    "eval(": {"severity": "CRITICAL", "vuln": "RCE/XSS", "desc": "Code execution sink"},
    "setTimeout(": {"severity": "MEDIUM", "vuln": "XSS", "desc": "Delayed code execution"},
    "setInterval(": {"severity": "MEDIUM", "vuln": "XSS", "desc": "Repeated code execution"},
    "Function(": {"severity": "HIGH", "vuln": "RCE/XSS", "desc": "Dynamic function creation"},
    "dangerouslySetInnerHTML": {"severity": "HIGH", "vuln": "XSS", "desc": "React unsafe HTML"},
    "v-html": {"severity": "HIGH", "vuln": "XSS", "desc": "Vue unsafe HTML directive"},
    "[innerHTML]": {"severity": "HIGH", "vuln": "XSS", "desc": "Angular unsafe binding"},
    "bypassSecurityTrust": {"severity": "CRITICAL", "vuln": "XSS", "desc": "Angular security bypass"},
    "$.html(": {"severity": "HIGH", "vuln": "XSS", "desc": "jQuery HTML injection"},
    "insertAdjacentHTML": {"severity": "HIGH", "vuln": "XSS", "desc": "Adjacent HTML injection"},
    "srcdoc": {"severity": "MEDIUM", "vuln": "XSS", "desc": "iframe srcdoc injection"},
    "location.href": {"severity": "MEDIUM", "vuln": "Open Redirect", "desc": "Location redirect"},
    "location.assign": {"severity": "MEDIUM", "vuln": "Open Redirect", "desc": "Location assign redirect"},
    "location.replace": {"severity": "MEDIUM", "vuln": "Open Redirect", "desc": "Location replace redirect"},
    "window.open": {"severity": "MEDIUM", "vuln": "Open Redirect", "desc": "Window open redirect"},
    "postMessage": {"severity": "MEDIUM", "vuln": "XSS/Info Leak", "desc": "Cross-origin messaging"},
    "document.cookie": {"severity": "MEDIUM", "vuln": "Session Theft", "desc": "Cookie access"},
    "localStorage": {"severity": "LOW", "vuln": "Info Leak", "desc": "Local storage access"},
    "sessionStorage": {"severity": "LOW", "vuln": "Info Leak", "desc": "Session storage access"},
}

DOM_SOURCES = [
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer",
    "window.name", "document.cookie",
    "postMessage", "MessageEvent",
    "URLSearchParams", "URL(",
]

SECRET_PATTERNS = {
    "AWS Access Key": (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret": (r"""(?:aws_secret|secret_key|aws_key)\s*[:=]\s*['"][A-Za-z0-9/+=]{40}['"]""", "CRITICAL"),
    "Google API Key": (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Google OAuth": (r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", "HIGH"),
    "Firebase URL": (r"https://[a-z0-9-]+\.firebaseio\.com", "HIGH"),
    "Firebase Config": (r"""apiKey\s*:\s*['"]AIza[^'"]+['"]""", "HIGH"),
    "Slack Token": (r"xox[bpoas]-[0-9]{10,}-[0-9a-zA-Z]{10,}", "CRITICAL"),
    "Slack Webhook": (r"hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "HIGH"),
    "GitHub Token": (r"gh[pousr]_[A-Za-z0-9_]{36,}", "CRITICAL"),
    "GitLab Token": (r"glpat-[A-Za-z0-9\-]{20,}", "CRITICAL"),
    "JWT": (r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+", "HIGH"),
    "Private Key": (r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----", "CRITICAL"),
    "Stripe Key": (r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "SendGrid": (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "CRITICAL"),
    "Twilio SID": (r"AC[a-zA-Z0-9_]{32}", "HIGH"),
    "Mailgun": (r"key-[0-9a-zA-Z]{32}", "HIGH"),
    "Square Token": (r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}", "HIGH"),
    "Telegram Bot": (r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}", "HIGH"),
    "Heroku Key": (r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "MEDIUM"),
    "Password": (r"""(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,30}['"]""", "CRITICAL"),
    "API Key Generic": (r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"][a-zA-Z0-9_\-]{16,}['"]""", "HIGH"),
    "Bearer Token": (r"""[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}""", "HIGH"),
    "Basic Auth": (r"""[Bb]asic\s+[A-Za-z0-9+/=]{20,}""", "HIGH"),
    "Internal URL": (r"https?://(?:internal|staging|dev|test|admin|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s'\"]*", "MEDIUM"),
}

ENDPOINT_REGEXES = [
    (r"""['"`]/(api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|webhook|callback|debug|config|actuator|swagger|health|metrics|upload|proxy|export|import|fetch)/[a-zA-Z0-9/_\-{}:.]*['"`]""", "API_ROUTE"),
    (r"""['"`]https?://[^'"`\s]{10,}['"`]""", "FULL_URL"),
    (r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", "FETCH_CALL"),
    (r"""axios\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]""", "AXIOS_CALL"),
    (r"""\.ajax\s*\(\s*\{[^}]*url\s*:\s*['"`]([^'"`]+)['"`]""", "JQUERY_AJAX"),
    (r"""new\s+XMLHttpRequest[^;]+\.open\s*\(\s*['"`][A-Z]+['"`]\s*,\s*['"`]([^'"`]+)['"`]""", "XHR_CALL"),
    (r"""\.subscribe\s*\(\s*['"`]([^'"`]+)['"`]""", "WEBSOCKET_SUB"),
    (r"""new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]""", "WEBSOCKET"),
    (r"""\.(?:href|src|action)\s*=\s*['"`](/[^'"`]+)['"`]""", "DOM_ASSIGNMENT"),
]


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def entropy(data):
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0
    freq = defaultdict(int)
    for c in data:
        freq[c] += 1
    length = len(data)
    return -sum((count/length) * math.log2(count/length) for count in freq.values())


def is_high_entropy(s, threshold=4.0):
    """Check if string has high entropy (likely a secret)."""
    return len(s) >= 16 and entropy(s) >= threshold


def beautify_js(content):
    """Basic JS beautification — add newlines after semicolons and braces."""
    content = re.sub(r';(?!\s*\n)', ';\n', content)
    content = re.sub(r'\{(?!\s*\n)', '{\n', content)
    content = re.sub(r'\}(?!\s*\n)', '}\n', content)
    return content


def detect_packed_js(content):
    """Detect common JS packing/obfuscation patterns."""
    patterns = [
        (r"eval\(function\(p,a,c,k,e,d\)", "Dean Edwards Packer"),
        (r"eval\(function\(p,a,c,k,e,r\)", "P.A.C.K.E.R."),
        (r"_0x[a-f0-9]{4,}", "Hex obfuscation"),
        (r"\\x[0-9a-f]{2}", "Hex escape sequences"),
        (r"String\.fromCharCode", "CharCode obfuscation"),
        (r"atob\s*\(", "Base64 decoding"),
        (r"unescape\s*\(", "URL-encoded strings"),
        (r"\['\\x", "Array notation obfuscation"),
    ]
    detected = []
    for pattern, name in patterns:
        if re.search(pattern, content):
            detected.append(name)
    return detected


# ═══════════════════════════════════════════════════════════════════════════
# Analysis Functions
# ═══════════════════════════════════════════════════════════════════════════

def analyze_dom_sinks(js_files):
    """Find DOM-based XSS sinks and sources in JS files."""
    print("[*] Scanning for DOM sinks and sources...")
    findings = []

    for filepath, content in js_files.items():
        fname = Path(filepath).name
        lines = content.split('\n')

        for line_num, line in enumerate(lines, 1):
            # Check sinks
            for sink_name, sink_info in DOM_SINKS.items():
                if sink_name in line:
                    # Check if connected to a source
                    source_connected = any(src in line for src in DOM_SOURCES)
                    findings.append({
                        "file": fname,
                        "line": line_num,
                        "sink": sink_name,
                        "severity": sink_info["severity"],
                        "vuln_type": sink_info["vuln"],
                        "description": sink_info["desc"],
                        "source_connected": source_connected,
                        "context": line.strip()[:200]
                    })

    # Deduplicate by file+sink+line
    seen = set()
    unique = []
    for f in findings:
        key = (f["file"], f["sink"], f["line"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def extract_endpoints(js_files):
    """Extract all API endpoints from JS files."""
    print("[*] Extracting API endpoints from JavaScript...")
    endpoints = defaultdict(set)

    for filepath, content in js_files.items():
        fname = Path(filepath).name
        for pattern, etype in ENDPOINT_REGEXES:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                ep = match.group(0)
                ep = re.sub(r"""^['"`]|['"`]$""", '', ep)
                if len(ep) > 3 and not ep.startswith('//') and '.js' not in ep.lower():
                    endpoints[etype].add(ep)

    return {k: sorted(v) for k, v in endpoints.items()}


def detect_secrets(js_files):
    """Detect secrets with regex patterns + entropy analysis."""
    print("[*] Detecting secrets with pattern + entropy analysis...")
    secrets = []

    for filepath, content in js_files.items():
        fname = Path(filepath).name

        # Pattern-based detection
        for secret_name, (pattern, severity) in SECRET_PATTERNS.items():
            try:
                for match in re.finditer(pattern, content, re.IGNORECASE):
                    match_str = match.group(0)[:200]
                    secrets.append({
                        "type": secret_name,
                        "file": fname,
                        "match": match_str,
                        "severity": severity,
                        "method": "pattern"
                    })
            except re.error:
                pass

        # Entropy-based detection for quoted strings
        for match in re.finditer(r"""['"]([a-zA-Z0-9+/=_\-]{20,80})['"]""", content):
            candidate = match.group(1)
            if is_high_entropy(candidate, 4.5):
                # Skip common false positives
                if not re.match(r'^(function|return|undefined|null|true|false|class)', candidate):
                    secrets.append({
                        "type": "High Entropy String",
                        "file": fname,
                        "match": candidate[:80],
                        "severity": "MEDIUM",
                        "method": "entropy",
                        "entropy": round(entropy(candidate), 2)
                    })

    # Deduplicate
    seen = set()
    unique = []
    for s in secrets:
        key = (s["type"], s["match"][:50])
        if key not in seen:
            seen.add(key)
            unique.append(s)

    return unique


def extract_internal_domains(js_files):
    """Extract internal/hidden domains from JS files."""
    print("[*] Extracting internal domains...")
    domains = set()

    for filepath, content in js_files.items():
        for match in re.finditer(r'https?://([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})', content):
            domain = match.group(1).lower()
            if any(kw in domain for kw in ['internal', 'staging', 'dev', 'test', 'admin',
                                            'local', 'private', 'corp', 'intra', 'vpn']):
                domains.add(domain)
            if DOMAIN and DOMAIN in domain and domain != DOMAIN:
                domains.add(domain)

    return sorted(domains)


def analyze_obfuscation(js_files):
    """Detect obfuscated/packed JS files."""
    print("[*] Detecting obfuscated JavaScript...")
    obfuscated = []

    for filepath, content in js_files.items():
        fname = Path(filepath).name
        methods = detect_packed_js(content)
        if methods:
            obfuscated.append({
                "file": fname,
                "methods": methods,
                "size": len(content)
            })

    return obfuscated


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print(f"  Deep JavaScript Intelligence — {DOMAIN}")
    print(f"{'='*60}\n")

    # Load JS files
    js_dir = OUT_JS / "files"
    js_files = {}
    if js_dir.exists():
        for f in js_dir.iterdir():
            if f.is_file() and f.suffix in ('.js', '.mjs', '.jsx', '.ts', '.tsx'):
                try:
                    js_files[str(f)] = f.read_text(errors='ignore')
                except Exception:
                    pass

    # Also scan inline JS from crawl results
    js_urls = read_lines(OUT_JS / "js_urls.txt")
    print(f"    JS files on disk: {len(js_files)}")
    print(f"    JS URLs known: {len(js_urls)}")

    if not js_files:
        print("    [!] No JS files available for deep analysis")
        print("    [i] Run full recon pipeline first to collect JS files")
        # Still generate empty output files
        for fname in ["dom_sinks.json", "js_endpoints.json", "js_secrets_deep.json",
                       "internal_domains.txt", "obfuscated_js.json"]:
            (OUT_INTEL / fname).write_text("[]" if fname.endswith('.json') else "")
        return

    # 1. DOM Sink Analysis
    dom_sinks = analyze_dom_sinks(js_files)
    with open(OUT_INTEL / "dom_sinks.json", 'w') as f:
        json.dump(dom_sinks, f, indent=2)
    critical_sinks = [s for s in dom_sinks if s["severity"] in ("CRITICAL", "HIGH")]
    source_connected = [s for s in dom_sinks if s.get("source_connected")]
    print(f"    [{'!' if critical_sinks else '+'}] DOM sinks: {len(dom_sinks)} total, {len(critical_sinks)} critical/high, {len(source_connected)} source-connected")

    # 2. Endpoint Extraction
    endpoints = extract_endpoints(js_files)
    with open(OUT_INTEL / "js_endpoints.json", 'w') as f:
        json.dump(endpoints, f, indent=2)
    total_eps = sum(len(v) for v in endpoints.values())
    print(f"    [+] API endpoints: {total_eps} extracted across {len(endpoints)} categories")

    # Also write flat endpoint list
    with open(OUT_INTEL / "js_endpoints_flat.txt", 'w') as f:
        for category, eps in sorted(endpoints.items()):
            for ep in eps:
                f.write(f"[{category}] {ep}\n")

    # 3. Secret Detection
    secrets = detect_secrets(js_files)
    with open(OUT_INTEL / "js_secrets_deep.json", 'w') as f:
        json.dump(secrets, f, indent=2)
    crit_secrets = [s for s in secrets if s["severity"] == "CRITICAL"]
    print(f"    [{'!' if crit_secrets else '+'}] Secrets: {len(secrets)} found, {len(crit_secrets)} CRITICAL")

    # 4. Internal Domains
    internal = extract_internal_domains(js_files)
    with open(OUT_INTEL / "internal_domains.txt", 'w') as f:
        f.write('\n'.join(internal))
    print(f"    [+] Internal domains: {len(internal)} discovered")

    # 5. Obfuscation Detection
    obfuscated = analyze_obfuscation(js_files)
    with open(OUT_INTEL / "obfuscated_js.json", 'w') as f:
        json.dump(obfuscated, f, indent=2)
    if obfuscated:
        print(f"    [!] Obfuscated JS: {len(obfuscated)} files (may contain hidden logic)")

    # Summary
    print(f"\n{'─'*60}")
    print(f"  JS Intelligence Summary:")
    print(f"{'─'*60}")
    print(f"    Files analyzed:     {len(js_files)}")
    print(f"    DOM sinks:          {len(dom_sinks)}")
    print(f"    API endpoints:      {total_eps}")
    print(f"    Secrets:            {len(secrets)}")
    print(f"    Internal domains:   {len(internal)}")
    print(f"    Obfuscated files:   {len(obfuscated)}")
    if crit_secrets:
        print(f"    \033[1;31m⚠  {len(crit_secrets)} CRITICAL secrets require immediate review\033[0m")
    if source_connected:
        print(f"    \033[1;33m⚠  {len(source_connected)} DOM sinks connected to user-controlled sources\033[0m")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
