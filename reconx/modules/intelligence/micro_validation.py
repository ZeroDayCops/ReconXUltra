#!/usr/bin/env python3
"""
ReconX Ultra X — Micro-Validation Engine
==========================================
Lightweight validation BEFORE strategy generation.
Tests: reflection, error leakage, response deltas, timing.
Every test produces OBSERVED evidence, not predictions.
"""
import json, os, re, sys, subprocess, time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: micro_validation.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
EVIDENCE_DIR = OUT / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []


class MicroFinding:
    """A micro-validation finding with observed + predicted separation."""
    def __init__(self, vuln_type: str, url: str, param: str = ""):
        self.vuln_type = vuln_type
        self.url = url
        self.param = param
        self.observed = []    # REAL evidence
        self.predicted = []   # Attack possibilities
        self.confidence = 0
        self.confidence_sources = []
        self.reasoning = ""
        self.recommended_tests = []
        self.level = "L1"     # Reasoning level

    def observe(self, what: str, weight: int = 10):
        self.observed.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def predict(self, what: str):
        self.predicted.append(what)

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "observed": self.observed,
            "predicted": self.predicted,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
            "reasoning": self.reasoning,
            "recommended_tests": self.recommended_tests,
            "level": self.level,
            "timestamp": datetime.now().isoformat(),
        }


def _curl_get(url: str, timeout: int = 6) -> tuple:
    """GET request, return (status, body, time)."""
    try:
        start = time.time()
        r = subprocess.run(
            ["curl", "-sk", "-m", str(timeout), "-w", "\n%{http_code}", url],
            capture_output=True, text=True, timeout=timeout + 2)
        elapsed = time.time() - start
        lines = r.stdout.rsplit("\n", 1)
        body = lines[0] if len(lines) > 1 else r.stdout
        status = int(lines[-1]) if lines[-1].isdigit() else 0
        return status, body, elapsed
    except:
        return 0, "", 0


def _inject_param(url: str, param: str, value: str) -> str:
    """Replace a parameter value in URL."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


# ═══════════════════════════════════════════════════════════════════════════
# XSS Micro-Validation
# ═══════════════════════════════════════════════════════════════════════════
def micro_validate_xss(url: str, param: str) -> MicroFinding:
    """Test XSS signals: reflection, context, CSP."""
    f = MicroFinding("XSS", url, param)
    f.level = "L2"

    # 1. Test reflection
    canary = "rxcanary7x7q"
    test_url = _inject_param(url, param, canary)
    status, body, _ = _curl_get(test_url)

    if status == 0:
        return f

    if canary in body:
        f.observe("Input reflected in response", 25)

        # 2. Check context
        idx = body.find(canary)
        context_before = body[max(0, idx-50):idx]
        context_after = body[idx:idx+80]

        if re.search(r'<[^>]*$', context_before):
            f.observe("Reflection inside HTML tag attribute", 15)
            f.predict("Attribute breakout XSS possible")
        elif re.search(r'<script', context_before, re.I):
            f.observe("Reflection inside <script> block", 20)
            f.predict("JS context XSS possible")
        elif "<" not in context_before[-20:]:
            f.observe("Reflection in HTML body context", 10)
            f.predict("Tag injection XSS possible")

        # 3. Test angle bracket encoding
        test_url2 = _inject_param(url, param, "<rxtest>")
        _, body2, _ = _curl_get(test_url2)
        if "<rxtest>" in body2:
            f.observe("Angle brackets not encoded", 20)
            f.predict("Direct HTML injection possible")
        elif "&lt;rxtest&gt;" in body2:
            f.observe("Angle brackets HTML-encoded", -5)

        # 4. Check CSP (from headers)
        try:
            r = subprocess.run(
                ["curl", "-skI", "-m", "5", url],
                capture_output=True, text=True, timeout=7)
            if "content-security-policy" not in r.stdout.lower():
                f.observe("No CSP header present", 15)
            elif "unsafe-inline" in r.stdout.lower():
                f.observe("CSP allows unsafe-inline", 10)
        except: pass
    else:
        f.observe("No reflection detected", 0)

    # Build reasoning
    if f.confidence >= 40:
        f.reasoning = (f"Input is reflected in the response at parameter '{param}'. "
                       f"{'Angle brackets pass through unencoded. ' if any('not encoded' in o for o in f.observed) else ''}"
                       f"{'No CSP protection. ' if any('No CSP' in o for o in f.observed) else ''}"
                       f"XSS exploitation is {'likely' if f.confidence >= 60 else 'possible'}.")
        f.recommended_tests = [
            f"Test payload: <script>alert(1)</script> on {param}",
            f"Test attribute breakout: \" onfocus=alert(1) autofocus",
            "Test DOM-based: javascript: URI in reflection context",
            "Test event handlers: <img src=x onerror=alert(1)>",
        ]
    else:
        f.reasoning = f"No significant XSS signals observed for parameter '{param}'."

    return f


# ═══════════════════════════════════════════════════════════════════════════
# SQLi Micro-Validation
# ═══════════════════════════════════════════════════════════════════════════
def micro_validate_sqli(url: str, param: str) -> MicroFinding:
    """Test SQLi signals: error, timing, boolean."""
    f = MicroFinding("SQLi", url, param)
    f.level = "L2"

    # 1. Baseline
    status_base, body_base, time_base = _curl_get(url)
    if status_base == 0:
        return f
    base_len = len(body_base)

    # 2. Single quote injection
    test_url = _inject_param(url, param, "1'")
    status_q, body_q, _ = _curl_get(test_url)

    sql_errors = [
        (r"sql\s*syntax|mysql|mariadb", "MySQL error", 25),
        (r"pg_query|postgresql|pg_exec", "PostgreSQL error", 25),
        (r"sqlite3?\.OperationalError|sqlite_", "SQLite error", 25),
        (r"ora-\d{5}|oracle", "Oracle error", 25),
        (r"microsoft.*odbc|mssql|sql\s*server", "MSSQL error", 25),
        (r"unclosed quotation|quoted string not properly terminated", "SQL quote error", 20),
    ]

    for pattern, name, weight in sql_errors:
        if re.search(pattern, body_q, re.I):
            f.observe(f"SQL error triggered: {name}", weight)
            f.predict("Error-based SQL injection possible")
            break

    # 3. Response length comparison (boolean)
    len_q = len(body_q)
    delta = abs(len_q - base_len)
    if delta > 50 and status_q != status_base:
        f.observe(f"Response changed: status {status_base}→{status_q}, delta {delta}B", 15)
        f.predict("Boolean-based injection possible")
    elif delta > 200:
        f.observe(f"Significant response delta: {delta} bytes", 10)

    # 4. Timing test (lightweight — 2 second delay only)
    if f.confidence < 20:
        timed_url = _inject_param(url, param, "1' AND SLEEP(2)-- -")
        _, _, time_delay = _curl_get(timed_url, timeout=8)
        if time_delay >= 2.0 and time_delay - time_base >= 1.5:
            f.observe(f"Time delay observed: {time_delay:.1f}s vs baseline {time_base:.1f}s", 25)
            f.predict("Time-based blind SQL injection possible")
            f.level = "L3"

    # Reasoning
    if f.confidence >= 20:
        f.reasoning = (f"SQL injection signals detected at parameter '{param}'. "
                       f"{'Database error messages leaked. ' if any('SQL error' in o for o in f.observed) else ''}"
                       f"{'Response behavior changed with quote injection. ' if any('delta' in o.lower() for o in f.observed) else ''}"
                       f"{'Time delay confirmed injection. ' if any('Time delay' in o for o in f.observed) else ''}")
        f.recommended_tests = [
            f"Run sqlmap: sqlmap -u '{url}' -p {param} --batch",
            f"Test UNION: {param}=1 UNION SELECT NULL--",
            "Test boolean: AND 1=1 vs AND 1=2",
            "Test stacked: ; SELECT SLEEP(5)--",
        ]
    else:
        f.reasoning = f"No significant SQLi signals at parameter '{param}'."

    return f


# ═══════════════════════════════════════════════════════════════════════════
# SSRF Micro-Validation
# ═══════════════════════════════════════════════════════════════════════════
def micro_validate_ssrf(url: str, param: str) -> MicroFinding:
    """Test SSRF signals: URL influence, redirect, internal access."""
    f = MicroFinding("SSRF", url, param)
    f.level = "L2"

    # 1. Check if param accepts URL-like values
    test_url = _inject_param(url, param, "http://127.0.0.1")
    status, body, _ = _curl_get(test_url)

    if status == 200 and len(body) > 100:
        f.observe("URL parameter accepted, 200 response", 15)
        f.predict("SSRF via URL parameter possible")

    # 2. Check with non-routable IP
    test_url2 = _inject_param(url, param, "http://169.254.169.254/latest/meta-data/")
    status2, body2, time2 = _curl_get(test_url2)

    if status2 == 200 and ("ami-id" in body2 or "instance-id" in body2):
        f.observe("Cloud metadata accessible via SSRF!", 40)
        f.predict("Critical SSRF — cloud metadata exposure")
        f.level = "L3"
    elif time2 > 3:
        f.observe(f"Slow response ({time2:.1f}s) — possible internal request", 10)

    # 3. DNS-based check (non-invasive)
    test_url3 = _inject_param(url, param, "http://localhost:22")
    status3, _, time3 = _curl_get(test_url3)
    if status3 != status and status3 in (200, 500):
        f.observe(f"Different response for localhost:22 (status {status3})", 15)
        f.predict("Port-based SSRF possible")

    if f.confidence >= 15:
        f.reasoning = (f"SSRF signals at parameter '{param}'. "
                       f"The parameter appears to influence server-side requests.")
        f.recommended_tests = [
            f"Test with collaborator/interactsh URL on {param}",
            "Test internal IPs: 127.0.0.1, 10.0.0.1, 172.16.0.1",
            "Test cloud metadata: 169.254.169.254",
            "Test port scanning: localhost:22, :3306, :6379",
            "Test URL schemes: file://, gopher://, dict://",
        ]
    else:
        f.reasoning = f"No SSRF signals observed at '{param}'."

    return f


# ═══════════════════════════════════════════════════════════════════════════
# IDOR Micro-Validation
# ═══════════════════════════════════════════════════════════════════════════
def micro_validate_idor(url: str, param: str) -> MicroFinding:
    """Test IDOR signals: ID variation, response differences."""
    f = MicroFinding("IDOR", url, param)
    f.level = "L2"

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    current_value = params.get(param, [""])[0]

    # Only test numeric IDs
    if not current_value.isdigit():
        f.reasoning = f"Parameter '{param}' is not numeric — skipping IDOR test."
        return f

    current_id = int(current_value)

    # 1. Baseline
    status_base, body_base, _ = _curl_get(url)
    if status_base == 0: return f

    # 2. Test adjacent IDs
    responses = []
    for test_id in [current_id - 1, current_id + 1, current_id + 100]:
        if test_id <= 0: continue
        test_url = _inject_param(url, param, str(test_id))
        status, body, _ = _curl_get(test_url)
        responses.append({
            "id": test_id, "status": status,
            "size": len(body), "body_hash": hash(body[:500])
        })

    # Analyze responses
    accessible = [r for r in responses if r["status"] == 200 and r["size"] > 100]
    if accessible:
        f.observe(f"Sequential IDs accessible ({len(accessible)}/{len(responses)})", 25)

        # Check if content actually differs (not just generic page)
        sizes = [r["size"] for r in accessible]
        hashes = [r["body_hash"] for r in accessible]

        if len(set(hashes)) > 1:
            f.observe("Different content per ID — real data variation", 20)
            f.predict("IDOR — different objects accessible")
        elif len(set(sizes)) == 1:
            f.observe("Same content for all IDs — may be generic response", -10)

    # Check for auth redirect
    redirected = [r for r in responses if r["status"] in (301, 302, 403, 401)]
    if not redirected and accessible:
        f.observe("No auth redirect or 403 for other IDs", 15)
        f.predict("Missing authorization check")
    elif redirected:
        f.observe(f"Auth enforcement detected (status {redirected[0]['status']})", -5)

    if f.confidence >= 25:
        f.reasoning = (f"IDOR signals at parameter '{param}'. "
                       f"Sequential object IDs are accessible and "
                       f"{'return different content' if any('Different content' in o for o in f.observed) else 'no access control was observed'}.")
        f.recommended_tests = [
            f"Enumerate IDs: {current_id-10} to {current_id+10}",
            "Test with different user's session token",
            "Test horizontal privilege escalation",
            f"Automate with: for i in $(seq 1 100); do curl -sk '{url.replace(str(current_id), '$i')}'; done",
        ]
    else:
        f.reasoning = f"No significant IDOR signals at '{param}'."

    return f


# ═══════════════════════════════════════════════════════════════════════════
# Main Orchestrator
# ═══════════════════════════════════════════════════════════════════════════
def main():
    print(f"\n  🔬 Micro-Validation Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    # Load candidate URLs
    candidates = {
        "xss": rl(OUT / "intelligence/xss_candidates.txt", 15),
        "sqli": rl(OUT / "intelligence/sqli_candidates.txt", 10),
        "ssrf": rl(OUT / "intelligence/ssrf_candidates.txt", 8),
        "idor": rl(OUT / "intelligence/idor_candidates.txt", 8),
    }

    all_findings = []

    # XSS validation
    for url in candidates["xss"]:
        params = parse_qs(urlparse(url).query)
        for param in list(params.keys())[:2]:
            finding = micro_validate_xss(url, param)
            if finding.confidence > 0:
                all_findings.append(finding)

    # SQLi validation
    for url in candidates["sqli"]:
        params = parse_qs(urlparse(url).query)
        for param in list(params.keys())[:2]:
            finding = micro_validate_sqli(url, param)
            if finding.confidence > 0:
                all_findings.append(finding)

    # SSRF validation
    for url in candidates["ssrf"]:
        params = parse_qs(urlparse(url).query)
        for param in list(params.keys())[:1]:
            finding = micro_validate_ssrf(url, param)
            if finding.confidence > 0:
                all_findings.append(finding)

    # IDOR validation
    for url in candidates["idor"]:
        params = parse_qs(urlparse(url).query)
        id_params = [p for p in params if re.search(r'id$|_id$|Id$', p)]
        for param in (id_params or list(params.keys()))[:1]:
            finding = micro_validate_idor(url, param)
            if finding.confidence > 0:
                all_findings.append(finding)

    # Sort by confidence
    all_findings.sort(key=lambda f: f.confidence, reverse=True)

    # Save
    (EVIDENCE_DIR / "micro_validation.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(all_findings),
        "findings": [f.to_dict() for f in all_findings],
    }, indent=2))

    # Human-readable evidence report
    lines = ["═" * 60, f"  🔬 MICRO-VALIDATION EVIDENCE — {DOMAIN}", "═" * 60, ""]
    for f in all_findings:
        if f.confidence < 10: continue
        icon = "🔴" if f.confidence >= 60 else "🟠" if f.confidence >= 30 else "🟡"
        lines.append(f"  {icon} {f.vuln_type} Risk: {'HIGH' if f.confidence >= 60 else 'MEDIUM' if f.confidence >= 30 else 'LOW'}")
        lines.append(f"  URL: {f.url[:100]}")
        lines.append(f"  Param: {f.param}")
        lines.append("")
        lines.append("  Observed:")
        for o in f.observed:
            lines.append(f"    ✔ {o}")
        if f.predicted:
            lines.append("  Predicted:")
            for p in f.predicted:
                lines.append(f"    → {p}")
        lines.append(f"\n  Confidence: {min(f.confidence, 100)}%")
        lines.append("  Confidence Sources:")
        for cs in f.confidence_sources:
            lines.append(f"    {cs}")
        lines.append(f"\n  Reasoning: {f.reasoning}")
        if f.recommended_tests:
            lines.append("  Recommended Tests:")
            for t in f.recommended_tests:
                lines.append(f"    • {t}")
        lines.append(f"  Level: {f.level}")
        lines.append("\n" + "─" * 50)

    (EVIDENCE_DIR / "micro_validation.txt").write_text("\n".join(lines))

    # Print
    print(f"\n  📊 {len(all_findings)} findings validated")
    for f in all_findings[:8]:
        icon = "🔴" if f.confidence >= 60 else "🟠" if f.confidence >= 30 else "🟡"
        print(f"    {icon} {f.vuln_type:8s} {min(f.confidence,100):3d}% | "
              f"{f.param:15s} | {len(f.observed)} observations")
    print(f"  💾 Evidence → {EVIDENCE_DIR}/")


if __name__ == "__main__":
    main()
