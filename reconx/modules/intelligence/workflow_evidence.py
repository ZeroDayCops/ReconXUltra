#!/usr/bin/env python3
"""
ReconX Ultra X — Workflow Evidence Engine
==========================================
Actually observes business workflows via lightweight HTTP probes.
Maps: login, upload, export, OAuth, GraphQL, admin, payment flows.
Explains WHY each workflow is risky with real evidence.
"""
import json, os, re, sys, subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: workflow_evidence.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
WF_DIR = OUT / "workflows"
WF_DIR.mkdir(parents=True, exist_ok=True)

def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


WORKFLOW_DETECTORS = {
    "authentication": {
        "url_patterns": [r"login|signin|auth|sso|oauth|session|logout|signup|register"],
        "risk_reasons": [
            "Credential theft via session fixation or brute force",
            "OAuth redirect manipulation",
            "Registration bypass / mass account creation",
            "Session management flaws",
        ],
        "vuln_types": ["Auth Bypass", "Session Fixation", "OAuth Redirect", "Brute Force"],
    },
    "upload": {
        "url_patterns": [r"upload|attach|import|media|avatar|file|image|document"],
        "risk_reasons": [
            "Unrestricted file upload → RCE",
            "SVG upload → Stored XSS",
            "File type bypass → malicious file execution",
            "SSRF via file import URL",
        ],
        "vuln_types": ["Unrestricted Upload", "Stored XSS", "RCE", "SSRF"],
    },
    "export": {
        "url_patterns": [r"export|download|pdf|report|invoice|generate|print|render"],
        "risk_reasons": [
            "SSRF via PDF generator",
            "SSTI via template rendering",
            "Information disclosure in exports",
            "HTML injection in generated reports",
        ],
        "vuln_types": ["SSRF", "SSTI", "Information Disclosure", "HTML Injection"],
    },
    "payment": {
        "url_patterns": [r"payment|checkout|billing|invoice|cart|order|subscribe|pricing"],
        "risk_reasons": [
            "Price manipulation via parameter tampering",
            "Race condition on discount/coupon application",
            "IDOR on invoice/order access",
            "Business logic bypass",
        ],
        "vuln_types": ["Price Manipulation", "Race Condition", "IDOR", "Logic Bypass"],
    },
    "graphql": {
        "url_patterns": [r"graphql|gql|playground"],
        "risk_reasons": [
            "Introspection leaks full schema",
            "Mutations may bypass authorization",
            "Batch queries enable brute force",
            "Nested query denial of service",
        ],
        "vuln_types": ["Info Disclosure", "Auth Bypass", "Brute Force", "DoS"],
    },
    "admin": {
        "url_patterns": [r"admin|dashboard|console|panel|manage|backend|control"],
        "risk_reasons": [
            "Unauthorized access to admin functions",
            "Privilege escalation",
            "Sensitive data exposure",
            "Admin action without CSRF protection",
        ],
        "vuln_types": ["Access Control", "Privilege Escalation", "CSRF", "Info Disclosure"],
    },
    "api_crud": {
        "url_patterns": [r"/api/|/v[0-9]+/|rest/|users|accounts|profiles|items"],
        "risk_reasons": [
            "IDOR on object-based endpoints",
            "Mass assignment on POST/PUT",
            "Missing rate limiting",
            "Verbose error responses",
        ],
        "vuln_types": ["IDOR", "Mass Assignment", "Rate Limiting", "Info Disclosure"],
    },
    "password_reset": {
        "url_patterns": [r"reset|forgot|recover|password|token"],
        "risk_reasons": [
            "Token prediction/brute force",
            "Account takeover via reset flow",
            "Host header injection in reset link",
            "Token reuse vulnerability",
        ],
        "vuln_types": ["Account Takeover", "Token Prediction", "Host Header Injection"],
    },
}


class WorkflowFinding:
    """An observed workflow with evidence."""
    def __init__(self, name: str):
        self.name = name
        self.endpoints = []
        self.observations = []
        self.risk_reasons = []
        self.vuln_types = []
        self.confidence = 0
        self.confidence_sources = []

    def add_endpoint(self, url: str, status: int = 0, detail: str = ""):
        self.endpoints.append({"url": url, "status": status, "detail": detail})

    def observe(self, what: str, weight: int = 10):
        self.observations.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def to_dict(self) -> dict:
        return {
            "workflow": self.name,
            "endpoints": self.endpoints[:15],
            "endpoint_count": len(self.endpoints),
            "observations": self.observations,
            "risk_reasons": self.risk_reasons,
            "vuln_types": self.vuln_types,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
        }


def _probe(url: str) -> dict:
    try:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w",
             '{"status":%{http_code},"size":%{size_download}}',
             "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        return json.loads(r.stdout.strip()) if r.returncode == 0 else {}
    except: return {}


def main():
    print(f"\n  🔄 Workflow Evidence Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    urls = rl(OUT / "urls/all_urls.txt")
    if not urls:
        print("  ⚪ No URLs to analyze")
        return

    workflows = []

    for wf_name, config in WORKFLOW_DETECTORS.items():
        wf = WorkflowFinding(wf_name)
        wf.risk_reasons = config["risk_reasons"]
        wf.vuln_types = config["vuln_types"]

        # Find matching endpoints
        for url in urls:
            for pattern in config["url_patterns"]:
                if re.search(pattern, url, re.I):
                    wf.add_endpoint(url)
                    break

        if not wf.endpoints:
            continue

        wf.observe(f"{len(wf.endpoints)} {wf_name} endpoints detected", 15)

        # Probe sample endpoints
        probed = 0
        for ep in wf.endpoints[:5]:
            resp = _probe(ep["url"])
            if resp:
                ep["status"] = resp.get("status", 0)
                ep["detail"] = f"Status {resp.get('status',0)}, {resp.get('size',0)}B"
                probed += 1

                status = resp.get("status", 0)
                if status == 200:
                    wf.observe(f"Endpoint accessible: {ep['url'][:60]}", 10)
                elif status in (301, 302):
                    wf.observe(f"Redirect detected: {ep['url'][:60]}", 5)
                elif status == 403:
                    wf.observe(f"Access control present: {ep['url'][:60]}", 3)

        # Additional probes per workflow type
        if wf_name == "upload":
            for ep in wf.endpoints[:3]:
                # Check if OPTIONS reveals accepted methods
                try:
                    r = subprocess.run(
                        ["curl", "-sk", "-X", "OPTIONS", "-I", "-m", "5", ep["url"]],
                        capture_output=True, text=True, timeout=7)
                    if "POST" in r.stdout or "PUT" in r.stdout:
                        wf.observe("Upload accepts POST/PUT methods", 15)
                    allow = re.search(r"allow:\s*(.+)", r.stdout, re.I)
                    if allow:
                        wf.observe(f"Allowed methods: {allow.group(1).strip()}", 5)
                except: pass

        if wf_name == "graphql":
            for ep in wf.endpoints[:2]:
                try:
                    r = subprocess.run(
                        ["curl", "-sk", "-m", "5",
                         "-H", "Content-Type: application/json",
                         "-d", '{"query":"{ __schema { types { name } } }"}',
                         ep["url"]],
                        capture_output=True, text=True, timeout=7)
                    if "__schema" in r.stdout:
                        wf.observe("GraphQL introspection enabled — full schema exposed", 25)
                except: pass

        if wf_name == "authentication":
            for ep in wf.endpoints[:2]:
                try:
                    r = subprocess.run(
                        ["curl", "-skI", "-m", "5", ep["url"]],
                        capture_output=True, text=True, timeout=7)
                    headers = r.stdout.lower()
                    if "set-cookie" in headers:
                        wf.observe("Session cookie set on auth endpoint", 10)
                        if "httponly" not in headers:
                            wf.observe("Cookie missing HttpOnly flag", 10)
                        if "secure" not in headers:
                            wf.observe("Cookie missing Secure flag", 8)
                except: pass

        workflows.append(wf)

    # Sort by confidence
    workflows.sort(key=lambda w: w.confidence, reverse=True)

    # Save
    (WF_DIR / "workflow_evidence.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "workflows": [w.to_dict() for w in workflows],
    }, indent=2))

    # Human-readable
    lines = [
        "═" * 60,
        f"  🔄 WORKFLOW EVIDENCE — {DOMAIN}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 60, "",
    ]
    for wf in workflows:
        d = wf.to_dict()
        icon = "🔴" if d["confidence"] >= 60 else "🟠" if d["confidence"] >= 30 else "🟡"
        lines.append(f"  {icon} Workflow: {d['workflow'].upper()}")
        lines.append(f"  Endpoints: {d['endpoint_count']}")
        lines.append("")
        lines.append("  Observed:")
        for o in d["observations"]:
            lines.append(f"    ✔ {o}")
        lines.append("")
        lines.append(f"  Confidence: {d['confidence']}%")
        for cs in d["confidence_sources"]:
            lines.append(f"    {cs}")
        lines.append("")
        lines.append("  Risk Reasons:")
        for r in d["risk_reasons"]:
            lines.append(f"    ⚠ {r}")
        lines.append("")
        lines.append("  Test For:")
        for v in d["vuln_types"]:
            lines.append(f"    🎯 {v}")
        lines.append("\n" + "─" * 50)

    (WF_DIR / "workflow_evidence.txt").write_text("\n".join(lines))

    # Print
    print(f"\n  📊 {len(workflows)} workflows observed:")
    for wf in workflows:
        d = wf.to_dict()
        icon = "🔴" if d["confidence"] >= 60 else "🟠" if d["confidence"] >= 30 else "🟡"
        print(f"    {icon} {d['workflow']:20s} {d['confidence']:3d}% | "
              f"{d['endpoint_count']:3d} endpoints | {len(d['observations'])} observations")
    print(f"  💾 Evidence → {WF_DIR}/")


if __name__ == "__main__":
    main()
