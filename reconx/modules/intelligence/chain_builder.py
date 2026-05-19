#!/usr/bin/env python3
"""
ReconX Ultra X — Predictive Chain Builder
===========================================
When one finding appears, predicts related bugs,
suggests chaining opportunities, correlates across
APIs + uploads + OAuth + JWT + cloud.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: chain_builder.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
CHAINS_DIR = OUT / "attack_chains"
CHAINS_DIR.mkdir(parents=True, exist_ok=True)

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None

# ═══════════════════════════════════════════════════════════════════════════
# Chain Templates — common exploit chains in bug bounty
# ═══════════════════════════════════════════════════════════════════════════
CHAIN_TEMPLATES = [
    {
        "id": "xss-to-ato",
        "name": "XSS → Session Theft → Account Takeover",
        "requires": ["xss", "jwt_or_session"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "XSS", "desc": "Inject payload in vulnerable parameter"},
            {"type": "TOKEN_THEFT", "desc": "Steal JWT/session via document.cookie or localStorage"},
            {"type": "SESSION_HIJACK", "desc": "Use stolen token to impersonate victim"},
            {"type": "ATO", "desc": "Full account takeover"},
        ],
        "impact": "Complete account compromise for any user",
    },
    {
        "id": "ssrf-to-cloud",
        "name": "SSRF → Cloud Metadata → IAM Credentials → Infra Pivot",
        "requires": ["ssrf", "cloud"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "SSRF", "desc": "Access internal endpoint via URL parameter"},
            {"type": "METADATA", "desc": "Read cloud metadata (169.254.169.254)"},
            {"type": "IAM_CREDS", "desc": "Extract temporary IAM credentials"},
            {"type": "INFRA_PIVOT", "desc": "Access S3, RDS, Lambda, etc."},
        ],
        "impact": "Full cloud infrastructure compromise",
    },
    {
        "id": "idor-chain",
        "name": "API IDOR → Mass Data Exfiltration",
        "requires": ["api", "idor_params"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "ENUMERATION", "desc": "Discover sequential/predictable IDs"},
            {"type": "IDOR", "desc": "Access other users' resources via ID manipulation"},
            {"type": "AUTOMATION", "desc": "Script to enumerate all records"},
            {"type": "DATA_EXFIL", "desc": "Mass PII/data extraction"},
        ],
        "impact": "Complete database exfiltration via IDOR",
    },
    {
        "id": "upload-rce",
        "name": "File Upload → Web Shell → RCE",
        "requires": ["upload"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "BYPASS", "desc": "Bypass file type validation"},
            {"type": "UPLOAD", "desc": "Upload web shell (PHP/JSP/ASPX)"},
            {"type": "ACCESS", "desc": "Navigate to uploaded file"},
            {"type": "RCE", "desc": "Execute commands on server"},
        ],
        "impact": "Remote code execution on web server",
    },
    {
        "id": "oauth-ato",
        "name": "OAuth Misconfiguration → Token Theft → ATO",
        "requires": ["oauth", "redirect"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "REDIRECT", "desc": "Manipulate redirect_uri parameter"},
            {"type": "TOKEN_LEAK", "desc": "OAuth token leaked to attacker domain"},
            {"type": "ATO", "desc": "Use leaked token for account access"},
        ],
        "impact": "Account takeover via OAuth token theft",
    },
    {
        "id": "graphql-idor",
        "name": "GraphQL Introspection → Hidden Mutations → IDOR",
        "requires": ["graphql"],
        "severity": "HIGH",
        "steps": [
            {"type": "INTROSPECT", "desc": "Query __schema for full type system"},
            {"type": "DISCOVER", "desc": "Find hidden mutations and queries"},
            {"type": "BYPASS", "desc": "Bypass field-level authorization"},
            {"type": "DATA_ACCESS", "desc": "Access unauthorized data"},
        ],
        "impact": "Unauthorized data access via GraphQL",
    },
    {
        "id": "ssti-rce",
        "name": "SSTI → Template Sandbox Escape → RCE",
        "requires": ["ssti_endpoint"],
        "severity": "CRITICAL",
        "steps": [
            {"type": "DETECT", "desc": "Identify template engine ({{7*7}})"},
            {"type": "ESCAPE", "desc": "Escape template sandbox"},
            {"type": "RCE", "desc": "Execute OS commands"},
        ],
        "impact": "Remote code execution via template injection",
    },
    {
        "id": "race-payment",
        "name": "Race Condition → Payment/Coupon Bypass",
        "requires": ["payment"],
        "severity": "HIGH",
        "steps": [
            {"type": "IDENTIFY", "desc": "Find race-prone payment/coupon endpoint"},
            {"type": "CONCURRENT", "desc": "Send concurrent requests"},
            {"type": "BYPASS", "desc": "Apply coupon/discount multiple times"},
        ],
        "impact": "Financial loss via race condition abuse",
    },
    {
        "id": "cors-data",
        "name": "CORS Misconfiguration → Sensitive Data Theft",
        "requires": ["cors_vuln", "api"],
        "severity": "HIGH",
        "steps": [
            {"type": "CORS", "desc": "Exploit permissive CORS policy"},
            {"type": "SCRIPT", "desc": "Craft JavaScript to read API responses"},
            {"type": "EXFIL", "desc": "Steal user data cross-origin"},
        ],
        "impact": "Cross-origin data theft via CORS misconfiguration",
    },
    {
        "id": "host-header-ato",
        "name": "Host Header Injection → Password Reset Poisoning → ATO",
        "requires": ["password_reset"],
        "severity": "HIGH",
        "steps": [
            {"type": "INJECT", "desc": "Inject attacker domain in Host header"},
            {"type": "TRIGGER", "desc": "Trigger password reset for victim"},
            {"type": "CAPTURE", "desc": "Capture reset token sent to attacker domain"},
            {"type": "ATO", "desc": "Reset victim's password"},
        ],
        "impact": "Account takeover via password reset poisoning",
    },
]


def detect_capabilities() -> dict:
    """Detect what capabilities/surfaces exist in the target."""
    caps = defaultdict(bool)

    # Check for various surface types
    urls = []
    for f in ["urls/all_urls.txt", "intelligence/xss_candidates.txt",
              "intelligence/sqli_candidates.txt"]:
        p = OUT / f
        if p.exists():
            urls.extend(l.strip() for l in p.read_text().splitlines() if l.strip())

    url_text = "\n".join(urls).lower()

    caps["xss"] = bool(lj(OUT / "validated/validated_xss.json")) or \
                  (OUT / "intelligence/xss_candidates.txt").exists()
    caps["sqli"] = bool(lj(OUT / "validated/validated_sqli.json")) or \
                   (OUT / "intelligence/sqli_candidates.txt").exists()
    caps["ssrf"] = (OUT / "intelligence/ssrf_candidates.txt").exists()
    caps["upload"] = "upload" in url_text or "attach" in url_text
    caps["oauth"] = "oauth" in url_text or "redirect_uri" in url_text
    caps["redirect"] = (OUT / "intelligence/redirect_candidates.txt").exists()
    caps["graphql"] = "graphql" in url_text or "gql" in url_text
    caps["api"] = "/api/" in url_text or "/v1/" in url_text
    caps["idor_params"] = any(p in url_text for p in ["id=", "user_id=", "order_id="])
    caps["cloud"] = any(c in url_text for c in ["amazonaws", "googleapis", "azure"])
    caps["jwt_or_session"] = "jwt" in url_text or "bearer" in url_text or "session" in url_text
    caps["ssti_endpoint"] = "template" in url_text or "render" in url_text
    caps["payment"] = "payment" in url_text or "checkout" in url_text
    caps["cors_vuln"] = (OUT / "validated/validated_cors.json") is not None
    caps["password_reset"] = "reset" in url_text or "forgot" in url_text

    return dict(caps)


def build_chains():
    """Build predicted attack chains based on detected capabilities."""
    print(f"\n  🔗 Predictive Chain Builder — {DOMAIN}")
    print(f"  {'━' * 50}")

    caps = detect_capabilities()
    active_caps = [k for k, v in caps.items() if v]
    print(f"  📋 Detected capabilities: {len(active_caps)}")

    chains = []
    for template in CHAIN_TEMPLATES:
        # Check if all required capabilities exist
        required = template["requires"]
        if all(caps.get(r, False) for r in required):
            confidence = sum(30 for r in required if caps.get(r)) + 10
            confidence = min(confidence, 90)

            chain = {
                **template,
                "confidence": confidence,
                "capabilities_matched": required,
                "timestamp": datetime.now().isoformat(),
            }
            chains.append(chain)

    chains.sort(key=lambda c: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(c["severity"], 9),
        -c["confidence"]
    ))

    # Merge with existing attack_chain.py output
    existing = lj(CHAINS_DIR / "attack_chains.json")
    existing_chains = []
    if isinstance(existing, dict):
        existing_chains = existing.get("chains", [])

    # Combine (avoid duplicates by ID)
    seen_ids = {c.get("id") for c in existing_chains}
    for c in chains:
        if c["id"] not in seen_ids:
            existing_chains.append(c)

    all_chains = sorted(existing_chains, key=lambda c: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(c.get("severity", ""), 9),
        -c.get("confidence", 0)
    ))

    output = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_chains": len(all_chains),
        "critical_chains": len([c for c in all_chains if c.get("severity") == "CRITICAL"]),
        "capabilities": caps,
        "chains": all_chains,
    }

    (CHAINS_DIR / "attack_chains.json").write_text(json.dumps(output, indent=2))

    # Human-readable
    lines = ["═" * 60, f"  🔗 ATTACK CHAIN PREDICTIONS — {DOMAIN}", "═" * 60, ""]
    for i, c in enumerate(chains, 1):
        sev_icon = "🔴" if c["severity"] == "CRITICAL" else "🟠"
        lines.append(f"  {sev_icon} Chain {i}: {c['name']}")
        lines.append(f"     Severity: {c['severity']} | Confidence: {c['confidence']}%")
        for s in c["steps"]:
            lines.append(f"     → [{s['type']}] {s['desc']}")
        lines.append(f"     💥 Impact: {c['impact']}")
        lines.append("")

    (CHAINS_DIR / "predicted_chains.txt").write_text("\n".join(lines))

    # Print
    if chains:
        print(f"\n  🔥 {len(chains)} exploit chains predicted:")
        for c in chains[:5]:
            icon = "🔴" if c["severity"] == "CRITICAL" else "🟠"
            print(f"    {icon} {c['name']} [{c['confidence']}%]")
    else:
        print("  ⚪ No chains predicted (need more intelligence data)")

    print(f"  💾 Chains → {CHAINS_DIR}/")


if __name__ == "__main__":
    build_chains()
