#!/usr/bin/env python3
"""ReconX Ultra X — Attack Chain Correlation Engine
Correlates validated findings into exploit paths and attack chains."""
import json, sys
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: attack_chain.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
CHAINS_DIR = OUT / "attack_chains"
CHAINS_DIR.mkdir(parents=True, exist_ok=True)

def lj(p):
    try: return json.loads(Path(p).read_text())
    except: return None

def main():
    print(f"  🔗 Attack Chain Correlation — {DOMAIN}")

    # Load all intelligence
    validated = lj(OUT / "validated/all_validated.json") or []
    risk = lj(OUT / "intelligence/risk_matrix.json") or {}
    api = lj(OUT / "intelligence/api_inventory.json") or {}
    workflows = lj(OUT / "intelligence/critical_workflows.json") or {}
    secrets = lj(OUT / "secrets/js_secrets_report.json") or {}
    dom_sinks = lj(OUT / "intelligence/dom_sinks.json") or []

    # Categorize findings
    xss = [f for f in validated if f.get("type") == "XSS"]
    sqli = [f for f in validated if f.get("type") == "SQLi"]
    ssrf = [f for f in validated if f.get("type") == "SSRF"]
    redirects = [f for f in validated if f.get("type") == "OpenRedirect"]

    # Find indicators
    has_jwt = any("jwt" in str(s).lower() for s in (secrets.get("findings",[]) if isinstance(secrets,dict) else secrets))
    has_upload = any(w.get("name","").lower() in ["upload","file"] for w in (workflows.get("workflows",[]) if isinstance(workflows,dict) else []))
    has_admin = bool(lj(OUT/"intelligence/admin_panels.txt"))
    has_graphql = len((api.get("graphql_endpoints",[]) if isinstance(api,dict) else []))
    has_csp_weak = any(s.get("severity") == "CRITICAL" for s in (dom_sinks if isinstance(dom_sinks,list) else []))

    chains = []

    # ── Chain 1: XSS → Session Hijack → Account Takeover ──────────────────
    if xss and has_jwt:
        chains.append({
            "id": "chain-001",
            "name": "XSS → JWT Theft → Account Takeover",
            "severity": "CRITICAL",
            "confidence": max(f["score"] for f in xss),
            "steps": [
                {"step": 1, "type": "XSS", "detail": f"Validated XSS at {xss[0]['url']}", "status": "confirmed"},
                {"step": 2, "type": "JWT_EXPOSURE", "detail": "JWT tokens detected in JavaScript", "status": "detected"},
                {"step": 3, "type": "SESSION_HIJACK", "detail": "XSS can steal JWT → session takeover", "status": "likely"},
                {"step": 4, "type": "ACCOUNT_TAKEOVER", "detail": "Full account compromise via stolen session", "status": "possible"},
            ],
            "impact": "Full account takeover via XSS-based JWT theft",
            "findings_used": [f["url"] for f in xss[:3]],
        })

    # ── Chain 2: SQLi → Data Exfiltration ─────────────────────────────────
    if sqli:
        chains.append({
            "id": "chain-002",
            "name": "SQLi → Database Access → Data Exfiltration",
            "severity": "CRITICAL",
            "confidence": max(f["score"] for f in sqli),
            "steps": [
                {"step": 1, "type": "SQLI", "detail": f"Validated SQLi at {sqli[0]['url']}", "status": "confirmed"},
                {"step": 2, "type": "DB_ACCESS", "detail": f"DBMS: {sqli[0].get('dbms','unknown')}", "status": "likely"},
                {"step": 3, "type": "DATA_DUMP", "detail": "User credentials, PII accessible", "status": "likely"},
                {"step": 4, "type": "PRIVILEGE_ESC", "detail": "Potential DB admin access", "status": "possible"},
            ],
            "impact": "Full database compromise and data exfiltration",
            "findings_used": [f["url"] for f in sqli[:3]],
        })

    # ── Chain 3: SSRF → Cloud Metadata → Internal Access ─────────────────
    if ssrf:
        chains.append({
            "id": "chain-003",
            "name": "SSRF → Cloud Metadata → IAM Credentials",
            "severity": "CRITICAL",
            "confidence": max(f["score"] for f in ssrf),
            "steps": [
                {"step": 1, "type": "SSRF", "detail": f"Validated SSRF at {ssrf[0]['url']}", "status": "confirmed"},
                {"step": 2, "type": "METADATA", "detail": "Cloud metadata endpoint accessible", "status": "confirmed"},
                {"step": 3, "type": "IAM_CREDS", "detail": "AWS/GCP/Azure credentials exposed", "status": "likely"},
                {"step": 4, "type": "INFRA_ACCESS", "detail": "Full cloud infrastructure compromise", "status": "possible"},
            ],
            "impact": "Cloud infrastructure takeover via SSRF",
            "findings_used": [f["url"] for f in ssrf[:3]],
        })

    # ── Chain 4: Open Redirect → OAuth Phishing ──────────────────────────
    if redirects:
        chains.append({
            "id": "chain-004",
            "name": "Open Redirect → OAuth Token Theft",
            "severity": "HIGH",
            "confidence": max(f.get("score",30) for f in redirects),
            "steps": [
                {"step": 1, "type": "REDIRECT", "detail": f"Open redirect at {redirects[0]['url']}", "status": "confirmed"},
                {"step": 2, "type": "OAUTH_ABUSE", "detail": "Can redirect OAuth callbacks to attacker", "status": "likely"},
                {"step": 3, "type": "TOKEN_THEFT", "detail": "Access token captured via redirect", "status": "possible"},
            ],
            "impact": "OAuth token theft via open redirect abuse",
            "findings_used": [f["url"] for f in redirects[:3]],
        })

    # ── Chain 5: XSS + Upload → Stored XSS → Worm ───────────────────────
    if xss and has_upload:
        chains.append({
            "id": "chain-005",
            "name": "File Upload + XSS → Stored XSS Worm",
            "severity": "CRITICAL",
            "confidence": max(f["score"] for f in xss) - 10,
            "steps": [
                {"step": 1, "type": "UPLOAD", "detail": "File upload functionality detected", "status": "detected"},
                {"step": 2, "type": "XSS", "detail": "XSS payload in uploaded content", "status": "likely"},
                {"step": 3, "type": "STORED_XSS", "detail": "Persistent XSS via uploads", "status": "possible"},
            ],
            "impact": "Self-propagating stored XSS via file upload",
            "findings_used": [f["url"] for f in xss[:2]],
        })

    # ── Chain 6: DOM XSS + Weak CSP ──────────────────────────────────────
    if has_csp_weak and dom_sinks:
        chains.append({
            "id": "chain-006",
            "name": "Weak CSP + DOM Sinks → Client-Side Attack",
            "severity": "HIGH",
            "confidence": 45,
            "steps": [
                {"step": 1, "type": "CSP_WEAK", "detail": "Missing or weak CSP headers", "status": "confirmed"},
                {"step": 2, "type": "DOM_SINK", "detail": f"{len(dom_sinks)} DOM sinks identified", "status": "confirmed"},
                {"step": 3, "type": "DOM_XSS", "detail": "Client-side code execution via DOM", "status": "likely"},
            ],
            "impact": "Client-side code execution due to weak CSP + DOM sinks",
        })

    # Sort by severity then confidence
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    chains.sort(key=lambda c: (sev_order.get(c["severity"],9), -c["confidence"]))

    # Save
    output = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_chains": len(chains),
        "critical_chains": len([c for c in chains if c["severity"] == "CRITICAL"]),
        "chains": chains,
    }
    (CHAINS_DIR / "attack_chains.json").write_text(json.dumps(output, indent=2))

    print(f"  ✅ {len(chains)} attack chains identified ({output['critical_chains']} critical)")

if __name__ == "__main__": main()
