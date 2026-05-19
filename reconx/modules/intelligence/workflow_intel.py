#!/usr/bin/env python3
"""
ReconX Ultra — Workflow & Authentication Intelligence Engine
=============================================================
Detects critical workflows, auth flows, and correlates all findings
into actionable intelligence for bug hunters.

Analyzes:
  - OAuth/SSO/JWT authentication flows
  - Upload/export/import workflows
  - Password reset flows
  - Billing/payment endpoints
  - Invitation/account linking systems
  - WebSocket/real-time endpoints

Outputs:
  - critical_workflows.json
  - auth_flows.json
  - attack_surface_summary.json
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: workflow_intel.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_URLS = OUTPUT_DIR / "urls"
OUT_JS = OUTPUT_DIR / "js"
OUT_LIVE = OUTPUT_DIR / "live"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_INTEL.mkdir(parents=True, exist_ok=True)


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


# ═══════════════════════════════════════════════════════════════════════════
# Workflow Detection
# ═══════════════════════════════════════════════════════════════════════════

WORKFLOW_PATTERNS = {
    "UPLOAD": {
        "url_patterns": [r"/upload", r"/import", r"/attach", r"/media", r"/file",
                         r"/image", r"/photo", r"/avatar", r"/document", r"/asset"],
        "param_patterns": [r"file=", r"upload=", r"attachment=", r"image=", r"document="],
        "severity": "HIGH",
        "bugs": ["Unrestricted file upload", "Path traversal", "SSRF via file fetch",
                 "XSS via filename", "DoS via large file"]
    },
    "EXPORT_PDF": {
        "url_patterns": [r"/export", r"/pdf", r"/print", r"/report", r"/download",
                         r"/generate", r"/render", r"/invoice"],
        "param_patterns": [r"url=", r"html=", r"template=", r"content=", r"format="],
        "severity": "HIGH",
        "bugs": ["SSRF via PDF generation", "XSS to PDF", "LFI via template",
                 "Information disclosure"]
    },
    "PASSWORD_RESET": {
        "url_patterns": [r"/reset", r"/forgot", r"/recover", r"/password",
                         r"/change-password", r"/update-password"],
        "param_patterns": [r"token=", r"email=", r"user=", r"code="],
        "severity": "MEDIUM",
        "bugs": ["Token prediction", "Host header injection", "Rate limiting bypass",
                 "Account takeover via reset"]
    },
    "OAUTH_SSO": {
        "url_patterns": [r"/oauth", r"/authorize", r"/callback", r"/sso",
                         r"/saml", r"/cas", r"/openid", r"/auth/redirect",
                         r"/login/callback", r"/signin"],
        "param_patterns": [r"redirect_uri=", r"client_id=", r"state=",
                           r"code=", r"scope=", r"response_type="],
        "severity": "HIGH",
        "bugs": ["Open redirect via redirect_uri", "CSRF via missing state",
                 "Token leakage", "OAuth misconfiguration"]
    },
    "BILLING_PAYMENT": {
        "url_patterns": [r"/billing", r"/payment", r"/checkout", r"/subscribe",
                         r"/plan", r"/pricing", r"/stripe", r"/pay",
                         r"/invoice", r"/order", r"/cart"],
        "param_patterns": [r"amount=", r"price=", r"plan=", r"quantity=",
                           r"coupon=", r"discount="],
        "severity": "HIGH",
        "bugs": ["Price manipulation", "IDOR on invoices", "Race condition on payments",
                 "Coupon bypass"]
    },
    "INVITATION": {
        "url_patterns": [r"/invite", r"/join", r"/signup", r"/register",
                         r"/onboard", r"/activate", r"/verify",
                         r"/confirm", r"/accept"],
        "param_patterns": [r"token=", r"invite=", r"code=", r"ref="],
        "severity": "MEDIUM",
        "bugs": ["Invite link reuse", "Account takeover via invite",
                 "Privilege escalation", "Rate limiting bypass"]
    },
    "ADMIN_PANEL": {
        "url_patterns": [r"/admin", r"/dashboard", r"/console", r"/panel",
                         r"/management", r"/control", r"/backoffice",
                         r"/staff", r"/internal", r"/moderator"],
        "param_patterns": [r"role=", r"admin=", r"level=", r"permission="],
        "severity": "CRITICAL",
        "bugs": ["Auth bypass", "Privilege escalation", "IDOR",
                 "Information disclosure"]
    },
    "WEBHOOK": {
        "url_patterns": [r"/webhook", r"/hook", r"/callback", r"/notify",
                         r"/event", r"/trigger", r"/listen", r"/receive"],
        "param_patterns": [r"url=", r"endpoint=", r"target=", r"callback="],
        "severity": "HIGH",
        "bugs": ["SSRF via webhook URL", "Information disclosure",
                 "Replay attacks", "DoS"]
    },
    "API_KEY_MGMT": {
        "url_patterns": [r"/api[/-]?key", r"/token", r"/credentials",
                         r"/access[/-]?key", r"/secret"],
        "param_patterns": [r"key=", r"token=", r"api_key="],
        "severity": "HIGH",
        "bugs": ["Key leakage", "Insecure key generation", "Missing rotation"]
    },
    "GRAPHQL": {
        "url_patterns": [r"/graphql", r"/graphiql", r"/playground", r"/gql",
                         r"/query", r"/mutation"],
        "param_patterns": [r"query=", r"mutation=", r"operationName="],
        "severity": "HIGH",
        "bugs": ["Introspection enabled", "Query depth attack", "Batch query abuse",
                 "Authorization bypass per field"]
    },
}


def detect_workflows(all_urls):
    """Detect critical workflows from URL patterns."""
    print("[*] Detecting critical workflows...")
    workflows = defaultdict(lambda: {"urls": [], "params": [], "severity": "", "bugs": []})

    for url in all_urls:
        url_lower = url.lower()
        for wf_name, wf_config in WORKFLOW_PATTERNS.items():
            matched = False
            for pattern in wf_config["url_patterns"]:
                if re.search(pattern, url_lower):
                    workflows[wf_name]["urls"].append(url)
                    workflows[wf_name]["severity"] = wf_config["severity"]
                    workflows[wf_name]["bugs"] = wf_config["bugs"]
                    matched = True
                    break
            if not matched:
                for pattern in wf_config["param_patterns"]:
                    if re.search(pattern, url_lower):
                        workflows[wf_name]["params"].append(url)
                        workflows[wf_name]["severity"] = wf_config["severity"]
                        workflows[wf_name]["bugs"] = wf_config["bugs"]
                        break

    # Deduplicate
    result = {}
    for name, data in workflows.items():
        if data["urls"] or data["params"]:
            data["urls"] = sorted(set(data["urls"]))[:100]
            data["params"] = sorted(set(data["params"]))[:100]
            data["total_endpoints"] = len(data["urls"]) + len(data["params"])
            result[name] = data

    return result


def detect_auth_flows(all_urls, js_content=""):
    """Map authentication and authorization flows."""
    print("[*] Mapping authentication flows...")
    auth_flows = {
        "oauth_endpoints": [],
        "jwt_endpoints": [],
        "sso_endpoints": [],
        "session_endpoints": [],
        "api_key_endpoints": [],
        "mfa_endpoints": [],
        "trust_boundaries": [],
    }

    for url in all_urls:
        url_lower = url.lower()
        if re.search(r'/oauth|/authorize|/callback.*code=|redirect_uri=|client_id=', url_lower):
            auth_flows["oauth_endpoints"].append(url)
        if re.search(r'/token|/jwt|/refresh|bearer|authorization', url_lower):
            auth_flows["jwt_endpoints"].append(url)
        if re.search(r'/sso|/saml|/cas|/openid|/adfs|/login.*idp', url_lower):
            auth_flows["sso_endpoints"].append(url)
        if re.search(r'/session|/login|/logout|/signin|/signout', url_lower):
            auth_flows["session_endpoints"].append(url)
        if re.search(r'/api[_-]?key|/credentials|/access[_-]?token', url_lower):
            auth_flows["api_key_endpoints"].append(url)
        if re.search(r'/mfa|/2fa|/totp|/verify|/otp|/challenge', url_lower):
            auth_flows["mfa_endpoints"].append(url)

    # Detect trust boundary crossings
    domains_seen = set()
    for url in all_urls:
        match = re.match(r'https?://([^/]+)', url)
        if match:
            domains_seen.add(match.group(1).lower())
    if len(domains_seen) > 1:
        auth_flows["trust_boundaries"] = sorted(domains_seen)

    # Deduplicate all
    for key in auth_flows:
        if isinstance(auth_flows[key], list):
            auth_flows[key] = sorted(set(auth_flows[key]))[:200]

    return auth_flows


def build_attack_surface_summary(workflows, auth_flows, all_urls):
    """Build a comprehensive attack surface summary."""
    print("[*] Building attack surface summary...")

    summary = {
        "domain": DOMAIN,
        "total_urls": len(all_urls),
        "total_parameterized": len([u for u in all_urls if '?' in u]),
        "workflow_count": len(workflows),
        "critical_workflows": [k for k, v in workflows.items() if v["severity"] == "CRITICAL"],
        "high_risk_workflows": [k for k, v in workflows.items() if v["severity"] == "HIGH"],
        "auth_surface": {
            "oauth": len(auth_flows.get("oauth_endpoints", [])),
            "jwt": len(auth_flows.get("jwt_endpoints", [])),
            "sso": len(auth_flows.get("sso_endpoints", [])),
            "mfa": len(auth_flows.get("mfa_endpoints", [])),
            "trust_boundaries": len(auth_flows.get("trust_boundaries", [])),
        },
        "attack_vectors": [],
    }

    # Identify attack vectors
    if workflows.get("UPLOAD"):
        summary["attack_vectors"].append({
            "vector": "File Upload",
            "risk": "HIGH",
            "endpoints": len(workflows["UPLOAD"]["urls"]),
            "tests": ["Unrestricted upload", "Path traversal", "SSRF", "XSS via filename"]
        })
    if workflows.get("EXPORT_PDF"):
        summary["attack_vectors"].append({
            "vector": "PDF/Export Generation",
            "risk": "HIGH",
            "endpoints": len(workflows["EXPORT_PDF"]["urls"]),
            "tests": ["SSRF via URL param", "HTML injection", "LFI via template"]
        })
    if workflows.get("OAUTH_SSO"):
        summary["attack_vectors"].append({
            "vector": "OAuth/SSO",
            "risk": "HIGH",
            "endpoints": len(workflows["OAUTH_SSO"]["urls"]),
            "tests": ["Open redirect", "State fixation", "Token leakage"]
        })
    if workflows.get("GRAPHQL"):
        summary["attack_vectors"].append({
            "vector": "GraphQL",
            "risk": "HIGH",
            "endpoints": len(workflows["GRAPHQL"]["urls"]),
            "tests": ["Introspection", "Batching", "Depth attack", "Field-level auth"]
        })
    if workflows.get("WEBHOOK"):
        summary["attack_vectors"].append({
            "vector": "Webhooks",
            "risk": "HIGH",
            "endpoints": len(workflows["WEBHOOK"]["urls"]),
            "tests": ["SSRF", "Information disclosure", "Replay"]
        })

    return summary


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print(f"\n{'='*60}")
    print(f"  Workflow & Auth Intelligence — {DOMAIN}")
    print(f"{'='*60}\n")

    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    live_hosts = read_lines(OUT_LIVE / "live_hosts.txt")
    print(f"    URLs to analyze: {len(all_urls)}")
    print(f"    Live hosts: {len(live_hosts)}")

    # 1. Workflow Detection
    workflows = detect_workflows(all_urls)
    with open(OUT_INTEL / "critical_workflows.json", 'w') as f:
        json.dump(workflows, f, indent=2)
    print(f"    [+] Workflows detected: {len(workflows)}")
    for wf_name, wf_data in sorted(workflows.items(), key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}.get(x[1]["severity"], 3)):
        icon = "⚠" if wf_data["severity"] in ("CRITICAL", "HIGH") else "○"
        print(f"        {icon} [{wf_data['severity']}] {wf_name}: {wf_data['total_endpoints']} endpoints")

    # 2. Auth Flow Mapping
    auth_flows = detect_auth_flows(all_urls)
    with open(OUT_INTEL / "auth_flows.json", 'w') as f:
        json.dump(auth_flows, f, indent=2)
    total_auth = sum(len(v) for v in auth_flows.values() if isinstance(v, list))
    print(f"    [+] Auth endpoints mapped: {total_auth}")

    # 3. Attack Surface Summary
    summary = build_attack_surface_summary(workflows, auth_flows, all_urls)
    with open(OUT_INTEL / "attack_surface_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    # Human-readable summary
    with open(OUT_INTEL / "sensitive_workflows.txt", 'w') as f:
        f.write(f"# ReconX Ultra — Sensitive Workflows for {DOMAIN}\n\n")
        for wf_name, wf_data in sorted(workflows.items()):
            f.write(f"\n## [{wf_data['severity']}] {wf_name}\n")
            f.write(f"Endpoints: {wf_data['total_endpoints']}\n")
            f.write(f"Potential bugs: {', '.join(wf_data['bugs'])}\n")
            for url in wf_data['urls'][:10]:
                f.write(f"  → {url}\n")

    # Final output
    print(f"\n{'─'*60}")
    print(f"  Attack Surface Summary:")
    print(f"{'─'*60}")
    print(f"    Total URLs:           {summary['total_urls']}")
    print(f"    Parameterized:        {summary['total_parameterized']}")
    print(f"    Critical workflows:   {len(summary['critical_workflows'])}")
    print(f"    High-risk workflows:  {len(summary['high_risk_workflows'])}")
    print(f"    Attack vectors:       {len(summary['attack_vectors'])}")
    if summary['critical_workflows']:
        print(f"    \033[1;31m⚠  CRITICAL: {', '.join(summary['critical_workflows'])}\033[0m")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
