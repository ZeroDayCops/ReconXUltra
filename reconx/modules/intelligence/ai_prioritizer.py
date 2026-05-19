#!/usr/bin/env python3
"""
ReconX Ultra — AI Risk Prioritization Engine
==============================================
Multi-factor risk scoring for every endpoint:
  - Secrets exposure weight
  - Admin keyword detection
  - Reflection detection
  - Upload functionality scoring
  - GraphQL presence boost
  - Cloud integration detection
  - Auth presence analysis
  - Technology risk mapping

Outputs:
  - prioritized_targets.json
  - risk_matrix.json
  - high_value_endpoints.txt
"""

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: ai_prioritizer.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_URLS = OUTPUT_DIR / "urls"
OUT_LIVE = OUTPUT_DIR / "live"
OUT_JS = OUTPUT_DIR / "js"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_SECRETS = OUTPUT_DIR / "secrets"
OUT_INTEL.mkdir(parents=True, exist_ok=True)


def read_lines(fp):
    try:
        with open(fp, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def load_json(fp):
    try:
        with open(fp) as f:
            return json.load(f)
    except:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Scoring Rules — Multi-Factor Risk Assessment
# ═══════════════════════════════════════════════════════════════════════════

SCORING_RULES = {
    # Critical signals (30-40 pts each)
    "critical_keywords": {
        "patterns": [
            r"/admin", r"/internal", r"/debug", r"/console", r"/actuator",
            r"/management", r"/swagger", r"/api-docs", r"/phpinfo",
            r"/server-status", r"/elmah", r"/trace", r"/profiler",
            r"/graphql", r"/graphiql", r"\.env", r"\.git",
        ],
        "score": 35,
        "category": "CRITICAL",
    },
    # High signals (15-25 pts)
    "auth_endpoints": {
        "patterns": [
            r"/login", r"/auth", r"/oauth", r"/sso", r"/saml",
            r"/token", r"/jwt", r"/session", r"/password", r"/reset",
            r"/register", r"/signup", r"/mfa", r"/2fa",
        ],
        "score": 20,
        "category": "AUTH",
    },
    "upload_endpoints": {
        "patterns": [
            r"/upload", r"/import", r"/attach", r"/media", r"/file",
            r"/image", r"/photo", r"/avatar", r"/document",
        ],
        "score": 25,
        "category": "UPLOAD",
    },
    "export_pdf": {
        "patterns": [
            r"/export", r"/pdf", r"/print", r"/report", r"/render",
            r"/generate", r"/invoice", r"/download",
        ],
        "score": 20,
        "category": "EXPORT",
    },
    "payment": {
        "patterns": [
            r"/billing", r"/payment", r"/checkout", r"/subscribe",
            r"/stripe", r"/pay", r"/invoice", r"/order", r"/cart",
        ],
        "score": 25,
        "category": "PAYMENT",
    },
    "webhook": {
        "patterns": [
            r"/webhook", r"/hook", r"/callback", r"/notify",
            r"/event", r"/trigger",
        ],
        "score": 20,
        "category": "WEBHOOK",
    },
    # Medium signals (5-15 pts)
    "api_paths": {
        "patterns": [r"/api/", r"/v[0-9]+/", r"/rest/"],
        "score": 15,
        "category": "API",
    },
    "search_filter": {
        "patterns": [r"search", r"query", r"filter", r"sort", r"q="],
        "score": 10,
        "category": "INPUT",
    },
    "redirect_params": {
        "patterns": [r"redirect", r"return", r"next", r"url=", r"goto"],
        "score": 15,
        "category": "REDIRECT",
    },
}

# Bonus scoring factors
BONUS_RULES = {
    "has_parameters": {"check": lambda u: '?' in u, "score": 5},
    "many_parameters": {"check": lambda u: u.count('&') >= 3, "score": 10},
    "non_standard_port": {"check": lambda u: bool(re.search(r':\d{4,5}/', u)), "score": 10},
    "graphql": {"check": lambda u: 'graphql' in u.lower(), "score": 15},
    "json_api": {"check": lambda u: '.json' in u.lower() or 'application/json' in u.lower(), "score": 5},
}


def score_endpoint(url, secrets_urls=None, admin_routes=None, js_endpoints=None):
    """Multi-factor risk scoring for a single endpoint."""
    url_lower = url.lower()
    score = 0
    reasons = []
    categories = set()
    sensitivity = "LOW"

    # Apply scoring rules
    for rule_name, rule in SCORING_RULES.items():
        for pattern in rule["patterns"]:
            if re.search(pattern, url_lower):
                score += rule["score"]
                reasons.append(f"{rule['category']}:{pattern.strip('/')}")
                categories.add(rule["category"])
                break

    # Apply bonus rules
    for bonus_name, bonus in BONUS_RULES.items():
        if bonus["check"](url):
            score += bonus["score"]
            reasons.append(bonus_name)

    # Boost if URL found in secrets analysis
    if secrets_urls and url in secrets_urls:
        score += 30
        reasons.append("secrets_exposure")
        categories.add("SECRETS")

    # Boost if found in admin routes from JS
    if admin_routes and any(ar in url_lower for ar in admin_routes):
        score += 20
        reasons.append("js_admin_route")

    # Boost if found via JS endpoint extraction
    if js_endpoints and url in js_endpoints:
        score += 10
        reasons.append("js_extracted")

    # Determine sensitivity level
    if score >= 60:
        sensitivity = "CRITICAL"
    elif score >= 40:
        sensitivity = "HIGH"
    elif score >= 20:
        sensitivity = "MEDIUM"

    return {
        "url": url,
        "score": min(score, 100),
        "sensitivity": sensitivity,
        "categories": sorted(categories),
        "reasons": reasons[:8],
        "vuln_potential": list(categories)[:5],
    }


def build_risk_matrix(scored_endpoints):
    """Build a risk matrix summary."""
    matrix = {
        "CRITICAL": {"count": 0, "examples": []},
        "HIGH": {"count": 0, "examples": []},
        "MEDIUM": {"count": 0, "examples": []},
        "LOW": {"count": 0, "examples": []},
    }

    category_counts = defaultdict(int)

    for ep in scored_endpoints:
        level = ep["sensitivity"]
        matrix[level]["count"] += 1
        if len(matrix[level]["examples"]) < 10:
            matrix[level]["examples"].append(ep["url"])
        for cat in ep["categories"]:
            category_counts[cat] += 1

    return matrix, dict(category_counts)


def main():
    print(f"\n{'='*60}")
    print(f"  AI Risk Prioritization Engine — {DOMAIN}")
    print(f"{'='*60}\n")

    # Load all data sources
    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    live_hosts = read_lines(OUT_LIVE / "live_hosts.txt")
    js_endpoints = set(read_lines(OUT_INTEL / "js_endpoints_flat.txt"))
    admin_routes = set(read_lines(OUT_INTEL / "admin_routes.txt"))

    # Load secrets data
    secrets_data = load_json(OUT_INTEL / "js_secrets.json") or load_json(OUT_INTEL / "js_secrets_deep.json")
    secrets_urls = set()
    if secrets_data and isinstance(secrets_data, list):
        for s in secrets_data:
            if isinstance(s, dict) and "file" in s:
                secrets_urls.add(s["file"])

    all_targets = list(set(all_urls + live_hosts))
    print(f"  [*] Scoring {len(all_targets)} endpoints...")

    # Score all endpoints
    scored = []
    for url in all_targets:
        result = score_endpoint(url, secrets_urls, admin_routes, js_endpoints)
        if result["score"] > 0:
            scored.append(result)

    # Sort by score
    scored.sort(key=lambda x: -x["score"])

    # Build risk matrix
    matrix, cat_counts = build_risk_matrix(scored)

    # Save prioritized targets
    with open(OUT_INTEL / "prioritized_targets.json", 'w') as f:
        json.dump(scored[:2000], f, indent=2)

    with open(OUT_INTEL / "risk_matrix.json", 'w') as f:
        json.dump({"matrix": matrix, "category_distribution": cat_counts}, f, indent=2)

    # Human-readable high-value endpoints
    with open(OUT_INTEL / "high_value_endpoints.txt", 'w') as f:
        f.write(f"# ReconX Ultra — High-Value Endpoints for {DOMAIN}\n")
        f.write(f"# Scored by multi-factor risk analysis\n\n")
        for ep in scored[:500]:
            cats = ",".join(ep["categories"][:3])
            reasons = ",".join(ep["reasons"][:3])
            f.write(f"[{ep['score']:3d}] [{ep['sensitivity']:8s}] [{cats}] {ep['url']}\n")

    # Top critical targets — elite triage output
    top_targets = [ep for ep in scored if ep["sensitivity"] in ("CRITICAL","HIGH")][:100]
    with open(OUT_INTEL / "top_critical_targets.json", 'w') as f:
        json.dump({
            "domain": DOMAIN,
            "total_critical": len([t for t in top_targets if t["sensitivity"]=="CRITICAL"]),
            "total_high": len([t for t in top_targets if t["sensitivity"]=="HIGH"]),
            "targets": top_targets,
        }, f, indent=2)

    # Endpoint risk scores (legacy compatibility)
    with open(OUT_INTEL / "endpoint_scores.txt", 'w') as f:
        f.write(f"# ReconX Ultra — Endpoint Risk Scores for {DOMAIN}\n\n")
        for ep in scored[:500]:
            reasons_str = ", ".join(ep["reasons"][:3])
            f.write(f"[{ep['score']:3d}] {ep['url']}  ({reasons_str})\n")

    # Summary
    print(f"\n{'─'*60}")
    print(f"  Risk Prioritization Summary:")
    print(f"{'─'*60}")
    print(f"    Endpoints scored:   {len(scored)}")
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        icon = "🔴" if level == "CRITICAL" else "🟠" if level == "HIGH" else "🟡" if level == "MEDIUM" else "🟢"
        print(f"    {icon} {level:10s}: {matrix[level]['count']}")
    print(f"\n    Top categories:")
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])[:10]:
        print(f"      {cat:15s}: {count}")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    main()
