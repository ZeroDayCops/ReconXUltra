#!/usr/bin/env python3
"""
ReconX Ultra X — Surface Ranker & Vulnerability Predictor
==========================================================
Ranks attack surfaces by risk, predicts likely vulnerabilities,
and generates high_priority_surface.txt for hunter focus.
"""
import json, os, re, sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: surface_ranker.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
INTEL = OUT / "intelligence"
PRIO = OUT / "prioritized"
PRIO.mkdir(parents=True, exist_ok=True)


def rl(f):
    try: return [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
    except: return []

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


# ═══════════════════════════════════════════════════════════════════════════
# Surface Classification & Scoring
# ═══════════════════════════════════════════════════════════════════════════
SURFACE_CATEGORIES = {
    "UPLOAD": {
        "patterns": [r"upload|attach|import|media|avatar|file|document|image"],
        "base_score": 85, "vuln_types": ["RCE", "XSS", "SSRF", "Path Traversal"],
        "icon": "📤",
    },
    "AUTH": {
        "patterns": [r"login|signup|register|auth|oauth|sso|callback|token|session"],
        "base_score": 80, "vuln_types": ["Auth Bypass", "Account Takeover", "CSRF"],
        "icon": "🔐",
    },
    "GRAPHQL": {
        "patterns": [r"graphql|gql|playground|graphiql|mutation"],
        "base_score": 80, "vuln_types": ["Introspection", "IDOR", "DoS", "Auth Bypass"],
        "icon": "📊",
    },
    "API": {
        "patterns": [r"/api/v[0-9]|/rest/|/internal/|/private/"],
        "base_score": 70, "vuln_types": ["IDOR", "Mass Assignment", "Rate Limit Bypass"],
        "icon": "🔌",
    },
    "ADMIN": {
        "patterns": [r"admin|dashboard|console|panel|management|backoffice|staff"],
        "base_score": 90, "vuln_types": ["Auth Bypass", "Privilege Escalation", "IDOR"],
        "icon": "👑",
    },
    "WEBHOOK": {
        "patterns": [r"webhook|hook|callback|notify|event|trigger"],
        "base_score": 75, "vuln_types": ["SSRF", "Info Disclosure", "Replay"],
        "icon": "🪝",
    },
    "CLOUD": {
        "patterns": [r"s3\.|amazonaws|googleapis|blob\.core|firebase|cloudfront"],
        "base_score": 75, "vuln_types": ["Bucket Takeover", "Data Exposure"],
        "icon": "☁️",
    },
    "PAYMENT": {
        "patterns": [r"payment|checkout|billing|invoice|order|cart|stripe|pay"],
        "base_score": 85, "vuln_types": ["Price Manipulation", "IDOR", "Race Condition"],
        "icon": "💳",
    },
    "EXPORT": {
        "patterns": [r"export|pdf|print|report|download|generate|render"],
        "base_score": 70, "vuln_types": ["SSRF", "XSS", "LFI", "Info Disclosure"],
        "icon": "📄",
    },
    "CONFIG": {
        "patterns": [r"\.env|\.git|config|debug|phpinfo|actuator|server-status"],
        "base_score": 95, "vuln_types": ["Info Disclosure", "Source Code Leak"],
        "icon": "⚙️",
    },
    "WEBSOCKET": {
        "patterns": [r"ws://|wss://|socket\.io|websocket"],
        "base_score": 65, "vuln_types": ["CSWSH", "Info Leak", "Auth Bypass"],
        "icon": "🔄",
    },
    "PASSWORD_RESET": {
        "patterns": [r"reset|forgot|recover|password|change-password"],
        "base_score": 70, "vuln_types": ["Account Takeover", "Host Header Injection"],
        "icon": "🔑",
    },
}


def rank_surfaces():
    """Rank all attack surfaces by risk."""
    print(f"\n  📊 Surface Ranker — {DOMAIN}")
    print(f"  {'━' * 50}")

    all_urls = rl(OUT / "urls/all_urls.txt")
    if not all_urls:
        print("  ⚪ No URLs found")
        return

    # Classify URLs into surface categories
    surfaces = defaultdict(lambda: {"urls": [], "score": 0, "density": 0})

    for url in all_urls:
        url_lower = url.lower()
        for cat, config in SURFACE_CATEGORIES.items():
            for pat in config["patterns"]:
                if re.search(pat, url_lower, re.IGNORECASE):
                    surfaces[cat]["urls"].append(url)
                    break

    # Score each surface
    ranked = []
    for cat, data in surfaces.items():
        if not data["urls"]:
            continue
        config = SURFACE_CATEGORIES[cat]
        count = len(data["urls"])
        density = min(count / max(len(all_urls), 1) * 100, 100)

        # Adjust score based on density
        score = config["base_score"]
        if count > 20: score += 5
        if count > 50: score += 5
        score = min(score, 99)

        ranked.append({
            "category": cat,
            "icon": config["icon"],
            "score": score,
            "endpoints": count,
            "density": round(density, 2),
            "vuln_types": config["vuln_types"],
            "sample_urls": sorted(set(data["urls"]))[:10],
        })

    ranked.sort(key=lambda x: x["score"], reverse=True)

    # Generate high_priority_surface.txt
    lines = [
        "═" * 60,
        "  🔥 HIGH PRIORITY ATTACK SURFACE",
        f"  Target: {DOMAIN}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 60, "",
    ]

    for i, s in enumerate(ranked, 1):
        icon = "🔴" if s["score"] >= 85 else "🟠" if s["score"] >= 70 else "🟡"
        lines.append(f"  {icon} {i}. {s['icon']} {s['category']} "
                     f"[Score: {s['score']}] ({s['endpoints']} endpoints)")
        lines.append(f"     Density: {s['density']}%")
        lines.append(f"     Test for: {', '.join(s['vuln_types'])}")
        for url in s["sample_urls"][:3]:
            lines.append(f"     → {url}")
        lines.append("")

    (PRIO / "high_priority_surface.txt").write_text("\n".join(lines))
    (PRIO / "surface_ranking.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_urls": len(all_urls),
        "ranked_surfaces": ranked,
    }, indent=2))

    # Generate per-category target files
    for s in ranked:
        cat = s["category"].lower()
        (PRIO / f"{cat}_targets.txt").write_text(
            "\n".join(sorted(set(s["sample_urls"]))))

    # Print summary
    print(f"  📋 {len(all_urls)} URLs analyzed")
    for s in ranked[:8]:
        icon = "🔴" if s["score"] >= 85 else "🟠" if s["score"] >= 70 else "🟡"
        print(f"    {icon} {s['icon']} {s['category']:15s} "
              f"Score:{s['score']:3d} | {s['endpoints']:4d} endpoints")

    print(f"\n  💾 Priority surface → {PRIO}/")

    # Generate vulnerability predictions
    generate_predictions(ranked, all_urls)


def generate_predictions(ranked_surfaces: list, all_urls: list):
    """Predict likely vulnerabilities based on surface analysis."""
    print(f"\n  🧠 AI Vulnerability Predictor")
    print(f"  {'━' * 50}")

    predictions = []

    # Based on surface categories present, predict vulns
    cats = {s["category"] for s in ranked_surfaces}

    if "UPLOAD" in cats and "AUTH" in cats:
        predictions.append({
            "prediction": "Stored XSS via file upload",
            "confidence": "HIGH", "severity": "HIGH",
            "reason": "Upload + auth endpoints found — test SVG/HTML upload",
        })
    if "GRAPHQL" in cats:
        predictions.append({
            "prediction": "GraphQL field-level authorization bypass",
            "confidence": "HIGH", "severity": "HIGH",
            "reason": "GraphQL detected — introspection likely enabled",
        })
    if "API" in cats:
        predictions.append({
            "prediction": "IDOR via sequential API resource IDs",
            "confidence": "MEDIUM", "severity": "HIGH",
            "reason": "REST APIs detected — test ID enumeration",
        })
    if "WEBHOOK" in cats:
        predictions.append({
            "prediction": "SSRF via webhook URL parameter",
            "confidence": "HIGH", "severity": "CRITICAL",
            "reason": "Webhook endpoints accept URL params",
        })
    if "EXPORT" in cats:
        predictions.append({
            "prediction": "SSRF via PDF/export generation",
            "confidence": "MEDIUM", "severity": "HIGH",
            "reason": "Export/PDF endpoints may fetch external URLs",
        })
    if "PAYMENT" in cats:
        predictions.append({
            "prediction": "Race condition on payment/discount",
            "confidence": "MEDIUM", "severity": "HIGH",
            "reason": "Payment flows detected — test concurrent requests",
        })
    if "CONFIG" in cats:
        predictions.append({
            "prediction": "Sensitive config/source code exposure",
            "confidence": "HIGH", "severity": "CRITICAL",
            "reason": "Config/debug endpoints detected",
        })
    if "AUTH" in cats:
        predictions.append({
            "prediction": "OAuth redirect_uri manipulation",
            "confidence": "MEDIUM", "severity": "HIGH",
            "reason": "OAuth flow detected — test redirect_uri bypass",
        })

    # Check param-based predictions
    param_urls = [u for u in all_urls if "?" in u]
    if len(param_urls) > 100:
        predictions.append({
            "prediction": "Reflected XSS via search/query parameters",
            "confidence": "MEDIUM", "severity": "MEDIUM",
            "reason": f"{len(param_urls)} parameterized URLs — high reflection surface",
        })

    predictions.sort(key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2,
                                     "LOW": 3}.get(x["severity"], 9))

    (PRIO / "vulnerability_predictions.json").write_text(
        json.dumps({"domain": DOMAIN, "predictions": predictions,
                     "timestamp": datetime.now().isoformat()}, indent=2))

    for p in predictions[:8]:
        icon = "🔴" if p["severity"] == "CRITICAL" else "🟠" if p["severity"] == "HIGH" else "🟡"
        print(f"    {icon} [{p['confidence']}] {p['prediction']}")

    print(f"  💾 Predictions saved: {len(predictions)}")


if __name__ == "__main__":
    rank_surfaces()
