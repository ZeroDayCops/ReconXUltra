#!/usr/bin/env python3
"""
ReconX Ultra X — AI Hunter Prioritizer & Vulnerability Predictor
Scores endpoints, predicts vulnerability likelihood, generates TOP 25 targets.
"""
import json, os, sys, re
from pathlib import Path
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
RECONX_ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = RECONX_ROOT / "output" / DOMAIN
INTEL = OUT / "intelligence"
FINAL = OUT / "final"
PRIORITIZED = OUT / "prioritized"
PRIORITIZED.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Scoring Rules — mimics how a hunter thinks
# ═══════════════════════════════════════════════════════════════════════════
VULN_SIGNALS = {
    # Endpoint patterns → (vuln_type, score, description)
    r"upload|attach|import|media|avatar|file": ("upload_vuln", 30, "File upload endpoint"),
    r"graphql|gql|query|playground|graphiql": ("graphql_abuse", 35, "GraphQL endpoint"),
    r"oauth|callback|redirect_uri|authorize|token": ("oauth_misconfig", 30, "OAuth flow"),
    r"login|signin|auth|session|register|signup": ("auth_bypass", 25, "Auth endpoint"),
    r"admin|manage|dashboard|control|panel": ("admin_exposure", 35, "Admin panel"),
    r"api/v[0-9]|rest/|internal|private": ("api_exposure", 30, "API endpoint"),
    r"webhook|hook|notify|callback": ("ssrf_via_webhook", 25, "Webhook endpoint"),
    r"download|export|pdf|report|generate": ("ssrf_lfi", 25, "Export/download endpoint"),
    r"preview|render|template|markdown": ("ssti_xss", 30, "Template/render endpoint"),
    r"search|query|keyword|q=|find": ("xss_sqli", 20, "Search endpoint"),
    r"redirect|return|next|goto|rurl|out": ("open_redirect", 20, "Redirect parameter"),
    r"image|img|picture|photo|thumb": ("ssrf_via_image", 20, "Image processing"),
    r"\.env|config|debug|trace|phpinfo|actuator": ("info_disclosure", 35, "Config exposure"),
    r"swagger|openapi|api-docs|redoc": ("api_docs_exposure", 25, "API docs exposure"),
    r"\.git|\.svn|backup|\.bak|\.old": ("source_exposure", 30, "Source code exposure"),
    r"firebase|firestore|realtime": ("firebase_misconfig", 30, "Firebase exposure"),
    r"s3\.amazonaws|storage\.googleapis|blob\.core": ("cloud_bucket", 35, "Cloud storage"),
    r"jwt|bearer|token|session_id": ("jwt_issue", 20, "Token handling"),
    r"password|reset|forgot|recover|verify": ("auth_flow_vuln", 25, "Password reset flow"),
    r"payment|checkout|cart|billing|invoice|order": ("business_logic", 30, "Payment/business flow"),
    r"websocket|ws://|wss://|socket\.io": ("websocket_abuse", 20, "WebSocket endpoint"),
    r"cors|access-control|origin": ("cors_misconfig", 15, "CORS related"),
}

PARAM_SIGNALS = {
    r"^(id|uid|user_id|account_id|profile_id|order_id)$": ("idor", 25),
    r"^(url|uri|endpoint|dest|redirect|return|next|goto)$": ("ssrf_redirect", 25),
    r"^(file|path|include|template|page|doc|dir)$": ("lfi", 25),
    r"^(q|search|query|keyword|name|text|msg|comment|input)$": ("xss", 20),
    r"^(sort|order|column|group|by|filter|where|limit)$": ("sqli", 20),
    r"^(callback|jsonp|func|handler)$": ("xss_callback", 20),
    r"^(email|template|render|content|body|subject)$": ("ssti", 20),
}


def score_url(url):
    """Score a URL for vulnerability likelihood."""
    scores = defaultdict(int)
    reasons = []
    url_lower = url.lower()

    # Check endpoint patterns
    for pattern, (vuln_type, score, desc) in VULN_SIGNALS.items():
        if re.search(pattern, url_lower):
            scores[vuln_type] += score
            reasons.append(f"{desc} (+{score})")

    # Check parameter names
    params = re.findall(r'[?&]([^=]+)=', url)
    for param in params:
        for pattern, (vuln_type, score) in PARAM_SIGNALS.items():
            if re.match(pattern, param.lower()):
                scores[vuln_type] += score
                reasons.append(f"Param '{param}' → {vuln_type} (+{score})")

    # Bonus: multiple params = more attack surface
    if len(params) >= 3:
        scores["multi_param"] = 10
        reasons.append(f"Multiple params ({len(params)}) (+10)")

    total = sum(scores.values())
    top_vuln = max(scores.items(), key=lambda x: x[1])[0] if scores else "unknown"

    return {
        "url": url,
        "score": total,
        "probability": min(total, 99),
        "top_vuln": top_vuln,
        "vulns": dict(scores),
        "reasons": reasons,
    }


def main():
    if not DOMAIN:
        print("Usage: ai_prioritizer.py <domain>")
        sys.exit(1)

    print(f"\n    🧠 AI Hunter Prioritizer — {DOMAIN}")
    print(f"    {'─' * 50}")

    # Load all URLs
    urls = set()
    for f in [OUT / "urls" / "all_urls.txt", FINAL / "urls.txt", FINAL / "live_urls.txt"]:
        if f.exists():
            urls.update(l.strip() for l in open(f) if l.strip().startswith("http"))

    # Also load intelligence files
    for f in INTEL.glob("*_candidates.txt"):
        if f.exists():
            urls.update(l.strip() for l in open(f) if l.strip().startswith("http"))

    if not urls:
        print("    ⚪ No URLs found")
        return

    print(f"    📋 Scoring {len(urls)} URLs...")

    # Score all URLs
    scored = [score_url(url) for url in urls]
    scored.sort(key=lambda x: x["score"], reverse=True)

    # Filter out zero-score
    interesting = [s for s in scored if s["score"] > 0]
    print(f"    🎯 {len(interesting)} interesting endpoints found")

    # ── TOP 25 ────────────────────────────────────────────────────────────
    top25 = interesting[:25]
    print(f"\n    🔥 TOP 25 — TEST THESE FIRST:")
    print(f"    {'─' * 50}")

    top25_lines = []
    for i, t in enumerate(top25):
        prob = t["probability"]
        vuln = t["top_vuln"]
        icon = "🔴" if prob >= 50 else "🟠" if prob >= 30 else "🟡"
        print(f"    {icon} #{i+1} [{prob}%] {vuln:20s} {t['url'][:70]}")
        top25_lines.append(f"# [{prob}%] {vuln} — {', '.join(t['reasons'][:3])}")
        top25_lines.append(t["url"])
        top25_lines.append("")

    # Save TOP 25
    with open(PRIORITIZED / "top25_targets.txt", "w") as f:
        f.write("# ReconX Ultra X — TOP 25 TARGETS\n")
        f.write(f"# Target: {DOMAIN}\n")
        f.write(f"# Scored {len(urls)} URLs, {len(interesting)} interesting\n\n")
        f.write("\n".join(top25_lines))

    # ── Categorized by vulnerability type ─────────────────────────────────
    print(f"\n    📊 Categorized Attack Surfaces:")
    vuln_groups = defaultdict(list)
    for s in interesting:
        for vuln_type in s["vulns"]:
            vuln_groups[vuln_type].append(s["url"])

    for vuln_type, urls_list in sorted(vuln_groups.items(), key=lambda x: len(x[1]), reverse=True):
        count = len(urls_list)
        print(f"      {vuln_type:25s} {count:4d} endpoints")
        with open(PRIORITIZED / f"{vuln_type}_targets.txt", "w") as f:
            f.write("\n".join(sorted(set(urls_list))[:200]))

    # ── Hunter Strategy ───────────────────────────────────────────────────
    strategy = generate_strategy(vuln_groups, top25)
    with open(PRIORITIZED / "hunter_strategy.txt", "w") as f:
        f.write(strategy)
    print(f"\n    📝 Hunter strategy saved")

    # ── Full scored data ──────────────────────────────────────────────────
    with open(PRIORITIZED / "all_scored.json", "w") as f:
        json.dump(interesting[:500], f, indent=2)

    print(f"\n    💾 All files → {PRIORITIZED}/")


def generate_strategy(vuln_groups, top25):
    """Generate hunter testing strategy."""
    lines = [
        "═══════════════════════════════════════════════════",
        "  🔥 HUNTER STRATEGY — ReconX Ultra X",
        "═══════════════════════════════════════════════════",
        "",
        "  RECOMMENDED TESTING ORDER:",
        ""
    ]

    # Priority order based on what exists
    priority_order = [
        ("admin_exposure", "🔴 Test admin panels for auth bypass"),
        ("graphql_abuse", "🔴 Introspect GraphQL, test mutations"),
        ("upload_vuln", "🔴 Test file upload for RCE/XSS"),
        ("auth_bypass", "🟠 Test auth flows for bypass"),
        ("oauth_misconfig", "🟠 Test OAuth for redirect manipulation"),
        ("api_exposure", "🟠 Test APIs for IDOR/auth issues"),
        ("ssrf_via_webhook", "🟠 Test webhooks for SSRF"),
        ("business_logic", "🟠 Test payment/order flows"),
        ("ssti_xss", "🟡 Test template rendering for SSTI/XSS"),
        ("xss_sqli", "🟡 Test search for XSS/SQLi"),
        ("idor", "🟡 Test sequential IDs for IDOR"),
        ("lfi", "🟡 Test file params for LFI"),
        ("open_redirect", "🟡 Test redirect params"),
        ("info_disclosure", "🔵 Check exposed configs"),
        ("cloud_bucket", "🔵 Test cloud storage permissions"),
    ]

    step = 1
    for vuln_type, action in priority_order:
        if vuln_type in vuln_groups:
            count = len(vuln_groups[vuln_type])
            lines.append(f"  {step}. {action} ({count} targets)")
            step += 1

    lines.extend(["", "  TOP 5 URLS TO TEST IMMEDIATELY:", ""])
    for i, t in enumerate(top25[:5]):
        lines.append(f"  {i+1}. [{t['probability']}%] {t['url'][:80]}")
        lines.append(f"     → {t['top_vuln']}: {', '.join(t['reasons'][:2])}")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
