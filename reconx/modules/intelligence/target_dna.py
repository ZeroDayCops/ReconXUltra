#!/usr/bin/env python3
"""
ReconX Ultra X — Target DNA Engine
====================================
Fingerprints the target's entire technology stack, architecture,
and generates a comprehensive target_dna.json profile.

Fingerprints: frameworks, auth systems, cloud providers, JS frameworks,
APIs, uploads, GraphQL, admin panels, CDNs, WAFs.
"""
import json, os, re, sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: target_dna.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
INTEL = OUT / "intelligence"
DNA_DIR = OUT / "target_dna"
DNA_DIR.mkdir(parents=True, exist_ok=True)


def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


# ═══════════════════════════════════════════════════════════════════════════
# Technology Fingerprinting Signatures
# ═══════════════════════════════════════════════════════════════════════════
TECH_SIGNATURES = {
    # Backend Frameworks
    "Laravel":        [r"laravel", r"csrf-token", r"x-powered-by.*laravel"],
    "Django":         [r"django", r"csrfmiddlewaretoken", r"__admin__"],
    "Rails":          [r"ruby.*rails", r"_rails_", r"authenticity_token"],
    "Spring":         [r"spring", r"actuator", r"x-application-context"],
    "Express":        [r"express", r"x-powered-by.*express"],
    "Flask":          [r"flask", r"werkzeug", r"jinja"],
    "ASP.NET":        [r"asp\.net", r"__viewstate", r"__requestverificationtoken"],
    "PHP":            [r"\.php", r"phpsessid", r"x-powered-by.*php"],
    "Node.js":        [r"node\.js", r"x-powered-by.*node"],
    "FastAPI":        [r"fastapi", r"openapi.*3\.", r"uvicorn"],
    "Next.js":        [r"__next", r"_next/", r"next\.js"],
    "Nuxt.js":        [r"__nuxt", r"nuxt\.js", r"_nuxt/"],
    # Frontend Frameworks
    "React":          [r"react", r"_reactRoot", r"__REACT", r"data-reactroot"],
    "Angular":        [r"angular", r"ng-version", r"ng-app"],
    "Vue.js":         [r"vue\.js", r"v-app", r"__vue__"],
    "jQuery":         [r"jquery", r"jquery\.min\.js"],
    "Webpack":        [r"webpack", r"webpackJsonp", r"__webpack_"],
    # Auth Systems
    "OAuth2":         [r"oauth", r"authorize\?", r"redirect_uri=", r"client_id="],
    "SAML":           [r"saml", r"SAMLRequest", r"SAMLResponse"],
    "JWT":            [r"jwt", r"eyJ[A-Za-z0-9]", r"bearer"],
    "Auth0":          [r"auth0\.com", r"auth0"],
    "Firebase Auth":  [r"firebase.*auth", r"identitytoolkit"],
    "Okta":           [r"okta\.com", r"okta"],
    # Cloud
    "AWS":            [r"amazonaws\.com", r"s3\.", r"cloudfront", r"aws-"],
    "GCP":            [r"googleapis\.com", r"storage\.cloud\.google", r"gcp"],
    "Azure":          [r"azure\.", r"blob\.core\.windows", r"microsoft\.com"],
    "Firebase":       [r"firebase", r"firebaseio\.com", r"firebaseapp\.com"],
    "Cloudflare":     [r"cloudflare", r"cf-ray", r"__cf"],
    "Vercel":         [r"vercel", r"\.vercel\.app"],
    "Netlify":        [r"netlify", r"\.netlify\.app"],
    # APIs
    "GraphQL":        [r"graphql", r"graphiql", r"playground", r"__schema"],
    "REST API":       [r"/api/v[0-9]", r"rest/", r"/api/"],
    "gRPC":           [r"grpc", r"protobuf"],
    "WebSocket":      [r"ws://", r"wss://", r"socket\.io", r"websocket"],
    "Swagger":        [r"swagger", r"openapi", r"api-docs"],
    # CDN/WAF
    "Akamai":         [r"akamai", r"akam"],
    "Fastly":         [r"fastly"],
    "Imperva":        [r"imperva", r"incapsula"],
    # CMS
    "WordPress":      [r"wp-content", r"wp-includes", r"wordpress"],
    "Drupal":         [r"drupal", r"sites/default"],
    "Joomla":         [r"joomla", r"com_content"],
}


def fingerprint_target():
    """Analyze all collected data to build target DNA."""
    print(f"\n  🧬 Target DNA Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    dna = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "technologies": {},
        "auth_systems": [],
        "cloud_providers": [],
        "api_types": [],
        "frameworks": {"backend": [], "frontend": []},
        "security": {"waf": [], "cdn": [], "headers": []},
        "attack_surface": {
            "uploads": 0, "graphql": 0, "admin_panels": 0,
            "oauth_endpoints": 0, "webhooks": 0, "websockets": 0,
            "apis": 0, "forms": 0,
        },
        "js_ecosystem": {"files": 0, "frameworks": [], "bundler": None},
        "risk_profile": "UNKNOWN",
        "hunting_recommendations": [],
    }

    # Load all available data
    all_urls = rl(OUT / "urls/all_urls.txt")
    live_hosts = rl(OUT / "live/live_hosts.txt")
    js_urls = rl(OUT / "js/js_urls.txt")
    all_text = "\n".join(all_urls + live_hosts + js_urls).lower()

    # Also scan httpx output for headers
    httpx_data = rl(OUT / "live/httpx_full.json")

    # Fingerprint technologies
    detected = {}
    for tech, patterns in TECH_SIGNATURES.items():
        confidence = 0
        matches = 0
        for pat in patterns:
            if re.search(pat, all_text, re.IGNORECASE):
                matches += 1
                confidence += 30
        if matches > 0:
            detected[tech] = min(confidence, 95)

    dna["technologies"] = detected
    print(f"  🔧 Technologies detected: {len(detected)}")

    # Classify by category
    backend = ["Laravel", "Django", "Rails", "Spring", "Express", "Flask",
               "ASP.NET", "PHP", "Node.js", "FastAPI", "Next.js", "Nuxt.js"]
    frontend = ["React", "Angular", "Vue.js", "jQuery", "Webpack"]
    auth = ["OAuth2", "SAML", "JWT", "Auth0", "Firebase Auth", "Okta"]
    cloud = ["AWS", "GCP", "Azure", "Firebase", "Cloudflare", "Vercel", "Netlify"]
    api_types = ["GraphQL", "REST API", "gRPC", "WebSocket", "Swagger"]

    dna["frameworks"]["backend"] = [t for t in detected if t in backend]
    dna["frameworks"]["frontend"] = [t for t in detected if t in frontend]
    dna["auth_systems"] = [t for t in detected if t in auth]
    dna["cloud_providers"] = [t for t in detected if t in cloud]
    dna["api_types"] = [t for t in detected if t in api_types]
    dna["security"]["waf"] = [t for t in detected if t in
                               ["Cloudflare", "Akamai", "Fastly", "Imperva"]]

    # Count attack surface elements
    url_text = "\n".join(all_urls)
    dna["attack_surface"]["uploads"] = len(
        [u for u in all_urls if re.search(r"upload|attach|import|media|file", u, re.I)])
    dna["attack_surface"]["graphql"] = len(
        [u for u in all_urls if re.search(r"graphql|gql|playground", u, re.I)])
    dna["attack_surface"]["admin_panels"] = len(
        [u for u in all_urls if re.search(r"admin|dashboard|console|panel", u, re.I)])
    dna["attack_surface"]["oauth_endpoints"] = len(
        [u for u in all_urls if re.search(r"oauth|authorize|callback|sso", u, re.I)])
    dna["attack_surface"]["webhooks"] = len(
        [u for u in all_urls if re.search(r"webhook|hook|callback|notify", u, re.I)])
    dna["attack_surface"]["apis"] = len(
        [u for u in all_urls if re.search(r"/api/|/v[0-9]+/|/rest/", u, re.I)])

    # JS ecosystem
    dna["js_ecosystem"]["files"] = len(js_urls)
    if "Webpack" in detected: dna["js_ecosystem"]["bundler"] = "webpack"
    dna["js_ecosystem"]["frameworks"] = dna["frameworks"]["frontend"]

    # Risk profile
    risk_score = 0
    if dna["attack_surface"]["uploads"] > 0: risk_score += 20
    if dna["attack_surface"]["graphql"] > 0: risk_score += 15
    if dna["attack_surface"]["admin_panels"] > 0: risk_score += 25
    if dna["attack_surface"]["oauth_endpoints"] > 0: risk_score += 15
    if len(dna["api_types"]) > 1: risk_score += 10
    if not dna["security"]["waf"]: risk_score += 10
    if dna["auth_systems"]: risk_score += 10

    if risk_score >= 60: dna["risk_profile"] = "CRITICAL"
    elif risk_score >= 40: dna["risk_profile"] = "HIGH"
    elif risk_score >= 20: dna["risk_profile"] = "MEDIUM"
    else: dna["risk_profile"] = "LOW"

    # Hunting recommendations
    recs = []
    if dna["attack_surface"]["uploads"] > 0:
        recs.append("🔴 Test upload endpoints for unrestricted file upload + path traversal")
    if "GraphQL" in detected:
        recs.append("🔴 Test GraphQL introspection, batch queries, field-level auth")
    if dna["attack_surface"]["admin_panels"] > 0:
        recs.append("🔴 Test admin panels for auth bypass + privilege escalation")
    if "OAuth2" in detected:
        recs.append("🟠 Test OAuth flows for redirect_uri manipulation + state bypass")
    if "JWT" in detected:
        recs.append("🟠 Test JWT for weak signing, algorithm confusion, claim bypass")
    if dna["attack_surface"]["webhooks"] > 0:
        recs.append("🟠 Test webhooks for SSRF + replay attacks")
    if "Firebase" in detected:
        recs.append("🟡 Check Firebase database rules + authentication bypass")
    if dna["attack_surface"]["apis"] > 10:
        recs.append("🟡 Large API surface — test for IDOR, mass assignment, rate limiting")
    dna["hunting_recommendations"] = recs

    # Save
    (DNA_DIR / "target_dna.json").write_text(json.dumps(dna, indent=2))

    # Human-readable
    lines = [
        "═" * 60,
        f"  🧬 TARGET DNA — {DOMAIN}",
        "═" * 60, "",
        f"  Risk Profile: {dna['risk_profile']}",
        f"  Technologies: {len(detected)}",
        "",
        "  ═══ TECH STACK ═══",
    ]
    if dna["frameworks"]["backend"]:
        lines.append(f"  Backend: {', '.join(dna['frameworks']['backend'])}")
    if dna["frameworks"]["frontend"]:
        lines.append(f"  Frontend: {', '.join(dna['frameworks']['frontend'])}")
    if dna["auth_systems"]:
        lines.append(f"  Auth: {', '.join(dna['auth_systems'])}")
    if dna["cloud_providers"]:
        lines.append(f"  Cloud: {', '.join(dna['cloud_providers'])}")
    if dna["api_types"]:
        lines.append(f"  APIs: {', '.join(dna['api_types'])}")
    lines.extend(["", "  ═══ ATTACK SURFACE ═══"])
    for k, v in dna["attack_surface"].items():
        if v: lines.append(f"  {k}: {v}")
    lines.extend(["", "  ═══ HUNTING RECOMMENDATIONS ═══"])
    for r in recs: lines.append(f"  {r}")
    lines.append("")

    (DNA_DIR / "target_dna.txt").write_text("\n".join(lines))

    # Print summary
    print(f"  🎯 Risk Profile: {dna['risk_profile']}")
    for cat in ["backend", "frontend"]:
        if dna["frameworks"][cat]:
            print(f"  {'🔧' if cat=='backend' else '🎨'} "
                  f"{cat.title()}: {', '.join(dna['frameworks'][cat])}")
    if dna["auth_systems"]:
        print(f"  🔐 Auth: {', '.join(dna['auth_systems'])}")
    if dna["cloud_providers"]:
        print(f"  ☁️  Cloud: {', '.join(dna['cloud_providers'])}")
    if recs:
        print(f"\n  🔥 {len(recs)} hunting recommendations generated")
    print(f"  💾 DNA → {DNA_DIR}/")


if __name__ == "__main__":
    fingerprint_target()
