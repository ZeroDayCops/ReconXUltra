#!/usr/bin/env python3
"""
ReconX Ultra X — Hunter Mode Engine
Dynamically adjusts recon pipeline based on hunt mode.
Usage: hunter_mode.py <domain> <mode>
"""
import json, os, sys
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
MODE = sys.argv[2] if len(sys.argv) > 2 else "full"

RECONX_ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = RECONX_ROOT / "output" / DOMAIN
HUNT_DIR = OUT / "hunter_modes"
HUNT_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Hunter Mode Definitions
# ═══════════════════════════════════════════════════════════════════════════
MODES = {
    "xss-hunt": {
        "name": "XSS Hunter",
        "icon": "💉",
        "gf_patterns": ["xss"],
        "param_keywords": ["q", "search", "keyword", "query", "callback", "name", "msg",
                           "message", "comment", "text", "input", "value", "data", "content",
                           "title", "desc", "body", "subject", "preview", "template", "render"],
        "endpoint_keywords": ["search", "comment", "preview", "render", "template", "callback",
                              "share", "embed", "widget", "markdown", "editor"],
        "priority": "reflection_analysis",
        "modules": ["subdomains", "live", "urls", "dedup", "js", "intelligence", "reporting"],
    },
    "sqli-hunt": {
        "name": "SQLi Hunter",
        "icon": "🗄️",
        "gf_patterns": ["sqli"],
        "param_keywords": ["id", "user", "cat", "page", "item", "order", "sort", "num", "no",
                           "count", "limit", "offset", "filter", "where", "column", "table",
                           "group", "by", "select", "from", "join"],
        "endpoint_keywords": ["api", "user", "product", "order", "invoice", "report", "export",
                              "download", "admin", "manage", "dashboard", "query", "filter"],
        "priority": "database_endpoints",
        "modules": ["subdomains", "live", "urls", "dedup", "js", "intelligence", "reporting"],
    },
    "ssrf-hunt": {
        "name": "SSRF Hunter",
        "icon": "🌐",
        "gf_patterns": ["ssrf"],
        "param_keywords": ["url", "endpoint", "image", "dest", "redirect", "uri", "path",
                           "domain", "site", "host", "proxy", "fetch", "load", "source",
                           "target", "link", "href", "src", "webhook", "callback"],
        "endpoint_keywords": ["proxy", "fetch", "image", "avatar", "screenshot", "pdf",
                              "export", "import", "webhook", "callback", "preview", "render"],
        "priority": "outbound_requests",
    },
    "idor-hunt": {
        "name": "IDOR Hunter",
        "icon": "🆔",
        "gf_patterns": ["idor"],
        "param_keywords": ["id", "uid", "user_id", "account", "profile", "order_id", "invoice",
                           "doc", "file_id", "ref", "number", "uuid", "token", "key", "hash"],
        "endpoint_keywords": ["user", "profile", "account", "order", "invoice", "document",
                              "file", "download", "settings", "api/v", "me", "my"],
        "priority": "sequential_ids",
    },
    "graphql-hunt": {
        "name": "GraphQL Hunter",
        "icon": "📊",
        "gf_patterns": [],
        "param_keywords": ["query", "operationName", "variables", "mutation"],
        "endpoint_keywords": ["graphql", "gql", "query", "api/graphql", "graphiql", "playground"],
        "priority": "graphql_introspection",
    },
    "api-hunt": {
        "name": "API Hunter",
        "icon": "🔌",
        "gf_patterns": [],
        "param_keywords": ["api_key", "token", "secret", "key", "auth", "bearer"],
        "endpoint_keywords": ["api/v1", "api/v2", "api/v3", "rest", "swagger", "openapi",
                              "docs", "internal", "admin/api", "webhook", "graphql"],
        "priority": "api_exposure",
    },
    "auth-hunt": {
        "name": "Auth Hunter",
        "icon": "🔐",
        "gf_patterns": [],
        "param_keywords": ["username", "password", "email", "token", "code", "redirect_uri",
                           "state", "nonce", "client_id", "response_type", "scope", "grant_type"],
        "endpoint_keywords": ["login", "signup", "register", "auth", "oauth", "sso", "saml",
                              "callback", "token", "session", "logout", "reset", "forgot",
                              "verify", "confirm", "mfa", "2fa", "otp"],
        "priority": "auth_flows",
    },
    "secrets-hunt": {
        "name": "Secrets Hunter",
        "icon": "🔑",
        "gf_patterns": [],
        "param_keywords": [],
        "endpoint_keywords": [".env", "config", "settings", "debug", "trace", "actuator",
                              "phpinfo", "server-status", "wp-config", ".git", "backup"],
        "priority": "secret_exposure",
        "modules": ["subdomains", "live", "urls", "js", "content", "intelligence", "reporting"],
    },
    "js-hunt": {
        "name": "JS Intelligence Hunter",
        "icon": "📜",
        "gf_patterns": [],
        "param_keywords": [],
        "endpoint_keywords": [".js", ".mjs", "webpack", "chunk", "bundle", "worker", "sw.js"],
        "priority": "js_analysis",
        "modules": ["subdomains", "live", "urls", "js", "intelligence", "reporting"],
    },
    "cloud-hunt": {
        "name": "Cloud Hunter",
        "icon": "☁️",
        "gf_patterns": [],
        "param_keywords": ["bucket", "region", "aws", "azure", "gcp"],
        "endpoint_keywords": ["s3.amazonaws", "storage.googleapis", "blob.core.windows",
                              "firebase", "cloudfront", "cdn", "storage", "bucket"],
        "priority": "cloud_exposure",
    },
    "redirect-hunt": {
        "name": "Open Redirect Hunter",
        "icon": "↩️",
        "gf_patterns": ["redirect"],
        "param_keywords": ["url", "redirect", "return", "next", "goto", "dest", "rurl", "out",
                           "continue", "target", "redir", "return_to", "returnUrl", "forward"],
        "endpoint_keywords": ["redirect", "login", "auth", "logout", "callback", "return", "out"],
        "priority": "redirect_params",
    },
    "lfi-hunt": {
        "name": "LFI Hunter",
        "icon": "📂",
        "gf_patterns": ["lfi"],
        "param_keywords": ["file", "path", "include", "page", "template", "doc", "folder",
                           "dir", "root", "view", "content", "read", "load", "lang", "locale"],
        "endpoint_keywords": ["download", "read", "view", "include", "template", "lang",
                              "locale", "theme", "style", "file"],
        "priority": "file_inclusion",
    },
    "upload-hunt": {
        "name": "Upload Hunter",
        "icon": "📤",
        "gf_patterns": [],
        "param_keywords": ["file", "upload", "image", "avatar", "attachment", "document", "media"],
        "endpoint_keywords": ["upload", "import", "attach", "media", "image", "avatar", "file",
                              "document", "csv", "pdf", "export"],
        "priority": "upload_endpoints",
    },
    "ssti-hunt": {
        "name": "SSTI Hunter",
        "icon": "🧪",
        "gf_patterns": ["ssti"],
        "param_keywords": ["template", "render", "content", "preview", "text", "message",
                           "body", "subject", "name", "title", "email"],
        "endpoint_keywords": ["template", "render", "preview", "email", "invoice", "pdf",
                              "report", "export", "generate"],
        "priority": "template_injection",
    },
    "chain-hunt": {
        "name": "Attack Chain Hunter",
        "icon": "⛓️",
        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "ssti"],
        "param_keywords": [],
        "endpoint_keywords": ["upload", "graphql", "oauth", "admin", "api", "webhook",
                              "export", "payment", "auth", "callback", "token"],
        "priority": "chain_correlation",
        "modules": ["subdomains", "live", "urls", "dedup", "js", "content", "api",
                     "intelligence", "exploit", "validation", "reporting"],
    },
    "stealth-hunt": {
        "name": "Stealth Hunter",
        "icon": "🥷",
        "gf_patterns": ["xss", "ssrf", "redirect"],
        "param_keywords": [],
        "endpoint_keywords": [".js", "api", "graphql", "config", ".env", "debug"],
        "priority": "passive_intelligence",
        "modules": ["subdomains", "live", "urls", "js", "intelligence", "reporting"],
        "rate_limit": 30,
        "threads": 10,
    },
    "aggressive-hunt": {
        "name": "Aggressive Hunter",
        "icon": "💀",
        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "ssti"],
        "param_keywords": [],
        "endpoint_keywords": [],
        "priority": "all",
        "modules": ["subdomains", "live", "urls", "dedup", "js", "content", "ports",
                     "nuclei", "screenshots", "takeover", "cors", "api",
                     "intelligence", "exploit", "validation", "reporting"],
        "rate_limit": 500,
        "threads": 100,
    },
    "full": {
        "name": "Full Recon",
        "icon": "🔥",
        "gf_patterns": ["xss", "sqli", "ssrf", "redirect", "lfi", "idor", "ssti"],
        "param_keywords": [],
        "endpoint_keywords": [],
        "priority": "all",
    },
}


def get_mode(mode_name):
    """Get mode config with defaults."""
    m = MODES.get(mode_name, MODES["full"])
    m.setdefault("modules", ["subdomains", "live", "urls", "dedup", "js", "content",
                              "nuclei", "intelligence", "reporting"])
    return m


def classify_urls_for_mode(mode_config, urls_file):
    """Filter and prioritize URLs for the given hunt mode."""
    if not urls_file or not os.path.exists(urls_file):
        return []

    keywords = mode_config.get("endpoint_keywords", [])
    param_kw = mode_config.get("param_keywords", [])
    if not keywords and not param_kw:
        return [l.strip() for l in open(urls_file) if l.strip()]

    scored = []
    for line in open(urls_file):
        url = line.strip()
        if not url:
            continue
        score = 0
        url_lower = url.lower()
        for kw in keywords:
            if kw.lower() in url_lower:
                score += 10
        for kw in param_kw:
            if f"{kw}=" in url_lower or f"{kw.lower()}=" in url_lower:
                score += 15
        scored.append((score, url))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [url for _, url in scored]


def generate_hunt_config(mode_name):
    """Generate hunt mode output files."""
    mode = get_mode(mode_name)
    print(f"\n    {mode['icon']} Hunter Mode: {mode['name']}")
    print(f"    {'─' * 50}")

    # Save mode config
    config_file = HUNT_DIR / f"{mode_name}_config.json"
    with open(config_file, "w") as f:
        json.dump(mode, f, indent=2)

    # Classify URLs if available
    urls_file = OUT / "urls" / "all_urls.txt"
    if urls_file.exists():
        prioritized = classify_urls_for_mode(mode, str(urls_file))
        prio_file = HUNT_DIR / f"{mode_name}_targets.txt"
        with open(prio_file, "w") as f:
            f.write("\n".join(prioritized[:200]))
        print(f"    📋 Prioritized targets: {min(len(prioritized), 200)}")

    # Classify params if available
    params_file = OUT / "params" / "all_params.txt"
    if params_file.exists():
        param_kw = mode.get("param_keywords", [])
        if param_kw:
            matched = []
            for line in open(params_file):
                p = line.strip().lower()
                if any(kw.lower() in p for kw in param_kw):
                    matched.append(line.strip())
            param_file = HUNT_DIR / f"{mode_name}_params.txt"
            with open(param_file, "w") as f:
                f.write("\n".join(sorted(set(matched))))
            print(f"    🔧 Matched params: {len(set(matched))}")

    print(f"    💾 Config → {config_file}")
    return mode


if __name__ == "__main__":
    if not DOMAIN:
        print("Usage: hunter_mode.py <domain> [mode]")
        print(f"Modes: {', '.join(MODES.keys())}")
        sys.exit(1)
    generate_hunt_config(MODE)
