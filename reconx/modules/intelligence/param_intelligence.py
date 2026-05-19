#!/usr/bin/env python3
"""
ReconX Ultra X — Parameter Intelligence Engine
Classifies ALL parameters by vulnerability type.
Generates: xss_params.txt, sqli_params.txt, ssrf_params.txt, etc.
"""
import json, os, sys, re
from pathlib import Path
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
RECONX_ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = RECONX_ROOT / "output" / DOMAIN
FINAL = OUT / "final"
FINAL.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Parameter Classification Rules
# ═══════════════════════════════════════════════════════════════════════════
PARAM_CLASSES = {
    "xss": {
        "keywords": ["q", "search", "query", "keyword", "callback", "name", "msg", "message",
                      "comment", "text", "input", "value", "data", "content", "title", "desc",
                      "body", "subject", "preview", "template", "render", "label", "bio",
                      "display", "note", "remark", "tag", "caption", "alt", "placeholder",
                      "jsonp", "func", "handler", "error", "success", "html", "markdown"],
        "icon": "💉",
    },
    "sqli": {
        "keywords": ["id", "user", "cat", "category", "page", "item", "order", "sort",
                      "num", "no", "count", "limit", "offset", "filter", "where", "column",
                      "table", "group", "by", "select", "from", "join", "type", "status",
                      "year", "month", "date", "start", "end", "price", "min", "max",
                      "product", "article", "post", "thread", "report"],
        "icon": "🗄️",
    },
    "ssrf": {
        "keywords": ["url", "endpoint", "image", "dest", "uri", "path", "domain", "site",
                      "host", "proxy", "fetch", "load", "source", "target", "link", "href",
                      "src", "webhook", "callback", "feed", "ping", "remote", "location",
                      "server", "addr", "connect", "forward", "external"],
        "icon": "🌐",
    },
    "idor": {
        "keywords": ["id", "uid", "user_id", "account_id", "profile_id", "order_id",
                      "invoice_id", "doc_id", "file_id", "ref", "number", "uuid", "token",
                      "key", "hash", "org_id", "team_id", "project_id", "workspace_id",
                      "customer_id", "subscription_id", "payment_id"],
        "icon": "🆔",
    },
    "redirect": {
        "keywords": ["url", "redirect", "return", "next", "goto", "dest", "rurl", "out",
                      "continue", "target", "redir", "return_to", "returnUrl", "forward",
                      "callback", "redirect_uri", "ReturnUrl", "back", "success_url",
                      "error_url", "cancel_url"],
        "icon": "↩️",
    },
    "lfi": {
        "keywords": ["file", "path", "include", "template", "page", "doc", "folder", "dir",
                      "root", "view", "content", "read", "load", "lang", "locale", "theme",
                      "style", "module", "plugin", "ext", "config"],
        "icon": "📂",
    },
    "ssti": {
        "keywords": ["template", "render", "content", "preview", "text", "message", "body",
                      "subject", "name", "title", "email", "format", "layout", "view",
                      "tpl", "skin", "theme"],
        "icon": "🧪",
    },
}


def extract_params_from_urls(urls_file):
    """Extract all parameter names from URL file."""
    params = defaultdict(int)
    param_urls = defaultdict(list)

    if not os.path.exists(urls_file):
        return params, param_urls

    for line in open(urls_file):
        url = line.strip()
        if not url:
            continue
        found = re.findall(r'[?&]([^=]+)=', url)
        for p in found:
            params[p] += 1
            if len(param_urls[p]) < 5:  # Keep max 5 example URLs
                param_urls[p].append(url)

    return params, param_urls


def classify_params(params):
    """Classify parameters by vulnerability type."""
    classified = defaultdict(list)

    for param in params:
        p_lower = param.lower()
        for vuln_type, config in PARAM_CLASSES.items():
            for kw in config["keywords"]:
                if kw.lower() == p_lower or kw.lower() in p_lower:
                    classified[vuln_type].append(param)
                    break

    return classified


def main():
    if not DOMAIN:
        print("Usage: param_intelligence.py <domain>")
        sys.exit(1)

    print(f"\n    🧠 Parameter Intelligence Engine — {DOMAIN}")
    print(f"    {'─' * 50}")

    # Collect params from all sources
    all_params = defaultdict(int)
    all_urls = defaultdict(list)

    sources = [
        OUT / "urls" / "all_urls.txt",
        OUT / "params" / "all_params_urls.txt",
        FINAL / "urls.txt",
    ]
    # Also check intelligence candidate files
    if INTEL := OUT / "intelligence":
        for f in INTEL.glob("*_candidates.txt"):
            sources.append(f)

    for src in sources:
        if src.exists():
            p, u = extract_params_from_urls(str(src))
            for k, v in p.items():
                all_params[k] += v
            for k, v in u.items():
                all_urls[k].extend(v)

    if not all_params:
        print("    ⚪ No parameters found")
        return

    print(f"    📊 Total unique parameters: {len(all_params)}")

    # Classify
    classified = classify_params(all_params)

    # Generate per-type files
    for vuln_type, config in PARAM_CLASSES.items():
        params = sorted(set(classified.get(vuln_type, [])))
        icon = config["icon"]
        out_file = FINAL / f"{vuln_type}_params.txt"

        with open(out_file, "w") as f:
            f.write(f"# {vuln_type.upper()} Parameters ({len(params)})\n")
            f.write(f"# Target: {DOMAIN}\n\n")
            for p in params:
                count = all_params.get(p, 0)
                examples = all_urls.get(p, [])[:2]
                f.write(f"{p} (seen {count}x)\n")
                for ex in examples:
                    f.write(f"  → {ex}\n")
                f.write("\n")

        print(f"    {icon} {vuln_type:12s} → {len(params):4d} params")

    # Generate master classification
    master = {}
    for vuln_type, params in classified.items():
        master[vuln_type] = sorted(set(params))

    with open(FINAL / "parameter_intelligence.json", "w") as f:
        json.dump({
            "domain": DOMAIN,
            "total_params": len(all_params),
            "classified": {k: len(v) for k, v in master.items()},
            "params": master,
            "top_params": sorted(all_params.items(), key=lambda x: x[1], reverse=True)[:30],
        }, f, indent=2)

    # Summary
    total_classified = sum(len(v) for v in classified.values())
    print(f"\n    ✅ {total_classified} params classified across {len(classified)} vuln types")
    print(f"    💾 Files → {FINAL}/")


if __name__ == "__main__":
    main()
