#!/usr/bin/env python3
"""
ReconX Ultra X — Smart GF Engine
==================================
Advanced GF pattern matching with context-aware scoring,
parameter entropy analysis, and deduplication intelligence.
Replaces basic gf usage with smart, weighted pattern matching.
"""
import json, os, re, sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: smart_gf.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
INTEL = OUT / "intelligence"
INTEL.mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# Smart Pattern Database — weighted, context-aware
# ═══════════════════════════════════════════════════════════════════════════
SMART_PATTERNS = {
    "xss": {
        "param_patterns": [
            (r"\b(q|query|search|keyword|term|s|text|input|content|value|data|body|message|comment|name|title|description|preview|callback|return|redirect|url|ref|src|href|img|onerror)\b", 30),
            (r"\b(template|render|display|echo|print|output|html|raw)\b", 25),
        ],
        "endpoint_patterns": [
            (r"(search|find|lookup|query|preview|render|display|echo|comment)", 20),
            (r"(feedback|review|contact|support|report|share)", 15),
        ],
        "response_hints": ["text/html", "reflection"],
        "severity": "HIGH",
    },
    "sqli": {
        "param_patterns": [
            (r"\b(id|uid|user_id|pid|cid|cat|category|page|item|order|sort|filter|where|column|table|field|select|from|group|limit|offset)\b", 35),
            (r"\b(report|export|action|view|show|list|detail|search|lookup)\b", 20),
        ],
        "endpoint_patterns": [
            (r"(\.php\?|\.asp\?|cgi-bin|servlet)", 25),
            (r"(report|export|download|print|invoice|stats|analytics|dashboard)", 20),
        ],
        "response_hints": ["application/json", "text/html"],
        "severity": "CRITICAL",
    },
    "ssrf": {
        "param_patterns": [
            (r"\b(url|uri|endpoint|dest|destination|redirect|proxy|fetch|request|load|feed|source|target|link|site|domain|host|addr|server|webhook|callback|api_url|image_url|avatar_url|pdf_url)\b", 40),
            (r"\b(import|export|preview|screenshot|render|pdf|generate|convert)\b", 25),
        ],
        "endpoint_patterns": [
            (r"(proxy|fetch|curl|wget|request|screenshot|pdf|export|import|webhook)", 30),
            (r"(image|avatar|media|thumbnail|preview|share|embed)", 20),
        ],
        "severity": "CRITICAL",
    },
    "idor": {
        "param_patterns": [
            (r"\b(id|uid|user_id|account_id|profile_id|order_id|invoice_id|doc_id|file_id|msg_id|chat_id|group_id|org_id|team_id|project_id|item_id|record_id|ticket_id)\b", 40),
            (r"\b(uuid|guid|ref|reference|num|number|code|key|token|hash)\b", 20),
        ],
        "endpoint_patterns": [
            (r"/api/(v[0-9]+/)?(user|account|profile|order|invoice|document|message|file|report)", 35),
            (r"/(me|self|current|mine)/?", 15),
        ],
        "severity": "HIGH",
    },
    "lfi": {
        "param_patterns": [
            (r"\b(file|path|filepath|filename|include|require|template|page|doc|document|dir|directory|folder|root|load|read|view|download|attachment|lang|locale|theme|skin|style|layout|config)\b", 35),
        ],
        "endpoint_patterns": [
            (r"(download|view|read|load|open|include|require|import|file|template|attachment|doc)", 25),
        ],
        "severity": "HIGH",
    },
    "ssti": {
        "param_patterns": [
            (r"\b(template|content|text|body|message|subject|name|title|description|preview|render|format|layout|email|sms|notification|greeting|bio|about|signature)\b", 30),
        ],
        "endpoint_patterns": [
            (r"(template|render|preview|email|invoice|report|generate|pdf|export|format)", 30),
        ],
        "severity": "CRITICAL",
    },
    "redirect": {
        "param_patterns": [
            (r"\b(redirect|redirect_uri|redirect_url|return|returnTo|return_url|next|goto|dest|destination|rurl|redir|forward|continue|url|to|target|link|callback|out|jump|follow)\b", 40),
        ],
        "endpoint_patterns": [
            (r"(login|logout|signin|signout|oauth|authorize|callback|return|redirect|sso|jump|link|out|go)", 25),
        ],
        "severity": "MEDIUM",
    },
    "crlf": {
        "param_patterns": [
            (r"\b(url|redirect|dest|location|header|host|referer|origin|path|return)\b", 25),
        ],
        "endpoint_patterns": [
            (r"(redirect|set-cookie|header|response|log)", 20),
        ],
        "severity": "MEDIUM",
    },
}


def calculate_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not value: return 0
    from math import log2
    freq = defaultdict(int)
    for c in value: freq[c] += 1
    length = len(value)
    return -sum((count/length) * log2(count/length) for count in freq.values())


def smart_classify(url: str) -> list:
    """Classify URL with smart scoring."""
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    path = parsed.path.lower()
    
    for vuln_type, config in SMART_PATTERNS.items():
        total_score = 0
        matched_params = []
        reasons = []
        
        # Check parameter names
        for param_name in params:
            for pattern, weight in config["param_patterns"]:
                if re.search(pattern, param_name, re.IGNORECASE):
                    total_score += weight
                    matched_params.append(param_name)
                    reasons.append(f"param:{param_name}")
                    break
        
        # Check endpoint path
        for pattern, weight in config["endpoint_patterns"]:
            if re.search(pattern, path, re.IGNORECASE):
                total_score += weight
                reasons.append(f"path:{pattern[:20]}")
                break

        # Bonus: multiple injectable params
        if len(matched_params) > 1:
            total_score += 10

        # Bonus: parameterized URL with high entropy values (real app data)
        for pv in params.values():
            if pv and calculate_entropy(str(pv[0])) > 3.5:
                total_score += 5
                break

        if total_score >= 20:
            results.append({
                "url": url,
                "vuln_type": vuln_type,
                "score": min(total_score, 100),
                "severity": config["severity"],
                "params": matched_params[:5],
                "reasons": reasons[:5],
            })

    return results


def main():
    print(f"\n  🧠 Smart GF Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    urls_file = OUT / "urls" / "all_urls.txt"
    if not urls_file.exists():
        print("  ⚪ No URLs found")
        return

    urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip() and "?" in l]
    print(f"  📋 Analyzing {len(urls)} parameterized URLs...")

    # Classify all URLs
    all_results = []
    vuln_buckets = defaultdict(list)
    
    for url in urls:
        classifications = smart_classify(url)
        for cls in classifications:
            all_results.append(cls)
            vuln_buckets[cls["vuln_type"]].append(cls)

    # Deduplicate by URL+param (keep highest score)
    for vtype in vuln_buckets:
        seen = {}
        for r in vuln_buckets[vtype]:
            key = f"{r['url']}|{'|'.join(r['params'])}"
            if key not in seen or r["score"] > seen[key]["score"]:
                seen[key] = r
        vuln_buckets[vtype] = sorted(seen.values(), key=lambda x: x["score"], reverse=True)

    # Write per-type candidate files
    for vtype, results in vuln_buckets.items():
        outfile = INTEL / f"{vtype}_candidates.txt"
        urls_out = [r["url"] for r in results]
        outfile.write_text("\n".join(urls_out))

    # Write full scored results
    (INTEL / "smart_gf_results.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_urls_analyzed": len(urls),
        "total_candidates": len(all_results),
        "by_type": {vt: {
            "count": len(rs),
            "top_score": rs[0]["score"] if rs else 0,
            "severity": SMART_PATTERNS[vt]["severity"],
            "top_urls": [r["url"] for r in rs[:5]],
        } for vt, rs in vuln_buckets.items()},
    }, indent=2))

    # Print summary
    print(f"\n  🔥 Results:")
    for vtype in sorted(vuln_buckets, key=lambda x: len(vuln_buckets[x]), reverse=True):
        rs = vuln_buckets[vtype]
        sev = SMART_PATTERNS[vtype]["severity"]
        icon = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
        print(f"    {icon} {vtype:12s} {len(rs):5d} candidates "
              f"(top score: {rs[0]['score'] if rs else 0})")

    print(f"\n  📊 Total: {len(all_results)} candidates from {len(urls)} URLs")
    print(f"  💾 Results → {INTEL}/")


if __name__ == "__main__":
    main()
