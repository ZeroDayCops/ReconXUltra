#!/usr/bin/env python3
"""
ReconX Ultra — Smart Wordlist Orchestration Engine v2.0
========================================================
Deeply integrates ALL custom wordlists into the recon pipeline.
Intelligently selects wordlists based on:
  - Detected technology stacks
  - Response headers / fingerprints
  - CMS detection, WAF behavior
  - URL patterns, parameter names
  - Cloud provider detection

Outputs:
  - wordlist_selections.json (audit trail)
  - Per-category candidate files
  - targeted fuzz results
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: wordlist_engine.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_LIVE = OUTPUT_DIR / "live"
OUT_URLS = OUTPUT_DIR / "urls"
OUT_INTEL = OUTPUT_DIR / "intelligence"
OUT_CONTENT = OUTPUT_DIR / "content"
OUT_JS = OUTPUT_DIR / "js"
WORDLISTS = RECONX_ROOT / "wordlists"
OUT_INTEL.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Complete Wordlist Registry — ALL wordlists with category tags
# ═══════════════════════════════════════════════════════════════════════════

WORDLIST_MAP = {
    # SQLi
    "sql":       {"file": "SQL.txt",       "cats": ["sqli"], "tags": ["injection","database"]},
    "allsqli":   {"file": "allsqli.txt",   "cats": ["sqli"], "tags": ["comprehensive"]},
    "blindsqli": {"file": "blindsqli.txt", "cats": ["sqli"], "tags": ["blind","time-based"]},
    "sqli2":     {"file": "sqli2.txt",     "cats": ["sqli"], "tags": ["extended"]},
    "sqldb":     {"file": "sqldb.txt",     "cats": ["sqli"], "tags": ["database","files"]},
    # XSS
    "xss":       {"file": "xss.txt",       "cats": ["xss"], "tags": ["reflected","stored"]},
    "xsspoly":   {"file": "xsspollygots.txt","cats": ["xss"], "tags": ["polyglot","waf-bypass"]},
    "xsswaf":    {"file": "xsswafbypss.txt","cats": ["xss"], "tags": ["waf-bypass"]},
    # SSRF
    "ssrf":      {"file": "ssrf.txt",      "cats": ["ssrf"], "tags": ["cloud","metadata"]},
    # LFI
    "lfi":       {"file": "lfi.txt",       "cats": ["lfi"], "tags": ["file-inclusion"]},
    "dt_unix":   {"file": "directory_traversal_unix.txt", "cats": ["lfi"], "tags": ["unix","linux"]},
    "dt_win":    {"file": "directory_traversal_win.txt",  "cats": ["lfi"], "tags": ["windows"]},
    # SSTI
    "ssti":      {"file": "ssti.txt",      "cats": ["ssti"], "tags": ["template","rce"]},
    # CRLF
    "crlf":      {"file": "crlf.txt",      "cats": ["crlf"], "tags": ["header-injection"]},
    # 403 Bypass
    "403_headers": {"file": "403_header_payloads.txt", "cats": ["bypass"], "tags": ["403","headers"]},
    "403_urls":    {"file": "403_url_payloads.txt",    "cats": ["bypass"], "tags": ["403","url"]},
    # Sensitive Files
    "juicy":     {"file": "juicy_files.txt",      "cats": ["sensitive"], "tags": ["files","leak"]},
    "juicy_p":   {"file": "juicy-paths.txt",      "cats": ["sensitive"], "tags": ["paths","services"]},
    "leaked":    {"file": "all-files-leaked.txt",  "cats": ["sensitive"], "tags": ["leaked"]},
    "backup":    {"file": "backup_files_only.txt", "cats": ["sensitive"], "tags": ["backup"]},
    "env":       {"file": "env.txt",              "cats": ["sensitive"], "tags": ["env","credentials"]},
    "config":    {"file": "config.txt",           "cats": ["sensitive"], "tags": ["config"]},
    "git":       {"file": "git_config.txt",       "cats": ["sensitive"], "tags": ["git","scm"]},
    "zip":       {"file": "zip.txt",              "cats": ["sensitive"], "tags": ["archive"]},
    "htaccess":  {"file": "htaccess",             "cats": ["sensitive"], "tags": ["apache"]},
    # Admin
    "admin":     {"file": "admin.txt",     "cats": ["admin"], "tags": ["panel","login"]},
    "adminer":   {"file": "adminer.txt",   "cats": ["admin","db"], "tags": ["database"]},
    "phpmyadmin":{"file": "phpmyadmin.txt","cats": ["admin","db"], "tags": ["php","mysql"]},
    # WordPress
    "wp_fuzz":   {"file": "coffin-wp-fuzz.txt",  "cats": ["wordpress"], "tags": ["plugins","themes"]},
    "wp_content":{"file": "wp-content.txt",      "cats": ["wordpress"], "tags": ["content"]},
    "wp_random": {"file": "wordpress-random.txt","cats": ["wordpress"], "tags": ["misc"]},
    # JS Intel
    "vuljs":     {"file": "vulJs.txt",       "cats": ["js_intel"], "tags": ["vulnerable-js"]},
    "jwt":       {"file": "jwt-secrets.txt", "cats": ["js_intel","secrets"], "tags": ["jwt","bruteforce"]},
    # API
    "api":       {"file": "api.txt",                         "cats": ["api"], "tags": ["rest","endpoints"]},
    "api_arch":  {"file": "httparchive_apiroutes_2022_08_28.txt","cats": ["api"], "tags": ["real-world"]},
    # Tech-Specific
    "jsp":       {"file": "jsp.txt",        "cats": ["tech"], "tags": ["java","tomcat"]},
    "jsf":       {"file": "jsf.txt",        "cats": ["tech"], "tags": ["java","faces"]},
    "aspx":      {"file": "aspx.txt",       "cats": ["tech"], "tags": ["dotnet","iis"]},
    "spring":    {"file": "spring-boot.txt","cats": ["tech"], "tags": ["java","actuator"]},
    "kibana":    {"file": "kibana.txt",     "cats": ["tech"], "tags": ["elastic","monitoring"]},
    "aem":       {"file": "aem",            "cats": ["tech"], "tags": ["adobe","cms"]},
    "cgi":       {"file": "cgi-bin.txt",    "cats": ["tech"], "tags": ["cgi","legacy"]},
    "cgi_f":     {"file": "cgi-files.txt",  "cats": ["tech"], "tags": ["cgi","legacy"]},
    "pl":        {"file": "pl.txt",         "cats": ["tech"], "tags": ["perl"]},
    "xml":       {"file": "xml.txt",        "cats": ["tech","xxe"], "tags": ["xml","soap"]},
    # Fuzzing
    "fuzz":      {"file": "fuzz.txt",       "cats": ["fuzz"], "tags": ["general"]},
    "fuzz_php":  {"file": "fuzz-php.php",   "cats": ["fuzz"], "tags": ["php"]},
    "fuzz_php_s":{"file": "fuzz_php_special.txt","cats": ["fuzz"], "tags": ["php","special"]},
    "all_fuzz":  {"file": "all_fuzz.txt",   "cats": ["fuzz"], "tags": ["comprehensive"]},
    "all_atk":   {"file": "all_attacks.txt","cats": ["fuzz"], "tags": ["attacks"]},
    "micro":     {"file": "onelistforallmicro.txt","cats": ["fuzz"], "tags": ["fast"]},
    "short":     {"file": "onelistforallshort.txt","cats": ["fuzz"], "tags": ["balanced"]},
    "everything":{"file": "everything.txt", "cats": ["fuzz"], "tags": ["exhaustive"]},
    # Params
    "param":     {"file": "param.txt",  "cats": ["params"], "tags": ["hidden","discovery"]},
    "params":    {"file": "params.txt", "cats": ["params"], "tags": ["fuzzing"]},
    # Misc
    "vhosts":    {"file": "vhosts.txt",     "cats": ["vhost"], "tags": ["virtual-host"]},
    "ext":       {"file": "extensions.txt", "cats": ["fuzz"], "tags": ["extensions"]},
    "xor":       {"file": "xor.txt",        "cats": ["fuzz"], "tags": ["encoding"]},
    "ghd":       {"file": "github-dork.txt","cats": ["osint"], "tags": ["github"]},
    "robots":    {"file": "robots.txt",     "cats": ["recon"], "tags": ["robots"]},
    "general":   {"file": "1.txt",          "cats": ["fuzz"], "tags": ["general"]},
}

# ═══════════════════════════════════════════════════════════════════════════
# Technology → Wordlist Priority Mapping (EXPANDED)
# ═══════════════════════════════════════════════════════════════════════════

TECH_MAP = {
    # Microsoft
    "iis":       ["aspx","admin","juicy","backup","env","fuzz"],
    "asp.net":   ["aspx","sql","xss","admin","juicy","fuzz"],
    ".net":      ["aspx","sql","xss","fuzz"],
    # Java
    "tomcat":    ["jsp","jsf","spring","ssti","admin","fuzz"],
    "java":      ["jsp","jsf","spring","ssti","fuzz"],
    "jboss":     ["jsp","jsf","ssti","fuzz","juicy"],
    "wildfly":   ["jsp","jsf","ssti","spring"],
    "weblogic":  ["jsp","jsf","ssti","xml"],
    "websphere": ["jsp","jsf","ssti"],
    "spring":    ["spring","jsp","ssti","env","config","fuzz"],
    "struts":    ["jsp","jsf","ssti"],
    # PHP
    "php":       ["fuzz_php","fuzz_php_s","sql","xss","lfi","phpmyadmin","admin","env","config","juicy"],
    "wordpress": ["wp_fuzz","wp_content","wp_random","fuzz_php","sql","xss","admin"],
    "laravel":   ["fuzz_php","ssti","sql","env","config"],
    "drupal":    ["fuzz_php","sql","xss","admin","fuzz"],
    "joomla":    ["fuzz_php","sql","xss","admin"],
    # Enterprise
    "aem":       ["aem","juicy","admin","fuzz"],
    "adobe":     ["aem","juicy","fuzz"],
    "sitecore":  ["aspx","admin","fuzz"],
    # Monitoring
    "kibana":    ["kibana","juicy_p","admin","env"],
    "elastic":   ["kibana","xml","juicy_p","api"],
    "grafana":   ["admin","param","env","fuzz"],
    "prometheus":["admin","juicy_p","env"],
    "jenkins":   ["admin","juicy","env","config"],
    # Legacy
    "cgi":       ["cgi","cgi_f","pl","fuzz"],
    "perl":      ["pl","cgi","cgi_f"],
    # Python
    "python":    ["ssti","param","env","config","fuzz","api"],
    "django":    ["ssti","admin","env","config","fuzz"],
    "flask":     ["ssti","env","config","param","fuzz"],
    # Node
    "node":      ["param","env","config","ssti","api","fuzz"],
    "express":   ["param","env","config","api","fuzz"],
    "next.js":   ["param","api","env","fuzz"],
    # XML/SOAP
    "soap":      ["xml","ssrf","fuzz"],
    "xml":       ["xml","ssrf"],
    # GraphQL
    "graphql":   ["api","param","params"],
    # Cloud
    "aws":       ["ssrf","env","config","api","juicy"],
    "azure":     ["ssrf","env","config","aspx"],
    "gcp":       ["ssrf","env","config","api"],
    # Servers
    "nginx":     ["fuzz","juicy","env","config","htaccess"],
    "apache":    ["fuzz","cgi","htaccess","juicy","env"],
    # CMS
    "magento":   ["fuzz_php","admin","sql","env","config"],
    "shopify":   ["api","param","admin"],
}


def read_lines(filepath):
    try:
        with open(filepath, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        return []


def detect_technologies():
    """Comprehensive technology detection from all available data."""
    print("[*] Fingerprinting target technologies...")
    techs = set()

    # From httpx JSON
    httpx_json = OUT_LIVE / "httpx_full.json"
    if httpx_json.exists():
        for line in read_lines(httpx_json):
            try:
                data = json.loads(line)
                for tech in data.get("tech", []):
                    techs.add(tech.lower())
                server = data.get("webserver", "").lower()
                if server:
                    for key in TECH_MAP:
                        if key in server:
                            techs.add(key)
                title = data.get("title", "").lower()
                for key in ["kibana","grafana","jenkins","elastic","aem","wordpress",
                           "drupal","joomla","magento","spring","django","flask",
                           "next.js","express","graphql","prometheus","gitlab"]:
                    if key in title:
                        techs.add(key)
            except (json.JSONDecodeError, AttributeError):
                pass

    # From technology detection file
    for line in read_lines(OUT_INTEL / "technologies.txt"):
        for key in TECH_MAP:
            if key in line.lower():
                techs.add(key)

    # From URLs — detect technology hints
    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    sample = '\n'.join(all_urls[:5000]).lower()
    url_tech_hints = {
        '.aspx': 'asp.net', '.ashx': 'asp.net', '.asmx': 'asp.net',
        '.jsp': 'java', '.jsf': 'java', '/faces/': 'java',
        '.php': 'php', 'wp-content': 'wordpress', 'wp-includes': 'wordpress',
        '.pl': 'perl', '/cgi-bin/': 'cgi',
        '.xml': 'xml', 'soap': 'soap', 'wsdl': 'soap',
        'graphql': 'graphql', '/api/': 'api',
        'spring': 'spring', 'actuator': 'spring',
        'django': 'django', 'flask': 'flask',
        'next': 'next.js', 'express': 'express',
    }
    for hint, tech in url_tech_hints.items():
        if hint in sample:
            techs.add(tech)

    # From response headers (sample first 20 hosts)
    for host in read_lines(OUT_LIVE / "live_hosts.txt")[:20]:
        try:
            result = subprocess.run(
                ['curl', '-sI', '--max-time', '5', host],
                capture_output=True, text=True, timeout=8
            )
            headers = result.stdout.lower()
            if 'x-powered-by: php' in headers: techs.add("php")
            if 'x-aspnet' in headers or 'asp.net' in headers: techs.add("asp.net")
            if 'server: apache' in headers: techs.add("apache")
            if 'server: nginx' in headers: techs.add("nginx")
            if 'server: iis' in headers or 'microsoft-iis' in headers: techs.add("iis")
            if 'tomcat' in headers: techs.add("tomcat")
            if 'express' in headers: techs.add("express")
            # WAF detection
            if any(w in headers for w in ['cloudflare','akamai','incapsula','sucuri','f5']):
                techs.add("waf_detected")
            # Cloud detection
            if 'amazonaws' in headers or 'aws' in headers: techs.add("aws")
            if 'azure' in headers: techs.add("azure")
            if 'gcp' in headers or 'google' in headers: techs.add("gcp")
        except Exception:
            pass

    return techs


def select_wordlists(techs):
    """Select optimal wordlists based on detected technologies."""
    print("[*] Selecting optimal wordlists...")
    selected = set()
    reasons = defaultdict(list)

    for tech in techs:
        for wl_key in TECH_MAP.get(tech, []):
            if wl_key in WORDLIST_MAP:
                wl_file = WORDLISTS / WORDLIST_MAP[wl_key]["file"]
                if wl_file.exists():
                    selected.add(wl_key)
                    reasons[wl_key].append(tech)

    # Always include baseline wordlists
    for baseline in ["param","fuzz","juicy","env","git","admin","backup","leaked"]:
        if baseline in WORDLIST_MAP:
            wl_file = WORDLISTS / WORDLIST_MAP[baseline]["file"]
            if wl_file.exists():
                selected.add(baseline)
                reasons[baseline].append("baseline")

    # WAF detected? Add bypass wordlists
    if "waf_detected" in techs:
        for wl in ["xsswaf","xsspoly","403_headers","403_urls"]:
            if wl in WORDLIST_MAP:
                selected.add(wl)
                reasons[wl].append("waf_bypass")

    return selected, dict(reasons)


def run_targeted_fuzz(selected_wordlists, live_hosts):
    """Run targeted content discovery with selected wordlists."""
    print("[*] Running targeted fuzzing with selected wordlists...")
    results = defaultdict(list)
    fuzz_hosts = live_hosts[:30]

    for wl_key in selected_wordlists:
        wl_info = WORDLIST_MAP.get(wl_key)
        if not wl_info:
            continue
        wl_path = WORDLISTS / wl_info["file"]
        if not wl_path.exists():
            continue

        wl_lines = read_lines(wl_path)
        if not wl_lines:
            continue

        # Limit wordlist size for speed
        paths_to_check = wl_lines[:200]
        category = wl_key.upper()
        found_count = 0

        for host in fuzz_hosts[:10]:
            host = host.rstrip('/')
            for path in paths_to_check:
                path = path.lstrip('/')
                url = f"{host}/{path}"
                try:
                    result = subprocess.run(
                        ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}|%{size_download}',
                         '--max-time', '5', url],
                        capture_output=True, text=True, timeout=8
                    )
                    parts = result.stdout.strip().split('|')
                    if len(parts) == 2:
                        status, size = parts[0], parts[1]
                        if status in ('200','301','302','401','403') and int(size) > 0:
                            results[category].append({
                                "url": url, "status": int(status), "size": int(size)
                            })
                            found_count += 1
                except Exception:
                    pass

        if found_count > 0:
            print(f"    [{wl_key}] {found_count} endpoints found")

    return dict(results)


def generate_candidate_files(fuzz_results, techs):
    """Generate categorized candidate files from fuzz results."""
    print("[*] Generating vulnerability candidate files...")
    total = 0

    # Map categories to output files
    category_files = {
        "sensitive": ("sensitive_file_hits.txt", ["JUICY","JUICY_P","LEAKED","BACKUP","ENV","CONFIG","GIT","ZIP","HTACCESS"]),
        "admin": ("admin_panel_hits.txt", ["ADMIN","ADMINER","PHPMYADMIN"]),
        "tech": ("tech_specific_hits.txt", ["JSP","JSF","ASPX","SPRING","KIBANA","AEM","CGI","CGI_F","PL","XML"]),
        "fuzz": ("fuzz_targets.txt", ["FUZZ","FUZZ_PHP","FUZZ_PHP_S","ALL_FUZZ","MICRO","SHORT","GENERAL"]),
        "api": ("api_fuzz_hits.txt", ["API","API_ARCH"]),
        "wordpress": ("wordpress_hits.txt", ["WP_FUZZ","WP_CONTENT","WP_RANDOM"]),
    }

    for out_name, (filename, keys) in category_files.items():
        items = []
        for key in keys:
            items.extend(fuzz_results.get(key, []))
        if items:
            with open(OUT_INTEL / filename, 'w') as f:
                for item in items:
                    f.write(f"[{item['status']}] {item['url']} ({item['size']}b)\n")
            print(f"    [+] {filename}: {len(items)} hits")
            total += len(items)

    # SSTI candidates
    all_urls = read_lines(OUT_URLS / "all_urls.txt")
    ssti_urls = [u for u in all_urls if re.search(
        r'template|render|preview|email|pdf|export|markdown|report|format|view|display|page',
        u, re.IGNORECASE
    )]
    ssti_items = fuzz_results.get("SSTI", [])
    with open(OUT_INTEL / "ssti_candidates.txt", 'w') as f:
        for item in ssti_items:
            f.write(f"[FUZZ] [{item['status']}] {item['url']}\n")
        for url in sorted(set(ssti_urls))[:500]:
            f.write(f"[URL] {url}\n")

    # Hidden params
    param_items = fuzz_results.get("PARAM", []) + fuzz_results.get("PARAMS", [])
    if param_items:
        with open(OUT_INTEL / "hidden_params.txt", 'w') as f:
            for item in param_items:
                f.write(f"[{item['status']}] {item['url']} ({item['size']}b)\n")
        print(f"    [+] hidden_params.txt: {len(param_items)} found")

    return total


def main():
    print(f"\n{'='*60}")
    print(f"  Smart Wordlist Orchestration v2.0 — {DOMAIN}")
    print(f"{'='*60}\n")

    techs = detect_technologies()
    print(f"    Technologies: {', '.join(sorted(techs)) if techs else 'none (defaults)'}")

    selected, reasons = select_wordlists(techs)
    print(f"    Wordlists selected: {len(selected)}")
    for wl_key in sorted(selected):
        wl_path = WORDLISTS / WORDLIST_MAP[wl_key]["file"]
        size = len(read_lines(wl_path)) if wl_path.exists() else 0
        reason_str = ", ".join(reasons.get(wl_key, ["auto"]))
        print(f"        → {WORDLIST_MAP[wl_key]['file']} ({size} entries) [reason: {reason_str}]")

    # Save audit
    audit = {
        "domain": DOMAIN,
        "technologies_detected": sorted(techs),
        "wordlists_selected": {k: {"file": WORDLIST_MAP[k]["file"], "reasons": reasons.get(k,[])} for k in sorted(selected)},
        "total_wordlists": len(selected),
    }
    with open(OUT_INTEL / "wordlist_selections.json", 'w') as f:
        json.dump(audit, f, indent=2)

    # Run targeted fuzzing
    live_hosts = read_lines(OUT_LIVE / "live_hosts.txt")
    if live_hosts:
        fuzz_results = run_targeted_fuzz(selected, live_hosts)
        total = generate_candidate_files(fuzz_results, techs)
        print(f"\n{'─'*60}")
        print(f"  Wordlist Engine Summary:")
        print(f"    Technologies:    {len(techs)}")
        print(f"    Wordlists used:  {len(selected)}")
        print(f"    Hosts fuzzed:    {min(len(live_hosts), 10)}")
        print(f"    Total findings:  {total}")
        print(f"{'─'*60}\n")
    else:
        print("    [!] No live hosts — skipping fuzzing")


if __name__ == "__main__":
    main()
