#!/usr/bin/env python3
"""
ReconX Ultra — Intelligent Wordlist Classification Engine
==========================================================
Automatically classifies ALL custom wordlists into vulnerability categories,
tracks metadata, and provides the foundation for smart wordlist selection.

Outputs:
  - intelligence/wordlist_catalog.json — Full catalog with metadata
  - intelligence/wordlist_categories.json — Category-to-wordlist mapping
"""

import json
import os
import sys
from pathlib import Path

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else None
if not DOMAIN:
    print("Usage: wordlist_classifier.py <domain>", file=sys.stderr)
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN
OUT_INTEL = OUTPUT_DIR / "intelligence"
WORDLISTS_DIR = RECONX_ROOT / "wordlists"

OUT_INTEL.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════
# Complete Wordlist Classification Map
# ═══════════════════════════════════════════════════════════════════════════

# Every wordlist → its categories, use-cases, and priority
WORDLIST_CLASSIFICATION = {
    # ── SQL Injection ────────────────────────────────────────────────────
    "SQL.txt": {
        "categories": ["sqli", "injection"],
        "use_cases": ["parameter_fuzzing", "error_based_sqli", "union_sqli"],
        "priority": "high",
        "description": "Core SQL injection payloads",
        "tech_triggers": ["php", "asp.net", "java", "mysql", "mssql", "oracle", "postgresql"],
    },
    "allsqli.txt": {
        "categories": ["sqli", "injection"],
        "use_cases": ["comprehensive_sqli", "waf_bypass_sqli"],
        "priority": "high",
        "description": "Comprehensive SQLi payload collection",
        "tech_triggers": ["php", "asp.net", "java", "mysql", "mssql", "oracle"],
    },
    "blindsqli.txt": {
        "categories": ["sqli", "blind_sqli", "injection"],
        "use_cases": ["blind_sqli", "time_based_sqli", "boolean_sqli"],
        "priority": "high",
        "description": "Blind SQL injection payloads (time/boolean-based)",
        "tech_triggers": ["php", "asp.net", "java", "mysql", "postgresql"],
    },
    "sqli2.txt": {
        "categories": ["sqli", "injection"],
        "use_cases": ["extended_sqli", "alternative_payloads"],
        "priority": "medium",
        "description": "Extended SQL injection payloads",
        "tech_triggers": ["php", "asp.net", "java"],
    },
    "sqldb.txt": {
        "categories": ["sqli", "database"],
        "use_cases": ["database_discovery", "table_enumeration"],
        "priority": "medium",
        "description": "SQL database path/file discovery",
        "tech_triggers": ["php", "asp.net", "java", "mysql"],
    },

    # ── XSS ──────────────────────────────────────────────────────────────
    "xss.txt": {
        "categories": ["xss", "injection"],
        "use_cases": ["reflected_xss", "stored_xss", "dom_xss"],
        "priority": "high",
        "description": "Core XSS payload collection",
        "tech_triggers": ["*"],  # XSS applies everywhere
    },
    "xsspollygots.txt": {
        "categories": ["xss", "polyglot"],
        "use_cases": ["waf_bypass_xss", "polyglot_xss", "filter_evasion"],
        "priority": "high",
        "description": "XSS polyglot payloads for WAF bypass",
        "tech_triggers": ["*"],
    },
    "xsswafbypss.txt": {
        "categories": ["xss", "waf_bypass"],
        "use_cases": ["waf_bypass_xss", "advanced_xss"],
        "priority": "high",
        "description": "XSS WAF bypass techniques",
        "tech_triggers": ["*"],
    },

    # ── SSRF ─────────────────────────────────────────────────────────────
    "ssrf.txt": {
        "categories": ["ssrf"],
        "use_cases": ["ssrf_detection", "cloud_metadata", "internal_access"],
        "priority": "high",
        "description": "SSRF payloads including cloud metadata",
        "tech_triggers": ["*"],
    },

    # ── LFI / Directory Traversal ────────────────────────────────────────
    "lfi.txt": {
        "categories": ["lfi", "path_traversal", "file_inclusion"],
        "use_cases": ["local_file_inclusion", "path_traversal"],
        "priority": "high",
        "description": "LFI payloads — comprehensive file inclusion",
        "tech_triggers": ["php", "java", "python", "node"],
    },
    "directory_traversal_unix.txt": {
        "categories": ["lfi", "path_traversal"],
        "use_cases": ["unix_lfi", "linux_file_read"],
        "priority": "high",
        "description": "Unix/Linux directory traversal payloads",
        "tech_triggers": ["linux", "unix", "apache", "nginx", "php"],
    },
    "directory_traversal_win.txt": {
        "categories": ["lfi", "path_traversal"],
        "use_cases": ["windows_lfi", "windows_file_read"],
        "priority": "medium",
        "description": "Windows directory traversal payloads",
        "tech_triggers": ["iis", "asp.net", "windows"],
    },

    # ── SSTI ─────────────────────────────────────────────────────────────
    "ssti.txt": {
        "categories": ["ssti", "template_injection"],
        "use_cases": ["template_injection", "rce_via_template"],
        "priority": "high",
        "description": "Server-Side Template Injection payloads",
        "tech_triggers": ["python", "flask", "django", "jinja2", "java", "twig", "smarty", "freemarker", "velocity"],
    },

    # ── CRLF ─────────────────────────────────────────────────────────────
    "crlf.txt": {
        "categories": ["crlf", "header_injection"],
        "use_cases": ["crlf_injection", "header_injection", "http_splitting"],
        "priority": "medium",
        "description": "CRLF injection payloads",
        "tech_triggers": ["*"],
    },

    # ── 403 Bypass ───────────────────────────────────────────────────────
    "403_header_payloads.txt": {
        "categories": ["bypass_403", "access_control"],
        "use_cases": ["403_bypass_headers", "access_control_bypass"],
        "priority": "high",
        "description": "HTTP header payloads for 403 bypass",
        "tech_triggers": ["*"],
    },
    "403_url_payloads.txt": {
        "categories": ["bypass_403", "access_control"],
        "use_cases": ["403_bypass_url", "path_normalization_bypass"],
        "priority": "high",
        "description": "URL-based 403 bypass techniques",
        "tech_triggers": ["*"],
    },

    # ── Sensitive Files & Configs ────────────────────────────────────────
    "juicy_files.txt": {
        "categories": ["sensitive_files", "content_discovery"],
        "use_cases": ["sensitive_file_discovery", "info_disclosure"],
        "priority": "high",
        "description": "High-value sensitive file paths",
        "tech_triggers": ["*"],
    },
    "juicy-paths.txt": {
        "categories": ["sensitive_files", "content_discovery"],
        "use_cases": ["sensitive_path_discovery", "service_exposure"],
        "priority": "high",
        "description": "High-value sensitive URL paths",
        "tech_triggers": ["*"],
    },
    "all-files-leaked.txt": {
        "categories": ["sensitive_files", "data_leak"],
        "use_cases": ["leaked_file_discovery", "backup_detection"],
        "priority": "high",
        "description": "Known leaked/exposed file patterns",
        "tech_triggers": ["*"],
    },
    "backup_files_only.txt": {
        "categories": ["sensitive_files", "backup"],
        "use_cases": ["backup_file_discovery", "source_code_leak"],
        "priority": "high",
        "description": "Backup file patterns (.bak, .old, .swp, etc.)",
        "tech_triggers": ["*"],
    },
    "env.txt": {
        "categories": ["sensitive_files", "config_leak"],
        "use_cases": ["env_file_discovery", "credential_exposure"],
        "priority": "critical",
        "description": "Environment file discovery patterns",
        "tech_triggers": ["*"],
    },
    "config.txt": {
        "categories": ["sensitive_files", "config_leak"],
        "use_cases": ["config_file_discovery"],
        "priority": "high",
        "description": "Configuration file patterns",
        "tech_triggers": ["*"],
    },
    "git_config.txt": {
        "categories": ["sensitive_files", "scm_leak"],
        "use_cases": ["git_exposure", "source_code_leak"],
        "priority": "critical",
        "description": "Git repository exposure detection",
        "tech_triggers": ["*"],
    },
    "zip.txt": {
        "categories": ["sensitive_files", "archive"],
        "use_cases": ["archive_discovery", "backup_detection"],
        "priority": "medium",
        "description": "Archive/zip file discovery patterns",
        "tech_triggers": ["*"],
    },
    "robots.txt": {
        "categories": ["reconnaissance", "content_discovery"],
        "use_cases": ["hidden_path_discovery"],
        "priority": "low",
        "description": "robots.txt analysis patterns",
        "tech_triggers": ["*"],
    },
    "htaccess": {
        "categories": ["sensitive_files", "config_leak"],
        "use_cases": ["htaccess_discovery", "apache_config"],
        "priority": "medium",
        "description": "Apache .htaccess patterns",
        "tech_triggers": ["apache"],
    },

    # ── Admin Panels ─────────────────────────────────────────────────────
    "admin.txt": {
        "categories": ["admin_panel", "content_discovery"],
        "use_cases": ["admin_panel_discovery", "login_page_discovery"],
        "priority": "high",
        "description": "Admin panel and login path discovery",
        "tech_triggers": ["*"],
    },
    "adminer.txt": {
        "categories": ["admin_panel", "database_admin"],
        "use_cases": ["database_admin_discovery", "adminer_detection"],
        "priority": "critical",
        "description": "Adminer database management discovery",
        "tech_triggers": ["php", "mysql", "postgresql"],
    },
    "phpmyadmin.txt": {
        "categories": ["admin_panel", "database_admin"],
        "use_cases": ["phpmyadmin_discovery"],
        "priority": "critical",
        "description": "phpMyAdmin path discovery",
        "tech_triggers": ["php", "mysql"],
    },

    # ── WordPress ────────────────────────────────────────────────────────
    "coffin-wp-fuzz.txt": {
        "categories": ["wordpress", "cms"],
        "use_cases": ["wordpress_enum", "wp_plugin_discovery"],
        "priority": "high",
        "description": "WordPress fuzzing — plugins, themes, endpoints",
        "tech_triggers": ["wordpress"],
    },
    "wp-content.txt": {
        "categories": ["wordpress", "cms"],
        "use_cases": ["wp_content_discovery", "wp_upload_enum"],
        "priority": "high",
        "description": "WordPress wp-content path enumeration",
        "tech_triggers": ["wordpress"],
    },
    "wordpress-random.txt": {
        "categories": ["wordpress", "cms"],
        "use_cases": ["wp_random_discovery", "wp_hidden_paths"],
        "priority": "medium",
        "description": "WordPress random/misc path discovery",
        "tech_triggers": ["wordpress"],
    },

    # ── JS Intelligence ──────────────────────────────────────────────────
    "vulJs.txt": {
        "categories": ["js_intelligence", "vulnerability"],
        "use_cases": ["vulnerable_js_detection", "outdated_library_check"],
        "priority": "high",
        "description": "Known vulnerable JavaScript library paths",
        "tech_triggers": ["*"],
    },
    "jwt-secrets.txt": {
        "categories": ["js_intelligence", "secrets", "jwt"],
        "use_cases": ["jwt_secret_bruteforce", "jwt_weakness_detection"],
        "priority": "critical",
        "description": "JWT secret key bruteforce dictionary",
        "tech_triggers": ["*"],
    },

    # ── API Discovery ────────────────────────────────────────────────────
    "api.txt": {
        "categories": ["api_discovery", "content_discovery"],
        "use_cases": ["api_endpoint_discovery", "rest_api_fuzzing"],
        "priority": "high",
        "description": "API endpoint path discovery (8.6M+ entries)",
        "tech_triggers": ["*"],
    },
    "httparchive_apiroutes_2022_08_28.txt": {
        "categories": ["api_discovery"],
        "use_cases": ["real_world_api_routes", "api_fuzzing"],
        "priority": "high",
        "description": "Real-world API routes from HTTP Archive (7.4M entries)",
        "tech_triggers": ["*"],
    },

    # ── Technology-Specific ──────────────────────────────────────────────
    "jsp.txt": {
        "categories": ["tech_specific", "java"],
        "use_cases": ["java_jsp_discovery", "tomcat_enum"],
        "priority": "high",
        "description": "JSP/Java servlet path discovery",
        "tech_triggers": ["java", "tomcat", "jboss", "wildfly", "weblogic", "websphere"],
    },
    "jsf.txt": {
        "categories": ["tech_specific", "java"],
        "use_cases": ["java_jsf_discovery", "faces_enum"],
        "priority": "medium",
        "description": "JSF (JavaServer Faces) path discovery",
        "tech_triggers": ["java", "jsf", "primefaces"],
    },
    "aspx.txt": {
        "categories": ["tech_specific", "dotnet"],
        "use_cases": ["aspx_discovery", "dotnet_enum"],
        "priority": "high",
        "description": "ASP.NET/ASPX path discovery",
        "tech_triggers": ["asp.net", "iis", ".net"],
    },
    "spring-boot.txt": {
        "categories": ["tech_specific", "java"],
        "use_cases": ["spring_boot_actuator", "spring_endpoint_discovery"],
        "priority": "critical",
        "description": "Spring Boot actuator and endpoint discovery",
        "tech_triggers": ["java", "spring", "spring-boot"],
    },
    "kibana.txt": {
        "categories": ["tech_specific", "monitoring"],
        "use_cases": ["kibana_discovery", "elastic_stack_enum"],
        "priority": "high",
        "description": "Kibana/Elasticsearch endpoint discovery",
        "tech_triggers": ["kibana", "elasticsearch", "elastic"],
    },
    "aem": {
        "categories": ["tech_specific", "cms"],
        "use_cases": ["aem_discovery", "adobe_experience_manager"],
        "priority": "high",
        "description": "Adobe Experience Manager path discovery",
        "tech_triggers": ["aem", "adobe"],
    },
    "cgi-bin.txt": {
        "categories": ["tech_specific", "legacy"],
        "use_cases": ["cgi_bin_discovery", "shellshock_check"],
        "priority": "medium",
        "description": "CGI-BIN path discovery",
        "tech_triggers": ["apache", "cgi"],
    },
    "cgi-files.txt": {
        "categories": ["tech_specific", "legacy"],
        "use_cases": ["cgi_file_discovery", "legacy_script_enum"],
        "priority": "medium",
        "description": "CGI file pattern discovery",
        "tech_triggers": ["apache", "cgi", "perl"],
    },
    "pl.txt": {
        "categories": ["tech_specific", "legacy"],
        "use_cases": ["perl_script_discovery"],
        "priority": "low",
        "description": "Perl script path discovery",
        "tech_triggers": ["perl", "cgi", "apache"],
    },

    # ── Fuzzing / General Discovery ──────────────────────────────────────
    "fuzz.txt": {
        "categories": ["fuzzing", "content_discovery"],
        "use_cases": ["general_fuzzing", "path_discovery"],
        "priority": "medium",
        "description": "General fuzzing wordlist",
        "tech_triggers": ["*"],
    },
    "fuzz-php.php": {
        "categories": ["fuzzing", "php"],
        "use_cases": ["php_specific_fuzzing"],
        "priority": "medium",
        "description": "PHP-specific fuzzing paths",
        "tech_triggers": ["php"],
    },
    "fuzz_php_special.txt": {
        "categories": ["fuzzing", "php"],
        "use_cases": ["php_special_fuzzing", "php_backdoor_detection"],
        "priority": "high",
        "description": "PHP special/sensitive path fuzzing (3.2M entries)",
        "tech_triggers": ["php"],
    },
    "all_fuzz.txt": {
        "categories": ["fuzzing", "content_discovery"],
        "use_cases": ["comprehensive_fuzzing"],
        "priority": "medium",
        "description": "Comprehensive fuzzing wordlist (10.9M entries)",
        "tech_triggers": ["*"],
    },
    "all_attacks.txt": {
        "categories": ["fuzzing", "attack_payloads"],
        "use_cases": ["all_attack_vectors", "payload_testing"],
        "priority": "medium",
        "description": "Combined attack payload collection",
        "tech_triggers": ["*"],
    },
    "everything.txt": {
        "categories": ["fuzzing", "content_discovery"],
        "use_cases": ["exhaustive_discovery"],
        "priority": "low",
        "description": "Exhaustive discovery wordlist (16.6M entries)",
        "tech_triggers": ["*"],
    },
    "onelistforallmicro.txt": {
        "categories": ["fuzzing", "content_discovery"],
        "use_cases": ["quick_fuzzing", "fast_discovery"],
        "priority": "medium",
        "description": "OneListForAll micro — fast comprehensive list",
        "tech_triggers": ["*"],
    },
    "onelistforallshort.txt": {
        "categories": ["fuzzing", "content_discovery"],
        "use_cases": ["medium_fuzzing", "balanced_discovery"],
        "priority": "medium",
        "description": "OneListForAll short — balanced comprehensive list (12M entries)",
        "tech_triggers": ["*"],
    },

    # ── Parameter Discovery ──────────────────────────────────────────────
    "param.txt": {
        "categories": ["parameter_discovery"],
        "use_cases": ["hidden_param_detection", "param_bruteforce"],
        "priority": "high",
        "description": "Hidden parameter name discovery",
        "tech_triggers": ["*"],
    },
    "params.txt": {
        "categories": ["parameter_discovery"],
        "use_cases": ["parameter_fuzzing", "param_pollution"],
        "priority": "high",
        "description": "Parameter name bruteforce list",
        "tech_triggers": ["*"],
    },

    # ── Miscellaneous ────────────────────────────────────────────────────
    "extensions.txt": {
        "categories": ["content_discovery"],
        "use_cases": ["file_extension_bruteforce"],
        "priority": "medium",
        "description": "File extension patterns",
        "tech_triggers": ["*"],
    },
    "xml.txt": {
        "categories": ["tech_specific", "xxe"],
        "use_cases": ["xml_endpoint_discovery", "xxe_detection"],
        "priority": "high",
        "description": "XML/SOAP/XXE endpoint discovery",
        "tech_triggers": ["xml", "soap", "java"],
    },
    "xor.txt": {
        "categories": ["fuzzing", "encoding"],
        "use_cases": ["xor_encoding_bypass"],
        "priority": "low",
        "description": "XOR-encoded payloads",
        "tech_triggers": ["*"],
    },
    "vhosts.txt": {
        "categories": ["reconnaissance", "vhost_discovery"],
        "use_cases": ["virtual_host_fuzzing"],
        "priority": "medium",
        "description": "Virtual host discovery patterns",
        "tech_triggers": ["*"],
    },
    "resolvers.txt": {
        "categories": ["dns", "reconnaissance"],
        "use_cases": ["dns_resolution"],
        "priority": "low",
        "description": "DNS resolvers list",
        "tech_triggers": ["*"],
    },
    "github-dork.txt": {
        "categories": ["osint", "reconnaissance"],
        "use_cases": ["github_dorking", "source_code_search"],
        "priority": "medium",
        "description": "GitHub dork patterns for secret discovery",
        "tech_triggers": ["*"],
    },
    "bambda.txt": {
        "categories": ["fuzzing", "tool_specific"],
        "use_cases": ["burp_bambda_patterns"],
        "priority": "low",
        "description": "Burp Suite Bambda filter patterns",
        "tech_triggers": ["*"],
    },
    "android_all_permissions.txt": {
        "categories": ["mobile", "android"],
        "use_cases": ["android_permission_analysis"],
        "priority": "low",
        "description": "Android permission enumeration list",
        "tech_triggers": ["android"],
    },
    "apac.txt": {
        "categories": ["regional", "content_discovery"],
        "use_cases": ["apac_path_discovery"],
        "priority": "low",
        "description": "APAC region-specific paths",
        "tech_triggers": ["*"],
    },
    "1.txt": {
        "categories": ["content_discovery", "fuzzing"],
        "use_cases": ["general_discovery"],
        "priority": "low",
        "description": "General path discovery list",
        "tech_triggers": ["*"],
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# Category Aggregation
# ═══════════════════════════════════════════════════════════════════════════

CATEGORY_DESCRIPTIONS = {
    "sqli": "SQL Injection payloads and detection",
    "xss": "Cross-Site Scripting payloads",
    "ssrf": "Server-Side Request Forgery payloads",
    "lfi": "Local File Inclusion / Path Traversal",
    "ssti": "Server-Side Template Injection",
    "crlf": "CRLF Injection / HTTP Splitting",
    "bypass_403": "403 Forbidden bypass techniques",
    "sensitive_files": "Sensitive file and config exposure",
    "admin_panel": "Admin panel and login discovery",
    "wordpress": "WordPress CMS-specific paths",
    "js_intelligence": "JavaScript vulnerability intelligence",
    "api_discovery": "API endpoint discovery",
    "tech_specific": "Technology-specific paths",
    "fuzzing": "General fuzzing and discovery",
    "parameter_discovery": "Hidden parameter detection",
    "content_discovery": "Content and directory discovery",
    "injection": "General injection payloads",
    "database_admin": "Database admin panel discovery",
    "secrets": "Secret and credential detection",
    "reconnaissance": "Passive/active reconnaissance",
}


def build_catalog():
    """Build a full catalog with metadata for each wordlist."""
    catalog = {}
    for wl_name, wl_info in WORDLIST_CLASSIFICATION.items():
        wl_path = WORDLISTS_DIR / wl_name
        line_count = 0
        size_bytes = 0

        if wl_path.exists():
            size_bytes = wl_path.stat().st_size
            try:
                with open(wl_path, 'r', errors='ignore') as f:
                    line_count = sum(1 for _ in f)
            except Exception:
                pass

        catalog[wl_name] = {
            **wl_info,
            "path": str(wl_path),
            "exists": wl_path.exists(),
            "line_count": line_count,
            "size_bytes": size_bytes,
            "size_human": f"{size_bytes / 1024:.1f}KB" if size_bytes < 1048576 else f"{size_bytes / 1048576:.1f}MB",
        }

    return catalog


def build_category_map(catalog):
    """Build category → wordlist mapping."""
    categories = defaultdict(list)
    for wl_name, wl_info in catalog.items():
        if not wl_info["exists"]:
            continue
        for cat in wl_info["categories"]:
            categories[cat].append({
                "file": wl_name,
                "priority": wl_info["priority"],
                "line_count": wl_info["line_count"],
                "use_cases": wl_info["use_cases"],
            })

    # Sort each category by priority
    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for cat in categories:
        categories[cat].sort(key=lambda x: priority_order.get(x["priority"], 9))

    return dict(categories)


def main():
    print(f"\n{'='*60}")
    print(f"  Wordlist Classification Engine — {DOMAIN}")
    print(f"{'='*60}\n")

    # Build catalog
    catalog = build_catalog()
    existing = sum(1 for v in catalog.values() if v["exists"])
    total_lines = sum(v["line_count"] for v in catalog.values())
    total_size = sum(v["size_bytes"] for v in catalog.values())

    print(f"  [+] Classified {len(catalog)} wordlists ({existing} exist on disk)")
    print(f"  [+] Total entries: {total_lines:,}")
    print(f"  [+] Total size: {total_size / 1048576:.1f}MB")

    # Build category map
    categories = build_category_map(catalog)
    print(f"  [+] Categories: {len(categories)}")
    print()

    for cat_name in sorted(categories.keys()):
        cat_items = categories[cat_name]
        desc = CATEGORY_DESCRIPTIONS.get(cat_name, "")
        total_cat_lines = sum(i["line_count"] for i in cat_items)
        file_list = ", ".join(i["file"] for i in cat_items[:5])
        if len(cat_items) > 5:
            file_list += f" +{len(cat_items)-5} more"
        print(f"      {cat_name:25s} [{len(cat_items):2d} lists] [{total_cat_lines:>10,} entries] {file_list}")

    # Save outputs
    with open(OUT_INTEL / "wordlist_catalog.json", 'w') as f:
        json.dump(catalog, f, indent=2)

    with open(OUT_INTEL / "wordlist_categories.json", 'w') as f:
        json.dump(categories, f, indent=2)

    print(f"\n{'─'*60}")
    print(f"  Wordlist classification complete")
    print(f"  Catalog: {OUT_INTEL / 'wordlist_catalog.json'}")
    print(f"  Categories: {OUT_INTEL / 'wordlist_categories.json'}")
    print(f"{'─'*60}\n")


if __name__ == "__main__":
    from collections import defaultdict
    main()
