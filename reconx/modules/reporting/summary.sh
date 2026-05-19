#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Summary Report Generator
# ============================================================================

DOMAIN="${1:?Usage: summary.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Report Generation" "$DOMAIN"
START_TIME="$(date +%s)"

# Generate markdown report
log_task_start "Generating markdown report"
python3 "${RECONX_MODULES}/reporting/markdown.py" "$DOMAIN" 2>/dev/null || true
log_task_done "Markdown report"

# Generate Premium Ultra X Dashboard (replaces old basic html report)
log_task_start "Generating Premium Ultra X dashboard → report.html"
python3 "${RECONX_MODULES}/reporting/dashboard_gen.py" "$DOMAIN" 2>/dev/null || true
log_task_done "Premium dashboard"

# ── Quick Text Summary ──────────────────────────────────────────────────────
SUMMARY_FILE="${OUT_REPORTS}/quick_summary.txt"
cat > "$SUMMARY_FILE" <<EOF
═══════════════════════════════════════════════════════════════
  ReconX Ultra — Intelligence Summary Report
  Domain: ${DOMAIN}
  Date: $(date -Iseconds)
  Mode: ${PERF_MODE:-balanced}
═══════════════════════════════════════════════════════════════

  SUBDOMAINS
  ├─ Total subdomains:      $(count_lines "${OUT_SUBS}/all_subdomains.txt")
  ├─ Passive:               $(count_lines "${OUT_SUBS}/passive_all.txt")
  └─ Active:                $(count_lines "${OUT_SUBS}/active_all.txt")

  DNS RESOLUTION
  ├─ Resolved:              $(count_lines "${OUT_RESOLVED}/resolved_subdomains.txt")
  └─ Unique IPs:            $(count_lines "${OUT_RESOLVED}/unique_ips.txt")

  LIVE HOSTS
  ├─ Live hosts:            $(count_lines "${OUT_LIVE}/live_hosts.txt")
  ├─ 200 OK:                $(count_lines "${OUT_LIVE}/status_200.txt")
  ├─ 403 Forbidden:         $(count_lines "${OUT_LIVE}/status_403.txt")
  └─ Interesting titles:    $(count_lines "${OUT_LIVE}/interesting_titles.txt")

  URLS
  ├─ Total URLs:            $(count_lines "${OUT_URLS}/all_urls.txt")
  ├─ Parameterized:         $(count_lines "${OUT_URLS}/parameterized_urls.txt")
  ├─ API endpoints:         $(count_lines "${OUT_URLS}/api_endpoints.txt")
  └─ Sensitive files:       $(count_lines "${OUT_URLS}/sensitive_urls.txt")

  JAVASCRIPT
  ├─ JS URLs:               $(count_lines "${OUT_JS}/js_urls.txt")
  └─ Endpoints extracted:   $(count_lines "${OUT_JS}/extracted_endpoints.txt")

  VULNERABILITY CANDIDATES
  ├─ XSS candidates:        $(count_lines "${OUT_INTEL}/xss_candidates.txt")
  ├─ SQLi candidates:       $(count_lines "${OUT_INTEL}/sqli_candidates.txt")
  ├─ SSRF candidates:       $(count_lines "${OUT_INTEL}/ssrf_candidates.txt")
  ├─ LFI candidates:        $(count_lines "${OUT_INTEL}/lfi_candidates.txt")
  ├─ SSTI candidates:       $(count_lines "${OUT_INTEL}/ssti_candidates.txt")
  ├─ IDOR candidates:       $(count_lines "${OUT_INTEL}/idor_candidates.txt")
  ├─ Redirect candidates:   $(count_lines "${OUT_INTEL}/redirect_candidates.txt")
  └─ CRLF candidates:       $(count_lines "${OUT_INTEL}/crlf_candidates.txt")

  INTELLIGENCE
  ├─ Technologies detected: $(jq '.technologies_detected | length // 0' "${OUT_INTEL}/wordlist_selections.json" 2>/dev/null || echo 0)
  ├─ Wordlists applied:     $(jq '.total_wordlists // 0' "${OUT_INTEL}/wordlist_selections.json" 2>/dev/null || echo 0)
  ├─ High-value endpoints:  $(count_lines "${OUT_INTEL}/high_value_endpoints.txt")
  ├─ API routes discovered:  $(count_lines "${OUT_INTEL}/api_routes_discovered.txt")
  ├─ Response clusters:     $(jq '.clusters | length // 0' "${OUT_INTEL}/response_clusters.json" 2>/dev/null || echo 0)
  ├─ Hidden params found:   $(count_lines "${OUT_INTEL}/discovered_params.txt")
  └─ 403 bypasses:          $(count_lines "${OUTPUT_DIR}/exploits/403_bypass_results.txt")

  SCANNING
  ├─ Nuclei findings:       $(count_lines "${OUT_SCANS}/nuclei_all_summary.txt")
  ├─ Open ports:            $(count_lines "${OUT_SCANS}/open_ports.txt")
  └─ Takeover findings:     $(count_lines "${OUT_TAKEOVER}/all_takeover_findings.txt")

  SECRETS
  └─ JS secret findings:    $(jq '.total_findings // 0' "${OUT_SECRETS}/js_secrets_report.json" 2>/dev/null || echo 0)

═══════════════════════════════════════════════════════════════
  Report files:
  ├─ ${OUT_REPORTS}/report.md
  ├─ ${OUT_REPORTS}/report.html (Interactive Dashboard)
  └─ ${OUT_REPORTS}/quick_summary.txt
═══════════════════════════════════════════════════════════════
EOF

cat "$SUMMARY_FILE"

# ── Generate Master Scan Index ──────────────────────────────────────────────
log_task_start "Generating scan history index"
INDEX_FILE="${RECONX_ROOT}/output/index.html"
cat > "$INDEX_FILE" <<'INDEXHEAD'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ReconX Ultra X — Scan History</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:#080b12;color:#e2e8f0;padding:2rem}
h1{font-size:1.5rem;background:linear-gradient(135deg,#06d6a0,#3b82f6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}
p.sub{color:#64748b;font-size:.8rem;margin-bottom:2rem}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:1rem}
.card{background:#151b23;border:1px solid #2a3142;border-radius:12px;padding:1.5rem;transition:all .3s}
.card:hover{border-color:#3b82f6;transform:translateY(-3px);box-shadow:0 8px 32px rgba(0,0,0,.4)}
.card h2{font-size:1rem;color:#06d6a0;margin-bottom:.5rem}
.card .meta{font-size:.75rem;color:#64748b;margin-bottom:.8rem}
.card .stats{display:flex;gap:.5rem;flex-wrap:wrap;margin-bottom:1rem}
.card .stats span{background:#1c2333;padding:.2rem .6rem;border-radius:6px;font-size:.7rem;font-family:'JetBrains Mono',monospace;color:#3b82f6}
.card a{display:inline-block;padding:.5rem 1.2rem;background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:#fff;text-decoration:none;border-radius:8px;font-size:.8rem;font-weight:600}
.card a:hover{opacity:.9}
</style></head><body>
<h1>⚡ ReconX Ultra X — Scan History</h1>
<p class="sub">All reconnaissance scan results</p>
<div class="grid">
INDEXHEAD

# Add a card for each scanned domain (only dirs with a dot = domain names)
for domain_dir in "${RECONX_ROOT}"/output/*/; do
    [[ ! -d "$domain_dir" ]] && continue
    d="$(basename "$domain_dir")"
    [[ "$d" == "." || "$d" == ".." ]] && continue
    # Skip non-domain dirs (must contain a dot like example.com)
    [[ "$d" != *.* ]] && continue
    rpt_file="${domain_dir}reports/report.html"
    [[ ! -f "$rpt_file" ]] && rpt_file="${domain_dir}reports/dashboard.html"

    subs=$(cat "${domain_dir}subs/all_subdomains.txt" 2>/dev/null | wc -l)
    urls=$(cat "${domain_dir}urls/all_urls.txt" 2>/dev/null | wc -l)
    js=$(cat "${domain_dir}js/js_urls.txt" 2>/dev/null | wc -l)
    live=$(cat "${domain_dir}live/live_hosts.txt" 2>/dev/null | wc -l)
    scanned=$(stat -c '%y' "${domain_dir}" 2>/dev/null | cut -d'.' -f1)

    cat >> "$INDEX_FILE" <<CARD
<div class="card">
<h2>${d}</h2>
<div class="meta">Scanned: ${scanned}</div>
<div class="stats">
<span>Subs: ${subs}</span>
<span>Live: ${live}</span>
<span>URLs: ${urls}</span>
<span>JS: ${js}</span>
</div>
CARD
    if [[ -f "$rpt_file" ]]; then
        echo "<a href=\"${d}/reports/report.html\">Open Dashboard →</a>" >> "$INDEX_FILE"
    else
        echo "<span style='color:#64748b;font-size:.75rem'>No dashboard yet</span>" >> "$INDEX_FILE"
    fi
    echo "</div>" >> "$INDEX_FILE"
done

echo '</div></body></html>' >> "$INDEX_FILE"
log_task_done "Scan history index → output/index.html"

log_module_end "Report Generation" "$START_TIME" 0
