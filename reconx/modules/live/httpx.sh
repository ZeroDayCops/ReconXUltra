#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Live Host Detection (httpx)
# ============================================================================
# Probes all discovered subdomains for live HTTP(S) services using httpx.
# Collects: title, status, tech, CDN, IP, CNAME, response size, favicon hash,
# JARM fingerprint, TLS metadata, and more.
# ============================================================================

DOMAIN="${1:?Usage: httpx.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

log_module_start "Live Host Detection (httpx)" "$DOMAIN"
START_TIME="$(date +%s)"

# ── Input Selection ──────────────────────────────────────────────────────────
INPUT_FILE="${OUT_SUBS}/all_subdomains.txt"
if [[ ! -f "$INPUT_FILE" || "$(count_lines "$INPUT_FILE")" -eq 0 ]]; then
    log_warn "No subdomains found — nothing to probe"
    exit 0
fi

SUB_COUNT="$(count_lines "$INPUT_FILE")"
log_info "Probing ${SUB_COUNT} subdomains for live hosts"

if ! cmd_exists httpx; then
    log_error "httpx is not installed — cannot perform live host detection"
    exit 1
fi

# ── httpx Full Probe ────────────────────────────────────────────────────────
log_task_start "httpx full probe"

httpx -l "$INPUT_FILE" \
    -silent \
    -threads "$THREADS" \
    -rate-limit "$RATE_LIMIT" \
    -timeout "$TIMEOUT" \
    -retries "$RETRIES" \
    -title \
    -status-code \
    -tech-detect \
    -cdn \
    -ip \
    -cname \
    -content-length \
    -content-type \
    -favicon \
    -jarm \
    -tls-grab \
    -tls-probe \
    -web-server \
    -method \
    -websocket \
    -pipeline \
    -http2 \
    -vhost \
    -follow-redirects \
    -json \
    -o "${OUT_LIVE}/httpx_full.json" 2>/dev/null || true

log_task_done "httpx full probe"

# ── Extract Live Hosts ──────────────────────────────────────────────────────
log_task_start "Extracting live hosts"

# Plain URL list
jq -r '.url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/live_hosts.txt" || true

LIVE_COUNT="$(count_lines "${OUT_LIVE}/live_hosts.txt")"
log_task_done "Live hosts" "$LIVE_COUNT"

# ── Categorize by Status Code ───────────────────────────────────────────────
log_task_start "Categorizing by status code"

# 200 OK
jq -r 'select(.status_code == 200) | .url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/status_200.txt" || true

# 301/302 Redirects
jq -r 'select(.status_code == 301 or .status_code == 302) | .url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/status_redirects.txt" || true

# 403 Forbidden
jq -r 'select(.status_code == 403) | .url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/status_403.txt" || true

# 401 Unauthorized
jq -r 'select(.status_code == 401) | .url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/status_401.txt" || true

# 500+ Server Errors
jq -r 'select(.status_code >= 500) | .url' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/status_5xx.txt" || true

log_task_done "Status categorization"

# ── Extract Technologies ────────────────────────────────────────────────────
log_task_start "Extracting technologies"
jq -r 'select(.tech != null) | "\(.url) [\(.tech | join(", "))]"' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/technologies.txt" || true

# Unique tech list
jq -r '.tech[]?' "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort | uniq -c | sort -rn > "${OUT_LIVE}/tech_summary.txt" || true

log_task_done "Technologies" "$(count_lines "${OUT_LIVE}/technologies.txt")"

# ── Extract CDN Information ─────────────────────────────────────────────────
log_task_start "Extracting CDN info"
jq -r 'select(.cdn_name != null and .cdn_name != "") | "\(.url) [\(.cdn_name)]"' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/cdn_hosts.txt" || true

# Non-CDN hosts (direct IP, better for pentesting)
jq -r 'select(.cdn_name == null or .cdn_name == "") | .url' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/non_cdn_hosts.txt" || true

log_task_done "CDN hosts" "$(count_lines "${OUT_LIVE}/cdn_hosts.txt")"

# ── Extract IP Mapping ──────────────────────────────────────────────────────
log_task_start "Extracting IP mapping"
jq -r 'select(.a != null) | "\(.host) \(.a | join(", "))"' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/ip_mapping.txt" || true
log_task_done "IP mappings" "$(count_lines "${OUT_LIVE}/ip_mapping.txt")"

# ── Extract JARM Fingerprints ───────────────────────────────────────────────
log_task_start "Extracting JARM fingerprints"
jq -r 'select(.jarm != null and .jarm != "") | "\(.url) \(.jarm)"' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/jarm_fingerprints.txt" || true
log_task_done "JARM fingerprints" "$(count_lines "${OUT_LIVE}/jarm_fingerprints.txt")"

# ── Extract Interesting Titles ──────────────────────────────────────────────
log_task_start "Identifying interesting titles"
jq -r 'select(.title != null) | "\(.url) [\(.title)]"' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    | sort -u > "${OUT_LIVE}/titles.txt" || true

# Flag interesting titles
local interesting_patterns="admin|login|dashboard|panel|jenkins|jira|grafana|kibana|gitlab|confluence|phpmyadmin|webmail|cpanel|sonarqube|swagger|api|graphql|debug|staging|internal"
grep -iE "$interesting_patterns" "${OUT_LIVE}/titles.txt" \
    > "${OUT_LIVE}/interesting_titles.txt" 2>/dev/null || true
log_task_done "Interesting titles" "$(count_lines "${OUT_LIVE}/interesting_titles.txt")"

# ── Generate Summary CSV ────────────────────────────────────────────────────
log_task_start "Generating summary CSV"
echo "url,status,title,tech,cdn,ip,content_length,web_server" > "${OUT_LIVE}/summary.csv"
jq -r '[.url, (.status_code|tostring), .title, (.tech // [] | join(";")), .cdn_name, (.a // [] | join(";")), (.content_length|tostring), .webserver] | @csv' \
    "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
    >> "${OUT_LIVE}/summary.csv" || true
log_task_done "Summary CSV"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Live Host Statistics:${RESET}"
log_stats "Input subdomains" "$SUB_COUNT"
log_stats "Live hosts" "$LIVE_COUNT"
log_stats "200 OK" "$(count_lines "${OUT_LIVE}/status_200.txt")"
log_stats "Redirects" "$(count_lines "${OUT_LIVE}/status_redirects.txt")"
log_stats "403 Forbidden" "$(count_lines "${OUT_LIVE}/status_403.txt")"
log_stats "401 Unauthorized" "$(count_lines "${OUT_LIVE}/status_401.txt")"
log_stats "CDN-backed" "$(count_lines "${OUT_LIVE}/cdn_hosts.txt")"
log_stats "Direct (non-CDN)" "$(count_lines "${OUT_LIVE}/non_cdn_hosts.txt")"
log_stats_final "Interesting titles" "$(count_lines "${OUT_LIVE}/interesting_titles.txt")"

log_module_end "Live Host Detection" "$START_TIME" "$LIVE_COUNT"
