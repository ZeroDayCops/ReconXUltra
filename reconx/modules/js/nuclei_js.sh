#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Nuclei JS Template Scanning
# ============================================================================
# Scans JavaScript files and URLs with nuclei templates focused on
# exposed secrets, sensitive info, and JS-specific vulnerabilities.
# ============================================================================

DOMAIN="${1:?Usage: nuclei_js.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

log_module_start "Nuclei JS Scanning" "$DOMAIN"
START_TIME="$(date +%s)"

JS_URLS="${OUT_JS}/js_urls.txt"
LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"

if ! cmd_exists nuclei; then
    log_error "nuclei not installed — cannot run JS scanning"
    exit 1
fi

if [[ ! -f "$JS_URLS" || "$(count_lines "$JS_URLS")" -eq 0 ]]; then
    log_warn "No JS URLs found — skipping nuclei JS scan"
    exit 0
fi

JS_COUNT="$(count_lines "$JS_URLS")"
log_info "Scanning ${JS_COUNT} JS URLs with nuclei"

# ── Nuclei JS Scan — Exposure Templates ─────────────────────────────────────
log_task_start "nuclei exposure templates"
nuclei -l "$JS_URLS" \
    -tags "exposure,token,secret,apikey" \
    -silent \
    -c "${CONFIG[nuclei.concurrency]:-25}" \
    -rl "${CONFIG[nuclei.rate_limit]:-150}" \
    -bs "${CONFIG[nuclei.bulk_size]:-25}" \
    -o "${OUT_JS}/nuclei_js_exposure.txt" \
    -json -me "${OUT_JS}/nuclei_js_exposure_matches/" 2>/dev/null || true
log_task_done "Nuclei exposure scan" "$(count_lines "${OUT_JS}/nuclei_js_exposure.txt")"

# ── Nuclei JS Scan — Technology Detection ───────────────────────────────────
log_task_start "nuclei tech detection on JS"
nuclei -l "$JS_URLS" \
    -tags "tech" \
    -silent \
    -c "${CONFIG[nuclei.concurrency]:-25}" \
    -o "${OUT_JS}/nuclei_js_tech.txt" 2>/dev/null || true
log_task_done "Nuclei tech detection" "$(count_lines "${OUT_JS}/nuclei_js_tech.txt")"

# ── TruffleHog (if available) ───────────────────────────────────────────────
if cmd_exists trufflehog; then
    log_task_start "trufflehog JS file scanning"
    local js_files_dir="${OUT_JS}/files"
    if [[ -d "$js_files_dir" ]]; then
        trufflehog filesystem "$js_files_dir" \
            --json \
            --no-update \
            > "${OUT_SECRETS}/trufflehog_js.json" 2>/dev/null || true
        local th_count
        th_count="$(jq -s 'length' "${OUT_SECRETS}/trufflehog_js.json" 2>/dev/null || echo 0)"
        log_task_done "trufflehog" "$th_count"
    fi
fi

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Nuclei JS Scan Statistics:${RESET}"
log_stats "JS URLs scanned" "$JS_COUNT"
log_stats "Exposure findings" "$(count_lines "${OUT_JS}/nuclei_js_exposure.txt")"
log_stats_final "Tech detections" "$(count_lines "${OUT_JS}/nuclei_js_tech.txt")"

TOTAL="$(count_lines "${OUT_JS}/nuclei_js_exposure.txt")"
log_module_end "Nuclei JS Scanning" "$START_TIME" "$TOTAL"
