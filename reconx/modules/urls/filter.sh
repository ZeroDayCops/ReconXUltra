#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — URL Filter & Cleaner
# ============================================================================
# Filters, deduplicates, and cleans gathered URLs. Removes noise, identifies
# high-value targets, and creates focused URL lists for downstream modules.
# ============================================================================

DOMAIN="${1:?Usage: filter.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"

log_module_start "URL Filtering" "$DOMAIN"
START_TIME="$(date +%s)"

ALL_URLS="${OUT_URLS}/all_urls.txt"

if [[ ! -f "$ALL_URLS" || "$(count_lines "$ALL_URLS")" -eq 0 ]]; then
    log_warn "No URLs to filter"
    exit 0
fi

INITIAL_COUNT="$(count_lines "$ALL_URLS")"
log_info "Filtering ${INITIAL_COUNT} URLs"

# ── Remove noise extensions ─────────────────────────────────────────────────
log_task_start "Removing noise (images, fonts, static assets)"
FILTERED="${OUT_URLS}/filtered_urls.txt"
grep -viE '\.(png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|css|mp4|mp3|avi|mov|webp|webm|flv|pdf)(\?|$)' \
    "$ALL_URLS" | sort -u > "$FILTERED" || cp "$ALL_URLS" "$FILTERED"
log_task_done "Filtered static assets" "$(count_lines "$FILTERED")"

# ── Remove duplicate parameters (keep unique patterns) ──────────────────────
if cmd_exists uro; then
    log_task_start "Advanced dedup with uro"
    tmp_uro="${RECONX_TMP}/uro_filtered.txt"
    cat "$FILTERED" | uro > "$tmp_uro" 2>/dev/null || cp "$FILTERED" "$tmp_uro"
    mv "$tmp_uro" "$FILTERED"
    log_task_done "uro dedup" "$(count_lines "$FILTERED")"
fi

# ── Separate by potential vulnerability class ────────────────────────────────
log_task_start "Classifying URLs by vulnerability potential"

# URLs with reflection points (potential XSS)
grep -iE '(\?|&)(q|search|query|keyword|name|value|text|msg|message|comment|body|content|title|desc|redirect|url|next|return|callback|data|input|page|ref|src|href|action|file|path|dir|view|template|include|require|load|read|fetch|open|show|display|render)=' \
    "$FILTERED" | sort -u > "${OUT_URLS}/xss_candidates.txt" 2>/dev/null || true

# URLs with file-related parameters (potential LFI/RFI)
grep -iE '(\?|&)(file|path|dir|folder|location|src|source|include|require|page|template|view|read|load|open|doc|document|filename|filepath|download)=' \
    "$FILTERED" | sort -u > "${OUT_URLS}/lfi_candidates.txt" 2>/dev/null || true

# URLs with redirect parameters (potential Open Redirect)
grep -iE '(\?|&)(url|redirect|next|return|redir|to|dest|destination|continue|forward|goto|target|link|out|checkout|rurl|returnurl|return_url|redirect_url|redirect_uri|callback)=' \
    "$FILTERED" | sort -u > "${OUT_URLS}/redirect_candidates.txt" 2>/dev/null || true

# URLs with server-side request parameters (potential SSRF)
grep -iE '(\?|&)(url|uri|src|source|href|link|fetch|proxy|img|image|request|endpoint|api|host|domain|server|addr|address|site|feed|rss|xml|callback|webhook)=' \
    "$FILTERED" | sort -u > "${OUT_URLS}/ssrf_candidates.txt" 2>/dev/null || true

# URLs with SQL-injectable parameters
grep -iE '(\?|&)(id|user|uid|pid|cid|nid|sid|tid|category|product|item|order|page|sort|column|table|field|select|where|from|limit|offset|num|number|count)=' \
    "$FILTERED" | sort -u > "${OUT_URLS}/sqli_candidates.txt" 2>/dev/null || true

log_task_done "URL classification"

# ── High-Value URL Extraction ───────────────────────────────────────────────
log_task_start "Extracting high-value URLs"

# Combine all vulnerability candidates into priority list
cat "${OUT_URLS}"/xss_candidates.txt \
    "${OUT_URLS}"/lfi_candidates.txt \
    "${OUT_URLS}"/redirect_candidates.txt \
    "${OUT_URLS}"/ssrf_candidates.txt \
    "${OUT_URLS}"/sqli_candidates.txt 2>/dev/null \
    | sort -u > "${OUT_URLS}/high_value_urls.txt" || true

log_task_done "High-value URLs" "$(count_lines "${OUT_URLS}/high_value_urls.txt")"

# ── Statistics ───────────────────────────────────────────────────────────────
FINAL_COUNT="$(count_lines "$FILTERED")"
echo ""
echo -e "  ${BOLD}${WHITE}URL Filter Statistics:${RESET}"
log_stats "Input URLs" "$INITIAL_COUNT"
log_stats "After filtering" "$FINAL_COUNT"
log_stats "XSS candidates" "$(count_lines "${OUT_URLS}/xss_candidates.txt")"
log_stats "LFI candidates" "$(count_lines "${OUT_URLS}/lfi_candidates.txt")"
log_stats "Redirect candidates" "$(count_lines "${OUT_URLS}/redirect_candidates.txt")"
log_stats "SSRF candidates" "$(count_lines "${OUT_URLS}/ssrf_candidates.txt")"
log_stats "SQLi candidates" "$(count_lines "${OUT_URLS}/sqli_candidates.txt")"
log_stats_final "High-value URLs" "$(count_lines "${OUT_URLS}/high_value_urls.txt")"

log_module_end "URL Filtering" "$START_TIME" "$FINAL_COUNT"
