#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — URL Gathering
# ============================================================================
# Aggregates URLs from multiple sources: gau, katana, hakrawler, waybackurls,
# waymore. Extracts archived URLs, APIs, JS files, parameters, hidden routes.
# ============================================================================

DOMAIN="${1:?Usage: gather.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

URL_GATHER_DIR="${OUT_URLS}/gathered"
mkdir -p "$URL_GATHER_DIR"

log_module_start "URL Gathering" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"

# ── Build crawl input ─────────────────────────────────────────────────────
# If we have live hosts use those, otherwise generate target URLs directly
CRAWL_INPUT="${RECONX_TMP}/crawl_input.txt"
if [[ -f "$LIVE_HOSTS" ]] && [[ "$(count_lines "$LIVE_HOSTS")" -gt 0 ]]; then
    cp "$LIVE_HOSTS" "$CRAWL_INPUT"
    log_info "Using $(count_lines "$CRAWL_INPUT") live hosts as crawl input"
else
    # No live hosts — generate URLs from domain directly
    echo "http://${DOMAIN}" > "$CRAWL_INPUT"
    echo "https://${DOMAIN}" >> "$CRAWL_INPUT"
    log_info "No live hosts — crawling domain directly: ${DOMAIN}"
fi

# ── gau (GetAllUrls) ────────────────────────────────────────────────────────
run_gau() {
    if cmd_exists gau; then
        log_task_start "gau"
        out="${URL_GATHER_DIR}/gau.txt"
        echo "$DOMAIN" | gau --threads "$THREADS" 2>/dev/null | sort -u > "$out" || true
        log_task_done "gau" "$(count_lines "$out")"
    else
        log_warn "gau not installed — skipping"
    fi
}

# ── katana ───────────────────────────────────────────────────────────────────
run_katana() {
    if cmd_exists katana; then
        log_task_start "katana (depth 5)"
        out="${URL_GATHER_DIR}/katana.txt"

        katana -list "$CRAWL_INPUT" \
            -silent \
            -d 5 \
            -jc \
            -kf all \
            -aff \
            -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico \
            -c "$THREADS" \
            -o "$out" 2>/dev/null || true
        log_task_done "katana" "$(count_lines "$out")"
    else
        log_warn "katana not installed — skipping"
    fi
}

# ── hakrawler ────────────────────────────────────────────────────────────────
run_hakrawler() {
    if cmd_exists hakrawler; then
        log_task_start "hakrawler"
        out="${URL_GATHER_DIR}/hakrawler.txt"
        cat "$CRAWL_INPUT" | hakrawler -d 3 -subs -u 2>/dev/null | sort -u > "$out" || true
        log_task_done "hakrawler" "$(count_lines "$out")"
    else
        log_warn "hakrawler not installed — skipping"
    fi
}

# ── waybackurls ──────────────────────────────────────────────────────────────
run_waybackurls() {
    if cmd_exists waybackurls; then
        log_task_start "waybackurls"
        out="${URL_GATHER_DIR}/waybackurls.txt"
        echo "$DOMAIN" | waybackurls 2>/dev/null | sort -u > "$out" || true
        log_task_done "waybackurls" "$(count_lines "$out")"
    else
        log_warn "waybackurls not installed — skipping"
    fi
}

# ── waymore ──────────────────────────────────────────────────────────────────
run_waymore() {
    if cmd_exists waymore; then
        log_task_start "waymore"
        out="${URL_GATHER_DIR}/waymore.txt"
        waymore -i "$DOMAIN" -mode U -oU "$out" 2>/dev/null || true
        log_task_done "waymore" "$(count_lines "$out")"
    else
        log_warn "waymore not installed — skipping"
    fi
}

# ── Run URL Gatherers ────────────────────────────────────────────────────────
run_gau &
run_waybackurls &
run_waymore &
wait

run_katana
run_hakrawler

# ── Merge All URLs ───────────────────────────────────────────────────────────
log_task_start "Merging all gathered URLs"
ALL_URLS="${OUT_URLS}/all_urls_raw.txt"
cat "${URL_GATHER_DIR}"/*.txt 2>/dev/null | sort -u > "$ALL_URLS"
RAW_COUNT="$(count_lines "$ALL_URLS")"
log_task_done "Total raw URLs" "$RAW_COUNT"

# ── Deduplicate with uro ────────────────────────────────────────────────────
if cmd_exists uro; then
    log_task_start "Deduplicating with uro"
    cat "$ALL_URLS" | uro > "${OUT_URLS}/all_urls.txt" 2>/dev/null || cp "$ALL_URLS" "${OUT_URLS}/all_urls.txt"
    DEDUP_COUNT="$(count_lines "${OUT_URLS}/all_urls.txt")"
    log_task_done "Deduplicated URLs" "$DEDUP_COUNT"
else
    cp "$ALL_URLS" "${OUT_URLS}/all_urls.txt"
    DEDUP_COUNT="$RAW_COUNT"
fi

# ── Extract URL Categories ──────────────────────────────────────────────────
log_task_start "Categorizing URLs"

# JavaScript files
grep -iE '\.(js|mjs)(\?|$)' "${OUT_URLS}/all_urls.txt" | sort -u > "${OUT_JS}/js_urls.txt" 2>/dev/null || true

# API endpoints
grep -iE '(/api/|/v[0-9]+/|/graphql|/rest/|/json|/xml|\.ashx|\.asmx|\.svc)' "${OUT_URLS}/all_urls.txt" \
    | sort -u > "${OUT_URLS}/api_endpoints.txt" 2>/dev/null || true

# URLs with parameters
grep -E '\?' "${OUT_URLS}/all_urls.txt" | sort -u > "${OUT_URLS}/parameterized_urls.txt" 2>/dev/null || true

# Potential sensitive files
grep -iE '\.(env|config|yml|yaml|json|xml|sql|bak|backup|old|orig|swp|log|git|svn|htaccess|htpasswd|ini|conf|cfg|properties|toml|pem|key|cer)' \
    "${OUT_URLS}/all_urls.txt" | sort -u > "${OUT_URLS}/sensitive_urls.txt" 2>/dev/null || true

# Archive/backup files
grep -iE '\.(zip|tar|gz|tgz|rar|7z|bak|backup|dump|sql\.gz)' "${OUT_URLS}/all_urls.txt" \
    | sort -u > "${OUT_URLS}/archive_urls.txt" 2>/dev/null || true

# Admin/login pages
grep -iE '(admin|login|signin|dashboard|panel|portal|manage|console|wp-admin|wp-login)' \
    "${OUT_URLS}/all_urls.txt" | sort -u > "${OUT_URLS}/admin_urls.txt" 2>/dev/null || true

log_task_done "URL categorization"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}URL Gathering Statistics:${RESET}"
log_stats "Raw URLs" "$RAW_COUNT"
log_stats "Deduplicated URLs" "$DEDUP_COUNT"
log_stats "JavaScript files" "$(count_lines "${OUT_JS}/js_urls.txt")"
log_stats "API endpoints" "$(count_lines "${OUT_URLS}/api_endpoints.txt")"
log_stats "Parameterized URLs" "$(count_lines "${OUT_URLS}/parameterized_urls.txt")"
log_stats "Sensitive files" "$(count_lines "${OUT_URLS}/sensitive_urls.txt")"
log_stats "Archive files" "$(count_lines "${OUT_URLS}/archive_urls.txt")"
log_stats_final "Admin/login pages" "$(count_lines "${OUT_URLS}/admin_urls.txt")"

echo ""
echo -e "  ${BOLD}${WHITE}Source Breakdown:${RESET}"
for src_file in "${URL_GATHER_DIR}"/*.txt; do
    [[ -f "$src_file" ]] || continue
    src_name="$(basename "$src_file" .txt)"
    src_count="$(count_lines "$src_file")"
    log_stats "$src_name" "$src_count"
done
echo ""

rm -f "$CRAWL_INPUT"
log_module_end "URL Gathering" "$START_TIME" "$DEDUP_COUNT"
