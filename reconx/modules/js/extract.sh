#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — JavaScript Extraction
# ============================================================================
# Collects JS URLs, downloads JS files, extracts source maps, webpack chunks,
# and hidden imports for downstream secret/endpoint analysis.
# ============================================================================

DOMAIN="${1:?Usage: extract.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"

JS_DIR="${OUT_JS}"
JS_FILES_DIR="${JS_DIR}/files"
mkdir -p "$JS_FILES_DIR"

log_module_start "JavaScript Extraction" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
JS_URLS="${JS_DIR}/js_urls.txt"

# ── Collect JS URLs from Multiple Sources ────────────────────────────────────
log_task_start "Collecting JavaScript URLs"

# From URL gathering
if [[ -f "${OUT_URLS}/all_urls.txt" ]]; then
    grep -iE '\.js(\?|$)' "${OUT_URLS}/all_urls.txt" 2>/dev/null >> "${JS_DIR}/js_raw.txt" || true
fi

# From katana (JS-focused crawl)
if cmd_exists katana; then
    log_task_start "katana JS-focused crawl"
    crawl_js_input="${RECONX_TMP}/js_crawl_input.txt"
    if [[ -f "$LIVE_HOSTS" ]] && [[ "$(count_lines "$LIVE_HOSTS")" -gt 0 ]]; then
        cp "$LIVE_HOSTS" "$crawl_js_input"
    else
        echo "http://${DOMAIN}" > "$crawl_js_input"
        echo "https://${DOMAIN}" >> "$crawl_js_input"
    fi
    katana -list "$crawl_js_input" \
        -silent \
        -d 5 \
        -jc \
        -ef css,png,jpg,jpeg,gif,svg,woff,woff2,ttf,eot,ico \
        -c "$THREADS" \
        -o "${JS_DIR}/katana_js.txt" 2>/dev/null || true
    # Extract JS URLs from katana output
    grep -iE '\.(js|mjs)(\?|$)' "${JS_DIR}/katana_js.txt" >> "${JS_DIR}/js_raw.txt" 2>/dev/null || true
    rm -f "$crawl_js_input"
    log_task_done "katana JS crawl" "$(count_lines "${JS_DIR}/katana_js.txt")"
fi

# From gau
if cmd_exists gau; then
    echo "$DOMAIN" | gau --fc 404 --mt "application/javascript" 2>/dev/null \
        >> "${JS_DIR}/js_raw.txt" || true
fi

# Deduplicate
sort -u "${JS_DIR}/js_raw.txt" > "$JS_URLS" 2>/dev/null || true
rm -f "${JS_DIR}/js_raw.txt"
JS_COUNT="$(count_lines "$JS_URLS")"
log_task_done "JS URLs collected" "$JS_COUNT"

# ── Download JS Files ────────────────────────────────────────────────────────
download_js_files() {
    if [[ "$JS_COUNT" -eq 0 ]]; then
        log_warn "No JS URLs to download"
        return
    fi

    log_task_start "Downloading JS files"

    download_count=0
    max_downloads=5000

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        [[ "$download_count" -ge "$max_downloads" ]] && break

        filename="$(echo "$url" | md5sum | cut -c1-12).js"
        filepath="${JS_FILES_DIR}/${filename}"

        # Download with timeout
        curl -s -L --max-time 10 -o "$filepath" "$url" 2>/dev/null || true

        # Skip empty/tiny files
        if [[ -f "$filepath" ]]; then
            size="$(stat -c%s "$filepath" 2>/dev/null || echo 0)"
            if [[ "$size" -lt 50 ]]; then
                rm -f "$filepath"
            else
                download_count=$((download_count + 1))
                echo "${url}|${filename}" >> "${JS_DIR}/js_url_map.txt"
            fi
        fi
    done < "$JS_URLS"

    log_task_done "Downloaded JS files" "$download_count"
}

# ── Extract Source Maps ──────────────────────────────────────────────────────
extract_source_maps() {
    log_task_start "Extracting source map references"
    sourcemap_urls="${JS_DIR}/sourcemap_urls.txt"
    > "$sourcemap_urls"

    for js_file in "${JS_FILES_DIR}"/*.js; do
        [[ -f "$js_file" ]] || continue
        grep -oP '//[#@]\s*sourceMappingURL=\K\S+' "$js_file" 2>/dev/null >> "$sourcemap_urls" || true
    done

    sed 's/$/.map/' "$JS_URLS" >> "$sourcemap_urls" 2>/dev/null || true
    sort -u "$sourcemap_urls" -o "$sourcemap_urls"

    map_dir="${JS_DIR}/sourcemaps"
    mkdir -p "$map_dir"
    map_count=0

    while IFS= read -r map_url; do
        [[ -z "$map_url" ]] && continue
        map_file="${map_dir}/$(echo "$map_url" | md5sum | cut -c1-12).map"
        curl -s -L --max-time 10 -o "$map_file" "$map_url" 2>/dev/null || true
        if [[ -f "$map_file" && "$(stat -c%s "$map_file" 2>/dev/null || echo 0)" -gt 100 ]]; then
            map_count=$((map_count + 1))
        else
            rm -f "$map_file"
        fi
    done < "$sourcemap_urls"

    log_task_done "Source maps found" "$map_count"
}

# ── Extract Webpack Chunks ──────────────────────────────────────────────────
extract_webpack_chunks() {
    log_task_start "Detecting webpack chunks"
    local chunks="${JS_DIR}/webpack_chunks.txt"
    > "$chunks"

    for js_file in "${JS_FILES_DIR}"/*.js; do
        [[ -f "$js_file" ]] || continue
        # Look for webpack chunk patterns
        grep -oP '(?:webpackChunkName|__webpack_require__|webpackJsonp|chunkId)[^;]*' \
            "$js_file" 2>/dev/null >> "$chunks" || true
    done

    sort -u "$chunks" -o "$chunks"
    log_task_done "Webpack chunks" "$(count_lines "$chunks")"
}

# ── Extract Hidden Imports ──────────────────────────────────────────────────
extract_hidden_imports() {
    log_task_start "Extracting hidden imports/requires"
    local imports="${JS_DIR}/hidden_imports.txt"
    > "$imports"

    for js_file in "${JS_FILES_DIR}"/*.js; do
        [[ -f "$js_file" ]] || continue
        # ES6 imports
        grep -oP "(?:import|require)\s*\(\s*['\"]([^'\"]+)['\"]" "$js_file" 2>/dev/null >> "$imports" || true
        # Dynamic imports
        grep -oP "import\s*\(['\"]([^'\"]+)['\"]\)" "$js_file" 2>/dev/null >> "$imports" || true
    done

    sort -u "$imports" -o "$imports"
    log_task_done "Hidden imports" "$(count_lines "$imports")"
}

# ── xnLinkFinder ─────────────────────────────────────────────────────────────
run_xnlinkfinder() {
    if cmd_exists xnLinkFinder; then
        log_task_start "xnLinkFinder endpoint extraction"
        xnLinkFinder -i "$LIVE_HOSTS" \
            -o "${JS_DIR}/xnlinkfinder_endpoints.txt" \
            -op "${JS_DIR}/xnlinkfinder_params.txt" \
            -d 3 > /dev/null 2>&1 || true
        log_task_done "xnLinkFinder" "$(count_lines "${JS_DIR}/xnlinkfinder_endpoints.txt")"
    fi
}

# ── Execute ──────────────────────────────────────────────────────────────────
download_js_files
extract_source_maps
extract_webpack_chunks
extract_hidden_imports
run_xnlinkfinder

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}JavaScript Extraction Statistics:${RESET}"
log_stats "JS URLs" "$JS_COUNT"
log_stats "Downloaded files" "$(ls "${JS_FILES_DIR}"/*.js 2>/dev/null | wc -l)"
log_stats "Source maps" "$(ls "${JS_DIR}/sourcemaps"/*.map 2>/dev/null | wc -l)"
log_stats "Webpack chunks" "$(count_lines "${JS_DIR}/webpack_chunks.txt")"
log_stats_final "Hidden imports" "$(count_lines "${JS_DIR}/hidden_imports.txt")"

log_module_end "JavaScript Extraction" "$START_TIME" "$JS_COUNT"
