#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Parameter Discovery
# ============================================================================
# Discovers hidden parameters using arjun, gf patterns, and regex extraction.
# Generates categorized parameter lists for various vulnerability classes.
# ============================================================================

DOMAIN="${1:?Usage: params.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

log_module_start "Parameter Discovery" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
ALL_URLS="${OUT_URLS}/filtered_urls.txt"
if [[ ! -f "$ALL_URLS" ]]; then
    ALL_URLS="${OUT_URLS}/all_urls.txt"
fi

# ── Extract parameters from URLs ────────────────────────────────────────────
log_task_start "Extracting parameters from discovered URLs"

if [[ -f "$ALL_URLS" ]]; then
    # Extract unique parameter names
    grep -oP '[\?&]([a-zA-Z0-9_-]+)=' "$ALL_URLS" 2>/dev/null \
        | sed 's/^[?&]//; s/=$//' \
        | sort | uniq -c | sort -rn > "${OUT_PARAMS}/param_frequency.txt" || true

    # Extract unique parameter names only
    awk '{print $2}' "${OUT_PARAMS}/param_frequency.txt" > "${OUT_PARAMS}/all_params.txt" 2>/dev/null || true
    log_task_done "URL parameter extraction" "$(count_lines "${OUT_PARAMS}/all_params.txt")"
fi

# ── unfurl parameter extraction ──────────────────────────────────────────────
if cmd_exists unfurl && [[ -f "$ALL_URLS" ]]; then
    log_task_start "unfurl parameter analysis"
    cat "$ALL_URLS" | unfurl -u keys 2>/dev/null | sort | uniq -c | sort -rn \
        > "${OUT_PARAMS}/unfurl_keys.txt" || true
    cat "$ALL_URLS" | unfurl -u keypairs 2>/dev/null | sort -u \
        > "${OUT_PARAMS}/unfurl_keypairs.txt" || true
    log_task_done "unfurl analysis" "$(count_lines "${OUT_PARAMS}/unfurl_keys.txt")"
fi

# ── Arjun — Hidden Parameter Discovery ──────────────────────────────────────
run_arjun() {
    if cmd_exists arjun; then
        log_task_start "Arjun hidden parameter discovery"

        # Select top targets (200 OK pages with parameters)
        local targets="${RECONX_TMP}/arjun_targets.txt"
        if [[ -f "${OUT_LIVE}/status_200.txt" ]]; then
            head -20 "${OUT_LIVE}/status_200.txt" > "$targets"
        elif [[ -f "$LIVE_HOSTS" ]]; then
            head -20 "$LIVE_HOSTS" > "$targets"
        else
            log_warn "No live hosts for Arjun — skipping"
            return
        fi

        local out="${OUT_PARAMS}/arjun_results.json"
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            arjun -u "$url" -t "$THREADS" -oJ "${OUT_PARAMS}/arjun_$(echo "$url" | md5sum | cut -c1-8).json" \
                --stable 2>/dev/null || true
        done < "$targets"

        # Merge arjun results
        cat "${OUT_PARAMS}"/arjun_*.json 2>/dev/null | jq -s '.' > "$out" 2>/dev/null || true
        rm -f "$targets"

        log_task_done "Arjun" "$(jq 'length' "$out" 2>/dev/null || echo 0)"
    else
        log_warn "arjun not installed — skipping"
    fi
}

# ── GF Pattern Matching ─────────────────────────────────────────────────────
run_gf_patterns() {
    if cmd_exists gf && [[ -f "$ALL_URLS" ]]; then
        log_task_start "GF pattern matching"

        local patterns=("xss" "ssrf" "lfi" "rce" "redirect" "sqli" "idor" "ssti" "debug_logic" "interestingparams" "cors")

        for pattern in "${patterns[@]}"; do
            local out="${OUT_PARAMS}/gf_${pattern}.txt"
            cat "$ALL_URLS" | gf "$pattern" 2>/dev/null | sort -u > "$out" || true
            local count
            count="$(count_lines "$out")"
            if [[ "$count" -gt 0 ]]; then
                log_stats "gf:${pattern}" "$count"
            fi
        done

        log_task_done "GF patterns"
    else
        log_warn "gf not installed or no URLs — skipping pattern matching"
    fi
}

# ── qsreplace for Parameter Injection Points ────────────────────────────────
run_qsreplace() {
    if cmd_exists qsreplace && [[ -f "$ALL_URLS" ]]; then
        log_task_start "qsreplace injection points"

        # Generate XSS test URLs
        cat "$ALL_URLS" | grep "=" | qsreplace "FUZZ" 2>/dev/null | sort -u \
            > "${OUT_PARAMS}/fuzzable_urls.txt" || true

        log_task_done "Fuzzable URLs" "$(count_lines "${OUT_PARAMS}/fuzzable_urls.txt")"
    fi
}

# ── Execute ──────────────────────────────────────────────────────────────────
run_arjun
run_gf_patterns
run_qsreplace

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Parameter Discovery Statistics:${RESET}"
log_stats "Unique parameters" "$(count_lines "${OUT_PARAMS}/all_params.txt")"
log_stats "Fuzzable URLs" "$(count_lines "${OUT_PARAMS}/fuzzable_urls.txt")"
for gf_file in "${OUT_PARAMS}"/gf_*.txt; do
    [[ -f "$gf_file" ]] || continue
    gf_name="$(basename "$gf_file" .txt | sed 's/gf_//')"
    gf_count="$(count_lines "$gf_file")"
    [[ "$gf_count" -gt 0 ]] && log_stats "gf:${gf_name}" "$gf_count"
done
echo ""

TOTAL="$(count_lines "${OUT_PARAMS}/all_params.txt")"
log_module_end "Parameter Discovery" "$START_TIME" "$TOTAL"
