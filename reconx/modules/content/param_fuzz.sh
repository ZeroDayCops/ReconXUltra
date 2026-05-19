#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Smart Parameter Discovery & Fuzzing
# ============================================================================
# Discovers hidden parameters using param.txt + params.txt wordlists.
# Performs technology-aware parameter fuzzing with response diff analysis.
# ============================================================================

DOMAIN="${1:?Usage: param_fuzz.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Parameter Discovery & Fuzzing" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping parameter fuzzing"
    exit 0
fi

PARAM_RESULTS="${OUT_INTEL}/discovered_params.txt"
> "$PARAM_RESULTS"

# ── Load parameter wordlists ────────────────────────────────────────────────
PARAM_WL_1="${RECONX_WORDLISTS}/param.txt"
PARAM_WL_2="${RECONX_WORDLISTS}/params.txt"

COMBINED_PARAMS="${RECONX_TMP}/combined_params_${RANDOM}.txt"
> "$COMBINED_PARAMS"

[[ -f "$PARAM_WL_1" ]] && cat "$PARAM_WL_1" >> "$COMBINED_PARAMS"
[[ -f "$PARAM_WL_2" ]] && cat "$PARAM_WL_2" >> "$COMBINED_PARAMS"
sort -u "$COMBINED_PARAMS" -o "$COMBINED_PARAMS"

PARAM_COUNT="$(count_lines "$COMBINED_PARAMS")"
if [[ "$PARAM_COUNT" -eq 0 ]]; then
    log_warn "No parameter wordlists found"
    exit 0
fi

log_info "Loaded ${PARAM_COUNT} unique parameters from wordlists"

# ── Arjun-style parameter discovery ─────────────────────────────────────────
run_param_discovery() {
    local url="$1"
    local host_hash
    host_hash="$(echo "$url" | md5sum | cut -c1-8)"

    # Get baseline response
    local baseline_size
    baseline_size="$(curl -s -o /dev/null -w '%{size_download}' --max-time 5 "$url" 2>/dev/null)"

    # Test parameters in batches
    local batch_size=10
    local batch=""
    local count=0

    while IFS= read -r param; do
        [[ -z "$param" ]] && continue
        count=$((count + 1))
        [[ "$count" -gt 500 ]] && break  # Limit per host

        if [[ -z "$batch" ]]; then
            batch="${param}=FUZZ"
        else
            batch="${batch}&${param}=FUZZ"
        fi

        if [[ $((count % batch_size)) -eq 0 ]]; then
            local test_url="${url}?${batch}"
            local resp_size
            resp_size="$(curl -s -o /dev/null -w '%{size_download}' --max-time 5 "$test_url" 2>/dev/null)"

            # Check if response differs (parameter accepted)
            if [[ "$resp_size" -ne "$baseline_size" ]] && [[ "$resp_size" -gt 0 ]]; then
                # Test individual params from this batch
                IFS='&' read -ra pairs <<< "$batch"
                for pair in "${pairs[@]}"; do
                    local p_name="${pair%%=*}"
                    local single_url="${url}?${p_name}=test123"
                    local single_size
                    single_size="$(curl -s -o /dev/null -w '%{size_download}' --max-time 5 "$single_url" 2>/dev/null)"
                    if [[ "$single_size" -ne "$baseline_size" ]] && [[ "$single_size" -gt 0 ]]; then
                        echo "[PARAM] ${url} | ${p_name} (${single_size}b vs ${baseline_size}b)" >> "$PARAM_RESULTS"
                    fi
                done
            fi
            batch=""
        fi
    done < "$COMBINED_PARAMS"
}

# ── ffuf-based parameter fuzzing ─────────────────────────────────────────────
run_ffuf_params() {
    if ! cmd_exists ffuf; then
        log_warn "ffuf not installed — using curl-only param discovery"
        return
    fi

    log_task_start "ffuf parameter fuzzing"
    local max_hosts=20
    local current=0

    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        current=$((current + 1))
        [[ "$current" -gt "$max_hosts" ]] && break

        local host_hash
        host_hash="$(echo "$url" | md5sum | cut -c1-8)"

        # GET parameter fuzzing
        ffuf -u "${url}?FUZZ=test" \
            -w "$COMBINED_PARAMS" \
            -mc 200,301,302,307,401,403,405 \
            -fs "$(curl -s -o /dev/null -w '%{size_download}' --max-time 5 "$url" 2>/dev/null)" \
            -t "$THREADS" -rate "$RATE_LIMIT" \
            -o "${OUT_CONTENT}/params_${host_hash}.json" \
            -of json -s 2>/dev/null || true
    done < <(head -"$max_hosts" "$LIVE_HOSTS")

    # Extract results
    for result_file in "${OUT_CONTENT}"/params_*.json; do
        [[ -f "$result_file" ]] || continue
        jq -r '.results[]? | "[FFUF-PARAM] \(.url) | \(.input.FUZZ) [\(.status)] [\(.length)]"' \
            "$result_file" >> "$PARAM_RESULTS" 2>/dev/null || true
    done

    log_task_done "ffuf params" "$(grep -c FFUF-PARAM "$PARAM_RESULTS" 2>/dev/null || echo 0)"
}

# ── Execute ──────────────────────────────────────────────────────────────────
log_task_start "curl-based parameter discovery"
CURRENT=0
MAX_HOSTS=15

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    CURRENT=$((CURRENT + 1))
    [[ "$CURRENT" -gt "$MAX_HOSTS" ]] && break
    run_param_discovery "$url"
done < "$LIVE_HOSTS"

log_task_done "curl param discovery" "$(grep -c '\[PARAM\]' "$PARAM_RESULTS" 2>/dev/null || echo 0)"

run_ffuf_params

sort -u "$PARAM_RESULTS" -o "$PARAM_RESULTS"
TOTAL="$(count_lines "$PARAM_RESULTS")"

echo ""
echo -e "  ${BOLD}${WHITE}Parameter Discovery Results:${RESET}"
log_stats "Parameters tested" "$PARAM_COUNT"
log_stats "Hosts scanned" "$MAX_HOSTS"
log_stats_final "Hidden params found" "$TOTAL"

rm -f "$COMBINED_PARAMS"
log_module_end "Parameter Discovery" "$START_TIME" "$TOTAL"
