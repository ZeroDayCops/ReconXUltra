#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra X — Streaming Recon Pipeline
# ============================================================================
# Real-time pipe-based streaming between tools:
#   subfinder | dnsx | httpx | katana → JS/API/Param engines
#
# No waiting for module completion. Continuous enrichment.
# ============================================================================

DOMAIN="${1:?Usage: streaming_pipeline.sh <domain>}"

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"

# ── Named Pipes (FIFOs) for streaming ───────────────────────────────────────
STREAM_DIR="${RECONX_TMP}/streams"
mkdir -p "$STREAM_DIR"

PIPE_SUBS="${STREAM_DIR}/subs.pipe"
PIPE_RESOLVED="${STREAM_DIR}/resolved.pipe"
PIPE_LIVE="${STREAM_DIR}/live.pipe"
PIPE_URLS="${STREAM_DIR}/urls.pipe"
PIPE_JS="${STREAM_DIR}/js.pipe"

# Create named pipes
for pipe in "$PIPE_SUBS" "$PIPE_RESOLVED" "$PIPE_LIVE" "$PIPE_URLS" "$PIPE_JS"; do
    [[ -p "$pipe" ]] && rm -f "$pipe"
    mkfifo "$pipe" 2>/dev/null || true
done

# Output files (accumulate results)
SUBS_OUT="${OUT_SUBS}/all_subdomains.txt"
LIVE_OUT="${OUT_LIVE}/live_hosts.txt"
URLS_OUT="${OUT_URLS}/all_urls.txt"
JS_OUT="${OUT_JS}/js_urls.txt"

> "$SUBS_OUT"
> "$LIVE_OUT"
> "$URLS_OUT"
> "$JS_OUT"

# Threads from env or default
T="${THREADS:-100}"
R="${RATE_LIMIT:-500}"

log_info "Starting STREAMING pipeline for ${DOMAIN} (threads:${T} rate:${R})"

# ── Stage 1: Parallel Subdomain Discovery → Stream ─────────────────────────
stream_subdomains() {
    log_info "[STREAM-1] Subdomain discovery → streaming"
    local tmp_subs="${STREAM_DIR}/subs_tmp_$$"
    > "$tmp_subs"

    # Run all subdomain tools in parallel, tee into stream
    (
        # Subfinder
        if cmd_exists subfinder; then
            subfinder -d "$DOMAIN" -all -silent 2>/dev/null &
        fi

        # Assetfinder
        if cmd_exists assetfinder; then
            assetfinder --subs-only "$DOMAIN" 2>/dev/null &
        fi

        # Findomain
        if cmd_exists findomain; then
            findomain -t "$DOMAIN" -q 2>/dev/null &
        fi

        # crt.sh
        curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" 2>/dev/null | \
            jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' &

        # AlienVault
        curl -s "https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/passive_dns" 2>/dev/null | \
            jq -r '.passive_dns[]?.hostname' 2>/dev/null &

        wait
    ) | sort -u | tee -a "$SUBS_OUT" > "$PIPE_SUBS" &

    PIDS_STAGE1=$!
}

# ── Stage 2: DNS Resolution (reads from subdomain stream) ──────────────────
stream_resolve() {
    log_info "[STREAM-2] DNS resolution ← streaming from subs"

    if cmd_exists dnsx; then
        cat "$PIPE_SUBS" | dnsx -silent -a -resp -t "$T" -r "${RECONX_WORDLISTS}/resolvers.txt" 2>/dev/null | \
            tee "${OUT_RESOLVED}/resolved_subdomains.txt" | \
            awk '{print $1}' | sort -u > "$PIPE_RESOLVED" &
    else
        # Fallback: pass through
        cat "$PIPE_SUBS" > "$PIPE_RESOLVED" &
    fi

    PIDS_STAGE2=$!
}

# ── Stage 3: Live Host Probing (reads from resolved stream) ────────────────
stream_live_probe() {
    log_info "[STREAM-3] Live probing ← streaming from resolved"

    if cmd_exists httpx; then
        cat "$PIPE_RESOLVED" | httpx -silent -t "$T" -rl "$R" \
            -status-code -title -tech-detect -content-length -follow-redirects \
            -json -o "${OUT_LIVE}/httpx_full.json" 2>/dev/null | \
            jq -r '.url // empty' 2>/dev/null | \
            tee -a "$LIVE_OUT" > "$PIPE_LIVE" &
    else
        cat "$PIPE_RESOLVED" | while IFS= read -r host; do
            local url="https://${host}"
            local status
            status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null)"
            if [[ "$status" =~ ^[23] ]]; then
                echo "$url" | tee -a "$LIVE_OUT"
            fi
        done > "$PIPE_LIVE" &
    fi

    PIDS_STAGE3=$!
}

# ── Stage 4: URL Discovery (reads from live stream) ────────────────────────
stream_url_discovery() {
    log_info "[STREAM-4] URL discovery ← streaming from live hosts"

    cat "$PIPE_LIVE" | while IFS= read -r host; do
        # Parallel URL sources per host
        (
            if cmd_exists gau; then
                echo "$host" | gau --threads 5 2>/dev/null &
            fi
            if cmd_exists katana; then
                katana -u "$host" -d 3 -silent -jc -kf all -c 20 2>/dev/null &
            fi
            if cmd_exists hakrawler; then
                echo "$host" | hakrawler -d 2 -subs -u 2>/dev/null &
            fi
            if cmd_exists waybackurls; then
                echo "$host" | waybackurls 2>/dev/null &
            fi
            wait
        )
    done | sort -u | tee -a "$URLS_OUT" | \
        grep -iE '\.js(\?|$)' | tee -a "$JS_OUT" > "$PIPE_JS" 2>/dev/null &

    PIDS_STAGE4=$!
}

# ── Stage 5: JS + API Processing (reads from JS stream) ────────────────────
stream_js_analysis() {
    log_info "[STREAM-5] JS/API analysis ← streaming from URLs"

    cat "$PIPE_JS" | while IFS= read -r js_url; do
        # Extract endpoints from JS content
        local content
        content="$(curl -s --max-time 10 "$js_url" 2>/dev/null)"
        [[ -z "$content" ]] && continue

        # Quick inline endpoint extraction
        echo "$content" | grep -oE '"(/[a-zA-Z0-9_/.-]+)"' | tr -d '"' | \
            sed "s|^|[JS-ENDPOINT] ${js_url} → |" >> "${OUT_INTEL}/js_endpoints_stream.txt"

        # Quick secret scan
        echo "$content" | grep -oiE '(api[_-]?key|secret|token|password|aws_access|firebase)["\x27]?\s*[:=]\s*["\x27][a-zA-Z0-9/+=_-]{8,}' | \
            sed "s|^|[SECRET] ${js_url} → |" >> "${OUT_INTEL}/js_secrets_stream.txt"

    done &

    PIDS_STAGE5=$!
}

# ── Execute Streaming Pipeline ──────────────────────────────────────────────
run_streaming_pipeline() {
    local pipeline_start
    pipeline_start="$(date +%s)"

    log_info "═══════════════════════════════════════════════════════════"
    log_info "  STREAMING PIPELINE — ${DOMAIN}"
    log_info "  All stages running simultaneously"
    log_info "═══════════════════════════════════════════════════════════"

    # Launch all stages — they connect via named pipes
    stream_subdomains
    stream_resolve
    stream_live_probe
    stream_url_discovery
    stream_js_analysis

    # Wait for all stages
    log_info "All 5 stages running... waiting for completion"
    wait $PIDS_STAGE1 2>/dev/null; log_info "[STREAM-1] Subdomain discovery complete"
    wait $PIDS_STAGE2 2>/dev/null; log_info "[STREAM-2] DNS resolution complete"
    wait $PIDS_STAGE3 2>/dev/null; log_info "[STREAM-3] Live probing complete"
    wait $PIDS_STAGE4 2>/dev/null; log_info "[STREAM-4] URL discovery complete"
    wait $PIDS_STAGE5 2>/dev/null; log_info "[STREAM-5] JS/API analysis complete"

    # Dedup final outputs
    sort -u "$SUBS_OUT" -o "$SUBS_OUT"
    sort -u "$LIVE_OUT" -o "$LIVE_OUT"
    sort -u "$URLS_OUT" -o "$URLS_OUT"
    sort -u "$JS_OUT" -o "$JS_OUT"

    # Extract parameterized URLs
    grep -E '\?' "$URLS_OUT" | sort -u > "${OUT_URLS}/parameterized_urls.txt" 2>/dev/null

    # Stats
    local pipeline_end
    pipeline_end="$(date +%s)"
    local duration=$((pipeline_end - pipeline_start))
    local mins=$((duration / 60))
    local secs=$((duration % 60))

    echo ""
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  STREAMING PIPELINE COMPLETE — ${mins}m ${secs}s"
    log_info "═══════════════════════════════════════════════════════════"
    log_info "  Subdomains:     $(wc -l < "$SUBS_OUT" 2>/dev/null || echo 0)"
    log_info "  Live hosts:     $(wc -l < "$LIVE_OUT" 2>/dev/null || echo 0)"
    log_info "  URLs:           $(wc -l < "$URLS_OUT" 2>/dev/null || echo 0)"
    log_info "  JS files:       $(wc -l < "$JS_OUT" 2>/dev/null || echo 0)"
    log_info "  Parameterized:  $(wc -l < "${OUT_URLS}/parameterized_urls.txt" 2>/dev/null || echo 0)"
    log_info "═══════════════════════════════════════════════════════════"

    # Cleanup pipes
    rm -f "$PIPE_SUBS" "$PIPE_RESOLVED" "$PIPE_LIVE" "$PIPE_URLS" "$PIPE_JS"
}

# Entry point
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    run_streaming_pipeline
fi
