#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — CORS Misconfiguration Detection
# ============================================================================

DOMAIN="${1:?Usage: cors.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "CORS Misconfiguration Detection" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping CORS check"
    exit 0
fi

HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
CORS_DIR="${OUT_SCANS}/cors"
mkdir -p "$CORS_DIR"

# ── Corsy (Python CORS scanner) ─────────────────────────────────────────────
if cmd_exists corsy || python3 -c "import corsy" 2>/dev/null; then
    log_task_start "Corsy CORS analysis"
    python3 -m corsy -i "$LIVE_HOSTS" -o "${CORS_DIR}/corsy_results.json" \
        -t "$THREADS" 2>/dev/null || true
    log_task_done "Corsy" "$(jq 'length' "${CORS_DIR}/corsy_results.json" 2>/dev/null || echo 0)"
fi

# ── Manual CORS Check ───────────────────────────────────────────────────────
log_task_start "Manual CORS misconfiguration check"
CORS_RESULTS="${CORS_DIR}/cors_findings.txt"
> "$CORS_RESULTS"

# Test origins
TEST_ORIGINS=(
    "https://evil.com"
    "https://${DOMAIN}.evil.com"
    "https://evil${DOMAIN}"
    "null"
    "https://${DOMAIN}"
)

SCAN_LIMIT=50
CURRENT=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    ((CURRENT++))
    [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

    for origin in "${TEST_ORIGINS[@]}"; do
        response_headers="$(curl -s -I -H "Origin: ${origin}" "$url" --max-time 10 2>/dev/null)"

        acao="$(echo "$response_headers" | grep -i 'access-control-allow-origin' | tr -d '\r')"
        acac="$(echo "$response_headers" | grep -i 'access-control-allow-credentials' | tr -d '\r')"

        if [[ -n "$acao" ]]; then
            # Check for wildcard
            if echo "$acao" | grep -q "\*"; then
                echo "[WILDCARD] ${url} | Origin: ${origin} | ${acao}" >> "$CORS_RESULTS"
            fi

            # Check for reflection
            if echo "$acao" | grep -qi "$origin"; then
                severity="MEDIUM"
                if echo "$acac" | grep -qi "true"; then
                    severity="HIGH"
                fi
                echo "[${severity}] ${url} | Origin: ${origin} | ${acao} ${acac}" >> "$CORS_RESULTS"
            fi

            # Check for null origin
            if echo "$acao" | grep -qi "null"; then
                echo "[HIGH] ${url} | Origin: null accepted | ${acao} ${acac}" >> "$CORS_RESULTS"
            fi
        fi
    done
done < "$LIVE_HOSTS"

sort -u "$CORS_RESULTS" -o "$CORS_RESULTS"
TOTAL="$(count_lines "$CORS_RESULTS")"
log_task_done "CORS findings" "$TOTAL"

# ── nuclei CORS templates ──────────────────────────────────────────────────
if cmd_exists nuclei; then
    log_task_start "nuclei CORS templates"
    nuclei -l "$LIVE_HOSTS" \
        -tags cors \
        -silent \
        -json \
        -o "${CORS_DIR}/nuclei_cors.json" 2>/dev/null || true
    log_task_done "nuclei CORS" "$(jq -s 'length' "${CORS_DIR}/nuclei_cors.json" 2>/dev/null || echo 0)"
fi

echo ""
echo -e "  ${BOLD}${WHITE}CORS Statistics:${RESET}"
log_stats "Hosts checked" "$CURRENT"
log_stats_final "CORS findings" "$TOTAL"

log_module_end "CORS Misconfiguration Detection" "$START_TIME" "$TOTAL"
