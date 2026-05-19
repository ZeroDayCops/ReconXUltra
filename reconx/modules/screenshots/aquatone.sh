#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Screenshots (aquatone/gowitness)
# ============================================================================

DOMAIN="${1:?Usage: aquatone.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Screenshots" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping screenshots"
    exit 0
fi

HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
log_info "Taking screenshots of ${HOST_COUNT} live hosts"

# ── Try gowitness first (more modern) ────────────────────────────────────────
if cmd_exists gowitness; then
    log_task_start "gowitness screenshot capture"
    gowitness file -f "$LIVE_HOSTS" \
        --screenshot-path "${OUT_SCREENSHOTS}" \
        --threads "$THREADS" \
        --timeout "$TIMEOUT" \
        --disable-logging 2>/dev/null || true
    TOTAL="$(ls "${OUT_SCREENSHOTS}"/*.png 2>/dev/null | wc -l)"
    log_task_done "gowitness screenshots" "$TOTAL"

# ── Fallback to aquatone ─────────────────────────────────────────────────────
elif cmd_exists aquatone; then
    log_task_start "aquatone screenshot capture"
    cat "$LIVE_HOSTS" | aquatone \
        -out "${OUT_SCREENSHOTS}" \
        -threads "$THREADS" \
        -timeout "$((TIMEOUT * 1000))" \
        -silent 2>/dev/null || true
    TOTAL="$(ls "${OUT_SCREENSHOTS}/screenshots"/*.png 2>/dev/null | wc -l)"
    log_task_done "aquatone screenshots" "$TOTAL"

# ── Fallback to httpx screenshots ────────────────────────────────────────────
elif cmd_exists httpx; then
    log_task_start "httpx screenshot capture"
    httpx -l "$LIVE_HOSTS" \
        -silent \
        -screenshot \
        -srd "${OUT_SCREENSHOTS}" \
        -threads "$THREADS" 2>/dev/null || true
    TOTAL="$(find "${OUT_SCREENSHOTS}" -name "*.png" 2>/dev/null | wc -l)"
    log_task_done "httpx screenshots" "$TOTAL"
else
    log_warn "No screenshot tool available (gowitness, aquatone, or httpx required)"
    TOTAL=0
fi

log_module_end "Screenshots" "$START_TIME" "$TOTAL"
