#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Nuclei Vulnerability Scanning
# ============================================================================
# Runs nuclei templates against live hosts with severity-based filtering,
# rate limiting, and organized output.
# ============================================================================

DOMAIN="${1:?Usage: scan.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

log_module_start "Nuclei Vulnerability Scanning" "$DOMAIN"
START_TIME="$(date +%s)"

if ! cmd_exists nuclei; then
    log_error "nuclei not installed"
    exit 1
fi

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping nuclei scan"
    exit 0
fi

HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
SEVERITY="${CONFIG[nuclei.severity]:-critical,high,medium}"
CONCURRENCY="${CONFIG[nuclei.concurrency]:-25}"
NUCLEI_RATE="${CONFIG[nuclei.rate_limit]:-150}"
BULK_SIZE="${CONFIG[nuclei.bulk_size]:-25}"
TEMPLATES_DIR="${CONFIG[nuclei.templates_dir]:-}"

log_info "Scanning ${HOST_COUNT} live hosts | Severity: ${SEVERITY}"

# ── Update Templates ────────────────────────────────────────────────────────
log_task_start "Updating nuclei templates"
nuclei -update-templates -silent 2>/dev/null || true
log_task_done "Templates updated"

# ── Full Scan — Critical & High ─────────────────────────────────────────────
log_task_start "nuclei scan: critical,high"
nuclei -l "$LIVE_HOSTS" \
    -severity critical,high \
    -silent \
    -c "$CONCURRENCY" \
    -rl "$NUCLEI_RATE" \
    -bs "$BULK_SIZE" \
    -timeout "$TIMEOUT" \
    -retries "$RETRIES" \
    -json \
    -o "${OUT_SCANS}/nuclei_critical_high.json" \
    -me "${OUT_SCANS}/nuclei_matches/" 2>/dev/null || true

# Extract plain text results
jq -r '"\(.info.severity | ascii_upcase) | \(.["template-id"]) | \(.host) | \(.info.name)"' \
    "${OUT_SCANS}/nuclei_critical_high.json" 2>/dev/null \
    | sort -u > "${OUT_SCANS}/nuclei_critical_high.txt" || true
log_task_done "Critical/High findings" "$(count_lines "${OUT_SCANS}/nuclei_critical_high.txt")"

# ── Medium Severity ─────────────────────────────────────────────────────────
log_task_start "nuclei scan: medium"
nuclei -l "$LIVE_HOSTS" \
    -severity medium \
    -silent \
    -c "$CONCURRENCY" \
    -rl "$NUCLEI_RATE" \
    -bs "$BULK_SIZE" \
    -json \
    -o "${OUT_SCANS}/nuclei_medium.json" 2>/dev/null || true

jq -r '"\(.info.severity | ascii_upcase) | \(.["template-id"]) | \(.host) | \(.info.name)"' \
    "${OUT_SCANS}/nuclei_medium.json" 2>/dev/null \
    | sort -u > "${OUT_SCANS}/nuclei_medium.txt" || true
log_task_done "Medium findings" "$(count_lines "${OUT_SCANS}/nuclei_medium.txt")"

# ── Specific Template Categories ────────────────────────────────────────────

# CVEs
log_task_start "nuclei CVE templates"
nuclei -l "$LIVE_HOSTS" \
    -tags cve \
    -severity critical,high \
    -silent \
    -c "$CONCURRENCY" \
    -rl "$NUCLEI_RATE" \
    -json \
    -o "${OUT_SCANS}/nuclei_cves.json" 2>/dev/null || true
log_task_done "CVE findings" "$(jq -s 'length' "${OUT_SCANS}/nuclei_cves.json" 2>/dev/null || echo 0)"

# Exposures
log_task_start "nuclei exposure templates"
nuclei -l "$LIVE_HOSTS" \
    -tags exposure \
    -silent \
    -c "$CONCURRENCY" \
    -json \
    -o "${OUT_SCANS}/nuclei_exposures.json" 2>/dev/null || true
log_task_done "Exposure findings" "$(jq -s 'length' "${OUT_SCANS}/nuclei_exposures.json" 2>/dev/null || echo 0)"

# Misconfigurations
log_task_start "nuclei misconfig templates"
nuclei -l "$LIVE_HOSTS" \
    -tags misconfig \
    -silent \
    -c "$CONCURRENCY" \
    -json \
    -o "${OUT_SCANS}/nuclei_misconfig.json" 2>/dev/null || true
log_task_done "Misconfig findings" "$(jq -s 'length' "${OUT_SCANS}/nuclei_misconfig.json" 2>/dev/null || echo 0)"

# ── Custom Templates (if available) ─────────────────────────────────────────
if [[ -n "$TEMPLATES_DIR" && -d "$TEMPLATES_DIR" ]]; then
    log_task_start "Custom nuclei templates"
    nuclei -l "$LIVE_HOSTS" \
        -t "$TEMPLATES_DIR" \
        -silent \
        -c "$CONCURRENCY" \
        -json \
        -o "${OUT_SCANS}/nuclei_custom.json" 2>/dev/null || true
    log_task_done "Custom template findings" "$(jq -s 'length' "${OUT_SCANS}/nuclei_custom.json" 2>/dev/null || echo 0)"
fi

# ── Merge All Results ────────────────────────────────────────────────────────
log_task_start "Merging all nuclei results"
cat "${OUT_SCANS}"/nuclei_*.json 2>/dev/null | jq -s '.' > "${OUT_SCANS}/nuclei_all.json" 2>/dev/null || true
cat "${OUT_SCANS}"/nuclei_*.txt 2>/dev/null | sort -u > "${OUT_SCANS}/nuclei_all_summary.txt" || true
TOTAL="$(count_lines "${OUT_SCANS}/nuclei_all_summary.txt")"
log_task_done "Total nuclei findings" "$TOTAL"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Nuclei Scan Statistics:${RESET}"
log_stats "Hosts scanned" "$HOST_COUNT"
log_stats "Critical/High" "$(count_lines "${OUT_SCANS}/nuclei_critical_high.txt")"
log_stats "Medium" "$(count_lines "${OUT_SCANS}/nuclei_medium.txt")"
log_stats_final "Total findings" "$TOTAL"

log_module_end "Nuclei Vulnerability Scanning" "$START_TIME" "$TOTAL"
