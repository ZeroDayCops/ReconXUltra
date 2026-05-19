#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Port Scanning (naabu)
# ============================================================================

DOMAIN="${1:?Usage: naabu.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Port Scanning (naabu)" "$DOMAIN"
START_TIME="$(date +%s)"

if ! cmd_exists naabu; then
    log_error "naabu not installed"
    exit 1
fi

INPUT="${OUT_SUBS}/all_subdomains.txt"
if [[ ! -f "$INPUT" || "$(count_lines "$INPUT")" -eq 0 ]]; then
    INPUT="${OUT_LIVE}/live_hosts.txt"
fi

if [[ ! -f "$INPUT" || "$(count_lines "$INPUT")" -eq 0 ]]; then
    log_warn "No targets for port scanning"
    exit 0
fi

TARGET_COUNT="$(count_lines "$INPUT")"
log_info "Scanning ports on ${TARGET_COUNT} targets"

# ── Top Ports Scan ──────────────────────────────────────────────────────────
log_task_start "naabu top 1000 ports"
naabu -list "$INPUT" \
    -top-ports 1000 \
    -silent \
    -c "$THREADS" \
    -rate "$RATE_LIMIT" \
    -json \
    -o "${OUT_SCANS}/naabu_results.json" 2>/dev/null || true

# Extract host:port pairs
jq -r '"\(.host):\(.port)"' "${OUT_SCANS}/naabu_results.json" 2>/dev/null \
    | sort -u > "${OUT_SCANS}/open_ports.txt" || true

# Extract unique ports
jq -r '.port' "${OUT_SCANS}/naabu_results.json" 2>/dev/null \
    | sort -u > "${OUT_SCANS}/unique_ports.txt" || true

# Extract hosts with open ports
jq -r '.host' "${OUT_SCANS}/naabu_results.json" 2>/dev/null \
    | sort -u > "${OUT_SCANS}/hosts_with_ports.txt" || true

TOTAL="$(count_lines "${OUT_SCANS}/open_ports.txt")"
log_task_done "Open ports found" "$TOTAL"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Port Scan Statistics:${RESET}"
log_stats "Targets scanned" "$TARGET_COUNT"
log_stats "Open ports" "$TOTAL"
log_stats "Unique ports" "$(count_lines "${OUT_SCANS}/unique_ports.txt")"
log_stats_final "Hosts w/ open ports" "$(count_lines "${OUT_SCANS}/hosts_with_ports.txt")"

# Show top ports
echo ""
echo -e "  ${BOLD}${WHITE}Top Ports:${RESET}"
jq -r '.port' "${OUT_SCANS}/naabu_results.json" 2>/dev/null \
    | sort | uniq -c | sort -rn | head -10 \
    | while read -r count port; do
        log_stats "Port ${port}" "${count} hosts"
    done

log_module_end "Port Scanning (naabu)" "$START_TIME" "$TOTAL"
