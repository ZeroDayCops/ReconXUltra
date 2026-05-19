#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Nmap Service Detection
# ============================================================================

DOMAIN="${1:?Usage: nmap.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Nmap Service Detection" "$DOMAIN"
START_TIME="$(date +%s)"

if ! cmd_exists nmap; then
    log_warn "nmap not installed — skipping"
    exit 0
fi

OPEN_PORTS="${OUT_SCANS}/open_ports.txt"
if [[ ! -f "$OPEN_PORTS" || "$(count_lines "$OPEN_PORTS")" -eq 0 ]]; then
    log_warn "No open ports found from naabu — running basic nmap scan"
    # Fallback: scan the domain directly
    nmap -sV -sC -T4 --top-ports 100 -oA "${OUT_SCANS}/nmap_${DOMAIN}" "$DOMAIN" 2>/dev/null || true
    TOTAL=1
else
    # Parse naabu results: group ports by host
    log_task_start "nmap service/version detection"

    declare -A HOST_PORTS
    while IFS=: read -r host port; do
        HOST_PORTS["$host"]="${HOST_PORTS[$host]:+${HOST_PORTS[$host]},}${port}"
    done < "$OPEN_PORTS"

    SCAN_LIMIT=20
    CURRENT=0
    for host in "${!HOST_PORTS[@]}"; do
        ((CURRENT++))
        [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

        ports="${HOST_PORTS[$host]}"
        host_safe="$(echo "$host" | tr '.' '_')"

        log_debug "Scanning $host ports: $ports"
        nmap -sV -sC -p "$ports" -T4 \
            -oA "${OUT_SCANS}/nmap_${host_safe}" \
            "$host" 2>/dev/null || true
    done

    log_task_done "nmap service detection"
    TOTAL="$CURRENT"
fi

# Merge nmap XML outputs
cat "${OUT_SCANS}"/nmap_*.xml 2>/dev/null > "${OUT_SCANS}/nmap_all.xml" || true

log_module_end "Nmap Service Detection" "$START_TIME" "$TOTAL"
