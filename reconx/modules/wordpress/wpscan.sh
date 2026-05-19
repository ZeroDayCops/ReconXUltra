#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — WordPress Detection & Scanning
# ============================================================================

DOMAIN="${1:?Usage: wpscan.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "WordPress Detection & Scanning" "$DOMAIN"
START_TIME="$(date +%s)"

WP_DIR="${OUT_SCANS}/wordpress"
mkdir -p "$WP_DIR"

# ── Detect WordPress Sites ─────────────────────────────────────────────────
log_task_start "Detecting WordPress installations"
WP_SITES="${WP_DIR}/wp_sites.txt"
> "$WP_SITES"

TECH_FILE="${OUT_LIVE}/technologies.txt"
if [[ -f "$TECH_FILE" ]]; then
    grep -i "wordpress" "$TECH_FILE" | awk '{print $1}' | sort -u > "$WP_SITES" || true
fi

# Also check from httpx JSON
if [[ -f "${OUT_LIVE}/httpx_full.json" ]]; then
    jq -r 'select(.tech != null) | select(.tech | map(ascii_downcase) | any(contains("wordpress"))) | .url' \
        "${OUT_LIVE}/httpx_full.json" 2>/dev/null \
        | sort -u >> "$WP_SITES" || true
fi

# Manual check for /wp-login.php and /wp-admin
LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ -f "$LIVE_HOSTS" ]]; then
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        status="$(curl -s -o /dev/null -w '%{http_code}' "${url}/wp-login.php" --max-time 10 2>/dev/null)"
        if [[ "$status" == "200" || "$status" == "302" ]]; then
            echo "$url" >> "$WP_SITES"
        fi
    done < <(head -50 "$LIVE_HOSTS")
fi

sort -u "$WP_SITES" -o "$WP_SITES"
WP_COUNT="$(count_lines "$WP_SITES")"
log_task_done "WordPress sites found" "$WP_COUNT"

if [[ "$WP_COUNT" -eq 0 ]]; then
    log_info "No WordPress sites detected — skipping WP scan"
    log_module_end "WordPress Detection" "$START_TIME" 0
    exit 0
fi

# ── WPScan ──────────────────────────────────────────────────────────────────
if cmd_exists wpscan; then
    log_task_start "WPScan vulnerability scanning"
    SCAN_LIMIT=10
    CURRENT=0

    while IFS= read -r wp_url; do
        [[ -z "$wp_url" ]] && continue
        ((CURRENT++))
        [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

        host_hash="$(echo "$wp_url" | md5sum | cut -c1-8)"
        log_debug "WPScan: $wp_url"

        wpscan --url "$wp_url" \
            --enumerate vp,vt,u1-10,m \
            --random-user-agent \
            --format json \
            --output "${WP_DIR}/wpscan_${host_hash}.json" \
            --no-banner 2>/dev/null || true
    done < "$WP_SITES"

    log_task_done "WPScan completed" "$CURRENT"
else
    log_warn "wpscan not installed — using nuclei WordPress templates"
fi

# ── Nuclei WordPress Templates ──────────────────────────────────────────────
if cmd_exists nuclei; then
    log_task_start "nuclei WordPress templates"
    nuclei -l "$WP_SITES" \
        -tags wordpress \
        -silent \
        -json \
        -o "${WP_DIR}/nuclei_wp.json" 2>/dev/null || true
    log_task_done "nuclei WordPress" "$(jq -s 'length' "${WP_DIR}/nuclei_wp.json" 2>/dev/null || echo 0)"
fi

echo ""
echo -e "  ${BOLD}${WHITE}WordPress Statistics:${RESET}"
log_stats "WordPress sites" "$WP_COUNT"
log_stats_final "Scan reports" "$(ls "${WP_DIR}"/wpscan_*.json 2>/dev/null | wc -l)"

log_module_end "WordPress Detection & Scanning" "$START_TIME" "$WP_COUNT"
