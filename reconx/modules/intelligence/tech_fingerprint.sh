#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — High-Risk Technology Fingerprinting
# ============================================================================
# Identifies high-value targets by fingerprinting technologies, admin panels,
# exposed services, and risky configurations from httpx probe data.
# ============================================================================

DOMAIN="${1:?Usage: tech_fingerprint.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Technology Fingerprinting" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
HTTPX_JSON="${OUT_LIVE}/httpx_full.json"
HVT_FILE="${OUT_INTEL}/high_value_targets.txt"
TECH_FILE="${OUT_INTEL}/technologies.txt"
ADMIN_FILE="${OUT_INTEL}/admin_panels.txt"

> "$HVT_FILE"
> "$TECH_FILE"
> "$ADMIN_FILE"

if [[ ! -f "$LIVE_HOSTS" ]] || [[ "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts found — skipping fingerprinting"
    exit 0
fi

HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
log_info "Fingerprinting ${HOST_COUNT} live hosts"

# ── High-Risk Technology Patterns ────────────────────────────────────────────
log_task_start "High-risk technology detection"

# Admin panel paths to probe
admin_paths="admin login dashboard manager wp-admin wp-login.php phpmyadmin adminer _profiler jenkins grafana kibana solr elasticsearch prometheus nagios zabbix webmin cpanel plesk directadmin jira confluence gitlab sonarqube rundeck airflow flower celery supervisor traefik consul vault portainer rancher argocd drone"

while IFS= read -r host; do
    host="${host%/}"
    for path in $admin_paths; do
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${host}/${path}" 2>/dev/null)"
        if [[ "$status" =~ ^(200|301|302|401|403)$ ]]; then
            echo "[${status}] ${host}/${path}" >> "$ADMIN_FILE"
            if [[ "$status" == "200" ]]; then
                echo "[ADMIN-PANEL] ${host}/${path}" >> "$HVT_FILE"
            fi
        fi
    done
done < <(head -50 "$LIVE_HOSTS")

log_task_done "Admin panel probing" "$(count_lines "$ADMIN_FILE")"

# ── Technology Detection from Headers ────────────────────────────────────────
log_task_start "Header-based technology detection"

while IFS= read -r host; do
    host="${host%/}"
    headers="$(curl -sI --max-time 5 "$host" 2>/dev/null)"
    [[ -z "$headers" ]] && continue

    # Server header
    server="$(echo "$headers" | grep -i '^server:' | head -1 | cut -d: -f2- | tr -d '\r' | xargs)"
    if [[ -n "$server" ]]; then
        echo "${host} | Server: ${server}" >> "$TECH_FILE"
    fi

    # X-Powered-By
    powered="$(echo "$headers" | grep -i '^x-powered-by:' | head -1 | cut -d: -f2- | tr -d '\r' | xargs)"
    if [[ -n "$powered" ]]; then
        echo "${host} | X-Powered-By: ${powered}" >> "$TECH_FILE"
        # Flag risky technologies
        if echo "$powered" | grep -qiE "PHP/[4-5]|ASP\.NET|Express|Django|Rails|Spring|Struts"; then
            echo "[RISKY-TECH] ${host} | ${powered}" >> "$HVT_FILE"
        fi
    fi

    # Missing security headers
    missing=""
    echo "$headers" | grep -qi "strict-transport-security" || missing="${missing}HSTS,"
    echo "$headers" | grep -qi "x-frame-options" || missing="${missing}XFO,"
    echo "$headers" | grep -qi "x-content-type-options" || missing="${missing}XCTO,"
    echo "$headers" | grep -qi "content-security-policy" || missing="${missing}CSP,"
    if [[ -n "$missing" ]]; then
        echo "${host} | Missing: ${missing%,}" >> "${OUT_INTEL}/missing_headers.txt"
    fi

    # Debug/information leakage headers
    if echo "$headers" | grep -qiE "x-debug|x-aspnet-version|x-aspnetmvc-version|x-runtime|x-version|x-generator"; then
        leak="$(echo "$headers" | grep -iE "x-debug|x-aspnet|x-runtime|x-version|x-generator" | tr '\n' ' ' | tr -d '\r')"
        echo "[INFO-LEAK] ${host} | ${leak}" >> "$HVT_FILE"
    fi
done < <(head -100 "$LIVE_HOSTS")

log_task_done "Technology detection" "$(count_lines "$TECH_FILE")"

# ── Nuclei Technology Detection ──────────────────────────────────────────────
if cmd_exists nuclei; then
    log_task_start "nuclei technology detection"
    nuclei -l "$LIVE_HOSTS" -tags tech -silent -c "$THREADS" \
        -json -o "${OUT_INTEL}/nuclei_tech.json" 2>/dev/null || true

    # Extract high-value findings
    if [[ -f "${OUT_INTEL}/nuclei_tech.json" ]]; then
        jq -r 'select(.info.severity == "info") | "\(.host) | \(.info.name)"' \
            "${OUT_INTEL}/nuclei_tech.json" >> "$TECH_FILE" 2>/dev/null || true
    fi
    log_task_done "nuclei tech" "$(jq -s 'length' "${OUT_INTEL}/nuclei_tech.json" 2>/dev/null || echo 0)"
fi

# ── Exposed Service Detection ───────────────────────────────────────────────
log_task_start "Exposed service detection"

svc_patterns="jenkins|grafana|kibana|elasticsearch|phpmyadmin|adminer|prometheus|nagios|solr|consul|traefik|portainer|gitlab|jira|confluence|sonarqube|minio|etcd|couchdb|redis|rabbitmq|mongodb|memcached"

if [[ -f "$HTTPX_JSON" ]]; then
    jq -r 'select(.title != null) | "\(.url) | \(.title)"' "$HTTPX_JSON" 2>/dev/null \
        | grep -iE "$svc_patterns" >> "$HVT_FILE" || true
fi

# Also check page titles via curl on live hosts
while IFS= read -r host; do
    title="$(curl -s --max-time 5 "$host" 2>/dev/null | grep -ioP '<title>\K[^<]+' | head -1)"
    if [[ -n "$title" ]]; then
        if echo "$title" | grep -qiE "$svc_patterns"; then
            echo "[EXPOSED-SVC] ${host} | Title: ${title}" >> "$HVT_FILE"
        fi
    fi
done < <(head -100 "$LIVE_HOSTS")

sort -u "$HVT_FILE" -o "$HVT_FILE"
log_task_done "Exposed services" "$(count_lines "$HVT_FILE")"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Technology Fingerprinting Results:${RESET}"
log_stats "Hosts scanned" "$HOST_COUNT"
log_stats "Technologies detected" "$(count_lines "$TECH_FILE")"
log_stats "Admin panels found" "$(count_lines "$ADMIN_FILE")"
log_stats "Missing security headers" "$(count_lines "${OUT_INTEL}/missing_headers.txt" 2>/dev/null || echo 0)"
log_stats_final "High-value targets" "$(count_lines "$HVT_FILE")"

log_module_end "Technology Fingerprinting" "$START_TIME" "$(count_lines "$HVT_FILE")"
