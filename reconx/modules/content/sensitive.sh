#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Sensitive File Discovery
# ============================================================================
# Probes for exposed sensitive files: .env, .git, backup files, config files,
# debug endpoints, and other common misconfigurations.
# ============================================================================

DOMAIN="${1:?Usage: sensitive.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Sensitive File Discovery" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping sensitive file check"
    exit 0
fi

# ── Sensitive Paths ──────────────────────────────────────────────────────────
SENSITIVE_PATHS=(
    ".env"
    ".env.bak"
    ".env.local"
    ".env.production"
    ".env.development"
    ".git/config"
    ".git/HEAD"
    ".git/index"
    ".gitignore"
    ".svn/entries"
    ".svn/wc.db"
    ".htaccess"
    ".htpasswd"
    ".DS_Store"
    "wp-config.php.bak"
    "web.config"
    "config.php"
    "config.yml"
    "config.json"
    "database.yml"
    "settings.py"
    "application.yml"
    "application.properties"
    "phpinfo.php"
    "info.php"
    "server-status"
    "server-info"
    ".well-known/security.txt"
    "robots.txt"
    "sitemap.xml"
    "crossdomain.xml"
    "clientaccesspolicy.xml"
    "elmah.axd"
    "trace.axd"
    "debug/default/view"
    "_debug_toolbar/"
    "__debug__/"
    "actuator"
    "actuator/env"
    "actuator/health"
    "actuator/configprops"
    "actuator/mappings"
    "actuator/beans"
    "actuator/heapdump"
    "api/swagger.json"
    "swagger.json"
    "swagger-ui.html"
    "api-docs"
    "openapi.json"
    ".aws/credentials"
    "docker-compose.yml"
    "Dockerfile"
    "Makefile"
    "package.json"
    "composer.json"
    "Gemfile"
    "requirements.txt"
    "webpack.config.js"
    ".npmrc"
    ".pypirc"
    "id_rsa"
    "id_dsa"
    "backup.sql"
    "dump.sql"
    "database.sql"
    "db.sql"
    "debug.log"
    "error.log"
    "access.log"
)

# ── Probe Function ──────────────────────────────────────────────────────────
probe_sensitive() {
    local url="$1"
    local path="$2"
    local full_url="${url%/}/${path}"

    local response
    response="$(curl -s -o /dev/null -w '%{http_code}|%{size_download}|%{content_type}' \
        --max-time 10 -L "$full_url" 2>/dev/null)" || return

    local status="${response%%|*}"
    local rest="${response#*|}"
    local size="${rest%%|*}"
    local ctype="${rest#*|}"

    # Filter out generic error pages (small 200s or large 404s)
    if [[ "$status" == "200" && "$size" -gt 50 ]]; then
        echo "${full_url} [${status}] [${size}B] [${ctype}]"
    elif [[ "$status" == "403" ]]; then
        echo "${full_url} [${status}] [FORBIDDEN]"
    fi
}

# ── Scan Hosts ──────────────────────────────────────────────────────────────
log_task_start "Probing for sensitive files"
RESULTS_FILE="${OUT_CONTENT}/sensitive_files.txt"
> "$RESULTS_FILE"

SCAN_LIMIT=30
CURRENT=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    ((CURRENT++))
    [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

    log_debug "Probing: $url"

    for path in "${SENSITIVE_PATHS[@]}"; do
        result="$(probe_sensitive "$url" "$path")"
        if [[ -n "$result" ]]; then
            echo "$result" >> "$RESULTS_FILE"
        fi
    done &

    # Limit parallelism
    if [[ $((CURRENT % 10)) -eq 0 ]]; then
        wait
    fi
done < "$LIVE_HOSTS"
wait

sort -u "$RESULTS_FILE" -o "$RESULTS_FILE"
TOTAL="$(count_lines "$RESULTS_FILE")"

# ── Categorize Findings ─────────────────────────────────────────────────────
log_task_start "Categorizing findings"

# Git exposure
grep -i "\.git" "$RESULTS_FILE" > "${OUT_CONTENT}/exposed_git.txt" 2>/dev/null || true

# Environment files
grep -i "\.env" "$RESULTS_FILE" > "${OUT_CONTENT}/exposed_env.txt" 2>/dev/null || true

# Config files
grep -iE "\.(yml|yaml|json|xml|ini|conf|cfg|properties)" "$RESULTS_FILE" \
    > "${OUT_CONTENT}/exposed_configs.txt" 2>/dev/null || true

# Debug endpoints
grep -iE "(debug|actuator|phpinfo|trace|server-status)" "$RESULTS_FILE" \
    > "${OUT_CONTENT}/exposed_debug.txt" 2>/dev/null || true

# API docs
grep -iE "(swagger|openapi|api-docs)" "$RESULTS_FILE" \
    > "${OUT_CONTENT}/exposed_api_docs.txt" 2>/dev/null || true

log_task_done "Categorization"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Sensitive File Statistics:${RESET}"
log_stats "Total findings" "$TOTAL"
log_stats "Git exposure" "$(count_lines "${OUT_CONTENT}/exposed_git.txt")"
log_stats "Env files" "$(count_lines "${OUT_CONTENT}/exposed_env.txt")"
log_stats "Config files" "$(count_lines "${OUT_CONTENT}/exposed_configs.txt")"
log_stats "Debug endpoints" "$(count_lines "${OUT_CONTENT}/exposed_debug.txt")"
log_stats_final "API docs" "$(count_lines "${OUT_CONTENT}/exposed_api_docs.txt")"

log_module_end "Sensitive File Discovery" "$START_TIME" "$TOTAL"
