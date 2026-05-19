#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Response Analysis Engine
# ============================================================================
# Analyzes HTTP responses for debug messages, stack traces, verbose errors,
# framework disclosure, and information leakage.
# ============================================================================

DOMAIN="${1:?Usage: response_analyzer.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Response Analysis Engine" "$DOMAIN"
START_TIME="$(date +%s)"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
RESPONSE_FILE="${OUT_INTEL}/response_analysis.txt"
DEBUG_FILE="${OUT_INTEL}/debug_leakage.txt"
ERROR_FILE="${OUT_INTEL}/verbose_errors.txt"

> "$RESPONSE_FILE"
> "$DEBUG_FILE"
> "$ERROR_FILE"

if [[ ! -f "$LIVE_HOSTS" ]] || [[ "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping response analysis"
    exit 0
fi

HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
log_info "Analyzing responses from ${HOST_COUNT} hosts"

# ── Error Page Analysis ──────────────────────────────────────────────────────
log_task_start "Error page analysis (404/500 triggers)"

error_triggers="/%00 /..%00 /AAAAAAAA /'\"><img> /{{7*7}} /<script> /WEB-INF/web.xml /test.aspx /test.php /nonexistent$(date +%s)"

scan_count=0
while IFS= read -r host; do
    [[ "$scan_count" -ge 75 ]] && break
    scan_count=$((scan_count + 1))
    host="${host%/}"

    for trigger in $error_triggers; do
        resp="$(curl -s --max-time 8 -o - -w '\n__STATUS__%{http_code}' "${host}${trigger}" 2>/dev/null)"
        status="$(echo "$resp" | grep '__STATUS__' | sed 's/__STATUS__//')"
        body="$(echo "$resp" | grep -v '__STATUS__')"

        [[ -z "$body" ]] && continue

        # Stack trace detection
        if echo "$body" | grep -qiE "stack\s*trace|traceback|exception|at\s+[a-zA-Z0-9_.]+\.(java|cs|py|rb|php|js):|System\.(Web|IO|Data)|Microsoft\.\w+|java\.\w+\.\w+|TypeError:|SyntaxError:|RuntimeError:"; then
            echo "[STACK-TRACE] ${host}${trigger} (${status})" >> "$DEBUG_FILE"
            echo "[CRITICAL] Stack trace exposed: ${host}${trigger}" >> "$RESPONSE_FILE"
        fi

        # Debug mode detection
        if echo "$body" | grep -qiE "debug\s*=\s*true|DJANGO_SETTINGS|DEBUG_MODE|WP_DEBUG|APP_DEBUG|display_errors|xdebug|Whoops!|Laravel|Symfony.*Debug"; then
            echo "[DEBUG-MODE] ${host}${trigger} (${status})" >> "$DEBUG_FILE"
            echo "[HIGH] Debug mode enabled: ${host}${trigger}" >> "$RESPONSE_FILE"
        fi

        # Verbose error messages
        if echo "$body" | grep -qiE "SQL syntax|mysql_|pg_query|ORA-[0-9]+|ODBC|sqlite3\.|SQLSTATE|syntax error.*SQL|Division by zero|Undefined (variable|index|offset)|Warning:.*on line|Fatal error|Parse error|Uncaught exception"; then
            echo "[SQL-ERROR] ${host}${trigger} (${status})" >> "$ERROR_FILE"
            echo "[CRITICAL] SQL/verbose error: ${host}${trigger}" >> "$RESPONSE_FILE"
        fi

        # Path disclosure
        if echo "$body" | grep -qoE "(/var/www|/home/\w+|C:\\\\[a-zA-Z]+|/usr/local|/opt/|/srv/|/etc/\w+)"; then
            path="$(echo "$body" | grep -oE "(/var/www|/home/\w+|C:\\\\[a-zA-Z]+|/usr/local|/opt/|/srv/)[^ <\"']*" | head -1)"
            echo "[PATH-LEAK] ${host}${trigger} -> ${path}" >> "$DEBUG_FILE"
            echo "[HIGH] Path disclosure: ${host}${trigger} -> ${path}" >> "$RESPONSE_FILE"
        fi

        # Framework/version disclosure in body
        if echo "$body" | grep -qiE "Apache/[0-9]|nginx/[0-9]|IIS/[0-9]|PHP/[0-9]|X-Powered-By|ASP\.NET Version"; then
            ver="$(echo "$body" | grep -oiE "(Apache|nginx|IIS|PHP)/[0-9][0-9.]*" | head -1)"
            if [[ -n "$ver" ]]; then
                echo "[VERSION] ${host} -> ${ver}" >> "$RESPONSE_FILE"
            fi
        fi
    done
done < "$LIVE_HOSTS"

log_task_done "Error page analysis" "$(count_lines "$DEBUG_FILE")"

# ── Sensitive Endpoint Response Check ────────────────────────────────────────
log_task_start "Sensitive endpoint probing"

sensitive_paths=".env .git/config .git/HEAD .svn/entries .DS_Store wp-config.php.bak web.config.bak .htaccess .htpasswd phpinfo.php info.php server-status server-info _profiler crossdomain.xml clientaccesspolicy.xml robots.txt sitemap.xml security.txt .well-known/security.txt"

sens_count=0
while IFS= read -r host; do
    [[ "$sens_count" -ge 50 ]] && break
    sens_count=$((sens_count + 1))
    host="${host%/}"

    for path in $sensitive_paths; do
        status="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "${host}/${path}" 2>/dev/null)"
        if [[ "$status" == "200" ]]; then
            size="$(curl -s --max-time 5 "${host}/${path}" 2>/dev/null | wc -c)"
            if [[ "$size" -gt 10 ]]; then
                echo "[EXPOSED] ${host}/${path} (${size} bytes)" >> "$RESPONSE_FILE"
            fi
        fi
    done
done < "$LIVE_HOSTS"

log_task_done "Sensitive endpoints" "$(grep -c EXPOSED "$RESPONSE_FILE" 2>/dev/null || echo 0)"

# ── Merge & Deduplicate ─────────────────────────────────────────────────────
sort -u "$RESPONSE_FILE" -o "$RESPONSE_FILE"
sort -u "$DEBUG_FILE" -o "$DEBUG_FILE"
sort -u "$ERROR_FILE" -o "$ERROR_FILE"

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Response Analysis Results:${RESET}"
log_stats "Hosts analyzed" "$HOST_COUNT"
log_stats "Debug leakage" "$(count_lines "$DEBUG_FILE")"
log_stats "Verbose errors" "$(count_lines "$ERROR_FILE")"
log_stats_final "Total findings" "$(count_lines "$RESPONSE_FILE")"

crit_count="$(grep -c '^\[CRITICAL\]' "$RESPONSE_FILE" 2>/dev/null || echo 0)"
if [[ "$crit_count" -gt 0 ]]; then
    echo ""
    echo -e "  ${BG_RED}${WHITE} ⚠  ${crit_count} CRITICAL findings detected! ${RESET}"
fi

log_module_end "Response Analysis Engine" "$START_TIME" "$(count_lines "$RESPONSE_FILE")"
