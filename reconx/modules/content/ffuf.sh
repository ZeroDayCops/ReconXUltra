#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Content Discovery (ffuf)
# ============================================================================
# Recursive directory/file brute-forcing with ffuf. Supports extension
# brute force, API path fuzzing, and vhost fuzzing.
# ============================================================================

DOMAIN="${1:?Usage: ffuf.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

log_module_start "Content Discovery (ffuf)" "$DOMAIN"
START_TIME="$(date +%s)"

if ! cmd_exists ffuf; then
    log_error "ffuf not installed — skipping content discovery"
    exit 1
fi

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts found — skipping content discovery"
    exit 0
fi

# ── Wordlist Selection ───────────────────────────────────────────────────────
CONTENT_WORDLIST="${CONFIG[wordlists.content]:-}"
if [[ -z "$CONTENT_WORDLIST" || ! -f "$CONTENT_WORDLIST" ]]; then
    for wl in \
        "${RECONX_WORDLISTS}/content.txt" \
        "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" \
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" \
        "/usr/share/seclists/Discovery/Web-Content/common.txt"; do
        if [[ -f "$wl" ]]; then
            CONTENT_WORDLIST="$wl"
            break
        fi
    done
fi

if [[ -z "$CONTENT_WORDLIST" || ! -f "$CONTENT_WORDLIST" ]]; then
    log_warn "No content wordlist found — creating minimal list"
    CONTENT_WORDLIST="${RECONX_TMP}/content_wordlist.txt"
    cat > "$CONTENT_WORDLIST" << 'EOF'
admin
api
backup
config
console
dashboard
debug
dev
docs
env
git
graphql
health
info
internal
login
manage
monitor
panel
phpmyadmin
portal
private
robots.txt
server-status
sitemap.xml
staging
status
swagger
test
wp-admin
wp-login.php
.env
.git
.git/config
.git/HEAD
.htaccess
.svn
crossdomain.xml
phpinfo.php
info.php
web.config
.well-known/security.txt
EOF
fi

log_info "Using wordlist: ${CONTENT_WORDLIST}"

# ── Directory Fuzzing ────────────────────────────────────────────────────────
run_dir_fuzz() {
    local url="$1"
    local host_hash
    host_hash="$(echo "$url" | md5sum | cut -c1-8)"
    local output_file="${OUT_CONTENT}/ffuf_${host_hash}.json"

    ffuf -u "${url}/FUZZ" \
        -w "$CONTENT_WORDLIST" \
        -mc 200,201,204,301,302,307,401,403,405,500 \
        -fc 404 \
        -fs 0 \
        -t "$THREADS" \
        -rate "$RATE_LIMIT" \
        -timeout "$TIMEOUT" \
        -recursion \
        -recursion-depth 2 \
        -o "$output_file" \
        -of json \
        -s 2>/dev/null || true
}

# ── Extension Brute Force ───────────────────────────────────────────────────
run_ext_fuzz() {
    local url="$1"
    local host_hash
    host_hash="$(echo "$url" | md5sum | cut -c1-8)"
    local output_file="${OUT_CONTENT}/ffuf_ext_${host_hash}.json"

    local extensions="php,asp,aspx,jsp,html,htm,json,xml,txt,cfg,conf,ini,yml,yaml,env,bak,old,log,sql,zip,tar.gz"

    ffuf -u "${url}/FUZZ" \
        -w "$CONTENT_WORDLIST" \
        -e ".${extensions//,/,.}" \
        -mc 200,204,301,302,307,401,403 \
        -fc 404 \
        -t "$THREADS" \
        -rate "$RATE_LIMIT" \
        -o "$output_file" \
        -of json \
        -s 2>/dev/null || true
}

# ── API Path Fuzzing ────────────────────────────────────────────────────────
run_api_fuzz() {
    local url="$1"
    local host_hash
    host_hash="$(echo "$url" | md5sum | cut -c1-8)"

    local api_wordlist="${RECONX_TMP}/api_wordlist.txt"
    cat > "$api_wordlist" << 'EOF'
api
api/v1
api/v2
api/v3
api/docs
api/swagger
api/swagger.json
api/openapi.json
api/graphql
api/health
api/status
api/info
api/debug
api/admin
api/users
api/config
api/settings
api/login
api/auth
api/token
api/register
api/search
api/upload
api/export
api/import
graphql
graphql/console
_api
_graphql
rest
swagger
swagger-ui
swagger-ui.html
swagger.json
openapi
openapi.json
api-docs
actuator
actuator/health
actuator/info
actuator/env
EOF

    ffuf -u "${url}/FUZZ" \
        -w "$api_wordlist" \
        -mc 200,201,204,301,302,307,401,403,405 \
        -fc 404 \
        -t "$THREADS" \
        -o "${OUT_CONTENT}/ffuf_api_${host_hash}.json" \
        -of json \
        -s 2>/dev/null || true

    rm -f "$api_wordlist"
}

# ── Smart Tech-Based Wordlist Selection ──────────────────────────────────────
select_tech_wordlists() {
    local url="$1"
    local tech_wl="${RECONX_TMP}/tech_wordlist_${RANDOM}.txt"
    > "$tech_wl"

    # Grab server header
    local headers
    headers="$(curl -sI --max-time 5 "$url" 2>/dev/null | tr '[:upper:]' '[:lower:]')"

    # IIS / ASP.NET
    if echo "$headers" | grep -qiE "iis|asp\.net|x-aspnet"; then
        [[ -f "${RECONX_WORDLISTS}/iis.txt" ]] && cat "${RECONX_WORDLISTS}/iis.txt" >> "$tech_wl"
        [[ -f "${RECONX_WORDLISTS}/aspx.txt" ]] && cat "${RECONX_WORDLISTS}/aspx.txt" >> "$tech_wl"
    fi

    # PHP
    if echo "$headers" | grep -qiE "php|x-powered-by:.*php"; then
        [[ -f "${RECONX_WORDLISTS}/fuzz-php.php" ]] && cat "${RECONX_WORDLISTS}/fuzz-php.php" >> "$tech_wl"
    fi

    # Java / Tomcat
    if echo "$headers" | grep -qiE "tomcat|java|jboss|wildfly|weblogic|servlet"; then
        [[ -f "${RECONX_WORDLISTS}/jsp.txt" ]] && cat "${RECONX_WORDLISTS}/jsp.txt" >> "$tech_wl"
        [[ -f "${RECONX_WORDLISTS}/jsf.txt" ]] && cat "${RECONX_WORDLISTS}/jsf.txt" >> "$tech_wl"
    fi

    # Apache/CGI
    if echo "$headers" | grep -qiE "apache|cgi"; then
        [[ -f "${RECONX_WORDLISTS}/cgi-bin.txt" ]] && cat "${RECONX_WORDLISTS}/cgi-bin.txt" >> "$tech_wl"
    fi

    # Always append general custom fuzz list
    [[ -f "${RECONX_WORDLISTS}/fuzz.txt" ]] && cat "${RECONX_WORDLISTS}/fuzz.txt" >> "$tech_wl"

    if [[ -s "$tech_wl" ]]; then
        sort -u "$tech_wl" -o "$tech_wl"
        echo "$tech_wl"
    else
        rm -f "$tech_wl"
        echo ""
    fi
}

# ── Process Targets ──────────────────────────────────────────────────────────
HOST_COUNT="$(count_lines "$LIVE_HOSTS")"
FUZZ_LIMIT=50
CURRENT=0

log_info "Fuzzing up to ${FUZZ_LIMIT} live hosts"

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    CURRENT=$((CURRENT + 1))
    [[ "$CURRENT" -gt "$FUZZ_LIMIT" ]] && break

    log_task_start "Fuzzing [${CURRENT}/${FUZZ_LIMIT}]: $(echo "$url" | cut -c1-60)..."

    run_dir_fuzz "$url"
    run_api_fuzz "$url"

    # Tech-specific fuzzing with custom wordlists
    tech_wl="$(select_tech_wordlists "$url")"
    if [[ -n "$tech_wl" && -f "$tech_wl" ]]; then
        host_hash="$(echo "$url" | md5sum | cut -c1-8)"
        ffuf -u "${url}/FUZZ" \
            -w "$tech_wl" \
            -mc 200,201,204,301,302,307,401,403,405 \
            -fc 404 -fs 0 \
            -t "$THREADS" -rate "$RATE_LIMIT" \
            -o "${OUT_CONTENT}/ffuf_tech_${host_hash}.json" \
            -of json -s 2>/dev/null || true
        rm -f "$tech_wl"
    fi

done < "$LIVE_HOSTS"

# ── Merge Results ────────────────────────────────────────────────────────────
log_task_start "Merging ffuf results"
> "${OUT_CONTENT}/all_discovered.txt"
for result_file in "${OUT_CONTENT}"/ffuf_*.json; do
    [[ -f "$result_file" ]] || continue
    jq -r '.results[]? | "\(.url) [\(.status)] [\(.length)]"' "$result_file" 2>/dev/null \
        >> "${OUT_CONTENT}/all_discovered.txt" || true
done
sort -u "${OUT_CONTENT}/all_discovered.txt" -o "${OUT_CONTENT}/all_discovered.txt"
TOTAL="$(count_lines "${OUT_CONTENT}/all_discovered.txt")"
log_task_done "Total discovered paths" "$TOTAL"

log_module_end "Content Discovery (ffuf)" "$START_TIME" "$TOTAL"
