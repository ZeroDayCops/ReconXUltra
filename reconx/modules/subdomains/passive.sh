#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Passive Subdomain Enumeration
# ============================================================================
# Aggregates subdomains from multiple passive sources:
# subfinder, assetfinder, amass, findomain, crt.sh, VirusTotal,
# GitHub scraping, SecurityTrails, URLScan, AlienVault OTX,
# HackerTarget, RapidDNS, Shodan, ThreatCrowd, Certspotter
# ============================================================================

DOMAIN="${1:?Usage: passive.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

PASSIVE_DIR="${OUT_SUBS}/passive"
mkdir -p "$PASSIVE_DIR"

log_module_start "Passive Subdomain Enumeration" "$DOMAIN"
START_TIME="$(date +%s)"

# ── subfinder ────────────────────────────────────────────────────────────────
run_subfinder() {
    if cmd_exists subfinder; then
        log_task_start "subfinder"
        local out="${PASSIVE_DIR}/subfinder.txt"
        subfinder -d "$DOMAIN" -all -silent -o "$out" \
            -t "$THREADS" 2>/dev/null || true
        log_task_done "subfinder" "$(count_lines "$out")"
    else
        log_warn "subfinder not installed — skipping"
    fi
}

# ── assetfinder ──────────────────────────────────────────────────────────────
run_assetfinder() {
    if cmd_exists assetfinder; then
        log_task_start "assetfinder"
        local out="${PASSIVE_DIR}/assetfinder.txt"
        assetfinder --subs-only "$DOMAIN" 2>/dev/null | sort -u > "$out" || true
        log_task_done "assetfinder" "$(count_lines "$out")"
    else
        log_warn "assetfinder not installed — skipping"
    fi
}

# ── amass ────────────────────────────────────────────────────────────────────
run_amass() {
    if cmd_exists amass; then
        log_task_start "amass (passive)"
        local out="${PASSIVE_DIR}/amass.txt"
        timeout 600 amass enum -passive -d "$DOMAIN" -o "$out" 2>/dev/null || true
        log_task_done "amass" "$(count_lines "$out")"
    else
        log_warn "amass not installed — skipping"
    fi
}

# ── findomain ────────────────────────────────────────────────────────────────
run_findomain() {
    if cmd_exists findomain; then
        log_task_start "findomain"
        local out="${PASSIVE_DIR}/findomain.txt"
        findomain -t "$DOMAIN" -u "$out" --quiet 2>/dev/null || true
        log_task_done "findomain" "$(count_lines "$out")"
    else
        log_warn "findomain not installed — skipping"
    fi
}

# ── crt.sh ───────────────────────────────────────────────────────────────────
run_crtsh() {
    log_task_start "crt.sh"
    local out="${PASSIVE_DIR}/crtsh.txt"
    local tmp="${RECONX_TMP}/crtsh_raw.json"
    > "$out"

    # Download JSON first, then parse — avoids retry_cmd pipe issues
    curl -s --max-time 60 "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
        -o "$tmp" 2>/dev/null || true

    if [[ -s "$tmp" ]]; then
        jq -r '.[].name_value' "$tmp" 2>/dev/null \
            | sed 's/\*\.//g' \
            | tr '[:upper:]' '[:lower:]' \
            | grep -E "\.${DOMAIN}$|^${DOMAIN}$" \
            | sort -u > "$out" || true
    fi
    rm -f "$tmp"
    log_task_done "crt.sh" "$(count_lines "$out")"
}

# ── VirusTotal ───────────────────────────────────────────────────────────────
run_virustotal() {
    local api_key="${CONFIG[api.virustotal]:-${VT_API_KEY:-}}"
    if [[ -z "$api_key" ]]; then
        log_warn "VirusTotal API key not set — skipping"
        return
    fi
    log_task_start "VirusTotal"
    local out="${PASSIVE_DIR}/virustotal.txt"
    curl -s --max-time 30 \
        "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${api_key}&domain=${DOMAIN}" \
        2>/dev/null \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | sort -u > "$out" || true
    log_task_done "VirusTotal" "$(count_lines "$out")"
}

# ── GitHub Scraping ──────────────────────────────────────────────────────────
run_github_scrape() {
    local token="${CONFIG[api.github_token]:-${GITHUB_TOKEN:-}}"
    if [[ -z "$token" ]]; then
        log_warn "GitHub token not set — skipping"
        return
    fi
    log_task_start "GitHub subdomain scraping"
    local out="${PASSIVE_DIR}/github.txt"
    > "$out"

    local page=1
    while [[ "$page" -le 5 ]]; do
        curl -s --max-time 15 \
            -H "Authorization: token ${token}" \
            -H "Accept: application/vnd.github.v3.text-match+json" \
            "https://api.github.com/search/code?q=${DOMAIN}&per_page=100&page=${page}" \
            2>/dev/null \
            | jq -r '.items[]?.text_matches[]?.fragment' 2>/dev/null \
            | grep -oiP "[a-zA-Z0-9._-]+\.${DOMAIN}" \
            >> "$out" || true
        page=$((page + 1))
        sleep 2
    done

    sort -u "$out" -o "$out"
    log_task_done "GitHub scraping" "$(count_lines "$out")"
}

# ── SecurityTrails ───────────────────────────────────────────────────────────
run_securitytrails() {
    local api_key="${CONFIG[api.securitytrails]:-${SECURITY_TRAILS_KEY:-}}"
    if [[ -z "$api_key" ]]; then
        log_warn "SecurityTrails API key not set — skipping"
        return
    fi
    log_task_start "SecurityTrails"
    local out="${PASSIVE_DIR}/securitytrails.txt"
    curl -s --max-time 30 \
        "https://api.securitytrails.com/v1/domain/${DOMAIN}/subdomains" \
        -H "APIKEY: ${api_key}" 2>/dev/null \
        | jq -r '.subdomains[]?' 2>/dev/null \
        | sed "s/$/\.${DOMAIN}/" \
        | sort -u > "$out" || true
    log_task_done "SecurityTrails" "$(count_lines "$out")"
}

# ── URLScan.io ───────────────────────────────────────────────────────────────
run_urlscan() {
    log_task_start "URLScan.io"
    local out="${PASSIVE_DIR}/urlscan.txt"
    curl -s --max-time 30 \
        "https://urlscan.io/api/v1/search/?q=domain:${DOMAIN}&size=10000" \
        2>/dev/null \
        | jq -r '.results[]?.page?.domain' 2>/dev/null \
        | grep -i "\.${DOMAIN}$" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$out" || true
    log_task_done "URLScan.io" "$(count_lines "$out")"
}

# ── AlienVault OTX ───────────────────────────────────────────────────────────
run_alienvault() {
    log_task_start "AlienVault OTX"
    local out="${PASSIVE_DIR}/alienvault.txt"
    local tmp_resp="${RECONX_TMP}/otx_resp.json"
    > "$out"

    local page=1
    while [[ "$page" -le 5 ]]; do
        local url="https://otx.alienvault.com/api/v1/indicators/domain/${DOMAIN}/url_list?limit=500&page=${page}"
        curl -s --max-time 20 "$url" -o "$tmp_resp" 2>/dev/null || true

        if [[ -s "$tmp_resp" ]]; then
            jq -r '.url_list[]?.hostname' "$tmp_resp" 2>/dev/null | grep -i "\.${DOMAIN}$" >> "$out" || true
            has_next="$(jq -r '.has_next' "$tmp_resp" 2>/dev/null)"
            [[ "$has_next" != "true" ]] && break
        else
            break
        fi

        page=$((page + 1))
        sleep 1
    done

    rm -f "$tmp_resp"
    sort -u "$out" -o "$out"
    log_task_done "AlienVault OTX" "$(count_lines "$out")"
}

# ── HackerTarget ─────────────────────────────────────────────────────────────
run_hackertarget() {
    log_task_start "HackerTarget"
    local out="${PASSIVE_DIR}/hackertarget.txt"
    curl -s --max-time 30 \
        "https://api.hackertarget.com/hostsearch/?q=${DOMAIN}" \
        2>/dev/null \
        | grep -v "error\|API" \
        | cut -d',' -f1 \
        | grep -i "\.${DOMAIN}$" \
        | sort -u > "$out" || true
    log_task_done "HackerTarget" "$(count_lines "$out")"
}

# ── RapidDNS ─────────────────────────────────────────────────────────────────
run_rapiddns() {
    log_task_start "RapidDNS"
    local out="${PASSIVE_DIR}/rapiddns.txt"
    curl -s --max-time 30 \
        "https://rapiddns.io/subdomain/${DOMAIN}?full=1#result" \
        2>/dev/null \
        | grep -oiP "[a-zA-Z0-9._-]+\.${DOMAIN}" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$out" || true
    log_task_done "RapidDNS" "$(count_lines "$out")"
}

# ── Certspotter ──────────────────────────────────────────────────────────────
run_certspotter() {
    log_task_start "Certspotter"
    local out="${PASSIVE_DIR}/certspotter.txt"
    curl -s --max-time 30 \
        "https://api.certspotter.com/v1/issuances?domain=${DOMAIN}&include_subdomains=true&expand=dns_names" \
        2>/dev/null \
        | jq -r '.[].dns_names[]?' 2>/dev/null \
        | sed 's/\*\.//g' \
        | grep -i "\.${DOMAIN}$" \
        | tr '[:upper:]' '[:lower:]' \
        | sort -u > "$out" || true
    log_task_done "Certspotter" "$(count_lines "$out")"
}

# ── ThreatMiner ──────────────────────────────────────────────────────────────
run_threatminer() {
    log_task_start "ThreatMiner"
    local out="${PASSIVE_DIR}/threatminer.txt"
    curl -s --max-time 30 \
        "https://api.threatminer.org/v2/domain.php?q=${DOMAIN}&rt=5" \
        2>/dev/null \
        | jq -r '.results[]?' 2>/dev/null \
        | grep -i "\.${DOMAIN}$" \
        | sort -u > "$out" || true
    log_task_done "ThreatMiner" "$(count_lines "$out")"
}

# ── Run All Passive Sources ─────────────────────────────────────────────────
# Parallel batch 1: No-auth sources
run_crtsh &
run_alienvault &
run_urlscan &
run_hackertarget &
run_rapiddns &
run_certspotter &
run_threatminer &
wait

# Parallel batch 2: Tool-based
run_subfinder &
run_assetfinder &
run_findomain &
wait

# Sequential: Rate-limited / auth-required
run_amass
run_virustotal
run_securitytrails
run_github_scrape

# ── Merge All Results ────────────────────────────────────────────────────────
log_task_start "Merging passive results"
MERGED="${OUT_SUBS}/passive_all.txt"
cat "${PASSIVE_DIR}"/*.txt 2>/dev/null \
    | grep -v "^$" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/\*\.//g; s/^\.//; s/\.$//' \
    | grep -E "\.($(echo "$DOMAIN" | sed 's/\./\\./g'))$" \
    | sort -u > "$MERGED"

# Also update the master subdomain list
if [[ -f "${OUT_SUBS}/all_subdomains.txt" ]]; then
    cat "$MERGED" >> "${OUT_SUBS}/all_subdomains.txt"
    sort -u "${OUT_SUBS}/all_subdomains.txt" -o "${OUT_SUBS}/all_subdomains.txt"
else
    cp "$MERGED" "${OUT_SUBS}/all_subdomains.txt"
fi

TOTAL="$(count_lines "$MERGED")"
log_task_done "Merged passive subdomains" "$TOTAL"

# ── Source Statistics ────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Passive Source Statistics:${RESET}"
for src_file in "${PASSIVE_DIR}"/*.txt; do
    [[ -f "$src_file" ]] || continue
    src_name="$(basename "$src_file" .txt)"
    src_count="$(count_lines "$src_file")"
    if [[ "$src_count" -gt 0 ]]; then
        echo -e "    ${GREEN}✓${RESET} ${src_name} — ${GREEN}${src_count}${RESET} found"
    else
        echo -e "    ${GRAY}○${RESET} ${src_name} — ${GRAY}0 found${RESET}"
    fi
done
log_stats_final "Total unique" "$TOTAL"

log_module_end "Passive Subdomain Enumeration" "$START_TIME" "$TOTAL"
