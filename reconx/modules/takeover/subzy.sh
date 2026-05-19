#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Subdomain Takeover Detection (subzy)
# ============================================================================

DOMAIN="${1:?Usage: subzy.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Subdomain Takeover Detection" "$DOMAIN"
START_TIME="$(date +%s)"

ALL_SUBS="${OUT_SUBS}/all_subdomains.txt"
if [[ ! -f "$ALL_SUBS" || "$(count_lines "$ALL_SUBS")" -eq 0 ]]; then
    log_warn "No subdomains — skipping takeover check"
    exit 0
fi

SUB_COUNT="$(count_lines "$ALL_SUBS")"
log_info "Checking ${SUB_COUNT} subdomains for takeover vulnerabilities"

# ── subzy ────────────────────────────────────────────────────────────────────
if cmd_exists subzy; then
    log_task_start "subzy takeover check"
    subzy run --targets "$ALL_SUBS" \
        --concurrency "$THREADS" \
        --timeout "$TIMEOUT" \
        --output "${OUT_TAKEOVER}/subzy_results.json" 2>/dev/null || true

    # Extract vulnerable domains
    if [[ -f "${OUT_TAKEOVER}/subzy_results.json" ]]; then
        jq -r 'select(.vulnerable == true) | "\(.subdomain) [\(.service)]"' \
            "${OUT_TAKEOVER}/subzy_results.json" 2>/dev/null \
            | sort -u > "${OUT_TAKEOVER}/vulnerable_takeover.txt" || true
    fi
    log_task_done "subzy" "$(count_lines "${OUT_TAKEOVER}/vulnerable_takeover.txt")"
else
    log_warn "subzy not installed — using CNAME-based analysis"
fi

# ── CNAME-based Takeover Analysis ───────────────────────────────────────────
log_task_start "CNAME-based takeover analysis"

CNAME_FILE="${OUT_RESOLVED}/cname_records.txt"
TAKEOVER_CANDIDATES="${OUT_TAKEOVER}/cname_takeover_candidates.txt"

if [[ -f "$CNAME_FILE" ]]; then
    # Known vulnerable CNAME patterns
    patterns=(
        "\.s3\.amazonaws\.com" "\.s3-website" "\.cloudfront\.net"
        "\.herokuapp\.com" "\.herokuspace\.com" "\.herokudns\.com"
        "\.github\.io" "\.github\.com"
        "\.azurewebsites\.net" "\.cloudapp\.net" "\.trafficmanager\.net"
        "\.blob\.core\.windows\.net" "\.azure-api\.net"
        "\.shopify\.com" "\.myshopify\.com"
        "\.zendesk\.com" "\.fastly\.net"
        "\.ghost\.io" "\.helpscoutdocs\.com"
        "\.helpjuice\.com" "\.wordpress\.com"
        "\.pantheon\.io" "\.teamwork\.com"
        "\.freshdesk\.com" "\.uservoice\.com"
        "\.surge\.sh" "\.bitbucket\.io"
        "\.netlify\.app" "\.netlify\.com"
        "\.fly\.dev" "\.vercel\.app"
        "\.webflow\.io" "\.uptimerobot\.com"
        "\.cargocollective\.com" "\.statuspage\.io"
        "\.tumblr\.com" "\.feedpress\.me"
        "\.unbounce\.com" "\.readme\.io"
        "\.tictail\.com" "\.campaignmonitor\.com"
        "\.acquia-test\.co" "\.proposify\.com"
    )

    > "$TAKEOVER_CANDIDATES"
    for pattern in "${patterns[@]}"; do
        grep -iE "$pattern" "$CNAME_FILE" >> "$TAKEOVER_CANDIDATES" 2>/dev/null || true
    done
    sort -u "$TAKEOVER_CANDIDATES" -o "$TAKEOVER_CANDIDATES"

    # Verify candidates — check if CNAME target resolves
    log_task_start "Verifying takeover candidates"
    VERIFIED="${OUT_TAKEOVER}/verified_takeover.txt"
    > "$VERIFIED"

    while IFS= read -r line; do
        subdomain="$(echo "$line" | awk '{print $1}')"
        cname_target="$(echo "$line" | grep -oP '\[.*?\]' | tr -d '[]')"

        # If CNAME target doesn't resolve, it's likely vulnerable
        if [[ -n "$cname_target" ]]; then
            resolves="$(dig +short "$cname_target" 2>/dev/null)"
            if [[ -z "$resolves" ]]; then
                echo "$line [POTENTIALLY VULNERABLE - NXDOMAIN]" >> "$VERIFIED"
            fi
        fi
    done < "$TAKEOVER_CANDIDATES"

    log_task_done "Verified candidates" "$(count_lines "$VERIFIED")"
fi

# ── nuclei takeover templates ───────────────────────────────────────────────
if cmd_exists nuclei; then
    log_task_start "nuclei takeover templates"
    nuclei -l "$ALL_SUBS" \
        -tags takeover \
        -silent \
        -c "$THREADS" \
        -json \
        -o "${OUT_TAKEOVER}/nuclei_takeover.json" 2>/dev/null || true
    log_task_done "nuclei takeover" "$(jq -s 'length' "${OUT_TAKEOVER}/nuclei_takeover.json" 2>/dev/null || echo 0)"
fi

# ── Merge Results ────────────────────────────────────────────────────────────
cat "${OUT_TAKEOVER}"/vulnerable_takeover.txt "${OUT_TAKEOVER}"/verified_takeover.txt 2>/dev/null \
    | sort -u > "${OUT_TAKEOVER}/all_takeover_findings.txt" || true
TOTAL="$(count_lines "${OUT_TAKEOVER}/all_takeover_findings.txt")"

echo ""
echo -e "  ${BOLD}${WHITE}Takeover Detection Statistics:${RESET}"
log_stats "Subdomains checked" "$SUB_COUNT"
log_stats "CNAME candidates" "$(count_lines "$TAKEOVER_CANDIDATES")"
log_stats "Verified vulnerable" "$(count_lines "${OUT_TAKEOVER}/verified_takeover.txt")"
log_stats_final "Total findings" "$TOTAL"

log_module_end "Subdomain Takeover Detection" "$START_TIME" "$TOTAL"
