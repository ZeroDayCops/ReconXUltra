#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — DNS Resolver
# ============================================================================
# Resolves all discovered subdomains to IPs using dnsx with resolver rotation.
# Performs A, AAAA, CNAME, MX, NS, TXT lookups and generates resolver reports.
# ============================================================================

DOMAIN="${1:?Usage: resolver.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"

log_module_start "DNS Resolution" "$DOMAIN"
START_TIME="$(date +%s)"

ALL_SUBS="${OUT_SUBS}/all_subdomains.txt"

if [[ ! -f "$ALL_SUBS" || "$(count_lines "$ALL_SUBS")" -eq 0 ]]; then
    log_warn "No subdomains to resolve"
    exit 0
fi

SUB_COUNT="$(count_lines "$ALL_SUBS")"
log_info "Resolving ${SUB_COUNT} subdomains"

# ── Resolver List ────────────────────────────────────────────────────────────
RESOLVER_FILE="${RECONX_WORDLISTS}/resolvers.txt"
if [[ ! -f "$RESOLVER_FILE" ]]; then
    log_info "Creating default resolver list"
    cat > "$RESOLVER_FILE" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
64.6.64.6
64.6.65.6
185.228.168.9
185.228.169.9
76.76.19.19
76.223.122.150
94.140.14.14
94.140.15.15
EOF
fi

# ── A Record Resolution ─────────────────────────────────────────────────────
if cmd_exists dnsx; then
    log_task_start "A record resolution"
    dnsx -l "$ALL_SUBS" \
        -a -resp \
        -silent \
        -t "$THREADS" \
        -retry "$RETRIES" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/a_records.txt" 2>/dev/null || true
    log_task_done "A records" "$(count_lines "${OUT_RESOLVED}/a_records.txt")"

    # ── AAAA Records ─────────────────────────────────────────────────────────
    log_task_start "AAAA record resolution"
    dnsx -l "$ALL_SUBS" \
        -aaaa -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/aaaa_records.txt" 2>/dev/null || true
    log_task_done "AAAA records" "$(count_lines "${OUT_RESOLVED}/aaaa_records.txt")"

    # ── CNAME Records ────────────────────────────────────────────────────────
    log_task_start "CNAME record resolution"
    dnsx -l "$ALL_SUBS" \
        -cname -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/cname_records.txt" 2>/dev/null || true
    log_task_done "CNAME records" "$(count_lines "${OUT_RESOLVED}/cname_records.txt")"

    # ── MX Records ───────────────────────────────────────────────────────────
    log_task_start "MX record resolution"
    dnsx -l "$ALL_SUBS" \
        -mx -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/mx_records.txt" 2>/dev/null || true
    log_task_done "MX records" "$(count_lines "${OUT_RESOLVED}/mx_records.txt")"

    # ── NS Records ───────────────────────────────────────────────────────────
    log_task_start "NS record resolution"
    dnsx -l "$ALL_SUBS" \
        -ns -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/ns_records.txt" 2>/dev/null || true
    log_task_done "NS records" "$(count_lines "${OUT_RESOLVED}/ns_records.txt")"

    # ── TXT Records ──────────────────────────────────────────────────────────
    log_task_start "TXT record resolution"
    dnsx -l "$ALL_SUBS" \
        -txt -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -o "${OUT_RESOLVED}/txt_records.txt" 2>/dev/null || true
    log_task_done "TXT records" "$(count_lines "${OUT_RESOLVED}/txt_records.txt")"

    # ── JSON Output ──────────────────────────────────────────────────────────
    log_task_start "Full JSON resolution"
    dnsx -l "$ALL_SUBS" \
        -a -aaaa -cname -mx -ns -txt -resp \
        -silent \
        -t "$THREADS" \
        -r "$RESOLVER_FILE" \
        -json -o "${OUT_RESOLVED}/dns_full.json" 2>/dev/null || true
    log_task_done "JSON resolution"

else
    # Fallback: use dig
    log_warn "dnsx not found — using dig fallback (slower)"
    > "${OUT_RESOLVED}/a_records.txt"

    while IFS= read -r sub; do
        ips="$(dig +short "$sub" 2>/dev/null | head -5)"
        if [[ -n "$ips" ]]; then
            while IFS= read -r ip; do
                echo "${sub} [${ip}]" >> "${OUT_RESOLVED}/a_records.txt"
            done <<< "$ips"
        fi
    done < "$ALL_SUBS"
fi

# ── Extract Unique IPs ──────────────────────────────────────────────────────
log_task_start "Extracting unique IPs"
grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' "${OUT_RESOLVED}/a_records.txt" 2>/dev/null \
    | sort -u > "${OUT_RESOLVED}/unique_ips.txt" || true
IP_COUNT="$(count_lines "${OUT_RESOLVED}/unique_ips.txt")"
log_task_done "Unique IPs" "$IP_COUNT"

# ── Extract Resolved Subdomains ──────────────────────────────────────────────
log_task_start "Extracting resolved subdomains"
awk '{print $1}' "${OUT_RESOLVED}/a_records.txt" 2>/dev/null \
    | sort -u > "${OUT_RESOLVED}/resolved_subdomains.txt" || true
RESOLVED_COUNT="$(count_lines "${OUT_RESOLVED}/resolved_subdomains.txt")"
log_task_done "Resolved subdomains" "$RESOLVED_COUNT"

# ── CNAME Analysis (Takeover Candidates) ────────────────────────────────────
if [[ -f "${OUT_RESOLVED}/cname_records.txt" ]]; then
    log_task_start "Analyzing CNAME records for potential takeovers"
    takeover_patterns=(
        "amazonaws.com" "cloudfront.net" "azurewebsites.net" "herokuapp.com"
        "github.io" "shopify.com" "fastly.net" "pantheon.io" "zendesk.com"
        "s3.amazonaws.com" "wordpress.com" "ghost.io" "surge.sh"
        "bitbucket.io" "netlify.app" "fly.dev" "vercel.app"
    )

    > "${OUT_TAKEOVER}/cname_takeover_candidates.txt"
    for pattern in "${takeover_patterns[@]}"; do
        grep -i "$pattern" "${OUT_RESOLVED}/cname_records.txt" \
            >> "${OUT_TAKEOVER}/cname_takeover_candidates.txt" 2>/dev/null || true
    done
    dedup_file "${OUT_TAKEOVER}/cname_takeover_candidates.txt"
    candidates="$(count_lines "${OUT_TAKEOVER}/cname_takeover_candidates.txt")"
    if [[ "$candidates" -gt 0 ]]; then
        log_warn "Found ${candidates} potential takeover candidates from CNAME analysis"
    fi
    log_task_done "CNAME takeover analysis" "$candidates"
fi

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Resolution Statistics:${RESET}"
log_stats "Total subdomains" "$SUB_COUNT"
log_stats "Resolved" "$RESOLVED_COUNT"
log_stats "Unique IPs" "$IP_COUNT"
log_stats_final "Resolution rate" "$((RESOLVED_COUNT * 100 / (SUB_COUNT > 0 ? SUB_COUNT : 1)))%"

log_module_end "DNS Resolution" "$START_TIME" "$RESOLVED_COUNT"
