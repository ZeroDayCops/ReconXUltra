#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Active Subdomain Enumeration
# ============================================================================
# Active brute-forcing and DNS-based subdomain discovery using dnsx and ffuf.
# ============================================================================

DOMAIN="${1:?Usage: active.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/config_loader.sh"

init_target_dirs "$DOMAIN"

ACTIVE_DIR="${OUT_SUBS}/active"
mkdir -p "$ACTIVE_DIR"

log_module_start "Active Subdomain Enumeration" "$DOMAIN"
START_TIME="$(date +%s)"

# ── Wordlist Selection ───────────────────────────────────────────────────────
SUBDOMAIN_WORDLIST="${CONFIG[wordlists.subdomains]:-}"
if [[ -z "$SUBDOMAIN_WORDLIST" || ! -f "$SUBDOMAIN_WORDLIST" ]]; then
    # Try common locations
    for wl in \
        "${RECONX_WORDLISTS}/subdomains.txt" \
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" \
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt" \
        "/opt/wordlists/best-dns-wordlist.txt"; do
        if [[ -f "$wl" ]]; then
            SUBDOMAIN_WORDLIST="$wl"
            break
        fi
    done
fi

if [[ -z "$SUBDOMAIN_WORDLIST" || ! -f "$SUBDOMAIN_WORDLIST" ]]; then
    log_warn "No subdomain wordlist found — generating minimal list"
    SUBDOMAIN_WORDLIST="${RECONX_TMP}/dns_wordlist.txt"
    cat > "$SUBDOMAIN_WORDLIST" << 'EOF'
www
mail
ftp
localhost
webmail
smtp
pop
ns1
ns2
blog
dev
staging
api
admin
portal
vpn
secure
test
beta
demo
app
cdn
cloud
git
jenkins
jira
status
monitor
dashboard
grafana
kibana
elastic
redis
db
mysql
postgres
mongo
minio
s3
backup
internal
intranet
wiki
docs
support
help
forum
shop
store
pay
billing
accounts
auth
sso
login
register
m
mobile
static
assets
media
img
images
video
files
download
upload
ws
socket
graphql
rest
v1
v2
v3
sandbox
qa
uat
prod
production
pre
preprod
EOF
fi

log_info "Using wordlist: ${SUBDOMAIN_WORDLIST} ($(count_lines "$SUBDOMAIN_WORDLIST") entries)"

# ── DNS Brute Force with dnsx ────────────────────────────────────────────────
run_dnsx_bruteforce() {
    if cmd_exists dnsx; then
        local out="${ACTIVE_DIR}/dnsx_bruteforce.txt"

        # Generate FQDNs from wordlist
        local fqdn_list="${RECONX_TMP}/fqdn_bruteforce.txt"
        sed "s/$/\.${DOMAIN}/" "$SUBDOMAIN_WORDLIST" > "$fqdn_list"
        local wl_count
        wl_count="$(count_lines "$fqdn_list")"
        log_task_start "dnsx brute force (${wl_count} FQDNs — this may take a while)"

        # Single run with both hostname and response
        dnsx -l "$fqdn_list" -silent -resp -o "${ACTIVE_DIR}/dnsx_resolved_full.txt" \
            -t "$THREADS" -retry "$RETRIES" 2>/dev/null || true

        # Extract just hostnames
        if [[ -f "${ACTIVE_DIR}/dnsx_resolved_full.txt" ]]; then
            awk '{print $1}' "${ACTIVE_DIR}/dnsx_resolved_full.txt" | sort -u > "$out"
        else
            > "$out"
        fi

        rm -f "$fqdn_list"
        log_task_done "dnsx brute force" "$(count_lines "$out")"
    else
        log_warn "dnsx not installed — skipping brute force"
    fi
}

# ── Wildcard Detection ──────────────────────────────────────────────────────
detect_wildcard() {
    log_task_start "Wildcard detection"
    local random_sub
    random_sub="$(head -c 32 /dev/urandom | md5sum | head -c 16)"
    local test_domain="${random_sub}.${DOMAIN}"

    local result
    result="$(dig +short "$test_domain" 2>/dev/null)"

    if [[ -n "$result" ]]; then
        log_warn "Wildcard DNS detected: ${test_domain} → ${result}"
        echo "$result" > "${ACTIVE_DIR}/wildcard_ips.txt"
        WILDCARD_DETECTED=true
        WILDCARD_IPS="$result"
    else
        log_task_done "No wildcard detected"
        WILDCARD_DETECTED=false
        WILDCARD_IPS=""
    fi
}

# ── Filter Wildcard Results ─────────────────────────────────────────────────
filter_wildcards() {
    local input="$1"
    local output="$2"

    if [[ "$WILDCARD_DETECTED" == true && -n "$WILDCARD_IPS" ]]; then
        log_task_start "Filtering wildcard IPs"
        if cmd_exists dnsx; then
            dnsx -l "$input" -silent -a -resp-only 2>/dev/null \
                | grep -v -F "$WILDCARD_IPS" > "${RECONX_TMP}/non_wildcard_ips.txt" || true
            # Re-resolve the non-wildcard entries
            cp "$input" "$output"
        else
            cp "$input" "$output"
        fi
        log_task_done "Wildcard filtering"
    else
        cp "$input" "$output"
    fi
}

# ── VHOST Discovery with ffuf ───────────────────────────────────────────────
run_vhost_discovery() {
    if cmd_exists ffuf; then
        log_task_start "VHOST discovery (ffuf)"
        local out="${ACTIVE_DIR}/vhosts.txt"

        # Get target IP
        local target_ip
        target_ip="$(dig +short "$DOMAIN" | head -1)"

        if [[ -n "$target_ip" ]]; then
            ffuf -w "$SUBDOMAIN_WORDLIST" \
                -u "http://${target_ip}" \
                -H "Host: FUZZ.${DOMAIN}" \
                -mc 200,301,302,403 \
                -fs 0 \
                -t "$THREADS" \
                -o "${ACTIVE_DIR}/vhosts.json" \
                -of json \
                -s 2>/dev/null || true

            # Extract discovered vhosts
            if [[ -f "${ACTIVE_DIR}/vhosts.json" ]]; then
                jq -r '.results[]?.input?.FUZZ' "${ACTIVE_DIR}/vhosts.json" 2>/dev/null \
                    | sed "s/$/.${DOMAIN}/" \
                    | sort -u > "$out"
            fi
            log_task_done "VHOST discovery" "$(count_lines "$out")"
        else
            log_warn "Could not resolve ${DOMAIN} — skipping VHOST discovery"
        fi
    fi
}

# ── Execute ──────────────────────────────────────────────────────────────────
detect_wildcard
run_dnsx_bruteforce
run_vhost_discovery

# ── Merge Active Results ────────────────────────────────────────────────────
log_task_start "Merging active results"
MERGED="${OUT_SUBS}/active_all.txt"
cat "${ACTIVE_DIR}"/*.txt 2>/dev/null \
    | grep -v "^$" \
    | tr '[:upper:]' '[:lower:]' \
    | sort -u > "$MERGED"

# Filter wildcards from merged results
if [[ "$WILDCARD_DETECTED" == true ]]; then
    filter_wildcards "$MERGED" "$MERGED"
fi

TOTAL="$(count_lines "$MERGED")"
log_task_done "Active subdomains discovered" "$TOTAL"

# ── Merge with Passive ──────────────────────────────────────────────────────
log_task_start "Merging passive + active"
ALL_SUBS="${OUT_SUBS}/all_subdomains.txt"
cat "${OUT_SUBS}/passive_all.txt" "$MERGED" 2>/dev/null | sort -u > "$ALL_SUBS"
GRAND_TOTAL="$(count_lines "$ALL_SUBS")"
log_task_done "Total unique subdomains" "$GRAND_TOTAL"

log_module_end "Active Subdomain Enumeration" "$START_TIME" "$GRAND_TOTAL"
