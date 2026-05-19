#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Subdomain Permutations
# ============================================================================
# Generates permutations of discovered subdomains using alterx and custom
# patterns to discover additional subdomains that brute-forcing might miss.
# ============================================================================

DOMAIN="${1:?Usage: permutations.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"

PERM_DIR="${OUT_SUBS}/permutations"
mkdir -p "$PERM_DIR"

log_module_start "Subdomain Permutations" "$DOMAIN"
START_TIME="$(date +%s)"

ALL_SUBS="${OUT_SUBS}/all_subdomains.txt"

if [[ ! -f "$ALL_SUBS" || "$(count_lines "$ALL_SUBS")" -eq 0 ]]; then
    log_warn "No subdomains found yet — skipping permutations"
    exit 0
fi

# ── alterx Permutations ─────────────────────────────────────────────────────
run_alterx() {
    if cmd_exists alterx; then
        log_task_start "alterx permutation generation"
        local out="${PERM_DIR}/alterx_permutations.txt"
        local resolved="${PERM_DIR}/alterx_resolved.txt"

        # Generate permutations
        alterx -l "$ALL_SUBS" -silent -o "$out" 2>/dev/null || true
        local generated
        generated="$(count_lines "$out")"
        log_info "Generated ${generated} permutations"

        # Resolve permutations with dnsx
        if cmd_exists dnsx && [[ "$generated" -gt 0 ]]; then
            log_task_start "Resolving permutations with dnsx"
            dnsx -l "$out" -silent -o "$resolved" \
                -t "$THREADS" -retry 2 2>/dev/null || true
            log_task_done "Resolved permutations" "$(count_lines "$resolved")"
        fi

        log_task_done "alterx" "$(count_lines "${resolved:-$out}")"
    else
        log_warn "alterx not installed — skipping"
    fi
}

# ── Custom Pattern Permutations ──────────────────────────────────────────────
run_custom_permutations() {
    log_task_start "Custom pattern permutations"
    local out="${PERM_DIR}/custom_permutations.txt"
    > "$out"

    # Extract unique subdomain prefixes
    local prefixes="${RECONX_TMP}/subdomain_prefixes.txt"
    sed "s/\.${DOMAIN}$//" "$ALL_SUBS" | sort -u > "$prefixes"

    # Common patterns to try
    local suffixes=("dev" "staging" "test" "api" "admin" "internal" "prod" "beta" "stage"
                    "uat" "qa" "sandbox" "demo" "old" "new" "v2" "v3" "backup" "bak"
                    "cdn" "static" "assets" "media" "img" "app" "mobile" "m")

    local separators=("-" "." "")

    while IFS= read -r prefix; do
        [[ -z "$prefix" ]] && continue
        for suffix in "${suffixes[@]}"; do
            for sep in "${separators[@]}"; do
                echo "${prefix}${sep}${suffix}.${DOMAIN}" >> "$out"
                echo "${suffix}${sep}${prefix}.${DOMAIN}" >> "$out"
            done
        done
    done < "$prefixes"

    sort -u "$out" -o "$out"

    # Remove already known subdomains
    if cmd_exists anew; then
        local new_perms="${PERM_DIR}/new_permutations.txt"
        comm -23 <(sort "$out") <(sort "$ALL_SUBS") > "$new_perms"
        mv "$new_perms" "$out"
    fi

    local perm_count
    perm_count="$(count_lines "$out")"
    log_info "Generated ${perm_count} custom permutations"

    # Resolve with dnsx
    if cmd_exists dnsx && [[ "$perm_count" -gt 0 ]]; then
        local resolved="${PERM_DIR}/custom_resolved.txt"
        dnsx -l "$out" -silent -o "$resolved" \
            -t "$THREADS" -retry 2 2>/dev/null || true
        log_task_done "Custom permutations resolved" "$(count_lines "$resolved")"
    fi

    rm -f "$prefixes"
}

# ── Execute ──────────────────────────────────────────────────────────────────
run_alterx
run_custom_permutations

# ── Merge Results ────────────────────────────────────────────────────────────
log_task_start "Merging permutation results"
PERM_RESOLVED="${PERM_DIR}/all_perm_resolved.txt"
cat "${PERM_DIR}"/*resolved*.txt 2>/dev/null | sort -u > "$PERM_RESOLVED" || true

# Append newly discovered subdomains to master list
if [[ -f "$PERM_RESOLVED" && "$(count_lines "$PERM_RESOLVED")" -gt 0 ]]; then
    local_new_count="$(comm -23 <(sort "$PERM_RESOLVED") <(sort "$ALL_SUBS") | wc -l)"
    cat "$PERM_RESOLVED" >> "$ALL_SUBS"
    dedup_file "$ALL_SUBS"
    log_task_done "New subdomains from permutations" "$local_new_count"
else
    log_info "No new subdomains from permutations"
fi

TOTAL="$(count_lines "$ALL_SUBS")"
log_module_end "Subdomain Permutations" "$START_TIME" "$TOTAL"
