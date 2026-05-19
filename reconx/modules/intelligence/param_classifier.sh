#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Parameter Vulnerability Classifier
# ============================================================================
# Classifies discovered parameters and URLs into vulnerability categories:
# XSS, SSRF, Open Redirect, LFI, SQLi, IDOR candidates.
# Uses gf patterns when available, falls back to built-in regex.
# ============================================================================

DOMAIN="${1:?Usage: param_classifier.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Parameter Vulnerability Classifier" "$DOMAIN"
START_TIME="$(date +%s)"

ALL_URLS="${OUT_URLS}/all_urls.txt"
PARAM_URLS="${OUT_PARAMS}/param_urls.txt"

# Gather all parameterized URLs
if [[ -f "$ALL_URLS" ]]; then
    grep -E '\?' "$ALL_URLS" 2>/dev/null | sort -u > "$PARAM_URLS" || true
fi

if [[ ! -f "$PARAM_URLS" ]] || [[ "$(count_lines "$PARAM_URLS")" -eq 0 ]]; then
    log_warn "No parameterized URLs found — skipping classification"
    exit 0
fi

PARAM_COUNT="$(count_lines "$PARAM_URLS")"
log_info "Classifying ${PARAM_COUNT} parameterized URLs"

# ── XSS Candidates ──────────────────────────────────────────────────────────
classify_xss() {
    log_task_start "XSS candidate detection"
    xss_out="${OUT_INTEL}/xss_candidates.txt"
    > "$xss_out"

    if cmd_exists gf; then
        gf xss < "$PARAM_URLS" >> "$xss_out" 2>/dev/null || true
    fi

    # Built-in patterns (always run as supplement)
    xss_params="q|search|query|keyword|term|s|message|msg|comment|text|body|content|value|input|data|payload|name|title|description|redirect|url|callback|return|next|html|template|preview|render|display|view|page|id|ref|src|href|action|style|class|onload|onerror|onclick"
    grep -iE "[?&](${xss_params})=" "$PARAM_URLS" >> "$xss_out" 2>/dev/null || true

    sort -u "$xss_out" -o "$xss_out"
    log_task_done "XSS candidates" "$(count_lines "$xss_out")"
}

# ── SSRF Candidates ─────────────────────────────────────────────────────────
classify_ssrf() {
    log_task_start "SSRF candidate detection"
    ssrf_out="${OUT_INTEL}/ssrf_candidates.txt"
    > "$ssrf_out"

    if cmd_exists gf; then
        gf ssrf < "$PARAM_URLS" >> "$ssrf_out" 2>/dev/null || true
    fi

    ssrf_params="url|uri|path|dest|destination|redirect|uri|site|html|feed|ref|next|data|domain|source|page|out|view|dir|show|navigation|open|file|val|validate|window|result|return|img|src|fetch|proxy|request|target|to|link|navigate|load|callback|endpoint|webhook|host|port|server|forward|wp"
    grep -iE "[?&](${ssrf_params})=" "$PARAM_URLS" >> "$ssrf_out" 2>/dev/null || true

    # Also match URLs with URL values in params
    grep -iE "[?&][a-zA-Z_]+=https?://" "$PARAM_URLS" >> "$ssrf_out" 2>/dev/null || true

    sort -u "$ssrf_out" -o "$ssrf_out"
    log_task_done "SSRF candidates" "$(count_lines "$ssrf_out")"
}

# ── Open Redirect Candidates ────────────────────────────────────────────────
classify_redirect() {
    log_task_start "Open Redirect candidate detection"
    redir_out="${OUT_INTEL}/redirect_candidates.txt"
    > "$redir_out"

    if cmd_exists gf; then
        gf redirect < "$PARAM_URLS" >> "$redir_out" 2>/dev/null || true
    fi

    redir_params="redirect|redirect_uri|redirect_url|return|return_to|return_url|returnTo|next|next_url|url|to|target|rurl|dest|destination|redir|redirect_to|out|view|login_url|logout|callback|cb|continue|goto|forward|follow|link|navigate|success_url|error_url|back|checkout_url"
    grep -iE "[?&](${redir_params})=" "$PARAM_URLS" >> "$redir_out" 2>/dev/null || true

    sort -u "$redir_out" -o "$redir_out"
    log_task_done "Open Redirect candidates" "$(count_lines "$redir_out")"
}

# ── LFI Candidates ──────────────────────────────────────────────────────────
classify_lfi() {
    log_task_start "LFI candidate detection"
    lfi_out="${OUT_INTEL}/lfi_candidates.txt"
    > "$lfi_out"

    if cmd_exists gf; then
        gf lfi < "$PARAM_URLS" >> "$lfi_out" 2>/dev/null || true
    fi

    lfi_params="file|path|folder|dir|directory|page|pg|include|require|read|doc|document|root|location|template|tmpl|tpl|conf|config|download|log|locale|lang|language|content|layout|mod|module|resource|attachment|prefix|suffix|category|style|theme|skin|type|action|name|view|display|load|pdf|report|fn"
    grep -iE "[?&](${lfi_params})=" "$PARAM_URLS" >> "$lfi_out" 2>/dev/null || true

    sort -u "$lfi_out" -o "$lfi_out"
    log_task_done "LFI candidates" "$(count_lines "$lfi_out")"
}

# ── SQLi Candidates ─────────────────────────────────────────────────────────
classify_sqli() {
    log_task_start "SQLi candidate detection"
    sqli_out="${OUT_INTEL}/sqli_candidates.txt"
    > "$sqli_out"

    if cmd_exists gf; then
        gf sqli < "$PARAM_URLS" >> "$sqli_out" 2>/dev/null || true
    fi

    sqli_params="id|ID|user|username|uid|page|report|search|query|q|item|order|sort|filter|column|field|table|from|sel|select|where|update|delete|insert|set|col|row|num|number|key|cat|category|dir|cmd|exec|process|view|result|role|group|date|year|month|type|name|code|token"
    grep -iE "[?&](${sqli_params})=" "$PARAM_URLS" >> "$sqli_out" 2>/dev/null || true

    sort -u "$sqli_out" -o "$sqli_out"
    log_task_done "SQLi candidates" "$(count_lines "$sqli_out")"
}

# ── IDOR Candidates ─────────────────────────────────────────────────────────
classify_idor() {
    log_task_start "IDOR candidate detection"
    idor_out="${OUT_INTEL}/idor_candidates.txt"
    > "$idor_out"

    if cmd_exists gf; then
        gf idor < "$PARAM_URLS" >> "$idor_out" 2>/dev/null || true
    fi

    idor_params="id|user_id|uid|userId|account|account_id|profile|doc|document_id|order|order_id|invoice|file_id|report|key|no|number|email|group|role|token"
    grep -iE "[?&](${idor_params})=[0-9]" "$PARAM_URLS" >> "$idor_out" 2>/dev/null || true

    sort -u "$idor_out" -o "$idor_out"
    log_task_done "IDOR candidates" "$(count_lines "$idor_out")"
}

# ── Run All Classifiers ─────────────────────────────────────────────────────
classify_xss
classify_ssrf
classify_redirect
classify_lfi
classify_sqli
classify_idor

# ── Statistics ───────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}${WHITE}Vulnerability Classification Results:${RESET}"
log_stats "Total parameterized URLs" "$PARAM_COUNT"
log_stats "XSS candidates" "$(count_lines "${OUT_INTEL}/xss_candidates.txt")"
log_stats "SSRF candidates" "$(count_lines "${OUT_INTEL}/ssrf_candidates.txt")"
log_stats "Open Redirect candidates" "$(count_lines "${OUT_INTEL}/redirect_candidates.txt")"
log_stats "LFI candidates" "$(count_lines "${OUT_INTEL}/lfi_candidates.txt")"
log_stats "SQLi candidates" "$(count_lines "${OUT_INTEL}/sqli_candidates.txt")"
log_stats_final "IDOR candidates" "$(count_lines "${OUT_INTEL}/idor_candidates.txt")"

log_module_end "Parameter Vulnerability Classifier" "$START_TIME" "$PARAM_COUNT"
