#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Module Runner
# ============================================================================
# Orchestrates module execution with timing, state management, error handling,
# and notification support.
# ============================================================================

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi
source "${RECONX_CORE}/logger.sh"
source "${RECONX_CORE}/state_manager.sh"
source "${RECONX_CORE}/async_runner.sh"
source "${RECONX_ROOT}/core/telegram.sh" 2>/dev/null || true

# ── Module Registry ─────────────────────────────────────────────────────────
declare -A MODULE_REGISTRY=(
    ["subdomains"]="modules/subdomains/passive.sh modules/subdomains/active.sh modules/subdomains/permutations.sh modules/subdomains/resolver.sh"
    ["live"]="modules/live/httpx.sh"
    ["urls"]="modules/urls/gather.sh modules/urls/filter.sh modules/urls/params.sh"
    ["dedup"]="core/dedup_engine.py"
    ["js"]="modules/js/extract.sh modules/js/secrets.py modules/js/nuclei_js.sh"
    ["content"]="modules/content/ffuf.sh modules/content/dirsearch.sh modules/content/sensitive.sh modules/content/bypass_403.sh"
    ["nuclei"]="modules/nuclei/scan.sh"
    ["screenshots"]="modules/screenshots/aquatone.sh"
    ["ports"]="modules/ports/naabu.sh modules/ports/nmap.sh"
    ["takeover"]="modules/takeover/subzy.sh"
    ["cors"]="modules/cors/cors.sh"
    ["wordpress"]="modules/wordpress/wpscan.sh"
    ["api"]="modules/api/graphql.sh modules/api/swagger.sh modules/api/api_intelligence.py"
    ["intelligence"]="modules/intelligence/wordlist_classifier.py modules/intelligence/param_classifier.sh modules/intelligence/tech_fingerprint.sh modules/intelligence/wordlist_engine.py modules/intelligence/response_analyzer.sh modules/intelligence/response_cluster.py modules/intelligence/js_deep_analysis.py modules/intelligence/workflow_intel.py modules/intelligence/bug_signal.py modules/intelligence/ai_prioritizer.py modules/intelligence/cloud_exposure.py modules/intelligence/memory_engine.py modules/intelligence/param_intelligence.py modules/intelligence/smart_gf.py modules/intelligence/target_dna.py modules/intelligence/surface_ranker.py modules/intelligence/ai_hunter.py"
    ["reasoning"]="modules/intelligence/observed_signals.py modules/intelligence/micro_validation.py modules/intelligence/workflow_evidence.py modules/intelligence/reasoning_engine.py modules/intelligence/attack_paths.py modules/intelligence/reasoning_trace.py modules/intelligence/strategy_engine.py"
    ["behavioral"]="modules/behavioral/auth_behavior.py modules/behavioral/object_relationships.py modules/behavioral/workflow_transitions.py modules/behavioral/dom_observer.py modules/behavioral/session_intelligence.py modules/behavioral/api_behavior.py modules/behavioral/target_understanding.py"
    ["exploit"]="modules/exploit/xss_scan.sh modules/exploit/sqli_scan.sh modules/exploit/vuln_fuzz.py"
    ["validation"]="modules/validation/engine.py modules/validation/browser_engine.py modules/validation/poc_generator.py modules/intelligence/attack_chain.py modules/intelligence/chain_builder.py"
    ["reporting"]="modules/reporting/final_output.sh modules/reporting/summary.sh modules/reporting/dashboard_gen.py"
)

# ── Ordered Module Pipeline ─────────────────────────────────────────────────
DEFAULT_PIPELINE=(
    "subdomains"
    "live"
    "urls"
    "dedup"
    "js"
    "content"
    "ports"
    "nuclei"
    "screenshots"
    "takeover"
    "cors"
    "wordpress"
    "api"
    "intelligence"
    "exploit"
    "validation"
    "reporting"
)

# ── Run a Single Module ─────────────────────────────────────────────────────
run_module() {
    local module_name="$1"
    local domain="$2"

    # Check if module should run (resume check)
    if ! should_run_module "$module_name"; then
        return 0
    fi

    # Check if module is enabled in config
    if ! is_module_enabled "$module_name"; then
        log_info "Module '${module_name}' is disabled in config — skipping"
        return 0
    fi

    local scripts="${MODULE_REGISTRY[$module_name]:-}"
    if [[ -z "$scripts" ]]; then
        log_error "Unknown module: $module_name"
        return 1
    fi

    local start_time
    start_time="$(date +%s)"
    export CURRENT_MODULE="$module_name"
    log_module_start "$module_name" "$domain"
    tg_module_start "$module_name" "$domain" 2>/dev/null || true

    local module_failed=false
    for script in $scripts; do
        local script_path="${RECONX_ROOT}/${script}"

        if [[ ! -f "$script_path" ]]; then
            log_warn "Script not found: $script_path — skipping"
            continue
        fi

        local script_name
        script_name="$(basename "$script_path")"
        log_task_start "Running ${script_name}"

        # Determine runner based on extension
        local ext="${script_path##*.}"
        local exit_code=0

        case "$ext" in
            sh)
                bash "$script_path" "$domain" || exit_code=$?
                ;;
            py)
                python3 "$script_path" "$domain" || exit_code=$?
                ;;
            *)
                log_warn "Unknown script type: $ext"
                continue
                ;;
        esac

        if [[ "$exit_code" -ne 0 ]]; then
            log_error "Script failed: ${script_name} (exit code: ${exit_code})"
            module_failed=true
        else
            log_task_done "Completed ${script_name}"
        fi
    done

    local result_count=0
    # Try to count results from the module's output directory
    case "$module_name" in
        subdomains) result_count="$(count_lines "${OUT_SUBS}/all_subdomains.txt")" ;;
        live) result_count="$(count_lines "${OUT_LIVE}/live_hosts.txt")" ;;
        urls) result_count="$(count_lines "${OUT_URLS}/all_urls.txt")" ;;
        js) result_count="$(count_lines "${OUT_JS}/js_urls.txt")" ;;
        *) result_count=0 ;;
    esac

    local _elapsed="$(( $(date +%s) - start_time ))"
    local _dur="$(( _elapsed / 60 ))m $(( _elapsed % 60 ))s"
    log_module_end "$module_name" "$start_time" "$result_count"
    tg_module_done "$module_name" "$_dur" "📊 Results: \`${result_count}\`" 2>/dev/null || true

    if [[ "$module_failed" == true ]]; then
        mark_failed "$module_name" "one_or_more_scripts_failed"
        if [[ "$NOTIFY_ENABLED" == true ]]; then
            send_notification "❌ <b>Module Failed</b>
━━━━━━━━━━━━━━━
📦 <code>${module_name}</code>
🎯 <code>${domain}</code>"
        fi
        return 1
    else
        mark_complete "$module_name" "$result_count"
        if [[ "$NOTIFY_ENABLED" == true ]]; then
            local elapsed="$(( $(date +%s) - start_time ))"
            local mins=$(( elapsed / 60 ))
            local secs_r=$(( elapsed % 60 ))
            local icon="✅"
            [[ "$result_count" -gt 100 ]] && icon="🔥"
            [[ "$result_count" -eq 0 ]] && icon="⚪"
            send_notification "${icon} <b>Module Complete</b>
━━━━━━━━━━━━━━━
📦 <code>${module_name}</code>
🎯 <code>${domain}</code>
📊 Results: <b>${result_count}</b>
⏱ Time: <b>${mins}m ${secs_r}s</b>"
        fi
        return 0
    fi
}

# ── Run Full Pipeline ───────────────────────────────────────────────────────
run_pipeline() {
    local domain="$1"
    local modules_csv="${2:-}"

    local pipeline=()

    if [[ -n "$modules_csv" ]]; then
        # Run specific modules
        IFS=',' read -ra pipeline <<< "$modules_csv"
    else
        # Run full default pipeline
        pipeline=("${DEFAULT_PIPELINE[@]}")
    fi

    local total=${#pipeline[@]}
    local current=0
    local failed=0

    log_info "Starting recon pipeline with ${total} modules for: ${domain}"
    echo ""

    for module in "${pipeline[@]}"; do
        current=$((current + 1))
        log_progress "$current" "$total" "Pipeline"

        if ! run_module "$module" "$domain"; then
            failed=$((failed + 1))
            log_warn "Module '${module}' had errors — continuing pipeline"
        fi
    done

    echo ""
    if [[ "$failed" -eq 0 ]]; then
        log_success "Pipeline completed successfully — all ${total} modules passed"
    else
        log_warn "Pipeline completed with ${failed}/${total} module(s) having errors"
    fi
}

# ── Run Module for Multiple Domains ─────────────────────────────────────────
run_for_domains() {
    local domain_file="$1"
    local modules_csv="${2:-}"

    if [[ ! -f "$domain_file" ]]; then
        log_error "Domain file not found: $domain_file"
        return 1
    fi

    local total_domains
    total_domains="$(count_lines "$domain_file")"
    local current=0

    log_info "Processing ${total_domains} domains from: ${domain_file}"

    while IFS= read -r domain; do
        [[ -z "$domain" || "$domain" =~ ^# ]] && continue
        current=$((current + 1))

        log_separator
        log_info "Domain ${current}/${total_domains}: ${domain}"
        log_separator

        TARGET_DOMAIN="$domain"
        init_target_dirs "$domain"
        init_state "$domain"
        init_logging "$domain"

        if ! acquire_lock "$domain"; then
            log_warn "Skipping $domain — locked by another instance"
            continue
        fi

        run_pipeline "$domain" "$modules_csv"
        release_lock "$domain"

    done < "$domain_file"
}

# ── Notification System ─────────────────────────────────────────────────────
send_notification() {
    local message="$1"

    # Telegram (HTML mode for premium formatting)
    local tg_token="${CONFIG[notify.telegram_token]:-}"
    local tg_chat="${CONFIG[notify.telegram_chat_id]:-}"
    if [[ -n "$tg_token" && -n "$tg_chat" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${tg_token}/sendMessage" \
            -d "chat_id=${tg_chat}" \
            -d "text=${message}" \
            -d "parse_mode=HTML" \
            -d "disable_web_page_preview=true" &>/dev/null &
    fi

    # Discord
    local discord_webhook="${CONFIG[notify.discord_webhook]:-}"
    if [[ -n "$discord_webhook" ]]; then
        # Strip HTML tags for Discord
        local discord_msg
        discord_msg=$(echo "$message" | sed 's/<[^>]*>//g')
        curl -s -X POST "$discord_webhook" \
            -H "Content-Type: application/json" \
            -d "{\"content\": \"${discord_msg}\"}" &>/dev/null &
    fi

    # Slack
    local slack_webhook="${CONFIG[notify.slack_webhook]:-}"
    if [[ -n "$slack_webhook" ]]; then
        local slack_msg
        slack_msg=$(echo "$message" | sed 's/<[^>]*>//g')
        curl -s -X POST "$slack_webhook" \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"${slack_msg}\"}" &>/dev/null &
    fi
}
