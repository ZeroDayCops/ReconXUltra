#!/usr/bin/env bash
# ============================================================================
#
#  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
#  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
#  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
#  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
#  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
#  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
#               U L T R A   X
#
#  Autonomous Hunter Intelligence Operating System v3.0.0
#  XBOW-Style Meta-Architecture | Confidence-Driven Reasoning
#
#  Author:  ReconX Team
#  License: MIT
#
# ============================================================================

set -o pipefail

# ── Bootstrap ────────────────────────────────────────────────────────────────
RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RECONX_ROOT

# Load core libraries
source "${RECONX_ROOT}/core/common.sh"
source "${RECONX_ROOT}/core/logger.sh"
source "${RECONX_ROOT}/core/config_loader.sh"
source "${RECONX_ROOT}/core/dependency_checker.sh"
source "${RECONX_ROOT}/core/state_manager.sh"
source "${RECONX_ROOT}/core/module_runner.sh"
source "${RECONX_ROOT}/core/telegram.sh" 2>/dev/null || true

# ── Default Values ──────────────────────────────────────────────────────────
TARGET_DOMAIN=""
HUNT_MODE="full"
TARGET_LIST=""
MODULES_LIST=""
CONFIG_FILE="${RECONX_CONFIGS}/default.yaml"
SKIP_DEPS_CHECK=false
RESET_STATE=false
LIST_MODULES=false
SHOW_STATUS=false
PARALLEL_MODE=false
STREAM_MODE=false
PERF_MODE="balanced"
AUTOPILOT_MODE=false
MONITOR_MODE=false
MONITOR_INTERVAL=30
AUTH_PROFILE=""
RUN_COMMAND=""
RUN_DNA=false
RUN_STRATEGY=false

# ── Usage ────────────────────────────────────────────────────────────────────
usage() {
    print_banner
    echo -e "${WHITE}Usage:${RESET}"
    echo -e "  ${CYAN}./reconx.sh${RESET} ${GREEN}-d${RESET} <domain>              Single domain recon"
    echo -e "  ${CYAN}./reconx.sh${RESET} ${GREEN}-l${RESET} <file>                Multi-domain recon"
    echo -e "  ${CYAN}./reconx.sh${RESET} ${GREEN}-d${RESET} <domain> ${GREEN}--modules${RESET} <list>  Selected modules"
    echo ""
    echo -e "${WHITE}Options:${RESET}"
    echo -e "  ${GREEN}-d, --domain${RESET}       Target domain"
    echo -e "  ${GREEN}-l, --list${RESET}         File containing list of domains"
    echo -e "  ${GREEN}-m, --modules${RESET}      Comma-separated module list"
    echo -e "  ${GREEN}-c, --config${RESET}       Path to YAML config file"
    echo -e "  ${GREEN}-t, --threads${RESET}      Number of threads (default: 50)"
    echo -e "  ${GREEN}-r, --rate${RESET}         Rate limit (default: 150)"
    echo -e "  ${GREEN}    --resume${RESET}       Resume from last state"
    echo -e "  ${GREEN}    --reset${RESET}        Reset state for target"
    echo -e "  ${GREEN}    --no-deps${RESET}      Skip dependency check"
    echo -e "  ${GREEN}    --debug${RESET}        Enable debug logging"
    echo -e "  ${GREEN}    --status${RESET}       Show scan status for domain"
    echo -e "  ${GREEN}    --list-modules${RESET} List available modules"
    echo -e "  ${GREEN}    --parallel${RESET}     Enable parallel pipeline execution"
    echo -e "  ${GREEN}    --mode${RESET}         Performance mode (safe|balanced|aggressive|ultra|nuclear)"
    echo -e "  ${GREEN}    --autopilot${RESET}    Full autonomous hunting pipeline"
    echo -e "  ${GREEN}    --monitor${RESET}      Continuous monitoring mode"
    echo -e "  ${GREEN}    --monitor-interval${RESET} Monitor interval in minutes (default: 30)"
    echo -e "  ${GREEN}    --auth${RESET}         Auth profile name for authenticated hunting"
    echo -e "  ${GREEN}    --dna${RESET}          Generate target DNA fingerprint"
    echo -e "  ${GREEN}    --strategy${RESET}     Generate AI hunter strategy"
    echo -e "  ${GREEN}    --command${RESET}      Run autonomous command (/recon, /hunt, etc.)"
    echo -e "  ${GREEN}    --install${RESET}      Run the installer"
    echo -e "  ${GREEN}    --update${RESET}       Update all tools"
    echo -e "  ${GREEN}    --check${RESET}        Check dependencies"
    echo -e "  ${GREEN}-h, --help${RESET}         Show this help"
    echo ""
    echo -e "${WHITE}Available Modules:${RESET}"
    echo -e "  ${CYAN}subdomains${RESET}   Passive + active subdomain enumeration"
    echo -e "  ${CYAN}live${RESET}         Live host detection (httpx)"
    echo -e "  ${CYAN}urls${RESET}         URL gathering + filtering + params"
    echo -e "  ${CYAN}js${RESET}           JavaScript analysis + secret extraction"
    echo -e "  ${CYAN}content${RESET}      Content discovery (ffuf + dirsearch)"
    echo -e "  ${CYAN}nuclei${RESET}       Nuclei vulnerability scanning"
    echo -e "  ${CYAN}screenshots${RESET}  Screenshot capture"
    echo -e "  ${CYAN}ports${RESET}        Port scanning (naabu + nmap)"
    echo -e "  ${CYAN}takeover${RESET}     Subdomain takeover detection"
    echo -e "  ${CYAN}cors${RESET}         CORS misconfiguration detection"
    echo -e "  ${CYAN}wordpress${RESET}    WordPress scanning"
    echo -e "  ${CYAN}api${RESET}          API discovery (GraphQL + Swagger)"
    echo -e "  ${CYAN}intelligence${RESET} Bug signal engine + vuln classification"
    echo -e "  ${CYAN}exploit${RESET}      Active exploitation (XSS, SQLi, vuln fuzzing)"
    echo -e "  ${CYAN}validation${RESET}   Autonomous validation + confidence scoring + PoC"
    echo -e "  ${CYAN}reporting${RESET}    Report generation + HTML dashboard"
    echo ""
    echo -e "${WHITE}Hunter Modes:${RESET}"
    echo -e "  ${CYAN}xss-hunt${RESET}     XSS-focused hunting    ${CYAN}sqli-hunt${RESET}    SQLi-focused hunting"
    echo -e "  ${CYAN}ssrf-hunt${RESET}    SSRF-focused hunting   ${CYAN}idor-hunt${RESET}    IDOR-focused hunting"
    echo -e "  ${CYAN}graphql-hunt${RESET} GraphQL hunting        ${CYAN}api-hunt${RESET}     API hunting"
    echo -e "  ${CYAN}auth-hunt${RESET}    Auth flow hunting      ${CYAN}upload-hunt${RESET}  Upload hunting"
    echo -e "  ${CYAN}cloud-hunt${RESET}   Cloud exposure         ${CYAN}secrets-hunt${RESET} Secret detection"
    echo -e "  ${CYAN}js-hunt${RESET}      JS intelligence        ${CYAN}chain-hunt${RESET}   Attack chain hunting"
    echo -e "  ${CYAN}stealth-hunt${RESET} Low-profile hunting    ${CYAN}aggressive-hunt${RESET} Full-spectrum"
    echo ""
    echo -e "${WHITE}Examples:${RESET}"
    echo -e "  ${GRAY}# Full recon on single domain${RESET}"
    echo -e "  ${CYAN}./reconx.sh -d example.com${RESET}"
    echo ""
    echo -e "  ${GRAY}# Specific modules only${RESET}"
    echo -e "  ${CYAN}./reconx.sh -d example.com --modules subdomains,live,urls,nuclei${RESET}"
    echo ""
    echo -e "  ${GRAY}# Multi-domain with custom config${RESET}"
    echo -e "  ${CYAN}./reconx.sh -l targets.txt --config configs/aggressive.yaml${RESET}"
    echo ""
    echo -e "  ${GRAY}# Resume interrupted scan${RESET}"
    echo -e "  ${CYAN}./reconx.sh -d example.com --resume${RESET}"
    echo ""
}

# ── Argument Parser ─────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d|--domain)
                TARGET_DOMAIN="$2"
                shift 2
                ;;
            -l|--list)
                TARGET_LIST="$2"
                shift 2
                ;;
            -m|--modules)
                MODULES_LIST="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -t|--threads)
                THREADS="$2"
                shift 2
                ;;
            -r|--rate)
                RATE_LIMIT="$2"
                shift 2
                ;;
            --resume)
                RESUME_MODE=true
                shift
                ;;
            --reset)
                RESET_STATE=true
                shift
                ;;
            --no-deps)
                SKIP_DEPS_CHECK=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --status)
                SHOW_STATUS=true
                shift
                ;;
            --list-modules)
                LIST_MODULES=true
                shift
                ;;
            --parallel)
                PARALLEL_MODE=true
                shift
                ;;
            --mode)
                PERF_MODE="$2"
                shift 2
                ;;
            --hunt)
                HUNT_MODE="$2"
                shift 2
                ;;
            --stream)
                STREAM_MODE=true
                PARALLEL_MODE=true
                shift
                ;;
            --autopilot)
                AUTOPILOT_MODE=true
                shift
                ;;
            --monitor)
                MONITOR_MODE=true
                shift
                ;;
            --monitor-interval)
                MONITOR_INTERVAL="$2"
                shift 2
                ;;
            --auth)
                AUTH_PROFILE="$2"
                shift 2
                ;;
            --dna)
                RUN_DNA=true
                shift
                ;;
            --strategy)
                RUN_STRATEGY=true
                shift
                ;;
            --command)
                RUN_COMMAND="$2"
                shift 2
                ;;
            --install)
                bash "${RECONX_INSTALL}/installer.sh"
                exit 0
                ;;
            --update)
                bash "${RECONX_INSTALL}/update.sh"
                exit 0
                ;;
            --check)
                check_dependencies
                exit 0
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${RESET}"
                usage
                exit 1
                ;;
        esac
    done
}

# ── List Modules ─────────────────────────────────────────────────────────────
list_available_modules() {
    print_banner
    echo -e "${WHITE}Available Modules:${RESET}"
    echo ""
    for module in "${DEFAULT_PIPELINE[@]}"; do
        local enabled="true"
        if [[ -n "${CONFIG[modules.${module}]:-}" ]]; then
            enabled="${CONFIG[modules.${module}]}"
        fi
        if [[ "$enabled" == "true" ]]; then
            echo -e "  ${GREEN}✓${RESET} ${module}"
        else
            echo -e "  ${GRAY}○${RESET} ${module} (disabled)"
        fi
    done
    echo ""
}

# ── Main Entry Point ────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    # Handle special modes
    if [[ "$LIST_MODULES" == true ]]; then
        list_available_modules
        exit 0
    fi

    # Validate target
    if [[ -z "$TARGET_DOMAIN" && -z "$TARGET_LIST" ]]; then
        usage
        exit 1
    fi

    # Print banner
    print_banner

    # Load configuration
    load_config "$CONFIG_FILE"

    # Dependency check
    if [[ "$SKIP_DEPS_CHECK" != true ]]; then
        if ! quick_check; then
            log_warn "Some required tools are missing — run with --install or --check"
        fi
    fi

    SCAN_START="$(date +%s)"

    # Apply performance mode
    apply_perf_mode "$PERF_MODE"

    # ── Single Domain Mode ──────────────────────────────────────────────────
    if [[ -n "$TARGET_DOMAIN" ]]; then
        # Validate domain
        if ! validate_domain "$TARGET_DOMAIN"; then
            log_error "Invalid domain: $TARGET_DOMAIN"
            exit 1
        fi

        log_info "Target: ${TARGET_DOMAIN}"
        log_info "Mode: Single domain | Hunt: ${HUNT_MODE}"
        log_info "Performance: ${PERF_MODE} | Threads: ${THREADS} | Rate: ${RATE_LIMIT}"
        [[ "$PARALLEL_MODE" == true ]] && log_info "Pipeline: PARALLEL"
        [[ "$AUTOPILOT_MODE" == true ]] && log_info "Pipeline: AUTOPILOT 🤖"
        [[ -n "$MODULES_LIST" ]] && log_info "Modules: ${MODULES_LIST}"
        [[ -n "$AUTH_PROFILE" ]] && log_info "Auth: ${AUTH_PROFILE}"

        # Initialize
        init_target_dirs "$TARGET_DOMAIN"
        init_state "$TARGET_DOMAIN"
        init_logging "$TARGET_DOMAIN"

        # Load auth profile if specified
        if [[ -n "$AUTH_PROFILE" ]]; then
            log_info "Loading auth profile: $AUTH_PROFILE"
            eval "$(python3 '${RECONX_CORE}/auth_manager.py' export '$AUTH_PROFILE' 2>/dev/null)" || true
        fi

        # Handle autonomous command
        if [[ -n "$RUN_COMMAND" ]]; then
            python3 "${RECONX_CORE}/command_router.py" "$RUN_COMMAND" "$TARGET_DOMAIN"
            exit 0
        fi

        # Handle DNA fingerprint
        if [[ "$RUN_DNA" == true ]]; then
            python3 "${RECONX_MODULES}/intelligence/target_dna.py" "$TARGET_DOMAIN"
            exit 0
        fi

        # Handle strategy generation
        if [[ "$RUN_STRATEGY" == true ]]; then
            python3 "${RECONX_CORE}/strategic_agent.py" "$TARGET_DOMAIN" "$HUNT_MODE"
            exit 0
        fi

        # Handle monitor mode
        if [[ "$MONITOR_MODE" == true ]]; then
            log_info "🔄 MONITOR MODE — continuous detection"
            python3 "${RECONX_CORE}/monitor_engine.py" "$TARGET_DOMAIN" "$MONITOR_INTERVAL"
            exit 0
        fi

        # Telegram scan start notification
        tg_scan_start "$TARGET_DOMAIN" "${HUNT_MODE:-default}" 2>/dev/null || true

        # Handle reset
        if [[ "$RESET_STATE" == true ]]; then
            reset_all_state "$TARGET_DOMAIN"
            log_info "State reset for: $TARGET_DOMAIN"
        fi

        # Handle status check
        if [[ "$SHOW_STATUS" == true ]]; then
            list_states
            exit 0
        fi

        # Acquire lock
        if ! acquire_lock "$TARGET_DOMAIN"; then
            exit 1
        fi

        # Notify scan start
        if [[ "$NOTIFY_ENABLED" == true ]]; then
            local pipe_mode="Sequential"
            [[ "$PARALLEL_MODE" == true ]] && pipe_mode="Parallel"
            [[ "$STREAM_MODE" == true ]] && pipe_mode="Streaming"
            [[ "$AUTOPILOT_MODE" == true ]] && pipe_mode="Autopilot 🤖"
            send_notification "🚀 <b>Hunter Intelligence OS — Scan Started</b>
━━━━━━━━━━━━━━━━━━
🎯 Target: <code>${TARGET_DOMAIN}</code>
⚙️ Hunt: <b>${HUNT_MODE}</b>
🔄 Pipeline: <b>${pipe_mode}</b>
🕐 <code>$(date '+%Y-%m-%d %H:%M:%S')</code>"
        fi

        # Run pipeline (autopilot, streaming, parallel, or sequential)
        if [[ "$AUTOPILOT_MODE" == true ]]; then
            log_info "🤖 AUTOPILOT MODE — full autonomous hunting"
            # Phase 1: Recon
            run_pipeline "$TARGET_DOMAIN" "subdomains,live,urls,dedup,js,content,api"
            # Phase 2: Intelligence (DNA + Surface Ranking)
            python3 "${RECONX_MODULES}/intelligence/target_dna.py" "$TARGET_DOMAIN" 2>/dev/null || true
            run_pipeline "$TARGET_DOMAIN" "intelligence"
            python3 "${RECONX_MODULES}/intelligence/surface_ranker.py" "$TARGET_DOMAIN" 2>/dev/null || true
            # Phase 3: EBRE — Evidence-Based Reasoning
            log_info "🧠 Phase 3: Evidence-Based Reasoning Engine"
            python3 "${RECONX_MODULES}/intelligence/observed_signals.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/micro_validation.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/workflow_evidence.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/reasoning_engine.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/attack_paths.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/reasoning_trace.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/intelligence/strategy_engine.py" "$TARGET_DOMAIN" 2>/dev/null || true
            # Phase 4: Behavioral Intelligence
            log_info "🔬 Phase 4: Behavioral Intelligence"
            python3 "${RECONX_MODULES}/behavioral/auth_behavior.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/object_relationships.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/workflow_transitions.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/dom_observer.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/session_intelligence.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/api_behavior.py" "$TARGET_DOMAIN" 2>/dev/null || true
            python3 "${RECONX_MODULES}/behavioral/target_understanding.py" "$TARGET_DOMAIN" 2>/dev/null || true
            # Phase 5: Strategic reasoning
            python3 "${RECONX_CORE}/strategic_agent.py" "$TARGET_DOMAIN" "$HUNT_MODE" 2>/dev/null || true
            # Phase 6: Exploitation + Validation
            run_pipeline "$TARGET_DOMAIN" "exploit,validation"
            # Phase 7: Chain building
            python3 "${RECONX_MODULES}/intelligence/chain_builder.py" "$TARGET_DOMAIN" 2>/dev/null || true
            # Phase 8: Reporting
            run_pipeline "$TARGET_DOMAIN" "reporting"
        elif [[ "$STREAM_MODE" == true ]]; then
            log_info "🌊 STREAMING MODE — real-time pipe-based recon"
            bash "${RECONX_CORE}/streaming_pipeline.sh" "$TARGET_DOMAIN"
            run_pipeline "$TARGET_DOMAIN" "intelligence,exploit,validation,reporting"
        elif [[ "$PARALLEL_MODE" == true ]]; then
            run_parallel_pipeline "$TARGET_DOMAIN" "$MODULES_LIST"
        else
            run_pipeline "$TARGET_DOMAIN" "$MODULES_LIST"
        fi

        # Release lock
        release_lock "$TARGET_DOMAIN"

    # ── Multi-Domain Mode ───────────────────────────────────────────────────
    elif [[ -n "$TARGET_LIST" ]]; then
        if [[ ! -f "$TARGET_LIST" ]]; then
            log_error "Domain list not found: $TARGET_LIST"
            exit 1
        fi

        log_info "Target list: ${TARGET_LIST}"
        log_info "Mode: Multi-domain ($(count_lines "$TARGET_LIST") targets)"

        run_for_domains "$TARGET_LIST" "$MODULES_LIST"
    fi

    # ── Final Summary ───────────────────────────────────────────────────────
    SCAN_END="$(date +%s)"
    TOTAL_TIME="$(elapsed_time "$SCAN_START" "$SCAN_END")"

    echo ""
    log_separator
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════╗"
    echo "  ║   Hunter Intelligence OS — Scan Complete         ║"
    echo "  ╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    log_stats "Total time" "$TOTAL_TIME"

    if [[ -n "$TARGET_DOMAIN" ]]; then
        log_stats "Output" "${RECONX_ROOT}/output/${TARGET_DOMAIN}/"
        log_stats "Report" "${RECONX_ROOT}/output/${TARGET_DOMAIN}/reports/"
        log_stats_final "Logs" "${RECONX_ROOT}/logs/"
    fi

    echo ""

    # Send completion notification with stats
    if [[ "$NOTIFY_ENABLED" == true && -n "${TARGET_DOMAIN:-}" ]]; then
        local out_dir="${RECONX_ROOT}/output/${TARGET_DOMAIN}"
        local n_subs=$(cat "${out_dir}/subs/all_subdomains.txt" 2>/dev/null | wc -l)
        local n_urls=$(cat "${out_dir}/urls/all_urls.txt" 2>/dev/null | wc -l)
        local n_live=$(cat "${out_dir}/live/live_hosts.txt" 2>/dev/null | wc -l)
        local n_js=$(cat "${out_dir}/js/js_urls.txt" 2>/dev/null | wc -l)
        local n_params=$(cat "${out_dir}/urls/parameterized_urls.txt" 2>/dev/null | wc -l)
        local n_nuclei=$(cat "${out_dir}/scans/nuclei_all_summary.txt" 2>/dev/null | wc -l)
        local n_xss=$(cat "${out_dir}/intelligence/xss_candidates.txt" 2>/dev/null | wc -l)
        local n_sqli=$(cat "${out_dir}/intelligence/sqli_candidates.txt" 2>/dev/null | wc -l)
        local n_ssrf=$(cat "${out_dir}/intelligence/ssrf_candidates.txt" 2>/dev/null | wc -l)
        local n_idor=$(cat "${out_dir}/intelligence/idor_candidates.txt" 2>/dev/null | wc -l)
        local n_secrets=$(cat "${out_dir}/secrets/js_secrets_summary.txt" 2>/dev/null | wc -l)
        # Validated findings stats
        local n_validated=0 n_confirmed=0 n_chains=0
        if [[ -f "${out_dir}/validated/confidence_report.json" ]]; then
            n_validated=$(python3 -c "import json;d=json.load(open('${out_dir}/validated/confidence_report.json'));print(d.get('total_validated',0))" 2>/dev/null || echo 0)
            n_confirmed=$(python3 -c "import json;d=json.load(open('${out_dir}/validated/confidence_report.json'));print(d.get('confirmed_findings',0))" 2>/dev/null || echo 0)
        fi
        if [[ -f "${out_dir}/attack_chains/attack_chains.json" ]]; then
            n_chains=$(python3 -c "import json;d=json.load(open('${out_dir}/attack_chains/attack_chains.json'));print(d.get('total_chains',0))" 2>/dev/null || echo 0)
        fi
        send_notification "⚡ <b>ReconX Ultra X — Scan Complete</b>
━━━━━━━━━━━━━━━━━━━━━━━━
🎯 Target: <code>${TARGET_DOMAIN}</code>
⏱ Duration: <b>${TOTAL_TIME}</b>

📊 <b>Reconnaissance</b>
┌─ Subdomains: <b>${n_subs}</b>
├─ Live Hosts: <b>${n_live}</b>
├─ URLs: <b>${n_urls}</b>
├─ Parameterized: <b>${n_params}</b>
└─ JS Files: <b>${n_js}</b>

🔥 <b>Candidates</b>
┌─ Nuclei: <b>${n_nuclei}</b>
├─ XSS: <b>${n_xss}</b>
├─ SQLi: <b>${n_sqli}</b>
├─ SSRF: <b>${n_ssrf}</b>
├─ IDOR: <b>${n_idor}</b>
└─ Secrets: <b>${n_secrets}</b>

🔬 <b>Validation</b>
┌─ Validated: <b>${n_validated}</b>
├─ Confirmed: <b>${n_confirmed}</b>
└─ Attack Chains: <b>${n_chains}</b>

📋 <i>Dashboard → output/${TARGET_DOMAIN}/reports/report.html</i>"
    fi
}

main "$@"
