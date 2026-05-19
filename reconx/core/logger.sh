#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Logging System
# ============================================================================
# Provides structured, colored, timestamped logging with file output support.
# ============================================================================

# ── Ensure common.sh is loaded ──────────────────────────────────────────────
if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# ── Log Levels ──────────────────────────────────────────────────────────────
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARN=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_CRITICAL=4

CURRENT_LOG_LEVEL=${LOG_LEVEL_INFO}
LOG_FILE=""
LOG_TO_FILE=true

# ── Initialize Log File ─────────────────────────────────────────────────────
init_logging() {
    local domain="${1:-reconx}"
    local log_dir="${RECONX_ROOT}/logs"
    mkdir -p "$log_dir"
    LOG_FILE="${log_dir}/${domain}_${TIMESTAMP}.log"
    touch "$LOG_FILE"
    log_info "Log file initialized: ${LOG_FILE}"
}

# ── Core Logging Function ───────────────────────────────────────────────────
_log() {
    local level="$1"
    local level_num="$2"
    local color="$3"
    local icon="$4"
    shift 4
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    # Skip if below current log level
    if [[ "$level_num" -lt "$CURRENT_LOG_LEVEL" ]]; then
        return
    fi

    # Console output (colored)
    echo -e "${GRAY}[${timestamp}]${RESET} ${color}${icon} [${level}]${RESET} ${message}"

    # File output (no colors)
    if [[ "$LOG_TO_FILE" == true && -n "$LOG_FILE" ]]; then
        echo "[${timestamp}] [${level}] ${message}" >> "$LOG_FILE"
    fi
}

# ── Public Logging Functions ─────────────────────────────────────────────────
log_debug() {
    if [[ "$DEBUG_MODE" == true ]]; then
        _log "DEBUG" "$LOG_LEVEL_DEBUG" "$GRAY" "🔍" "$@"
    fi
}

log_info() {
    _log "INFO" "$LOG_LEVEL_INFO" "$CYAN" "ℹ️ " "$@"
}

log_success() {
    _log "SUCCESS" "$LOG_LEVEL_INFO" "$GREEN" "✅" "$@"
}

log_warn() {
    _log "WARN" "$LOG_LEVEL_WARN" "$YELLOW" "⚠️ " "$@"
}

log_error() {
    _log "ERROR" "$LOG_LEVEL_ERROR" "$RED" "❌" "$@"
}

log_critical() {
    _log "CRITICAL" "$LOG_LEVEL_CRITICAL" "${BG_RED}${WHITE}" "🚨" "$@"
}

# ── Module Logging ──────────────────────────────────────────────────────────
log_module_start() {
    local module_name="$1"
    local target="${2:-$TARGET_DOMAIN}"
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${MAGENTA}  ▶ MODULE: ${module_name}${RESET}"
    echo -e "${GRAY}  Target: ${target}${RESET}"
    echo -e "${GRAY}  Started: $(date '+%Y-%m-%d %H:%M:%S')${RESET}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    _log "MODULE" "$LOG_LEVEL_INFO" "$MAGENTA" "🚀" "Starting module: ${module_name} | Target: ${target}"
    # Clear batch file for new module
    > "$_TG_BATCH_FILE" 2>/dev/null || true
    # Telegram: module started
    if type tg_send &>/dev/null; then
        tg_send "📦 *${module_name}* started
🎯 \`${target}\`" 2>/dev/null &
    fi
}

log_module_end() {
    local module_name="$1"
    local start_time="$2"
    local result_count="${3:-0}"
    local elapsed
    elapsed="$(elapsed_time "$start_time")"
    echo ""
    echo -e "${GREEN}  ✓ Module ${module_name} completed in ${elapsed} — ${result_count} results${RESET}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    _log "MODULE" "$LOG_LEVEL_INFO" "$GREEN" "✅" "Completed: ${module_name} | Time: ${elapsed} | Results: ${result_count}"
    # Telegram: send accumulated tool results + completion
    if type tg_send &>/dev/null; then
        local batch=""
        [[ -f "$_TG_BATCH_FILE" ]] && batch=$(cat "$_TG_BATCH_FILE" 2>/dev/null)
        rm -f "$_TG_BATCH_FILE" 2>/dev/null
        local msg=""
        [[ -n "$batch" ]] && msg="${batch}
"
        msg="${msg}✅ *${module_name}* completed in \`${elapsed}\` — *${result_count}* results"
        tg_send "$msg" 2>/dev/null &
    fi
}

# ── Progress Indicator ──────────────────────────────────────────────────────
log_progress() {
    local current="$1"
    local total="$2"
    local label="${3:-Processing}"
    local pct=$((current * 100 / total))
    local filled=$((pct / 2))
    local empty=$((50 - filled))
    local bar=""
    bar="$(printf '█%.0s' $(seq 1 "$filled" 2>/dev/null) 2>/dev/null)$(printf '░%.0s' $(seq 1 "$empty" 2>/dev/null) 2>/dev/null)"
    printf "\r${CYAN}  ${label}: [${bar}] ${pct}%% (${current}/${total})${RESET}"
    if [[ "$current" -eq "$total" ]]; then
        echo ""
    fi
}

# ── Statistics Logging ──────────────────────────────────────────────────────
log_stats() {
    local label="$1"
    local value="$2"
    echo -e "${GRAY}    ├─ ${WHITE}${label}: ${CYAN}${value}${RESET}"
}

log_stats_final() {
    local label="$1"
    local value="$2"
    echo -e "${GRAY}    └─ ${WHITE}${label}: ${CYAN}${value}${RESET}"
}

# ── Separator ───────────────────────────────────────────────────────────────
log_separator() {
    echo -e "${GRAY}──────────────────────────────────────────────────────────${RESET}"
}

# ── Task Timer ──────────────────────────────────────────────────────────────
log_task_start() {
    local task="$1"
    echo -e "${GRAY}  ⏳ ${task}...${RESET}"
}

log_task_done() {
    local task="$1"
    local count="${2:-}"
    if [[ -n "$count" ]]; then
        echo -e "${GREEN}  ✓ ${task} — ${count} found${RESET}"
        # Real-time Telegram: every tool result
        _tg_task "✓ ${task} — ${count} found" 2>/dev/null &
    else
        echo -e "${GREEN}  ✓ ${task}${RESET}"
        _tg_task "✓ ${task}" 2>/dev/null &
    fi
}

# ── Telegram Step Accumulator ──────────────────────────────────────────────
# Batches tool results and sends them as one message per module
_TG_BATCH_FILE="/tmp/.reconx_tg_batch_$$"

_tg_task() {
    local msg="$1"
    echo "$msg" >> "$_TG_BATCH_FILE" 2>/dev/null || true
}

_tg_flush_batch() {
    [[ ! -f "$_TG_BATCH_FILE" ]] && return
    local lines
    lines=$(cat "$_TG_BATCH_FILE" 2>/dev/null)
    rm -f "$_TG_BATCH_FILE" 2>/dev/null
    [[ -z "$lines" ]] && return
    # Send accumulated results
    if type tg_send &>/dev/null; then
        tg_send "$lines" 2>/dev/null || true
    fi
}

