#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Core Common Library
# ============================================================================
# Shared variables, constants, and utility functions used across all modules.
# ============================================================================

# Note: Do NOT use set -euo pipefail here — it causes silent exits
# when arithmetic expressions evaluate to 0 or optional tools are missing.

# ── Version ──────────────────────────────────────────────────────────────────
RECONX_VERSION="2.0.0"
RECONX_CODENAME="Ultra"

# ── Paths ────────────────────────────────────────────────────────────────────
RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RECONX_CORE="${RECONX_ROOT}/core"
RECONX_MODULES="${RECONX_ROOT}/modules"
RECONX_CONFIGS="${RECONX_ROOT}/configs"
RECONX_WORDLISTS="${RECONX_ROOT}/wordlists"
RECONX_TEMPLATES="${RECONX_ROOT}/templates"
RECONX_TOOLS="${RECONX_ROOT}/tools"
RECONX_TMP="${RECONX_ROOT}/tmp"
RECONX_INSTALL="${RECONX_ROOT}/install"

# ── Output Directories ──────────────────────────────────────────────────────
# These are set per-target in init_target_dirs()
OUTPUT_DIR=""
OUT_SUBS=""
OUT_RESOLVED=""
OUT_LIVE=""
OUT_URLS=""
OUT_JS=""
OUT_PARAMS=""
OUT_CONTENT=""
OUT_SCANS=""
OUT_SCREENSHOTS=""
OUT_TAKEOVER=""
OUT_SECRETS=""
OUT_REPORTS=""
OUT_LOGS=""
OUT_INTEL=""

# ── Runtime Variables ────────────────────────────────────────────────────────
TARGET_DOMAIN=""
TARGET_LIST=""
MODULES_LIST=""
CONFIG_FILE="${RECONX_CONFIGS}/default.yaml"
DEBUG_MODE=false
RESUME_MODE=false
NOTIFY_ENABLED=false
THREADS=50
RATE_LIMIT=150
TIMEOUT=30
RETRIES=3
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# ── Color Codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
RESET='\033[0m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'

# ── Banner ───────────────────────────────────────────────────────────────────
print_banner() {
    echo -e "${CYAN}"
    cat << 'BANNER'

    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
                        ╚═══ U L T R A ═══╝

BANNER
    echo -e "${WHITE}    ⚡ ReconX Ultra v${RECONX_VERSION} — Attack Surface Intelligence${RESET}"
    echo -e "${GRAY}    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ── Target Directory Initialization ─────────────────────────────────────────
init_target_dirs() {
    local domain="$1"
    OUTPUT_DIR="${RECONX_ROOT}/output/${domain}"
    OUT_SUBS="${OUTPUT_DIR}/subs"
    OUT_RESOLVED="${OUTPUT_DIR}/resolved"
    OUT_LIVE="${OUTPUT_DIR}/live"
    OUT_URLS="${OUTPUT_DIR}/urls"
    OUT_JS="${OUTPUT_DIR}/js"
    OUT_PARAMS="${OUTPUT_DIR}/params"
    OUT_CONTENT="${OUTPUT_DIR}/content"
    OUT_SCANS="${OUTPUT_DIR}/scans"
    OUT_SCREENSHOTS="${OUTPUT_DIR}/screenshots"
    OUT_TAKEOVER="${OUTPUT_DIR}/takeover"
    OUT_SECRETS="${OUTPUT_DIR}/secrets"
    OUT_REPORTS="${OUTPUT_DIR}/reports"
    OUT_LOGS="${OUTPUT_DIR}/logs"
    OUT_INTEL="${OUTPUT_DIR}/intelligence"

    local dirs=(
        "$OUT_SUBS" "$OUT_RESOLVED" "$OUT_LIVE" "$OUT_URLS" "$OUT_JS"
        "$OUT_PARAMS" "$OUT_CONTENT" "$OUT_SCANS" "$OUT_SCREENSHOTS"
        "$OUT_TAKEOVER" "$OUT_SECRETS" "$OUT_REPORTS" "$OUT_LOGS" "$OUT_INTEL"
    )
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
    done
}

# ── Utility Functions ────────────────────────────────────────────────────────

# Check if a command exists
cmd_exists() {
    command -v "$1" &>/dev/null
}

# Count lines in a file (zero if missing)
count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Deduplicate and sort a file in-place
dedup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        sort -u "$file" -o "$file"
    fi
}

# Merge multiple files into one, deduped
merge_dedup() {
    local output="$1"
    shift
    cat "$@" 2>/dev/null | sort -u > "$output"
}

# Safe append using anew if available, otherwise basic dedup append
safe_append() {
    local input="$1"
    local output="$2"
    if cmd_exists anew; then
        cat "$input" | anew -q "$output"
    else
        cat "$input" >> "$output"
        dedup_file "$output"
    fi
}

# Retry a command with exponential backoff
retry_cmd() {
    local max_retries="${1:-$RETRIES}"
    local delay=2
    shift
    local cmd=("$@")
    for ((i=1; i<=max_retries; i++)); do
        if "${cmd[@]}"; then
            return 0
        fi
        log_warn "Retry $i/$max_retries failed for: ${cmd[*]}"
        sleep "$delay"
        delay=$((delay * 2))
    done
    log_error "Command failed after $max_retries retries: ${cmd[*]}"
    return 1
}

# Run a command with a timeout
timed_run() {
    local max_time="${1:-$TIMEOUT}"
    shift
    timeout "$max_time" "$@"
}

# Calculate elapsed time in human-readable format
elapsed_time() {
    local start="$1"
    local end="${2:-$(date +%s)}"
    local diff=$((end - start))
    local hours=$((diff / 3600))
    local mins=$(((diff % 3600) / 60))
    local secs=$((diff % 60))
    printf "%02d:%02d:%02d" "$hours" "$mins" "$secs"
}

# Get current timestamp for filenames
get_timestamp() {
    date +%Y%m%d_%H%M%S
}

# Validate that target domain looks sane
validate_domain() {
    local domain="$1"
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        return 0
    fi
    return 1
}

# URL-encode a string
urlencode() {
    python3 -c "import urllib.parse; print(urllib.parse.quote('$1', safe=''))"
}

# Extract root domain from input
extract_root_domain() {
    echo "$1" | awk -F. '{print $(NF-1)"."$NF}'
}

# Check if running as root
is_root() {
    [[ "$EUID" -eq 0 ]]
}

# Calculate file hash for change detection
file_hash() {
    local file="$1"
    if [[ -f "$file" ]]; then
        md5sum "$file" | awk '{print $1}'
    else
        echo "none"
    fi
}

# Cleanup temporary files
cleanup_tmp() {
    rm -rf "${RECONX_TMP:?}"/*
}

# Trap handler for graceful shutdown
graceful_shutdown() {
    echo ""
    log_warn "Interrupt received — saving state and shutting down..."
    if [[ -n "${TARGET_DOMAIN:-}" && -n "${CURRENT_MODULE:-}" ]]; then
        save_state "$TARGET_DOMAIN" "$CURRENT_MODULE" "interrupted"
    elif [[ -n "${TARGET_DOMAIN:-}" ]]; then
        # No specific module running — just update the state file timestamp
        if [[ -f "${STATE_FILE:-}" ]]; then
            echo "global=interrupted|$(date +%s)" >> "$STATE_FILE"
        fi
    fi
    # Release lock
    if [[ -n "${TARGET_DOMAIN:-}" ]]; then
        release_lock "$TARGET_DOMAIN" 2>/dev/null || true
    fi
    exit 130
}

trap graceful_shutdown SIGINT SIGTERM
