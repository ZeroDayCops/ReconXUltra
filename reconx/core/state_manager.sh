#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — State Manager / Resume Engine
# ============================================================================
# Provides state persistence for resumable workflows.
# Tracks module completion, allows skipping completed modules, and handles
# interrupted scan recovery.
# ============================================================================

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

STATE_DIR=""
STATE_FILE=""

# ── Initialize State ────────────────────────────────────────────────────────
init_state() {
    local domain="$1"
    STATE_DIR="${RECONX_ROOT}/output/${domain}/.state"
    STATE_FILE="${STATE_DIR}/reconx.state"
    mkdir -p "$STATE_DIR"

    if [[ ! -f "$STATE_FILE" ]]; then
        cat > "$STATE_FILE" << EOF
# ReconX Ultra State File
# Domain: ${domain}
# Created: $(date -Iseconds)
# ─────────────────────────────────
domain=${domain}
status=running
started=$(date +%s)
last_updated=$(date +%s)
EOF
        log_debug "State file created: $STATE_FILE"
    else
        log_info "Existing state found — resume mode available"
    fi
}

# ── Save Module State ───────────────────────────────────────────────────────
save_state() {
    local domain="$1"
    local module="$2"
    local status="$3"  # completed | failed | skipped | interrupted
    local extra="${4:-}"

    # Guard against empty module name (would break sed)
    if [[ -z "$module" ]]; then
        log_debug "save_state called with empty module name — skipping"
        return 0
    fi

    if [[ -z "${STATE_DIR:-}" ]] || [[ -z "${STATE_FILE:-}" ]]; then
        init_state "$domain"
    fi

    [[ -f "$STATE_FILE" ]] || return 0

    local state_entry="${module}=${status}|$(date +%s)"
    if [[ -n "$extra" ]]; then
        state_entry="${state_entry}|${extra}"
    fi

    # Escape special characters for sed
    local escaped_module
    escaped_module="$(printf '%s' "$module" | sed 's/[.[\*^$()+?{|]/\\&/g')"

    # Update or append the module state
    if grep -q "^${escaped_module}=" "$STATE_FILE" 2>/dev/null; then
        sed -i "s|^${escaped_module}=.*|${state_entry}|" "$STATE_FILE"
    else
        echo "$state_entry" >> "$STATE_FILE"
    fi

    # Update last_updated timestamp
    if grep -q "^last_updated=" "$STATE_FILE" 2>/dev/null; then
        sed -i "s|^last_updated=.*|last_updated=$(date +%s)|" "$STATE_FILE"
    else
        echo "last_updated=$(date +%s)" >> "$STATE_FILE"
    fi

    log_debug "State saved: ${module} → ${status}"
}

# ── Check Module State ──────────────────────────────────────────────────────
get_module_state() {
    local module="$1"

    if [[ ! -f "$STATE_FILE" ]]; then
        echo "none"
        return
    fi

    local state_line
    state_line="$(grep "^${module}=" "$STATE_FILE" 2>/dev/null | tail -1)"

    if [[ -z "$state_line" ]]; then
        echo "none"
        return
    fi

    # Extract status from module=status|timestamp format
    local value="${state_line#*=}"
    echo "${value%%|*}"
}

# ── Check if Module Should Run ──────────────────────────────────────────────
should_run_module() {
    local module="$1"

    if [[ "$RESUME_MODE" != true ]]; then
        return 0  # Always run if not in resume mode
    fi

    local state
    state="$(get_module_state "$module")"

    case "$state" in
        completed)
            log_info "Skipping module '${module}' — already completed (resume mode)"
            return 1
            ;;
        failed|interrupted|none)
            return 0
            ;;
        *)
            return 0
            ;;
    esac
}

# ── Mark Module Complete ────────────────────────────────────────────────────
mark_complete() {
    local module="$1"
    local result_count="${2:-0}"
    save_state "$TARGET_DOMAIN" "$module" "completed" "results=${result_count}"
}

# ── Mark Module Failed ──────────────────────────────────────────────────────
mark_failed() {
    local module="$1"
    local reason="${2:-unknown}"
    save_state "$TARGET_DOMAIN" "$module" "failed" "reason=${reason}"
}

# ── Reset Module State ──────────────────────────────────────────────────────
reset_module() {
    local module="$1"
    if [[ -f "$STATE_FILE" ]]; then
        sed -i "/^${module}=/d" "$STATE_FILE"
        log_info "State reset for module: $module"
    fi
}

# ── Reset All State ─────────────────────────────────────────────────────────
reset_all_state() {
    local domain="$1"
    local state_dir="${RECONX_ROOT}/output/${domain}/.state"
    if [[ -d "$state_dir" ]]; then
        rm -rf "$state_dir"
        log_info "All state cleared for: $domain"
    fi
}

# ── List Module States ──────────────────────────────────────────────────────
list_states() {
    if [[ ! -f "$STATE_FILE" ]]; then
        log_warn "No state file found"
        return
    fi

    echo ""
    echo -e "${BOLD}${WHITE}  Module States:${RESET}"
    echo -e "${GRAY}  ──────────────────────────────────────────${RESET}"

    while IFS= read -r line; do
        # Skip comments and metadata
        [[ "$line" =~ ^# ]] && continue
        [[ "$line" =~ ^(domain|status|started|last_updated)= ]] && continue
        [[ -z "$line" ]] && continue

        local module="${line%%=*}"
        local value="${line#*=}"
        local status="${value%%|*}"

        case "$status" in
            completed)
                echo -e "    ${GREEN}✓${RESET} ${module}: ${GREEN}${status}${RESET}"
                ;;
            failed)
                echo -e "    ${RED}✗${RESET} ${module}: ${RED}${status}${RESET}"
                ;;
            interrupted)
                echo -e "    ${YELLOW}⚡${RESET} ${module}: ${YELLOW}${status}${RESET}"
                ;;
            *)
                echo -e "    ${GRAY}○${RESET} ${module}: ${GRAY}${status}${RESET}"
                ;;
        esac
    done < "$STATE_FILE"
    echo ""
}

# ── Get Scan Duration ───────────────────────────────────────────────────────
get_scan_duration() {
    if [[ ! -f "$STATE_FILE" ]]; then
        echo "unknown"
        return
    fi

    local started
    started="$(grep '^started=' "$STATE_FILE" | cut -d= -f2)"
    local last_updated
    last_updated="$(grep '^last_updated=' "$STATE_FILE" | cut -d= -f2)"

    if [[ -n "$started" && -n "$last_updated" ]]; then
        elapsed_time "$started" "$last_updated"
    else
        echo "unknown"
    fi
}

# ── Lock File Management ────────────────────────────────────────────────────
acquire_lock() {
    local domain="$1"
    local lock_file="${RECONX_ROOT}/output/${domain}/.state/reconx.lock"
    mkdir -p "$(dirname "$lock_file")"

    if [[ -f "$lock_file" ]]; then
        local pid
        pid="$(cat "$lock_file")"
        if kill -0 "$pid" 2>/dev/null; then
            log_error "Another ReconX instance is running for ${domain} (PID: ${pid})"
            return 1
        else
            log_warn "Stale lock file found — removing"
            rm -f "$lock_file"
        fi
    fi

    echo $$ > "$lock_file"
    log_debug "Lock acquired for: $domain"
    return 0
}

release_lock() {
    local domain="$1"
    local lock_file="${RECONX_ROOT}/output/${domain}/.state/reconx.lock"
    rm -f "$lock_file"
    log_debug "Lock released for: $domain"
}
