#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — YAML Configuration Loader
# ============================================================================
# Parses YAML config files and exports variables for use across modules.
# Uses a lightweight pure-bash parser (no external YAML libraries needed).
# ============================================================================

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# ── Default Configuration Values ────────────────────────────────────────────
declare -A CONFIG=(
    # General
    [general.threads]="50"
    [general.rate_limit]="150"
    [general.timeout]="30"
    [general.retries]="3"
    [general.debug]="false"
    [general.resume]="true"
    [general.notify]="false"

    # API Keys
    [api.shodan]=""
    [api.censys_id]=""
    [api.censys_secret]=""
    [api.virustotal]=""
    [api.securitytrails]=""
    [api.chaos]=""
    [api.github_token]=""
    [api.urlscan]=""
    [api.hunter]=""
    [api.whoisxml]=""

    # Notification Webhooks
    [notify.telegram_token]=""
    [notify.telegram_chat_id]=""
    [notify.discord_webhook]=""
    [notify.slack_webhook]=""

    # Module Toggles
    [modules.subdomains]="true"
    [modules.live]="true"
    [modules.urls]="true"
    [modules.js]="true"
    [modules.content]="false"
    [modules.nuclei]="true"
    [modules.screenshots]="true"
    [modules.ports]="false"
    [modules.takeover]="true"
    [modules.cors]="true"
    [modules.wordpress]="false"
    [modules.api]="true"
    [modules.params]="true"
    [modules.reporting]="true"

    # Tool Paths (auto-detected by default)
    [tools.subfinder]="subfinder"
    [tools.httpx]="httpx"
    [tools.nuclei]="nuclei"
    [tools.katana]="katana"
    [tools.naabu]="naabu"
    [tools.ffuf]="ffuf"
    [tools.dnsx]="dnsx"
    [tools.gau]="gau"
    [tools.hakrawler]="hakrawler"

    # Wordlists
    [wordlists.subdomains]=""
    [wordlists.content]=""
    [wordlists.params]=""
    [wordlists.vhosts]=""

    # Nuclei Settings
    [nuclei.severity]="critical,high,medium"
    [nuclei.concurrency]="25"
    [nuclei.rate_limit]="150"
    [nuclei.bulk_size]="25"
    [nuclei.templates_dir]=""

    # Output Settings
    [output.format]="all"
    [output.screenshots]="true"
    [output.json]="true"
)

# ── YAML Parser ─────────────────────────────────────────────────────────────
# Lightweight YAML parser supporting flat key.value notation.
# Handles comments, quoted strings, and nested keys (one level deep).
parse_yaml() {
    local yaml_file="$1"
    local prefix="${2:-}"

    if [[ ! -f "$yaml_file" ]]; then
        log_error "Config file not found: $yaml_file"
        return 1
    fi

    local current_section=""
    local re_section='^([a-zA-Z_][a-zA-Z0-9_]*):[ ]*$'
    local re_keyval='^[[:space:]]+([a-zA-Z_][a-zA-Z0-9_]*):[ ]*(.*)'
    local re_comment='^[[:space:]]*#'

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Strip trailing CR if present
        line="${line%$'\r'}"

        # Skip empty lines and comments
        [[ -z "$line" ]] && continue
        [[ "$line" =~ $re_comment ]] && continue

        # Remove inline comments
        line="${line%%#*}"

        # Detect section headers (no leading whitespace, ends with colon)
        if [[ "$line" =~ $re_section ]]; then
            current_section="${BASH_REMATCH[1]}"
            continue
        fi

        # Detect key-value pairs (indented)
        if [[ "$line" =~ $re_keyval ]]; then
            local key="${BASH_REMATCH[1]}"
            local value="${BASH_REMATCH[2]}"

            # Strip surrounding quotes
            value="${value#\"}"
            value="${value%\"}"
            value="${value#\'}"
            value="${value%\'}"

            # Trim whitespace
            value="$(echo "$value" | xargs)"

            local full_key="${current_section}.${key}"
            CONFIG["$full_key"]="$value"
        fi
    done < "$yaml_file"
}

# ── Load Configuration ──────────────────────────────────────────────────────
load_config() {
    local config_file="${1:-$CONFIG_FILE}"

    if [[ ! -f "$config_file" ]]; then
        log_warn "Config file not found: $config_file — using defaults"
        return 0
    fi

    log_info "Loading configuration from: $config_file"
    parse_yaml "$config_file"

    # Apply loaded values to runtime variables
    THREADS="${CONFIG[general.threads]}"
    RATE_LIMIT="${CONFIG[general.rate_limit]}"
    TIMEOUT="${CONFIG[general.timeout]}"
    RETRIES="${CONFIG[general.retries]}"
    DEBUG_MODE="${CONFIG[general.debug]}"
    RESUME_MODE="${CONFIG[general.resume]}"
    NOTIFY_ENABLED="${CONFIG[general.notify]}"

    # Export API keys
    export SHODAN_API_KEY="${CONFIG[api.shodan]}"
    export CENSYS_API_ID="${CONFIG[api.censys_id]}"
    export CENSYS_API_SECRET="${CONFIG[api.censys_secret]}"
    export VT_API_KEY="${CONFIG[api.virustotal]}"
    export SECURITY_TRAILS_KEY="${CONFIG[api.securitytrails]}"
    export CHAOS_KEY="${CONFIG[api.chaos]}"
    export GITHUB_TOKEN="${CONFIG[api.github_token]}"
    export URLSCAN_API_KEY="${CONFIG[api.urlscan]}"

    log_success "Configuration loaded successfully"
    if [[ "$DEBUG_MODE" == true ]]; then
        log_debug "Threads: $THREADS | Rate Limit: $RATE_LIMIT | Timeout: ${TIMEOUT}s"
    fi
}

# ── Get Config Value ─────────────────────────────────────────────────────────
get_config() {
    local key="$1"
    local default="${2:-}"
    echo "${CONFIG[$key]:-$default}"
}

# ── Check Module Enabled ────────────────────────────────────────────────────
is_module_enabled() {
    local module="$1"
    local value="${CONFIG[modules.${module}]:-true}"
    [[ "$value" == "true" ]]
}

# ── Export API Key Helper ────────────────────────────────────────────────────
get_api_key() {
    local service="$1"
    echo "${CONFIG[api.${service}]:-}"
}

# ── Validate Required APIs ──────────────────────────────────────────────────
validate_apis() {
    local missing=0
    local apis=("shodan" "virustotal" "securitytrails" "chaos" "github_token")

    log_info "Validating API keys..."
    for api in "${apis[@]}"; do
        local key
        key="$(get_api_key "$api")"
        if [[ -z "$key" ]]; then
            log_warn "API key not configured: $api (some features may be limited)"
            ((missing++))
        else
            log_debug "API key found: $api"
        fi
    done

    if [[ "$missing" -gt 0 ]]; then
        log_warn "$missing API key(s) missing — some modules may produce limited results"
    else
        log_success "All API keys validated"
    fi
}
