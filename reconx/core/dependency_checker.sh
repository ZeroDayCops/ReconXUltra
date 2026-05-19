#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Dependency Checker
# ============================================================================
# Validates that all required tools are installed and accessible.
# ============================================================================

if [[ -z "${RECONX_ROOT:-}" ]]; then
    source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
fi

# ── Tool Categories ─────────────────────────────────────────────────────────
REQUIRED_TOOLS=(
    "subfinder"
    "httpx"
    "dnsx"
    "nuclei"
    "naabu"
    "katana"
    "ffuf"
)

OPTIONAL_GO_TOOLS=(
    "assetfinder"
    "gau"
    "waybackurls"
    "hakrawler"
    "alterx"
    "subzy"
    "gf"
    "qsreplace"
    "unfurl"
    "anew"
    "uncover"
    "chaos"
    "notify"
    "interactsh-client"
)

OPTIONAL_PYTHON_TOOLS=(
    "arjun"
    "uro"
    "trufflehog"
    "xnLinkFinder"
    "dirsearch"
    "corsy"
)

SYSTEM_TOOLS=(
    "curl"
    "wget"
    "jq"
    "python3"
    "pip3"
    "go"
    "git"
    "nmap"
    "dig"
    "host"
    "whois"
    "openssl"
    "chromium-browser:chromium:google-chrome"
)

# ── Check Single Tool ───────────────────────────────────────────────────────
check_tool() {
    local tool="$1"
    # Support colon-separated alternatives (e.g. chromium-browser:chromium:google-chrome)
    IFS=':' read -ra alternatives <<< "$tool"
    for alt in "${alternatives[@]}"; do
        if cmd_exists "$alt"; then
            return 0
        fi
    done
    return 1
}

# ── Check All Dependencies ──────────────────────────────────────────────────
check_dependencies() {
    local missing_required=()
    local missing_optional=()
    local missing_system=()
    local total_found=0
    local total_checked=0

    echo ""
    log_info "Checking dependencies..."
    echo ""

    # ── Required Go Tools ──
    echo -e "  ${BOLD}${WHITE}Required Go Tools:${RESET}"
    for tool in "${REQUIRED_TOOLS[@]}"; do
        total_checked=$((total_checked + 1))
        if check_tool "$tool"; then
            echo -e "    ${GREEN}✓${RESET} ${tool}"
            total_found=$((total_found + 1))
        else
            echo -e "    ${RED}✗${RESET} ${tool} ${RED}(MISSING)${RESET}"
            missing_required+=("$tool")
        fi
    done
    echo ""

    # ── Optional Go Tools ──
    echo -e "  ${BOLD}${WHITE}Optional Go Tools:${RESET}"
    for tool in "${OPTIONAL_GO_TOOLS[@]}"; do
        total_checked=$((total_checked + 1))
        if check_tool "$tool"; then
            echo -e "    ${GREEN}✓${RESET} ${tool}"
            total_found=$((total_found + 1))
        else
            echo -e "    ${YELLOW}○${RESET} ${tool} ${GRAY}(optional)${RESET}"
            missing_optional+=("$tool")
        fi
    done
    echo ""

    # ── Python Tools ──
    echo -e "  ${BOLD}${WHITE}Python Tools:${RESET}"
    for tool in "${OPTIONAL_PYTHON_TOOLS[@]}"; do
        total_checked=$((total_checked + 1))
        if check_tool "$tool"; then
            echo -e "    ${GREEN}✓${RESET} ${tool}"
            total_found=$((total_found + 1))
        else
            echo -e "    ${YELLOW}○${RESET} ${tool} ${GRAY}(optional)${RESET}"
            missing_optional+=("$tool")
        fi
    done
    echo ""

    # ── System Tools ──
    echo -e "  ${BOLD}${WHITE}System Tools:${RESET}"
    for tool in "${SYSTEM_TOOLS[@]}"; do
        total_checked=$((total_checked + 1))
        local display_name="${tool%%:*}"
        if check_tool "$tool"; then
            echo -e "    ${GREEN}✓${RESET} ${display_name}"
            total_found=$((total_found + 1))
        else
            echo -e "    ${RED}✗${RESET} ${display_name} ${RED}(MISSING)${RESET}"
            missing_system+=("$display_name")
        fi
    done
    echo ""

    # ── Summary ──
    log_separator
    echo -e "  ${BOLD}${WHITE}Dependency Summary:${RESET}"
    log_stats "Tools found" "${total_found}/${total_checked}"
    log_stats "Required missing" "${#missing_required[@]}"
    log_stats "Optional missing" "${#missing_optional[@]}"
    log_stats_final "System missing" "${#missing_system[@]}"
    echo ""

    # ── Handle Missing Required ──
    if [[ ${#missing_required[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_required[*]}"
        log_info "Run: ./install/installer.sh to install missing tools"
        return 1
    fi

    if [[ ${#missing_system[@]} -gt 0 ]]; then
        log_warn "Missing system tools: ${missing_system[*]}"
        log_info "Install via: sudo apt install <package>"
    fi

    log_success "All required dependencies satisfied"
    return 0
}

# ── Quick Check (Silent) ────────────────────────────────────────────────────
quick_check() {
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! check_tool "$tool"; then
            return 1
        fi
    done
    return 0
}

# ── Check Go Installation ───────────────────────────────────────────────────
check_go() {
    if cmd_exists go; then
        local go_version
        go_version="$(go version | awk '{print $3}')"
        log_info "Go found: $go_version"
        return 0
    else
        log_error "Go is not installed"
        return 1
    fi
}

# ── Check Python Installation ───────────────────────────────────────────────
check_python() {
    if cmd_exists python3; then
        local py_version
        py_version="$(python3 --version 2>&1)"
        log_info "Python found: $py_version"
        return 0
    else
        log_error "Python3 is not installed"
        return 1
    fi
}

# ── Validate Tool Version ───────────────────────────────────────────────────
check_tool_version() {
    local tool="$1"
    local min_version="${2:-}"

    if ! cmd_exists "$tool"; then
        return 1
    fi

    if [[ -z "$min_version" ]]; then
        return 0
    fi

    local current_version
    current_version="$($tool -version 2>/dev/null | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")"
    log_debug "$tool version: $current_version (minimum: $min_version)"
}
