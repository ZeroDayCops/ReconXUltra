#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Master Installer
# ============================================================================
# Detects OS, installs all dependencies, tools, wordlists, and validates
# the complete installation.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECONX_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}"
cat << 'BANNER'

    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
                    INSTALLER v2.0.0

BANNER
echo -e "${RESET}"

# ── OS Detection ─────────────────────────────────────────────────────────────
detect_os() {
    echo -e "${BLUE}[*]${RESET} Detecting operating system..."

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="$ID"
        OS_VERSION="$VERSION_ID"
        OS_PRETTY="$PRETTY_NAME"
    elif command -v lsb_release &>/dev/null; then
        OS_NAME="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        OS_VERSION="$(lsb_release -sr)"
        OS_PRETTY="$(lsb_release -sd)"
    elif [[ "$(uname)" == "Darwin" ]]; then
        OS_NAME="macos"
        OS_VERSION="$(sw_vers -productVersion)"
        OS_PRETTY="macOS $OS_VERSION"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
        OS_PRETTY="Unknown OS"
    fi

    echo -e "${GREEN}[✓]${RESET} Detected: ${OS_PRETTY}"

    # Set package manager
    case "$OS_NAME" in
        ubuntu|debian|kali|parrot)
            PKG_MANAGER="apt"
            PKG_INSTALL="sudo apt install -y"
            PKG_UPDATE="sudo apt update"
            ;;
        fedora|rhel|centos|rocky|alma)
            PKG_MANAGER="dnf"
            PKG_INSTALL="sudo dnf install -y"
            PKG_UPDATE="sudo dnf check-update || true"
            ;;
        arch|manjaro)
            PKG_MANAGER="pacman"
            PKG_INSTALL="sudo pacman -S --noconfirm"
            PKG_UPDATE="sudo pacman -Sy"
            ;;
        macos)
            PKG_MANAGER="brew"
            PKG_INSTALL="brew install"
            PKG_UPDATE="brew update"
            ;;
        *)
            echo -e "${YELLOW}[!]${RESET} Unsupported OS: $OS_NAME — manual installation may be required"
            PKG_MANAGER="apt"
            PKG_INSTALL="sudo apt install -y"
            PKG_UPDATE="sudo apt update"
            ;;
    esac
}

# ── Pre-flight Checks ───────────────────────────────────────────────────────
preflight() {
    echo -e "\n${BLUE}[*]${RESET} Running pre-flight checks..."

    # Check internet
    if ! curl -s --max-time 5 https://google.com &>/dev/null; then
        echo -e "${RED}[✗]${RESET} No internet connection detected"
        exit 1
    fi
    echo -e "${GREEN}[✓]${RESET} Internet connectivity OK"

    # Check disk space (need at least 2GB)
    local avail_kb
    avail_kb="$(df -k "$RECONX_ROOT" | tail -1 | awk '{print $4}')"
    if [[ "$avail_kb" -lt 2097152 ]]; then
        echo -e "${YELLOW}[!]${RESET} Low disk space: $(( avail_kb / 1024 ))MB available (2GB recommended)"
    else
        echo -e "${GREEN}[✓]${RESET} Disk space: $(( avail_kb / 1024 ))MB available"
    fi
}

# ── Run Installer Components ────────────────────────────────────────────────
run_installer() {
    local component="$1"
    local script="${SCRIPT_DIR}/${component}"

    if [[ -f "$script" ]]; then
        echo ""
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo -e "${BOLD}${WHITE}  Installing: ${component%.sh}${RESET}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        bash "$script"
    else
        echo -e "${YELLOW}[!]${RESET} Installer component not found: $component"
    fi
}

# ── Main Installation Flow ──────────────────────────────────────────────────
main() {
    local start_time
    start_time="$(date +%s)"

    detect_os
    preflight

    echo ""
    echo -e "${BOLD}${WHITE}Starting full installation...${RESET}"
    echo ""

    # Step 1: System packages
    run_installer "apt_tools.sh"

    # Step 2: Go tools
    run_installer "go_tools.sh"

    # Step 3: Python tools
    run_installer "python_tools.sh"

    # Step 4: Wordlists
    run_installer "wordlists.sh"

    # Step 5: Nuclei templates
    run_installer "nuclei_templates.sh"

    # Step 6: Validate tools
    run_installer "validate_tools.sh"

    # Step 7: Validate APIs
    run_installer "validate_apis.sh"

    # Make all scripts executable
    echo -e "\n${BLUE}[*]${RESET} Setting permissions..."
    find "$RECONX_ROOT" -name "*.sh" -exec chmod +x {} \;
    find "$RECONX_ROOT" -name "*.py" -exec chmod +x {} \;
    echo -e "${GREEN}[✓]${RESET} Permissions set"

    # Configure PATH
    echo ""
    echo -e "${BLUE}[*]${RESET} Configuring PATH..."
    local go_bin="${GOPATH:-$HOME/go}/bin"
    local local_bin="$HOME/.local/bin"

    if ! grep -q "reconx" "$HOME/.bashrc" 2>/dev/null; then
        cat >> "$HOME/.bashrc" << EOF

# ReconX Ultra PATH
export GOPATH="\${GOPATH:-\$HOME/go}"
export PATH="\${GOPATH}/bin:\$HOME/.local/bin:\$PATH"
EOF
        echo -e "${GREEN}[✓]${RESET} PATH configured in ~/.bashrc"
    fi

    # Final summary
    local end_time
    end_time="$(date +%s)"
    local duration=$(( end_time - start_time ))

    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${GREEN}  ✅ ReconX Ultra installation complete!${RESET}"
    echo -e "${GRAY}  Duration: ${duration}s${RESET}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
    echo -e "  ${WHITE}Usage:${RESET}"
    echo -e "    ${CYAN}./reconx.sh -d example.com${RESET}"
    echo -e "    ${CYAN}./reconx.sh -l domains.txt${RESET}"
    echo -e "    ${CYAN}./reconx.sh -d example.com --modules subdomains,urls,nuclei${RESET}"
    echo ""
    echo -e "  ${YELLOW}Don't forget to:${RESET}"
    echo -e "    1. Add API keys to ${CYAN}configs/default.yaml${RESET}"
    echo -e "    2. Run ${CYAN}source ~/.bashrc${RESET} to update PATH"
    echo ""
}

main "$@"
