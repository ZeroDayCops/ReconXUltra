#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Go Tools Installer
# ============================================================================

set -euo pipefail

echo -e "\033[0;34m[*]\033[0m Installing Go tools..."

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

if ! command -v go &>/dev/null; then
    echo -e "\033[0;31m[✗]\033[0m Go not found — install Go first"
    exit 1
fi

# ── Go Tool Registry ────────────────────────────────────────────────────────
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    ["uncover"]="github.com/projectdiscovery/uncover/cmd/uncover@latest"
    ["chaos"]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    ["notify"]="github.com/projectdiscovery/notify/cmd/notify@latest"
    ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
    ["alterx"]="github.com/projectdiscovery/alterx/cmd/alterx@latest"
    ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
    ["hakrawler"]="github.com/hakluke/hakrawler@latest"
    ["subzy"]="github.com/PentestPad/subzy@latest"
    ["gf"]="github.com/tomnomnom/gf@latest"
    ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
    ["unfurl"]="github.com/tomnomnom/unfurl@latest"
    ["anew"]="github.com/tomnomnom/anew@latest"
)

FAILED=()
SUCCESS=0

for tool in "${!GO_TOOLS[@]}"; do
    pkg="${GO_TOOLS[$tool]}"
    if command -v "$tool" &>/dev/null; then
        echo -e "  \033[0;32m✓\033[0m ${tool} (already installed)"
        ((SUCCESS++))
    else
        echo -e "  \033[0;34m→\033[0m Installing ${tool}..."
        if go install "$pkg" 2>/dev/null; then
            echo -e "  \033[0;32m✓\033[0m ${tool} installed"
            ((SUCCESS++))
        else
            echo -e "  \033[0;31m✗\033[0m Failed to install ${tool}"
            FAILED+=("$tool")
        fi
    fi
done

# ── Install gf patterns ─────────────────────────────────────────────────────
echo -e "\n\033[0;34m[*]\033[0m Installing gf patterns..."
GF_PATTERNS_DIR="${HOME}/.gf"
mkdir -p "$GF_PATTERNS_DIR"

if [[ ! -f "${GF_PATTERNS_DIR}/xss.json" ]]; then
    git clone --quiet https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns 2>/dev/null || true
    cp /tmp/gf-patterns/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
    rm -rf /tmp/gf-patterns
    echo -e "  \033[0;32m✓\033[0m gf patterns installed"
else
    echo -e "  \033[0;32m✓\033[0m gf patterns (already installed)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "\033[0;32m[✓]\033[0m Go tools installed: ${SUCCESS}/${#GO_TOOLS[@]}"
if [[ ${#FAILED[@]} -gt 0 ]]; then
    echo -e "\033[1;33m[!]\033[0m Failed: ${FAILED[*]}"
fi
