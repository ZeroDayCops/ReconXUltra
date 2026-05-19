#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Update All Tools
# ============================================================================

set -euo pipefail

echo -e "\033[0;34m[*]\033[0m Updating ReconX Ultra tools...\n"

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="${GOPATH}/bin:/usr/local/go/bin:${HOME}/.local/bin:${PATH}"

# ── Update Go tools ─────────────────────────────────────────────────────────
echo -e "\033[0;34m[*]\033[0m Updating Go tools..."

GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/alterx/cmd/alterx@latest"
    "github.com/ffuf/ffuf/v2@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/PentestPad/subzy@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    name="$(basename "${tool%%@*}")"
    echo -e "  \033[0;34m→\033[0m Updating ${name}..."
    go install "$tool" 2>/dev/null || echo -e "  \033[1;33m!\033[0m Failed: ${name}"
done

# ── Update Python tools ─────────────────────────────────────────────────────
echo -e "\n\033[0;34m[*]\033[0m Updating Python tools..."
pip3 install --user --upgrade --quiet arjun uro trufflehog xnLinkFinder dirsearch waymore 2>/dev/null || true

# ── Update Nuclei templates ─────────────────────────────────────────────────
echo -e "\n\033[0;34m[*]\033[0m Updating nuclei templates..."
nuclei -update-templates -silent 2>/dev/null || true

# ── Update wordlists ────────────────────────────────────────────────────────
RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo -e "\n\033[0;34m[*]\033[0m Updating resolvers..."
curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
    -o "${RECONX_ROOT}/wordlists/resolvers.txt" 2>/dev/null || true

echo -e "\n\033[0;32m[✓]\033[0m Update complete!"
