#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — APT/System Package Installer
# ============================================================================

set -euo pipefail

echo -e "\033[0;34m[*]\033[0m Installing system packages..."

PACKAGES=(
    # Core utilities
    curl wget git jq whois dnsutils net-tools
    # Build tools
    build-essential gcc g++ make
    # Python
    python3 python3-pip python3-venv python3-dev
    # Network tools
    nmap masscan netcat-openbsd
    # Security
    openssl libssl-dev
    # DNS
    bind9-dnsutils ldnsutils
    # Web
    chromium-browser
    # Misc
    unzip p7zip-full libpcap-dev
    # Ruby (for wpscan)
    ruby ruby-dev
    # Libs
    libffi-dev libxml2-dev libxslt1-dev zlib1g-dev
)

# Update package lists
sudo apt update -qq 2>/dev/null || true

# Install packages
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo -e "  \033[0;32m✓\033[0m ${pkg} (already installed)"
    else
        echo -e "  \033[0;34m→\033[0m Installing ${pkg}..."
        sudo apt install -y -qq "$pkg" 2>/dev/null || echo -e "  \033[1;33m!\033[0m Failed to install ${pkg}"
    fi
done

# Install Go if not present
if ! command -v go &>/dev/null; then
    echo -e "\n\033[0;34m[*]\033[0m Installing Go..."
    GO_VERSION="1.22.4"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH="/usr/local/go/bin:$PATH"
    export GOPATH="${HOME}/go"
    export PATH="${GOPATH}/bin:${PATH}"

    # Add to profile
    if ! grep -q '/usr/local/go/bin' "$HOME/.bashrc" 2>/dev/null; then
        echo 'export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"' >> "$HOME/.bashrc"
        echo 'export GOPATH="$HOME/go"' >> "$HOME/.bashrc"
    fi
    echo -e "  \033[0;32m✓\033[0m Go ${GO_VERSION} installed"
else
    echo -e "  \033[0;32m✓\033[0m Go $(go version | awk '{print $3}') already installed"
fi

echo -e "\n\033[0;32m[✓]\033[0m System packages installation complete"
