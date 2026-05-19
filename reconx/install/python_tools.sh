#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Python Tools Installer
# ============================================================================

set -euo pipefail

echo -e "\033[0;34m[*]\033[0m Installing Python tools..."

if ! command -v pip3 &>/dev/null; then
    echo -e "\033[0;31m[✗]\033[0m pip3 not found"
    exit 1
fi

# ── pip packages ─────────────────────────────────────────────────────────────
PIP_PACKAGES=(
    "arjun"
    "uro"
    "trufflehog"
    "pyyaml"
    "requests"
    "beautifulsoup4"
    "colorama"
    "Jinja2"
)

for pkg in "${PIP_PACKAGES[@]}"; do
    if pip3 show "$pkg" &>/dev/null; then
        echo -e "  \033[0;32m✓\033[0m ${pkg} (already installed)"
    else
        echo -e "  \033[0;34m→\033[0m Installing ${pkg}..."
        pip3 install --user --quiet "$pkg" 2>/dev/null || echo -e "  \033[1;33m!\033[0m Failed: ${pkg}"
    fi
done

# ── Clone-based tools ───────────────────────────────────────────────────────
TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../tools" && pwd)"
mkdir -p "$TOOLS_DIR"

# xnLinkFinder
if ! command -v xnLinkFinder &>/dev/null; then
    echo -e "  \033[0;34m→\033[0m Installing xnLinkFinder..."
    pip3 install --user --quiet xnLinkFinder 2>/dev/null || {
        git clone --quiet https://github.com/xnl-h4ck3r/xnLinkFinder.git "$TOOLS_DIR/xnLinkFinder" 2>/dev/null || true
        cd "$TOOLS_DIR/xnLinkFinder" && pip3 install --user --quiet . 2>/dev/null || true
        cd "$OLDPWD"
    }
    echo -e "  \033[0;32m✓\033[0m xnLinkFinder installed"
else
    echo -e "  \033[0;32m✓\033[0m xnLinkFinder (already installed)"
fi

# dirsearch
if ! command -v dirsearch &>/dev/null; then
    echo -e "  \033[0;34m→\033[0m Installing dirsearch..."
    pip3 install --user --quiet dirsearch 2>/dev/null || {
        git clone --quiet https://github.com/maurosoria/dirsearch.git "$TOOLS_DIR/dirsearch" 2>/dev/null || true
        ln -sf "$TOOLS_DIR/dirsearch/dirsearch.py" "$HOME/.local/bin/dirsearch" 2>/dev/null || true
    }
    echo -e "  \033[0;32m✓\033[0m dirsearch installed"
else
    echo -e "  \033[0;32m✓\033[0m dirsearch (already installed)"
fi

# Corsy
if [[ ! -d "$TOOLS_DIR/Corsy" ]]; then
    echo -e "  \033[0;34m→\033[0m Installing Corsy..."
    git clone --quiet https://github.com/s0md3v/Corsy.git "$TOOLS_DIR/Corsy" 2>/dev/null || true
    cd "$TOOLS_DIR/Corsy" && pip3 install --user --quiet -r requirements.txt 2>/dev/null || true
    cd "$OLDPWD"
    echo -e "  \033[0;32m✓\033[0m Corsy installed"
else
    echo -e "  \033[0;32m✓\033[0m Corsy (already installed)"
fi

# CORScanner
if [[ ! -d "$TOOLS_DIR/CORScanner" ]]; then
    echo -e "  \033[0;34m→\033[0m Installing CORScanner..."
    git clone --quiet https://github.com/chenjj/CORScanner.git "$TOOLS_DIR/CORScanner" 2>/dev/null || true
    cd "$TOOLS_DIR/CORScanner" && pip3 install --user --quiet -r requirements.txt 2>/dev/null || true
    cd "$OLDPWD"
    echo -e "  \033[0;32m✓\033[0m CORScanner installed"
else
    echo -e "  \033[0;32m✓\033[0m CORScanner (already installed)"
fi

# waymore
if ! command -v waymore &>/dev/null; then
    echo -e "  \033[0;34m→\033[0m Installing waymore..."
    pip3 install --user --quiet waymore 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m waymore installed"
else
    echo -e "  \033[0;32m✓\033[0m waymore (already installed)"
fi

echo -e "\n\033[0;32m[✓]\033[0m Python tools installation complete"
