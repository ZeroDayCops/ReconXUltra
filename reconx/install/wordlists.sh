#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Wordlist Installer
# ============================================================================

set -euo pipefail

RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORDLISTS_DIR="${RECONX_ROOT}/wordlists"
mkdir -p "$WORDLISTS_DIR"

echo -e "\033[0;34m[*]\033[0m Installing wordlists..."

# ── SecLists ─────────────────────────────────────────────────────────────────
SECLISTS_DIR="/usr/share/seclists"
if [[ ! -d "$SECLISTS_DIR" ]]; then
    SECLISTS_DIR="/opt/seclists"
    if [[ ! -d "$SECLISTS_DIR" ]]; then
        echo -e "  \033[0;34m→\033[0m Downloading SecLists..."
        sudo git clone --quiet --depth 1 https://github.com/danielmiessler/SecLists.git "$SECLISTS_DIR" 2>/dev/null || {
            echo -e "  \033[1;33m!\033[0m Failed to clone SecLists — downloading key wordlists only"
            # Download individual important files
            mkdir -p "$WORDLISTS_DIR"
            curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt" \
                -o "$WORDLISTS_DIR/subdomains.txt" 2>/dev/null || true
            curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" \
                -o "$WORDLISTS_DIR/content.txt" 2>/dev/null || true
        }
        echo -e "  \033[0;32m✓\033[0m SecLists installed"
    else
        echo -e "  \033[0;32m✓\033[0m SecLists (already installed at $SECLISTS_DIR)"
    fi
else
    echo -e "  \033[0;32m✓\033[0m SecLists (already installed at $SECLISTS_DIR)"
fi

# ── Create symlinks to important wordlists ──────────────────────────────────
if [[ -d "$SECLISTS_DIR" ]]; then
    ln -sf "$SECLISTS_DIR/Discovery/DNS/subdomains-top1million-110000.txt" \
        "$WORDLISTS_DIR/subdomains.txt" 2>/dev/null || true
    ln -sf "$SECLISTS_DIR/Discovery/Web-Content/raft-medium-directories.txt" \
        "$WORDLISTS_DIR/content.txt" 2>/dev/null || true
    ln -sf "$SECLISTS_DIR/Discovery/Web-Content/raft-medium-files.txt" \
        "$WORDLISTS_DIR/files.txt" 2>/dev/null || true
    ln -sf "$SECLISTS_DIR/Fuzzing/fuzz-Bo0oM.txt" \
        "$WORDLISTS_DIR/fuzz.txt" 2>/dev/null || true
fi

# ── Best DNS Wordlist (Assetnote) ────────────────────────────────────────────
if [[ ! -f "$WORDLISTS_DIR/best-dns-wordlist.txt" ]]; then
    echo -e "  \033[0;34m→\033[0m Downloading Assetnote best DNS wordlist..."
    curl -sL "https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt" \
        -o "$WORDLISTS_DIR/best-dns-wordlist.txt" 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m Assetnote DNS wordlist"
else
    echo -e "  \033[0;32m✓\033[0m Assetnote DNS wordlist (already installed)"
fi

# ── Resolvers ────────────────────────────────────────────────────────────────
if [[ ! -f "$WORDLISTS_DIR/resolvers.txt" ]]; then
    echo -e "  \033[0;34m→\033[0m Downloading fresh resolvers..."
    curl -sL "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" \
        -o "$WORDLISTS_DIR/resolvers.txt" 2>/dev/null || true

    # Fallback: create default resolvers
    if [[ ! -s "$WORDLISTS_DIR/resolvers.txt" ]]; then
        cat > "$WORDLISTS_DIR/resolvers.txt" << 'EOF'
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
149.112.112.112
208.67.222.222
208.67.220.220
EOF
    fi
    echo -e "  \033[0;32m✓\033[0m Resolvers list"
else
    echo -e "  \033[0;32m✓\033[0m Resolvers (already installed)"
fi

# ── Parameter Wordlist ───────────────────────────────────────────────────────
if [[ ! -f "$WORDLISTS_DIR/params.txt" ]]; then
    echo -e "  \033[0;34m→\033[0m Downloading parameter wordlist..."
    curl -sL "https://raw.githubusercontent.com/s0md3v/Arjun/master/arjun/db/large.txt" \
        -o "$WORDLISTS_DIR/params.txt" 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m Parameter wordlist"
fi

echo -e "\n\033[0;32m[✓]\033[0m Wordlist installation complete"
echo -e "  \033[0;90mLocation: ${WORDLISTS_DIR}\033[0m"
