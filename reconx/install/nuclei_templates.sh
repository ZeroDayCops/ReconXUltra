#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Nuclei Templates Installer
# ============================================================================

set -euo pipefail

echo -e "\033[0;34m[*]\033[0m Installing nuclei templates..."

if command -v nuclei &>/dev/null; then
    echo -e "  \033[0;34m→\033[0m Updating default nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m Default nuclei templates updated"
else
    echo -e "  \033[1;33m[!]\033[0m nuclei not installed — skipping template update"
fi

# ── Community Templates ─────────────────────────────────────────────────────
RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATES_DIR="${RECONX_ROOT}/templates"
mkdir -p "$TEMPLATES_DIR"

# ProjectDiscovery Fuzzing Templates
if [[ ! -d "${TEMPLATES_DIR}/fuzzing-templates" ]]; then
    echo -e "  \033[0;34m→\033[0m Downloading fuzzing templates..."
    git clone --quiet --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git \
        "${TEMPLATES_DIR}/fuzzing-templates" 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m Fuzzing templates"
else
    echo -e "  \033[0;32m✓\033[0m Fuzzing templates (already installed)"
fi

# Community Nuclei Templates
if [[ ! -d "${TEMPLATES_DIR}/community-templates" ]]; then
    echo -e "  \033[0;34m→\033[0m Downloading community templates..."
    git clone --quiet --depth 1 https://github.com/projectdiscovery/nuclei-templates.git \
        "${TEMPLATES_DIR}/community-templates" 2>/dev/null || true
    echo -e "  \033[0;32m✓\033[0m Community templates"
else
    echo -e "  \033[0;32m✓\033[0m Community templates (already installed)"
fi

echo -e "\n\033[0;32m[✓]\033[0m Nuclei templates installation complete"
