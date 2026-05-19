#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Initial Setup
# ============================================================================
# Creates directory structure, validates environment, and prepares workspace.
# ============================================================================

source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

log_info "Initializing ReconX Ultra workspace..."

# Create all required directories
dirs=(
    "${RECONX_ROOT}/output"
    "${RECONX_ROOT}/logs"
    "${RECONX_ROOT}/reports"
    "${RECONX_ROOT}/tmp"
    "${RECONX_ROOT}/tools"
    "${RECONX_ROOT}/wordlists"
    "${RECONX_ROOT}/configs"
    "${RECONX_ROOT}/templates"
)

for dir in "${dirs[@]}"; do
    mkdir -p "$dir"
done

# Create default config if not exists
if [[ ! -f "${RECONX_CONFIGS}/default.yaml" ]]; then
    log_info "Creating default configuration..."
    cp "${RECONX_ROOT}/configs/default.yaml" "${RECONX_CONFIGS}/default.yaml" 2>/dev/null || true
fi

# Ensure all scripts are executable
find "${RECONX_ROOT}" -name "*.sh" -exec chmod +x {} \;

# Validate GOPATH
if [[ -z "${GOPATH:-}" ]]; then
    export GOPATH="${HOME}/go"
fi
export PATH="${GOPATH}/bin:${HOME}/.local/bin:${PATH}"

log_success "Workspace initialized successfully"
