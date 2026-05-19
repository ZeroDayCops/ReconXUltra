#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Tool Validation
# ============================================================================

set -euo pipefail

RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "${RECONX_ROOT}/core/common.sh"
source "${RECONX_ROOT}/core/dependency_checker.sh"

echo -e "\n\033[0;34m[*]\033[0m Validating tool installation...\n"
check_dependencies
