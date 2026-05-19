#!/bin/bash
# ReconX Ultra X — Continuous Recon Scheduler
# Runs scheduled scans and detects new attack surface.
# Usage: continuous_recon.sh <domain|list> [interval_hours] [modules]

set -euo pipefail
RECONX_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="$1"
INTERVAL="${2:-24}"
MODULES="${3:-subdomains,live,urls,js,intelligence,validation,reporting}"

echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║     ReconX Ultra X — Continuous Monitoring       ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
echo "    Target:   $TARGET"
echo "    Interval: Every ${INTERVAL}h"
echo "    Modules:  $MODULES"
echo "    Started:  $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

SCAN_COUNT=0
while true; do
    ((SCAN_COUNT++))
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  🔄 Scan #${SCAN_COUNT} — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    if [[ -f "$TARGET" ]]; then
        # Multi-domain
        "${RECONX_ROOT}/reconx.sh" -l "$TARGET" -m "$MODULES" --mode aggressive --reset
    else
        # Single domain
        "${RECONX_ROOT}/reconx.sh" -d "$TARGET" -m "$MODULES" --mode aggressive --reset
    fi

    echo ""
    echo "  ✅ Scan #${SCAN_COUNT} complete. Next scan in ${INTERVAL}h..."
    echo "  ⏰ Next run: $(date -d "+${INTERVAL} hours" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    sleep "$((INTERVAL * 3600))"
done
