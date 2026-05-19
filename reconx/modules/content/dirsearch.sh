#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Content Discovery (dirsearch)
# ============================================================================

DOMAIN="${1:?Usage: dirsearch.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Content Discovery (dirsearch)" "$DOMAIN"
START_TIME="$(date +%s)"

if ! cmd_exists dirsearch; then
    log_warn "dirsearch not installed — skipping"
    exit 0
fi

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping dirsearch"
    exit 0
fi

SCAN_LIMIT=20
CURRENT=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    CURRENT=$((CURRENT + 1))
    [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

    host_hash="$(echo "$url" | md5sum | cut -c1-8)"
    log_task_start "dirsearch [${CURRENT}/${SCAN_LIMIT}]: $(echo "$url" | cut -c1-60)"

    dirsearch -u "$url" \
        -e php,asp,aspx,jsp,html,json,xml,txt,env,bak,yml \
        -t "$THREADS" \
        --format json \
        -o "${OUT_CONTENT}/dirsearch_${host_hash}.json" \
        -q --no-color 2>/dev/null || true

done < "$LIVE_HOSTS"

# Merge
log_task_start "Merging dirsearch results"
> "${OUT_CONTENT}/dirsearch_all.txt"
for result_file in "${OUT_CONTENT}"/dirsearch_*.json; do
    [[ -f "$result_file" ]] || continue
    jq -r '.results[]? | "\(.url) [\(.status)] [\(.content_length)]"' "$result_file" 2>/dev/null \
        >> "${OUT_CONTENT}/dirsearch_all.txt" || true
done
sort -u "${OUT_CONTENT}/dirsearch_all.txt" -o "${OUT_CONTENT}/dirsearch_all.txt"
TOTAL="$(count_lines "${OUT_CONTENT}/dirsearch_all.txt")"
log_task_done "dirsearch results" "$TOTAL"

log_module_end "Content Discovery (dirsearch)" "$START_TIME" "$TOTAL"
