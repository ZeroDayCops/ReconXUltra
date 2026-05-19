#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — GraphQL Endpoint Discovery
# ============================================================================

DOMAIN="${1:?Usage: graphql.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "GraphQL Discovery" "$DOMAIN"
START_TIME="$(date +%s)"

API_DIR="${OUT_SCANS}/api"
mkdir -p "$API_DIR"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping GraphQL discovery"
    exit 0
fi

# ── GraphQL Path Detection ──────────────────────────────────────────────────
log_task_start "Probing for GraphQL endpoints"
GRAPHQL_PATHS=(
    "/graphql"
    "/graphiql"
    "/gql"
    "/query"
    "/api/graphql"
    "/v1/graphql"
    "/v2/graphql"
    "/graphql/console"
    "/graphql/playground"
    "/graphql/v1"
    "/_graphql"
    "/api/gql"
    "/graphql/schema"
    "/altair"
    "/playground"
)

GRAPHQL_ENDPOINTS="${API_DIR}/graphql_endpoints.txt"
> "$GRAPHQL_ENDPOINTS"

INTROSPECTION_QUERY='{"query":"{__schema{types{name}}}"}'

SCAN_LIMIT=50
CURRENT=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    ((CURRENT++))
    [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

    for gql_path in "${GRAPHQL_PATHS[@]}"; do
        full_url="${url%/}${gql_path}"

        # Test with GET
        status="$(curl -s -o /dev/null -w '%{http_code}' "$full_url" --max-time 10 2>/dev/null)"

        if [[ "$status" == "200" || "$status" == "400" || "$status" == "405" ]]; then
            # Try introspection
            intro_response="$(curl -s -X POST "$full_url" \
                -H 'Content-Type: application/json' \
                -d "$INTROSPECTION_QUERY" --max-time 10 2>/dev/null)"

            if echo "$intro_response" | grep -q "__schema\|__type\|types" 2>/dev/null; then
                echo "${full_url} [INTROSPECTION ENABLED]" >> "$GRAPHQL_ENDPOINTS"
                # Save introspection result
                host_hash="$(echo "$full_url" | md5sum | cut -c1-8)"
                echo "$intro_response" | jq '.' > "${API_DIR}/introspection_${host_hash}.json" 2>/dev/null || true
            elif [[ "$status" == "200" || "$status" == "400" ]]; then
                echo "${full_url} [FOUND - status:${status}]" >> "$GRAPHQL_ENDPOINTS"
            fi
        fi
    done
done < "$LIVE_HOSTS"

sort -u "$GRAPHQL_ENDPOINTS" -o "$GRAPHQL_ENDPOINTS"
TOTAL="$(count_lines "$GRAPHQL_ENDPOINTS")"
log_task_done "GraphQL endpoints" "$TOTAL"

# ── Nuclei GraphQL Templates ───────────────────────────────────────────────
if cmd_exists nuclei && [[ "$TOTAL" -gt 0 ]]; then
    log_task_start "nuclei GraphQL templates"
    awk '{print $1}' "$GRAPHQL_ENDPOINTS" | nuclei \
        -tags graphql \
        -silent \
        -json \
        -o "${API_DIR}/nuclei_graphql.json" 2>/dev/null || true
    log_task_done "nuclei GraphQL" "$(jq -s 'length' "${API_DIR}/nuclei_graphql.json" 2>/dev/null || echo 0)"
fi

echo ""
echo -e "  ${BOLD}${WHITE}GraphQL Discovery Statistics:${RESET}"
log_stats "Hosts checked" "$CURRENT"
log_stats "GraphQL endpoints" "$TOTAL"
introspection_count="$(grep -c "INTROSPECTION ENABLED" "$GRAPHQL_ENDPOINTS" 2>/dev/null || echo 0)"
log_stats_final "Introspection enabled" "$introspection_count"

log_module_end "GraphQL Discovery" "$START_TIME" "$TOTAL"
