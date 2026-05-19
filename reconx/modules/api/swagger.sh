#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — Swagger/OpenAPI Discovery
# ============================================================================

DOMAIN="${1:?Usage: swagger.sh <domain>}"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/../../core" && pwd)/common.sh"
source "${RECONX_CORE}/logger.sh"

init_target_dirs "$DOMAIN"
log_module_start "Swagger/OpenAPI Discovery" "$DOMAIN"
START_TIME="$(date +%s)"

API_DIR="${OUT_SCANS}/api"
mkdir -p "$API_DIR"

LIVE_HOSTS="${OUT_LIVE}/live_hosts.txt"
if [[ ! -f "$LIVE_HOSTS" || "$(count_lines "$LIVE_HOSTS")" -eq 0 ]]; then
    log_warn "No live hosts — skipping Swagger discovery"
    exit 0
fi

# ── Swagger/OpenAPI Paths ───────────────────────────────────────────────────
SWAGGER_PATHS=(
    "/swagger.json"
    "/swagger.yaml"
    "/swagger-ui.html"
    "/swagger-ui/"
    "/swagger/"
    "/api-docs"
    "/api-docs.json"
    "/api/docs"
    "/api/swagger.json"
    "/api/swagger.yaml"
    "/api/swagger-ui.html"
    "/openapi.json"
    "/openapi.yaml"
    "/openapi/"
    "/api/openapi.json"
    "/v1/swagger.json"
    "/v2/swagger.json"
    "/v3/swagger.json"
    "/v1/api-docs"
    "/v2/api-docs"
    "/v3/api-docs"
    "/docs"
    "/docs/api"
    "/redoc"
    "/api/v1/docs"
    "/api/v2/docs"
    "/api/schema"
    "/.well-known/openapi.json"
    "/api/spec"
    "/api/documentation"
)

SWAGGER_RESULTS="${API_DIR}/swagger_endpoints.txt"
> "$SWAGGER_RESULTS"

log_task_start "Probing for Swagger/OpenAPI endpoints"

SCAN_LIMIT=50
CURRENT=0

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    ((CURRENT++))
    [[ "$CURRENT" -gt "$SCAN_LIMIT" ]] && break

    for swagger_path in "${SWAGGER_PATHS[@]}"; do
        full_url="${url%/}${swagger_path}"
        response="$(curl -s -o /dev/null -w '%{http_code}|%{content_type}|%{size_download}' \
            "$full_url" --max-time 10 2>/dev/null)" || continue

        status="${response%%|*}"
        rest="${response#*|}"
        ctype="${rest%%|*}"
        size="${rest#*|}"

        if [[ "$status" == "200" && "$size" -gt 100 ]]; then
            if echo "$ctype" | grep -qiE "json|yaml|html|text"; then
                echo "${full_url} [${status}] [${ctype}] [${size}B]" >> "$SWAGGER_RESULTS"

                # Download the spec if it's JSON/YAML
                if echo "$ctype" | grep -qiE "json|yaml"; then
                    host_hash="$(echo "$full_url" | md5sum | cut -c1-8)"
                    curl -s "$full_url" --max-time 10 \
                        > "${API_DIR}/swagger_spec_${host_hash}.json" 2>/dev/null || true
                fi
            fi
        fi
    done
done < "$LIVE_HOSTS"

sort -u "$SWAGGER_RESULTS" -o "$SWAGGER_RESULTS"
TOTAL="$(count_lines "$SWAGGER_RESULTS")"
log_task_done "Swagger/OpenAPI endpoints" "$TOTAL"

# ── Extract API Routes from Specs ───────────────────────────────────────────
if [[ "$TOTAL" -gt 0 ]]; then
    log_task_start "Extracting API routes from specs"
    API_ROUTES="${API_DIR}/api_routes.txt"
    > "$API_ROUTES"

    for spec_file in "${API_DIR}"/swagger_spec_*.json; do
        [[ -f "$spec_file" ]] || continue
        jq -r '.paths | keys[]?' "$spec_file" 2>/dev/null >> "$API_ROUTES" || true
    done

    sort -u "$API_ROUTES" -o "$API_ROUTES"
    log_task_done "API routes extracted" "$(count_lines "$API_ROUTES")"
fi

echo ""
echo -e "  ${BOLD}${WHITE}Swagger/OpenAPI Statistics:${RESET}"
log_stats "Hosts checked" "$CURRENT"
log_stats "Swagger endpoints" "$TOTAL"
log_stats_final "API routes" "$(count_lines "${API_DIR}/api_routes.txt")"

log_module_end "Swagger/OpenAPI Discovery" "$START_TIME" "$TOTAL"
