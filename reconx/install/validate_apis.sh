#!/usr/bin/env bash
# ============================================================================
# ReconX Ultra — API Key Validation
# ============================================================================

set -euo pipefail

RECONX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${RECONX_ROOT}/configs/default.yaml"

echo -e "\033[0;34m[*]\033[0m Validating API keys..."

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "\033[1;33m[!]\033[0m Config file not found: $CONFIG_FILE"
    echo -e "\033[0;90m    Create configs/default.yaml with your API keys\033[0m"
    exit 0
fi

# ── Check API Keys ──────────────────────────────────────────────────────────
check_api() {
    local name="$1"
    local key="$2"
    local test_url="$3"

    if [[ -z "$key" || "$key" == '""' || "$key" == "''" ]]; then
        echo -e "  \033[1;33m○\033[0m ${name}: \033[0;90mnot configured\033[0m"
        return
    fi

    # Test the API
    local status
    status="$(curl -s -o /dev/null -w '%{http_code}' "$test_url" --max-time 10 2>/dev/null || echo "000")"

    if [[ "$status" == "200" || "$status" == "401" ]]; then
        echo -e "  \033[0;32m✓\033[0m ${name}: \033[0;32mvalid\033[0m"
    elif [[ "$status" == "000" ]]; then
        echo -e "  \033[1;33m?\033[0m ${name}: \033[0;90mcould not verify (network)\033[0m"
    else
        echo -e "  \033[0;31m✗\033[0m ${name}: \033[0;31minvalid (HTTP ${status})\033[0m"
    fi
}

# Parse keys from config
get_yaml_value() {
    local key="$1"
    grep -A0 "^\s*${key}:" "$CONFIG_FILE" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"'"'"
}

SHODAN_KEY="$(get_yaml_value "shodan")"
VT_KEY="$(get_yaml_value "virustotal")"
ST_KEY="$(get_yaml_value "securitytrails")"
CHAOS_KEY="$(get_yaml_value "chaos")"
GH_TOKEN="$(get_yaml_value "github_token")"

check_api "Shodan" "$SHODAN_KEY" "https://api.shodan.io/api-info?key=${SHODAN_KEY}"
check_api "VirusTotal" "$VT_KEY" "https://www.virustotal.com/vtapi/v2/url/report?apikey=${VT_KEY}&resource=google.com"
check_api "SecurityTrails" "$ST_KEY" "https://api.securitytrails.com/v1/ping?apikey=${ST_KEY}"
check_api "Chaos" "$CHAOS_KEY" "https://dns.projectdiscovery.io/dns/example.com/subdomains"
check_api "GitHub" "$GH_TOKEN" "https://api.github.com/user"

echo -e "\n\033[0;32m[✓]\033[0m API validation complete"
echo -e "\033[0;90m    Configure missing keys in: ${CONFIG_FILE}\033[0m"
