#!/bin/bash
# ReconX Ultra X — CORS Validation Pipeline
# Usage: cors_validator.sh <domain> <candidates_file> <output_json>
DOMAIN="$1"
CANDIDATES="$2"
OUTPUT="$3"
[[ -z "$DOMAIN" || ! -f "$CANDIDATES" ]] && exit 1
mkdir -p "$(dirname "$OUTPUT")"

TOTAL=$(wc -l < "$CANDIDATES")
echo "    ⏳ Testing $TOTAL CORS candidates..."

RESULTS="[]"
CORS_FILE="$(dirname "$OUTPUT")/cors_confirmed.txt"
> "$CORS_FILE"

# Test payload origins
ORIGINS=("https://evil.com" "null" "https://$DOMAIN.evil.com")

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    for origin in "${ORIGINS[@]}"; do
        resp=$(curl -skI -H "Origin: $origin" --max-time 8 "$url" 2>/dev/null)
        
        # Check ACAO and ACAC
        acao=$(echo "$resp" | grep -i "Access-Control-Allow-Origin:" | tr -d '\r' | awk '{print $2}')
        acac=$(echo "$resp" | grep -i "Access-Control-Allow-Credentials:" | tr -d '\r' | awk '{print $2}')
        
        if [[ "$acao" == "$origin" || "$acao" == "null" ]]; then
            # If ACAC is true, it's high severity. Otherwise, medium.
            if [[ "$acac" == "true" ]]; then
                echo "${url}|||${origin}|||High|||Credentials Allowed" >> "$CORS_FILE"
                break
            else
                echo "${url}|||${origin}|||Medium|||Origin Reflected" >> "$CORS_FILE"
                break
            fi
        fi
    done
done < <(head -50 "$CANDIDATES")

count=$(wc -l < "$CORS_FILE" 2>/dev/null || echo 0)
echo "    ✓ CORS misconfigurations confirmed: $count"

python3 -c "
import json
results = []
try:
    with open('$CORS_FILE') as f:
        for line in f:
            parts = line.strip().split('|||')
            if len(parts) >= 4:
                results.append({
                    'url': parts[0], 'origin': parts[1],
                    'severity': parts[2], 'detail': parts[3],
                    'confirmed': True
                })
except: pass
with open('$OUTPUT', 'w') as f:
    json.dump(results, f, indent=2)
" 2>/dev/null

echo "    ✅ CORS validation complete"
