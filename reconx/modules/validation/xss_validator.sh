#!/bin/bash
# ============================================================================
# ReconX Ultra X — Lightweight XSS Validator v5.0
# ============================================================================
# FAST: gf → dedup → quick reflection → optional dalfox → clean output
# NO: heavy Selenium, browser clusters, massive fuzzing
# ============================================================================
set -o pipefail
DOMAIN="$1"
CANDIDATES="$2"
OUTPUT="$3"
[[ -z "$DOMAIN" || ! -f "$CANDIDATES" ]] && exit 1

RECONX_ROOT="${RECONX_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"
OUT_DIR="${OUT_DIR:-${RECONX_ROOT}/output/${DOMAIN}}"
WORK="$(dirname "$OUTPUT")"
FINAL="${OUT_DIR}/final"
mkdir -p "$WORK" "$FINAL"

source "$RECONX_ROOT/core/telegram.sh" 2>/dev/null || true

echo "    ⚡ Lightweight XSS Validator v5.0"

# ── Clean + Dedup ─────────────────────────────────────────────────────────
CLEAN="$WORK/xss_clean.txt"
grep -E '^https?://' "$CANDIDATES" | sort -u > "$CLEAN"
TOTAL=$(wc -l < "$CLEAN")

DEDUP="$WORK/xss_dedup.txt"
awk -F'?' '{if(!seen[$1]++){print}}' "$CLEAN" | head -50 > "$DEDUP"
DEDUP_N=$(wc -l < "$DEDUP")
echo "    ✅ $TOTAL URLs → $DEDUP_N unique endpoints"

# ── Quick Reflection Check ────────────────────────────────────────────────
echo "    ⏳ Quick reflection check..."
REFLECTED="$WORK/xss_reflected.txt"
> "$REFLECTED"

while IFS= read -r url; do
    [[ -z "$url" ]] && continue
    params=$(echo "$url" | grep -oP '[?&]\K[^=]+' 2>/dev/null)
    [[ -z "$params" ]] && continue
    for param in $params; do
        probe="RX$(shuf -i 10000-99999 -n1)ZQ"
        test_url=$(echo "$url" | sed "s|\(${param}=\)[^&]*|\1${probe}|g")
        if curl -skL --max-time 4 "$test_url" 2>/dev/null | grep -qF "$probe"; then
            echo "$url" >> "$REFLECTED"
            echo "      ✓ $param reflects — $url"
            break
        fi
    done
done < "$DEDUP"

ref_count=$(wc -l < "$REFLECTED" 2>/dev/null || echo 0)
echo "    ✅ $ref_count reflective URLs"

# Copy to final output
cp "$CLEAN" "$FINAL/possible_xss.txt" 2>/dev/null
cp "$REFLECTED" "$FINAL/reflected_xss.txt" 2>/dev/null

# ── Optional Dalfox Quick Scan ────────────────────────────────────────────
DALFOX_OUT="$WORK/dalfox_xss.txt"
> "$DALFOX_OUT"

if command -v dalfox &>/dev/null && [[ "$ref_count" -gt 0 ]]; then
    echo "    ⏳ Dalfox quick scan ($ref_count URLs)..."
    timeout 60 dalfox file "$REFLECTED" \
        --silence --timeout 5 --worker 5 --skip-bav \
        -o "$DALFOX_OUT" 2>/dev/null || true
    dalfox_n=$(wc -l < "$DALFOX_OUT" 2>/dev/null || echo 0)
    echo "    ✅ Dalfox: $dalfox_n findings"
    [[ "$dalfox_n" -gt 0 ]] && cp "$DALFOX_OUT" "$FINAL/dalfox_xss.txt"
fi

# ── Build JSON output ─────────────────────────────────────────────────────
python3 -c "
import json
results = []
try:
    for line in open('$REFLECTED'):
        url = line.strip()
        if url: results.append({'url': url, 'reflected': True, 'type': 'xss'})
except: pass
try:
    for line in open('$DALFOX_OUT'):
        url = line.strip()
        if url and url not in [r['url'] for r in results]:
            results.append({'url': url, 'dalfox_confirmed': True, 'type': 'xss'})
except: pass
with open('$OUTPUT', 'w') as f:
    json.dump(results, f, indent=2)
print(f'    ✅ Total: {len(results)} XSS candidates')
" 2>/dev/null || echo "[]" > "$OUTPUT"

# ── Telegram notification ─────────────────────────────────────────────────
tg_gf_results "$DOMAIN" "$TOTAL" "0" "0" "0" "0" 2>/dev/null || true

echo "    🏁 XSS validator done (${ref_count} reflected, files in final/)"
