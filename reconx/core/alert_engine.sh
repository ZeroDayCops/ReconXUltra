#!/bin/bash
# ReconX Ultra X — Critical Finding Alert Engine
# Sends rich Telegram alerts for validated HIGH/CRITICAL findings
# Usage: alert_engine.sh '<json_finding>'

FINDING_JSON="$1"
[[ -z "$FINDING_JSON" ]] && exit 0

# Load config
RECONX_ROOT="${RECONX_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
source "${RECONX_ROOT}/core/common.sh" 2>/dev/null || true

# Parse finding
read_field() { echo "$FINDING_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('$1',''))" 2>/dev/null; }

TYPE=$(read_field "type")
URL=$(read_field "url")
PARAM=$(read_field "param")
PAYLOAD=$(read_field "payload")
SCORE=$(read_field "score")
CONFIDENCE=$(read_field "confidence")
SOURCE=$(read_field "source")
SCREENSHOT=$(read_field "screenshot")

# Determine severity icon
ICON="⚠️"
[[ "$SCORE" -ge 76 ]] && ICON="🚨"
[[ "$SCORE" -ge 51 && "$SCORE" -lt 76 ]] && ICON="🔴"

# Severity label
SEV="MEDIUM"
[[ "$SCORE" -ge 76 ]] && SEV="CRITICAL"
[[ "$SCORE" -ge 51 && "$SCORE" -lt 76 ]] && SEV="HIGH"

# Build message
MSG="${ICON} <b>${SEV} ${TYPE} DETECTED</b>
━━━━━━━━━━━━━━━━━━━━━━━━

🎯 <b>Target:</b>
<code>${URL}</code>

💉 <b>Payload:</b>
<code>${PAYLOAD:-N/A}</code>

📊 <b>Details:</b>
┌─ Type: <b>${TYPE}</b>
├─ Parameter: <code>${PARAM:-N/A}</code>
├─ Confidence: <b>${CONFIDENCE} (${SCORE}/100)</b>
├─ Validator: <code>${SOURCE}</code>
└─ Time: <code>$(date '+%Y-%m-%d %H:%M:%S')</code>

🔍 <i>Validated by ReconX Ultra X</i>"

# Load Telegram config
TG_TOKEN=""
TG_CHAT=""

# Try loading from YAML config
for cfg in "${RECONX_ROOT}/configs/aggressive.yaml" "${RECONX_ROOT}/configs/default.yaml"; do
    if [[ -f "$cfg" ]]; then
        TG_TOKEN=$(grep -oP 'telegram_token:\s*"\K[^"]+' "$cfg" 2>/dev/null | head -1)
        TG_CHAT=$(grep -oP 'telegram_chat_id:\s*"\K[^"]+' "$cfg" 2>/dev/null | head -1)
        [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]] && break
    fi
done

# Try from CONFIG array (if sourced from module_runner)
[[ -z "$TG_TOKEN" ]] && TG_TOKEN="${CONFIG[notify.telegram_token]:-}"
[[ -z "$TG_CHAT" ]] && TG_CHAT="${CONFIG[notify.telegram_chat_id]:-}"

if [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]]; then
    # Send text message
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT}" \
        --data-urlencode "text=${MSG}" \
        -d "parse_mode=HTML" \
        -d "disable_web_page_preview=true" &>/dev/null

    # Send screenshot if available
    if [[ -n "$SCREENSHOT" && -f "$SCREENSHOT" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendPhoto" \
            -F "chat_id=${TG_CHAT}" \
            -F "photo=@${SCREENSHOT}" \
            -F "caption=📸 Proof: ${TYPE} on ${PARAM:-target}" &>/dev/null
    fi
fi
