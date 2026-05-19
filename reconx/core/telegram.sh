#!/bin/bash
# ============================================================================
# ReconX Ultra X — Telegram Notification Engine
# ============================================================================
# Source this in any module: source "$RECONX_ROOT/core/telegram.sh"
# Usage: tg_send "message" | tg_notify "module" "status" "details"
# ============================================================================

RECONX_ROOT="${RECONX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

# Load Telegram credentials
_tg_load() {
    [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]] && return
    for cfg in "$RECONX_ROOT/configs/aggressive.yaml" "$RECONX_ROOT/configs/default.yaml"; do
        [[ -f "$cfg" ]] || continue
        TG_TOKEN=$(grep -oP 'telegram_token:\s*"\K[^"]+' "$cfg" 2>/dev/null | head -1)
        TG_CHAT=$(grep -oP 'telegram_chat_id:\s*"\K[^"]+' "$cfg" 2>/dev/null | head -1)
        [[ -n "$TG_TOKEN" && -n "$TG_CHAT" ]] && return
    done
}

# Send raw message
tg_send() {
    _tg_load
    [[ -z "$TG_TOKEN" || -z "$TG_CHAT" ]] && return
    local msg="$1"
    curl -sk --max-time 5 \
        "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
        -d "chat_id=${TG_CHAT}" \
        -d "text=${msg}" \
        -d "parse_mode=Markdown" \
        -d "disable_web_page_preview=true" \
        >/dev/null 2>&1 &
}

# Scan start notification
tg_scan_start() {
    local target="$1" mode="${2:-default}"
    tg_send "🚀 *ReconX Ultra Started*

🎯 Target: \`${target}\`
⚙️ Mode: \`${mode}\`
🕐 Started: \`$(date '+%Y-%m-%d %H:%M')\`"
}

# Module start
tg_module_start() {
    local module="$1" target="$2"
    tg_send "📦 *Module Started*

🔧 Module: \`${module}\`
🎯 Target: \`${target}\`
🕐 Time: \`$(date '+%H:%M:%S')\`"
}

# Module complete
tg_module_done() {
    local module="$1" duration="$2"
    shift 2
    local details="$*"
    tg_send "✅ *Module Completed*

🔧 Module: \`${module}\`
⏱ Duration: \`${duration}\`
${details}"
}

# GF results
tg_gf_results() {
    local target="$1" xss="$2" sqli="$3" ssrf="$4" lfi="$5" redirect="$6"
    tg_send "🔥 *GF Intelligence Results*

🎯 Target: \`${target}\`

📊 Candidates:
• XSS: \`${xss}\`
• SQLi: \`${sqli}\`
• SSRF: \`${ssrf}\`
• LFI: \`${lfi}\`
• Redirect: \`${redirect}\`"
}

# Parameter intelligence
tg_params() {
    local total="$1" reflective="$2" interesting="$3"
    tg_send "🧠 *Parameter Intelligence*

• Unique Params: \`${total}\`
• Reflective: \`${reflective}\`
• Interesting: \`${interesting}\`"
}

# JS intelligence
tg_js_intel() {
    local files="$1" secrets="$2" apis="$3"
    tg_send "📜 *JS Intelligence*

• JS Files: \`${files}\`
• Secrets: \`${secrets}\`
• Hidden APIs: \`${apis}\`"
}

# Final scan summary
tg_scan_done() {
    local target="$1"
    shift
    tg_send "🏁 *ReconX Ultra Completed*

🎯 Target: \`${target}\`

$*

📁 Output: \`output/${target}/final/\`
🕐 Finished: \`$(date '+%Y-%m-%d %H:%M')\`"
}

# Critical finding alert
tg_finding() {
    local type="$1" url="$2" param="$3" detail="$4"
    tg_send "⚠️ *Possible ${type}*

🔗 URL: \`${url}\`
📌 Param: \`${param}\`
📝 Detail: \`${detail}\`"
}

# Critical JS secret alert
tg_secret_alert() {
    local type="$1" file="$2" severity="$3" endpoint="$4"
    tg_send "🚨 *CRITICAL JS SECRET FOUND*

🔑 Type: \`${type}\`
📜 JS File: \`${file}\`
⚡ Severity: \`${severity}\`
🔗 Endpoint: \`${endpoint}\`"
}

# Attack chain alert
tg_chain_alert() {
    local name="$1" severity="$2" confidence="$3"
    tg_send "🔗 *Attack Chain Detected*

⚡ Chain: \`${name}\`
🎯 Severity: \`${severity}\`
📊 Confidence: \`${confidence}%\`"
}

# Hunter strategy notification
tg_strategy() {
    local target="$1"
    shift
    tg_send "🧠 *Hunter Strategy Generated*

🎯 Target: \`${target}\`

$*

🕐 \`$(date '+%H:%M:%S')\`"
}

# Surface ranking alert
tg_surface_alert() {
    local target="$1" critical="$2" high="$3" total="$4"
    tg_send "📊 *Attack Surface Ranked*

🎯 Target: \`${target}\`
🔴 Critical surfaces: \`${critical}\`
🟠 High-risk surfaces: \`${high}\`
📋 Total surfaces: \`${total}\`"
}

# Autopilot phase notification
tg_autopilot_phase() {
    local phase="$1" target="$2" detail="$3"
    tg_send "🤖 *Autopilot — ${phase}*

🎯 Target: \`${target}\`
📝 ${detail}
🕐 \`$(date '+%H:%M:%S')\`"
}

# Monitor change alert
tg_monitor_change() {
    local target="$1" changes="$2"
    tg_send "👁️ *Monitor Alert*

🎯 Target: \`${target}\`
🔔 Changes detected: \`${changes}\`
🕐 \`$(date '+%H:%M:%S')\`"
}

# Target DNA notification
tg_target_dna() {
    local target="$1" risk="$2" techs="$3"
    tg_send "🧬 *Target DNA Complete*

🎯 Target: \`${target}\`
⚡ Risk Profile: \`${risk}\`
🔧 Technologies: \`${techs}\`"
}

# Evidence-based reasoning alert
tg_reasoning_alert() {
    local target="$1" vuln_type="$2" confidence="$3" risk="$4"
    shift 4
    tg_send "🧠 *EVIDENCE-BASED FINDING*

🎯 Target: \`${target}\`
⚡ Type: \`${vuln_type}\`
📊 Confidence: \`${confidence}%\`
🔴 Risk: \`${risk}\`

$*

🕐 \`$(date '+%H:%M:%S')\`"
}

# Observed evidence alert
tg_observed_evidence() {
    local target="$1" signal_count="$2" micro_count="$3" workflow_count="$4"
    tg_send "📡 *Evidence Collection Complete*

🎯 Target: \`${target}\`
📡 Observed signals: \`${signal_count}\`
🔬 Micro-validations: \`${micro_count}\`
🔄 Workflows mapped: \`${workflow_count}\`"
}

# Attack path alert
tg_attack_path() {
    local target="$1" path_name="$2" confidence="$3" severity="$4"
    tg_send "🔗 *JUSTIFIED ATTACK PATH*

🎯 Target: \`${target}\`
⛓ Path: \`${path_name}\`
📊 Confidence: \`${confidence}%\`
🔴 Severity: \`${severity}\`"
}

export -f tg_send tg_scan_start tg_module_start tg_module_done tg_gf_results tg_params tg_js_intel tg_scan_done tg_finding tg_secret_alert tg_chain_alert tg_strategy tg_surface_alert tg_autopilot_phase tg_monitor_change tg_target_dna tg_reasoning_alert tg_observed_evidence tg_attack_path _tg_load

# ── Behavioral Intelligence Alerts ─────────────────────────────────────

tg_auth_behavior() {
    local target="$1" finding="$2" risk="$3" confidence="$4"
    tg_send "🔐 *AUTH BEHAVIORAL DIFFERENTIAL*

🎯 Target: \`${target}\`
🔓 Finding: \`${finding}\`
⚠ Risk: \`${risk}\`
📊 Confidence: \`${confidence}%\`"
}

tg_object_exposure() {
    local target="$1" obj_type="$2" count="$3" exposed="$4"
    tg_send "🔗 *OBJECT EXPOSURE DETECTED*

🎯 Target: \`${target}\`
📦 Object: \`${obj_type}\`
📊 Total: \`${count}\` | Exposed: \`${exposed}\`
⚠ Risk: IDOR / Broken Access Control"
}

tg_workflow_bypass() {
    local target="$1" workflow="$2" bypass="$3" confidence="$4"
    tg_send "🔄 *WORKFLOW BYPASS DETECTED*

🎯 Target: \`${target}\`
📋 Workflow: \`${workflow}\`
🔓 Bypass: \`${bypass}\`
📊 Confidence: \`${confidence}%\`"
}

tg_hunter_guidance() {
    local target="$1" insight="$2" priority="$3" action="$4"
    tg_send "🎯 *HUNTER GUIDANCE*

🎯 Target: \`${target}\`
💡 Insight: \`${insight}\`
🔴 Priority: \`${priority}\`
🎯 Action: \`${action}\`"
}

export -f tg_auth_behavior tg_object_exposure tg_workflow_bypass tg_hunter_guidance
export TG_TOKEN TG_CHAT
