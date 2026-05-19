#!/bin/bash
# ============================================================================
# ReconX Ultra X — Final Output Generator & Intelligence Organizer
# ============================================================================
# Generates clean final/ directory from all recon output for manual hunting
# ============================================================================
set -o pipefail
DOMAIN="$1"
[[ -z "$DOMAIN" ]] && echo "Usage: final_output.sh <domain>" && exit 1

RECONX_ROOT="${RECONX_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OUT="${RECONX_ROOT}/output/${DOMAIN}"
FINAL="${OUT}/final"
INTEL="${OUT}/intelligence"
source "$RECONX_ROOT/core/telegram.sh" 2>/dev/null

mkdir -p "$FINAL"
echo ""
echo "    ╔═══════════════════════════════════════════════╗"
echo "    ║  📁 Final Output Generator — $DOMAIN"
echo "    ╚═══════════════════════════════════════════════╝"
echo ""

# ── URLs ──────────────────────────────────────────────────────────────────
echo "    ⏳ Collecting URLs..."
cat "${OUT}/urls/"*.txt 2>/dev/null | sort -u > "$FINAL/urls.txt"
urls_count=$(wc -l < "$FINAL/urls.txt" 2>/dev/null || echo 0)
echo "    ✅ urls.txt → $urls_count URLs"

# Live URLs
cat "${OUT}/live/"*.txt 2>/dev/null | sort -u > "$FINAL/live_urls.txt"
live_count=$(wc -l < "$FINAL/live_urls.txt" 2>/dev/null || echo 0)
echo "    ✅ live_urls.txt → $live_count live URLs"

# ── Parameters ────────────────────────────────────────────────────────────
echo "    ⏳ Extracting parameters..."
cat "${OUT}/params/"*.txt 2>/dev/null | sort -u > "$FINAL/params.txt"
params_count=$(wc -l < "$FINAL/params.txt" 2>/dev/null || echo 0)
echo "    ✅ params.txt → $params_count params"

# ── GF Pattern Candidates ────────────────────────────────────────────────
echo "    ⏳ Organizing GF candidates..."
# XSS
cat "$INTEL/xss_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_xss.txt"
xss_count=$(wc -l < "$FINAL/possible_xss.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_xss.txt → $xss_count"

# SQLi
cat "$INTEL/sqli_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_sqli.txt"
sqli_count=$(wc -l < "$FINAL/possible_sqli.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_sqli.txt → $sqli_count"

# SSRF
cat "$INTEL/ssrf_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_ssrf.txt"
ssrf_count=$(wc -l < "$FINAL/possible_ssrf.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_ssrf.txt → $ssrf_count"

# LFI
cat "$INTEL/lfi_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_lfi.txt"
lfi_count=$(wc -l < "$FINAL/possible_lfi.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_lfi.txt → $lfi_count"

# Open Redirect
cat "$INTEL/redirect_candidates.txt" "$INTEL/or_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_redirect.txt"
redirect_count=$(wc -l < "$FINAL/possible_redirect.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_redirect.txt → $redirect_count"

# IDOR
cat "$INTEL/idor_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_idor.txt"
idor_count=$(wc -l < "$FINAL/possible_idor.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_idor.txt → $idor_count"

# CRLF
cat "$INTEL/crlf_candidates.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$FINAL/possible_crlf.txt"
crlf_count=$(wc -l < "$FINAL/possible_crlf.txt" 2>/dev/null || echo 0)
echo "    ✅ possible_crlf.txt → $crlf_count"

# ── JS & API Intelligence ────────────────────────────────────────────────
echo "    ⏳ JS & API intelligence..."
cat "${OUT}/js/"*.txt 2>/dev/null | sort -u > "$FINAL/js_files.txt"
js_count=$(wc -l < "$FINAL/js_files.txt" 2>/dev/null || echo 0)
echo "    ✅ js_files.txt → $js_count"

cat "$INTEL/js_endpoints_flat.txt" "$INTEL/api_inventory.json" 2>/dev/null | grep -oP 'https?://[^\s"]+' | sort -u > "$FINAL/api_endpoints.txt"
api_count=$(wc -l < "$FINAL/api_endpoints.txt" 2>/dev/null || echo 0)
echo "    ✅ api_endpoints.txt → $api_count"

# Admin panels
cp "$INTEL/admin_panels.txt" "$FINAL/admin_panels.txt" 2>/dev/null
admin_count=$(wc -l < "$FINAL/admin_panels.txt" 2>/dev/null || echo 0)
echo "    ✅ admin_panels.txt → $admin_count"

# High-value targets
cp "$INTEL/high_value_targets.txt" "$FINAL/high_value_targets.txt" 2>/dev/null
hv_count=$(wc -l < "$FINAL/high_value_targets.txt" 2>/dev/null || echo 0)
echo "    ✅ high_value_targets.txt → $hv_count"

# Secrets
cat "${OUT}/secrets/"*.txt 2>/dev/null | sort -u > "$FINAL/sensitive_files.txt"
secrets_count=$(wc -l < "$FINAL/sensitive_files.txt" 2>/dev/null || echo 0)
echo "    ✅ sensitive_files.txt → $secrets_count"

# ── Parameter Groups ─────────────────────────────────────────────────────
echo "    ⏳ Classifying parameters..."
python3 -c "
import json, re

params = {}
try:
    for line in open('$FINAL/params.txt'):
        p = line.strip()
        if not p: continue
        pl = p.lower()
        if any(k in pl for k in ['q','search','keyword','query','callback','name','msg','message','comment','text','input','value']):
            params.setdefault('xss', []).append(p)
        if any(k in pl for k in ['id','user','cat','page','item','order','num','no','count']):
            params.setdefault('sqli', []).append(p)
        if any(k in pl for k in ['url','endpoint','image','dest','redirect','return','next','link','site','uri']):
            params.setdefault('ssrf', []).append(p)
        if any(k in pl for k in ['file','path','include','template','page','doc','folder','dir']):
            params.setdefault('lfi', []).append(p)
        if any(k in pl for k in ['url','redirect','return','next','goto','dest','rurl','out']):
            params.setdefault('redirect', []).append(p)
except: pass

for k in params:
    params[k] = list(set(params[k]))

with open('$FINAL/parameter_groups.json', 'w') as f:
    json.dump(params, f, indent=2)

total = sum(len(v) for v in params.values())
print(f'    ✅ parameter_groups.json → {total} classified')
" 2>/dev/null || echo "    ⚠️  Parameter classification skipped"

# ── Quick Summary ─────────────────────────────────────────────────────────
echo "    ⏳ Generating summary..."
cat > "$FINAL/quick_summary.txt" << EOF
═══════════════════════════════════════════════
  ReconX Ultra X — Quick Summary
  Target: $DOMAIN
  Generated: $(date '+%Y-%m-%d %H:%M')
═══════════════════════════════════════════════

📊 URLs:          $urls_count
🟢 Live URLs:     $live_count
🔧 Parameters:    $params_count

🔥 Possible XSS:       $xss_count
💉 Possible SQLi:      $sqli_count
🌐 Possible SSRF:      $ssrf_count
📂 Possible LFI:       $lfi_count
↩️  Possible Redirect:  $redirect_count
🆔 Possible IDOR:      $idor_count
📜 JS Files:            $js_count
🔌 API Endpoints:       $api_count
🔑 Admin Panels:        $admin_count
🎯 High Value:          $hv_count

═══════════════════════════════════════════════
EOF

cat "$FINAL/quick_summary.txt"

# ── Telegram Final Summary ────────────────────────────────────────────────
tg_scan_done "$DOMAIN" "📊 Summary:
• URLs: \`$urls_count\`
• Live: \`$live_count\`
• Params: \`$params_count\`
• XSS: \`$xss_count\`
• SQLi: \`$sqli_count\`
• SSRF: \`$ssrf_count\`
• LFI: \`$lfi_count\`
• JS: \`$js_count\`
• APIs: \`$api_count\`
• Admin: \`$admin_count\`" 2>/dev/null

echo ""
echo "    📁 All files → $FINAL/"
echo ""
