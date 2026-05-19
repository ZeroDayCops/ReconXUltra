#!/bin/bash
# ============================================================================
# ReconX Ultra X — DEEP HUNT MODE
# ============================================================================
# Runs ALL intelligence engines with maximum depth on already-collected data.
# Use AFTER the main scan completes for deep behavioral analysis.
# ============================================================================

set -euo pipefail

DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
    echo "Usage: ./deep_hunt.sh <domain>"
    exit 1
fi

export RECONX_ROOT="$(cd "$(dirname "$0")" && pwd)"
export RECONX_PROBE_WORKERS="${RECONX_PROBE_WORKERS:-6}"

MODULES="${RECONX_ROOT}/modules"
OUT="${RECONX_ROOT}/output/${DOMAIN}"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   🔬 DEEP HUNT MODE — ${DOMAIN}"
echo "║   $(date '+%Y-%m-%d %H:%M:%S')"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Verify data exists ──────────────────────────────────────────────────
if [[ ! -d "${OUT}/subs" ]] && [[ ! -d "${OUT}/urls" ]]; then
    echo "❌ No scan data found for ${DOMAIN}"
    echo "   Run the main scan first: ./reconx.sh -d ${DOMAIN} --autopilot"
    exit 1
fi

URL_COUNT=$(wc -l < "${OUT}/urls/all_urls.txt" 2>/dev/null || echo "0")
SUB_COUNT=$(wc -l < "${OUT}/subs/all_subs.txt" 2>/dev/null || echo "0")
LIVE_COUNT=$(wc -l < "${OUT}/live/live_full.txt" 2>/dev/null || echo "0")

echo "  📊 Existing Data:"
echo "     Subdomains: ${SUB_COUNT}"
echo "     Live Hosts: ${LIVE_COUNT}"
echo "     URLs: ${URL_COUNT}"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Deep Target DNA
# ═══════════════════════════════════════════════════════════════════════════
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🧬 PHASE 1/8: Deep Target DNA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/intelligence/target_dna.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ target_dna skipped"
python3 "${MODULES}/intelligence/surface_ranker.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ surface_ranker skipped"
python3 "${MODULES}/intelligence/ai_prioritizer.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ ai_prioritizer skipped"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Deep JS Intelligence
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📜 PHASE 2/8: Deep JS Intelligence"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/intelligence/js_deep_analysis.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ js_deep skipped"
python3 "${MODULES}/intelligence/smart_gf.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ smart_gf skipped"
python3 "${MODULES}/intelligence/param_intelligence.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ param_intel skipped"
python3 "${MODULES}/intelligence/cloud_exposure.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ cloud_exposure skipped"
python3 "${MODULES}/intelligence/memory_engine.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ memory_engine skipped"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Full EBRE Reasoning Pipeline
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🧠 PHASE 3/8: Evidence-Based Reasoning Engine"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/intelligence/observed_signals.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ observed_signals skipped"
python3 "${MODULES}/intelligence/micro_validation.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ micro_validation skipped"
python3 "${MODULES}/intelligence/workflow_evidence.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ workflow_evidence skipped"
python3 "${MODULES}/intelligence/reasoning_engine.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ reasoning_engine skipped"
python3 "${MODULES}/intelligence/attack_paths.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ attack_paths skipped"
python3 "${MODULES}/intelligence/reasoning_trace.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ reasoning_trace skipped"
python3 "${MODULES}/intelligence/strategy_engine.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ strategy_engine skipped"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Full Behavioral Intelligence
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔬 PHASE 4/8: Auth-State Behavioral Intelligence"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/behavioral/auth_behavior.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ auth_behavior skipped"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔗 PHASE 5/8: Object Relationship Intelligence"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/behavioral/object_relationships.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ object_relationships skipped"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🔄 PHASE 6/8: Workflow + DOM + Session + API Analysis"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/behavioral/workflow_transitions.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ workflow_transitions skipped"
python3 "${MODULES}/behavioral/dom_observer.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ dom_observer skipped"
python3 "${MODULES}/behavioral/session_intelligence.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ session_intelligence skipped"
python3 "${MODULES}/behavioral/api_behavior.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ api_behavior skipped"
python3 "${MODULES}/behavioral/state_diff_engine.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ state_diff skipped"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: Target Understanding + Hunter Guidance
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  🧠 PHASE 7/8: Target Understanding + Hunter Guidance"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/behavioral/target_understanding.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ target_understanding skipped"
python3 "${MODULES}/intelligence/chain_builder.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ chain_builder skipped"

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8: Visualizations
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  📊 PHASE 8/8: Behavior Graph + Dashboard"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
python3 "${MODULES}/behavioral/target_behavior_graph.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ behavior_graph skipped"
python3 "${MODULES}/reporting/dashboard_gen.py" "$DOMAIN" 2>/dev/null || echo "  ⚠ dashboard skipped"

# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║   🔬 DEEP HUNT COMPLETE                                 ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# Count outputs
AUTH_COUNT=$(python3 -c "import json; d=json.loads(open('${OUT}/auth_intelligence/auth_behavior.json').read()); print(d.get('total_findings',0))" 2>/dev/null || echo "0")
OBJ_COUNT=$(python3 -c "import json; d=json.loads(open('${OUT}/object_relationships/object_relationships.json').read()); print(d.get('total_objects',0))" 2>/dev/null || echo "0")
OBJ_EXPOSED=$(python3 -c "import json; d=json.loads(open('${OUT}/object_relationships/object_relationships.json').read()); print(d.get('exposed_objects',0))" 2>/dev/null || echo "0")
WF_COUNT=$(python3 -c "import json; d=json.loads(open('${OUT}/workflow_transitions/workflow_transitions.json').read()); print(d.get('total_workflows',0))" 2>/dev/null || echo "0")
GUIDANCE=$(python3 -c "import json; d=json.loads(open('${OUT}/target_understanding/target_understanding.json').read()); print(len(d.get('hunter_guidance',[])))" 2>/dev/null || echo "0")
APP_TYPE=$(python3 -c "import json; d=json.loads(open('${OUT}/target_understanding/target_understanding.json').read()); print(d.get('app_type','unknown'))" 2>/dev/null || echo "unknown")

echo "  🎯 Target: ${DOMAIN}"
echo "  🏷️  App Type: ${APP_TYPE}"
echo "  🔐 Auth Findings: ${AUTH_COUNT}"
echo "  🔗 Objects: ${OBJ_COUNT} (${OBJ_EXPOSED} exposed)"
echo "  🔄 Workflows: ${WF_COUNT}"
echo "  🎯 Hunter Guidance: ${GUIDANCE} items"
echo ""
echo "  📁 Key Files:"
echo "     cat ${OUT}/live_guidance/live_hunter_guidance.md"
echo "     cat ${OUT}/target_understanding/target_understanding.txt"
echo "     cat ${OUT}/auth_intelligence/auth_behavior.txt"
echo "     xdg-open ${OUT}/reports/behavior_graph.html"
echo ""
echo "  ⏱️  Completed: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""
