#!/usr/bin/env python3
"""
ReconX Ultra X — Dynamic Strategy Engine
==========================================
Generates ADAPTIVE hunting strategies based on
REAL evidence from observed signals, micro-validation,
workflow analysis, and target DNA.

NOT static recommendations.
EVIDENCE-DRIVEN strategy generation.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: strategy_engine.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
STRAT_DIR = OUT / "hunter_strategy"
STRAT_DIR.mkdir(parents=True, exist_ok=True)

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


def main():
    print(f"\n  🎯 Dynamic Strategy Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    # Load ALL evidence
    dna = lj(OUT / "target_dna/target_dna.json") or {}
    signals = lj(OUT / "observed_signals/observed_signals.json") or {}
    micro = lj(OUT / "evidence/micro_validation.json") or {}
    workflows = lj(OUT / "workflows/workflow_evidence.json") or {}
    reasoning = lj(OUT / "reasoning/reasoned_findings.json") or {}
    surface = lj(OUT / "prioritized/surface_ranking.json") or {}

    signal_list = signals.get("signals", []) if isinstance(signals, dict) else []
    micro_list = micro.get("findings", []) if isinstance(micro, dict) else []
    wf_list = workflows.get("workflows", []) if isinstance(workflows, dict) else []
    finding_list = reasoning.get("findings", []) if isinstance(reasoning, dict) else []
    ranked = surface.get("ranked_surfaces", []) if isinstance(surface, dict) else []

    # ── Build Evidence-Based Strategy ─────────────────────────────────
    strategy = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "priority_actions": [],
        "attack_surface_focus": [],
        "workflow_focus": [],
        "technology_considerations": [],
        "evidence_summary": {},
        "reasoning_level": "L1",
    }

    # Determine reasoning level from evidence depth
    if micro_list:
        strategy["reasoning_level"] = "L2"
    if wf_list:
        strategy["reasoning_level"] = "L3"
    if finding_list:
        strategy["reasoning_level"] = "L3"

    # ── Priority Actions (from validated findings) ────────────────────
    for finding in finding_list:
        vt = finding.get("vuln_type", "")
        conf = finding.get("confidence", 0)
        risk = finding.get("risk", "MEDIUM")
        observed = finding.get("observed", [])
        tests = finding.get("recommended_tests", [])

        if conf < 15:
            continue

        action = {
            "vuln_type": vt,
            "priority": "CRITICAL" if conf >= 60 else "HIGH" if conf >= 30 else "MEDIUM",
            "confidence": conf,
            "reason": f"Based on {len(observed)} observations: {', '.join(observed[:3])}",
            "recommended_tests": tests[:4],
            "evidence_count": len(observed),
        }
        strategy["priority_actions"].append(action)

    # ── Attack Surface Focus (from ranked surfaces) ───────────────────
    for surf in ranked[:8]:
        cat = surf.get("category", "")
        score = surf.get("score", 0)
        eps = surf.get("endpoints", 0)
        vtypes = surf.get("vuln_types", [])

        strategy["attack_surface_focus"].append({
            "category": cat,
            "risk_score": score,
            "endpoint_count": eps,
            "vuln_types": vtypes[:4],
            "reason": f"{'Critical' if score >= 85 else 'High' if score >= 70 else 'Medium'} risk — {eps} endpoints, test for: {', '.join(vtypes[:3])}",
        })

    # ── Workflow Focus (from workflow evidence) ───────────────────────
    for wf in wf_list:
        if wf.get("confidence", 0) < 15:
            continue
        strategy["workflow_focus"].append({
            "workflow": wf.get("workflow", ""),
            "confidence": wf.get("confidence", 0),
            "observations": wf.get("observations", [])[:5],
            "risk_reasons": wf.get("risk_reasons", [])[:3],
            "test_for": wf.get("vuln_types", [])[:4],
        })

    # ── Technology Considerations ─────────────────────────────────────
    techs = dna.get("technologies", {})
    auth_systems = dna.get("auth_systems", [])
    cloud = dna.get("cloud_providers", [])
    backend = dna.get("frameworks", {}).get("backend", [])

    if techs:
        for tech, details in list(techs.items())[:10]:
            consideration = {
                "technology": tech,
                "impact": _tech_impact(tech),
            }
            strategy["technology_considerations"].append(consideration)

    if auth_systems:
        strategy["technology_considerations"].append({
            "technology": f"Auth: {', '.join(auth_systems)}",
            "impact": "Test OAuth redirects, JWT validation, session management",
        })
    if cloud:
        strategy["technology_considerations"].append({
            "technology": f"Cloud: {', '.join(cloud)}",
            "impact": "Test SSRF to metadata, cloud bucket enumeration, IAM misconfig",
        })

    # ── Evidence Summary ──────────────────────────────────────────────
    strategy["evidence_summary"] = {
        "observed_signals": len(signal_list),
        "micro_validations": len(micro_list),
        "confirmed_micro": len([m for m in micro_list if m.get("confidence", 0) >= 40]),
        "workflows_mapped": len(wf_list),
        "reasoned_findings": len(finding_list),
        "critical_findings": len([f for f in finding_list if f.get("risk") == "CRITICAL"]),
        "high_findings": len([f for f in finding_list if f.get("risk") == "HIGH"]),
    }

    # Sort by priority
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    strategy["priority_actions"].sort(
        key=lambda a: (priority_order.get(a["priority"], 3), -a["confidence"]))

    # ── Save ──────────────────────────────────────────────────────────
    (STRAT_DIR / "dynamic_strategy.json").write_text(
        json.dumps(strategy, indent=2))

    # Human-readable strategy report
    lines = [
        "═" * 64,
        f"  🎯 DYNAMIC HUNTER STRATEGY — {DOMAIN}",
        f"  Reasoning Level: {strategy['reasoning_level']}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 64, "",
        "  📊 EVIDENCE SUMMARY",
        "  ─" * 20,
    ]
    es = strategy["evidence_summary"]
    lines.append(f"    📡 Observed signals:   {es['observed_signals']}")
    lines.append(f"    🔬 Micro-validations:  {es['micro_validations']} ({es['confirmed_micro']} confirmed)")
    lines.append(f"    🔄 Workflows mapped:   {es['workflows_mapped']}")
    lines.append(f"    🧠 Reasoned findings:  {es['reasoned_findings']}")
    lines.append(f"    🔴 Critical:           {es['critical_findings']}")
    lines.append(f"    🟠 High:               {es['high_findings']}")
    lines.append("")

    if strategy["priority_actions"]:
        lines.append("  🔥 PRIORITY ACTIONS")
        lines.append("  ─" * 20)
        for i, action in enumerate(strategy["priority_actions"], 1):
            icon = "🔴" if action["priority"] == "CRITICAL" else "🟠" if action["priority"] == "HIGH" else "🟡"
            lines.append(f"\n    {icon} #{i} {action['vuln_type']} ({action['priority']})")
            lines.append(f"       Confidence: {action['confidence']}%")
            lines.append(f"       Reason: {action['reason'][:100]}")
            lines.append("       Tests:")
            for t in action["recommended_tests"]:
                lines.append(f"         • {t}")

    if strategy["workflow_focus"]:
        lines.append(f"\n  🔄 WORKFLOW FOCUS")
        lines.append("  ─" * 20)
        for wf in strategy["workflow_focus"]:
            lines.append(f"\n    📋 {wf['workflow'].upper()} (confidence: {wf['confidence']}%)")
            for o in wf["observations"][:3]:
                lines.append(f"      ✔ {o}")
            lines.append("      Test for:")
            for v in wf["test_for"]:
                lines.append(f"        🎯 {v}")

    if strategy["technology_considerations"]:
        lines.append(f"\n  🔧 TECHNOLOGY CONSIDERATIONS")
        lines.append("  ─" * 20)
        for tc in strategy["technology_considerations"]:
            lines.append(f"    ⚙ {tc['technology']}")
            lines.append(f"      → {tc['impact']}")

    lines.append(f"\n{'═' * 64}")

    (STRAT_DIR / "hunter_strategy_dynamic.txt").write_text("\n".join(lines))

    # Print
    print(f"\n  📊 Evidence: {es['observed_signals']} signals | "
          f"{es['micro_validations']} validations | "
          f"{es['workflows_mapped']} workflows")
    print(f"  🎯 {len(strategy['priority_actions'])} priority actions")
    for action in strategy["priority_actions"][:5]:
        icon = "🔴" if action["priority"] == "CRITICAL" else "🟠" if action["priority"] == "HIGH" else "🟡"
        print(f"    {icon} {action['vuln_type']:20s} {action['confidence']:3d}% — "
              f"{action['reason'][:60]}")
    print(f"  💾 Strategy → {STRAT_DIR}/")


def _tech_impact(tech: str) -> str:
    """Map technology to hunting impact."""
    impacts = {
        "react": "Test for DOM XSS via dangerouslySetInnerHTML",
        "angular": "Test for template injection, bypass Angular sanitizer",
        "vue": "Test for v-html directive XSS",
        "django": "Test for SSTI (Jinja2), ORM injection, debug mode",
        "flask": "Test for SSTI, debug console, secret_key exposure",
        "laravel": "Test for .env exposure, debug mode, mass assignment",
        "express": "Test for prototype pollution, NoSQL injection",
        "spring": "Test for SpEL injection, actuator exposure",
        "rails": "Test for mass assignment, YAML deserialization",
        "php": "Test for type juggling, file inclusion, deserialization",
        "graphql": "Test introspection, batch queries, mutation auth",
        "jwt": "Test algorithm confusion, weak secret, token replay",
        "oauth": "Test redirect URI manipulation, CSRF on authorization",
        "aws": "Test SSRF to metadata, S3 bucket permissions",
        "mysql": "Use MySQL-specific SQLi payloads",
        "postgresql": "Use PostgreSQL-specific payloads, test COPY",
        "mongodb": "Test NoSQL injection with JSON operators",
        "redis": "Test SSRF to Redis (6379), CRLF injection",
        "nginx": "Test path traversal via misconfigured alias",
        "apache": "Test .htaccess upload, mod_cgi abuse",
    }
    tech_lower = tech.lower()
    for key, impact in impacts.items():
        if key in tech_lower:
            return impact
    return f"Research known vulnerabilities for {tech}"


if __name__ == "__main__":
    main()
