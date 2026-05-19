#!/usr/bin/env python3
"""
ReconX Ultra X — Reasoning Trace Engine
=========================================
Generates full reasoning chains showing the AI's "thought process"
from initial observation to final prediction.

Produces human-readable reasoning traces that explain
HOW each conclusion was reached.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: reasoning_trace.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
TRACE_DIR = OUT / "reasoning"
TRACE_DIR.mkdir(parents=True, exist_ok=True)

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


class ReasoningTrace:
    """A complete reasoning chain."""
    def __init__(self, finding_type: str, target: str):
        self.finding_type = finding_type
        self.target = target
        self.steps = []
        self.conclusion = ""
        self.confidence = 0

    def think(self, step: str, level: str = "observe"):
        """Add a reasoning step."""
        icons = {
            "observe": "👁️ OBSERVE",
            "analyze": "🔍 ANALYZE",
            "correlate": "🔗 CORRELATE",
            "reason": "🧠 REASON",
            "predict": "💡 PREDICT",
            "conclude": "✅ CONCLUDE",
        }
        self.steps.append({
            "phase": icons.get(level, level),
            "thought": step,
            "timestamp": datetime.now().isoformat(),
        })

    def set_conclusion(self, conclusion: str, confidence: int):
        self.conclusion = conclusion
        self.confidence = confidence

    def to_dict(self) -> dict:
        return {
            "finding_type": self.finding_type,
            "target": self.target,
            "steps": self.steps,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
        }

    def render(self) -> str:
        """Render human-readable trace."""
        lines = [
            f"  ┌─ Reasoning Trace: {self.finding_type}",
            f"  │  Target: {self.target[:80]}",
            "  │",
        ]
        for i, step in enumerate(self.steps):
            connector = "├" if i < len(self.steps) - 1 else "└"
            lines.append(f"  {connector}─ {step['phase']}: {step['thought']}")

        lines.append(f"  ")
        lines.append(f"  → Conclusion: {self.conclusion}")
        lines.append(f"  → Confidence: {self.confidence}%")
        return "\n".join(lines)


def build_traces():
    """Build reasoning traces from all intelligence data."""
    findings = lj(OUT / "reasoning/reasoned_findings.json") or {}
    finding_list = findings.get("findings", []) if isinstance(findings, dict) else []

    signals = lj(OUT / "observed_signals/observed_signals.json") or {}
    signal_list = signals.get("signals", []) if isinstance(signals, dict) else []
    dna = lj(OUT / "target_dna/target_dna.json") or {}

    traces = []

    for finding in finding_list:
        vt = finding.get("vuln_type", "Unknown")
        urls = finding.get("urls", [])
        target = urls[0] if urls else DOMAIN

        trace = ReasoningTrace(vt, target)

        # Phase 1: Observe
        for obs in finding.get("observed", []):
            trace.think(obs, "observe")

        # Phase 2: Analyze evidence
        for ev in finding.get("evidence", []):
            trace.think(f"Evidence: {ev}", "analyze")

        # Phase 3: Correlate with DNA
        techs = dna.get("technologies", {})
        if techs:
            relevant_techs = []
            if vt == "XSS" and any(t in str(techs).lower() for t in ["react", "angular", "vue"]):
                relevant_techs.append("Frontend framework may sanitize client-side")
            if vt == "SQLi" and any(t in str(techs).lower() for t in ["mysql", "postgres", "mongo"]):
                relevant_techs.append("Database technology identified — affects payload syntax")
            if vt == "SSRF" and dna.get("cloud_providers"):
                relevant_techs.append(f"Cloud: {', '.join(dna['cloud_providers'])} — metadata endpoint is a target")

            for rt in relevant_techs:
                trace.think(rt, "correlate")

        # Phase 4: Correlate with signals
        relevant_signals = [s for s in signal_list
                            if s.get("signal_type") in _signal_relevance(vt)]
        for sig in relevant_signals[:3]:
            for obs in sig.get("observations", [])[:2]:
                trace.think(f"Signal: {obs.get('what', '')}: {obs.get('detail', '')[:60]}", "correlate")

        # Phase 5: Reason
        reasoning_trace = finding.get("reasoning_trace", [])
        for step in reasoning_trace:
            trace.think(step, "reason")

        # Phase 6: Attack path
        path = finding.get("attack_path", [])
        if path:
            trace.think(f"Attack path: {' → '.join(path)}", "predict")

        # Conclude
        risk = finding.get("risk", "MEDIUM")
        conf = finding.get("confidence", 0)
        trace.set_conclusion(
            finding.get("reasoning", f"{vt} is {'likely' if conf >= 50 else 'possible'}"),
            conf)

        traces.append(trace)

    return traces


def _signal_relevance(vuln_type: str) -> list:
    """Map vuln type to relevant signal types."""
    return {
        "XSS": ["security_headers", "error_leakage"],
        "SQLi": ["error_leakage", "status_behavior"],
        "SSRF": ["status_behavior", "security_headers"],
        "IDOR": ["response_delta", "status_behavior"],
        "Secret Exposure": ["jwt_exposure"],
        "Business Logic": ["upload_behavior", "graphql_behavior"],
    }.get(vuln_type, [])


def main():
    print(f"\n  📜 Reasoning Trace Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    traces = build_traces()

    if not traces:
        print("  ⚪ No findings to trace. Run reasoning_engine.py first.")
        return

    # Save JSON
    (TRACE_DIR / "reasoning_traces.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "traces": [t.to_dict() for t in traces],
    }, indent=2))

    # Human-readable
    lines = [
        "═" * 64,
        f"  📜 REASONING TRACES — {DOMAIN}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 64, "",
    ]
    for trace in traces:
        lines.append(trace.render())
        lines.append("\n" + "─" * 50 + "\n")

    (TRACE_DIR / "reasoning_traces.txt").write_text("\n".join(lines))

    # Print
    for trace in traces:
        print(trace.render())
        print()

    print(f"  💾 Traces → {TRACE_DIR}/")


if __name__ == "__main__":
    main()
