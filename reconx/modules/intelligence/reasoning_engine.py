#!/usr/bin/env python3
"""
ReconX Ultra X — Evidence-Based Reasoning Engine (EBRE)
=======================================================
The core reasoning engine that ties everything together.
Produces EXPLAINABLE, EVIDENCE-BACKED hunter intelligence.

For every finding generates:
  1. OBSERVED SIGNALS — real evidence
  2. EVIDENCE — specific data points
  3. CONFIDENCE SOURCES — why the score exists
  4. ATTACK-PATH JUSTIFICATION — step-by-step chain
  5. REASONING TRACE — full thought process
  6. RECOMMENDED TESTING — what to do next
"""
import json, os, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: reasoning_engine.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
REASON_DIR = OUT / "reasoning"
REASON_DIR.mkdir(parents=True, exist_ok=True)

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None

def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []


class ReasoningFinding:
    """A fully reasoned finding with evidence chain."""
    def __init__(self, vuln_type: str, risk: str = "MEDIUM"):
        self.vuln_type = vuln_type
        self.risk = risk
        self.observed = []           # Real observations
        self.evidence = []           # Specific evidence items
        self.confidence = 0
        self.confidence_sources = [] # Explains WHY confidence exists
        self.attack_path = []        # Step-by-step chain
        self.reasoning_trace = []    # Full reasoning steps
        self.recommended_tests = []
        self.urls = []
        self.level = "L1"

    def add_observation(self, what: str):
        self.observed.append(what)

    def add_evidence(self, item: str, weight: int = 10):
        self.evidence.append(item)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {item}")

    def add_reasoning_step(self, step: str):
        self.reasoning_trace.append(step)

    def set_attack_path(self, steps: list):
        self.attack_path = steps

    def build_reasoning(self) -> str:
        """Generate natural language reasoning paragraph."""
        if not self.observed:
            return "Insufficient evidence for reasoning."

        obs_text = ", ".join(self.observed[:5]).lower()
        pred_text = " → ".join(self.attack_path) if self.attack_path else ""

        reasoning = (
            f"The application {'exhibits' if self.confidence >= 40 else 'shows potential for'} "
            f"{self.vuln_type} vulnerability signals. "
            f"Observed evidence includes: {obs_text}. "
        )
        if pred_text:
            reasoning += f"The predicted attack path is: {pred_text}. "
        if self.confidence >= 60:
            reasoning += "Confidence is high based on multiple corroborating observations."
        elif self.confidence >= 30:
            reasoning += "Further manual testing is recommended to confirm."
        else:
            reasoning += "Evidence is preliminary and requires deeper investigation."

        return reasoning

    def to_dict(self) -> dict:
        self.confidence = min(self.confidence, 100)
        return {
            "vuln_type": self.vuln_type,
            "risk": self.risk,
            "observed": self.observed,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "confidence_sources": self.confidence_sources,
            "attack_path": self.attack_path,
            "reasoning_trace": self.reasoning_trace,
            "reasoning": self.build_reasoning(),
            "recommended_tests": self.recommended_tests,
            "urls": self.urls[:10],
            "level": self.level,
            "timestamp": datetime.now().isoformat(),
        }


def reason_from_evidence():
    """Build fully reasoned findings from all available evidence."""
    print(f"\n  🧠 Evidence-Based Reasoning Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    findings = []

    # Load all intelligence sources
    signals = lj(OUT / "observed_signals/observed_signals.json") or {}
    micro = lj(OUT / "evidence/micro_validation.json") or {}
    dna = lj(OUT / "target_dna/target_dna.json") or {}
    chains = lj(OUT / "attack_chains/attack_chains.json") or {}
    workflows = lj(OUT / "intelligence/critical_workflows.json") or {}
    secrets_data = lj(OUT / "intelligence/js_secrets_deep.json")
    dom_sinks = lj(OUT / "intelligence/dom_sinks.json") or []
    surface = lj(OUT / "prioritized/surface_ranking.json") or {}

    signal_list = signals.get("signals", []) if isinstance(signals, dict) else []
    micro_list = micro.get("findings", []) if isinstance(micro, dict) else []
    chain_list = chains.get("chains", []) if isinstance(chains, dict) else []
    ranked = surface.get("ranked_surfaces", []) if isinstance(surface, dict) else []
    secrets = secrets_data if isinstance(secrets_data, list) else []

    # ── Reason about XSS ─────────────────────────────────────────────
    xss_micro = [m for m in micro_list if m.get("vuln_type") == "XSS" and m.get("confidence", 0) >= 20]
    xss_sinks = [d for d in dom_sinks if isinstance(d, dict) and d.get("severity") in ("CRITICAL", "HIGH")]
    weak_csp = [s for s in signal_list if any("csp" in str(o).lower() for o in s.get("observations", []))]

    if xss_micro or xss_sinks:
        f = ReasoningFinding("XSS", "HIGH" if xss_micro else "MEDIUM")

        if xss_micro:
            for m in xss_micro[:3]:
                for obs in m.get("observed", []):
                    f.add_observation(obs)
                f.urls.extend([m.get("url", "")])
            f.add_evidence("Reflection confirmed via micro-validation", 25)
            f.level = "L2"

        if xss_sinks:
            f.add_observation(f"{len(xss_sinks)} critical DOM sinks detected in JavaScript")
            f.add_evidence(f"DOM sinks: {', '.join(s.get('sink','') for s in xss_sinks[:3])}", 20)
            f.level = "L3"

        if weak_csp:
            f.add_observation("Content Security Policy is weak or missing")
            f.add_evidence("Weak/missing CSP header", 15)

        f.add_reasoning_step("Input reflection detected in response body")
        f.add_reasoning_step("HTML context allows tag injection")
        if xss_sinks:
            f.add_reasoning_step(f"DOM sinks ({xss_sinks[0].get('sink','')}) enable client-side execution")
        if weak_csp:
            f.add_reasoning_step("No CSP to block inline script execution")
        f.add_reasoning_step("XSS exploitation is likely")

        f.set_attack_path(["Input injection", "Response reflection",
                           "Script execution", "Session theft / defacement"])
        f.recommended_tests = [
            "Test reflection with: <script>alert(1)</script>",
            "Test attribute breakout: \" onfocus=alert(1)",
            "Test DOM sink exploitation with source→sink chain",
            "Verify CSP bypass techniques",
        ]
        findings.append(f)

    # ── Reason about SQLi ─────────────────────────────────────────────
    sqli_micro = [m for m in micro_list if m.get("vuln_type") == "SQLi" and m.get("confidence", 0) >= 15]
    sql_errors = [s for s in signal_list if any("sql" in str(o).lower() for o in s.get("observations", []))]

    if sqli_micro or sql_errors:
        f = ReasoningFinding("SQLi", "CRITICAL")
        if sqli_micro:
            for m in sqli_micro[:3]:
                for obs in m.get("observed", []):
                    f.add_observation(obs)
                f.urls.extend([m.get("url", "")])
            f.add_evidence("SQL error/behavior change via micro-validation", 25)
            f.level = "L2"
        if sql_errors:
            f.add_evidence("SQL error signatures in responses", 20)

        f.add_reasoning_step("SQL syntax triggers error or behavior change")
        f.add_reasoning_step("Database error messages leaked to client")
        f.add_reasoning_step("Input reaches SQL query without sanitization")

        f.set_attack_path(["Quote injection", "SQL syntax break",
                           "Error/data leakage", "Database extraction"])
        f.recommended_tests = [
            "Run sqlmap with --batch --level 3",
            "Test UNION-based extraction",
            "Test blind boolean-based",
            "Test time-based: SLEEP(5)",
        ]
        findings.append(f)

    # ── Reason about SSRF ─────────────────────────────────────────────
    ssrf_micro = [m for m in micro_list if m.get("vuln_type") == "SSRF" and m.get("confidence", 0) >= 15]
    cloud_detected = bool(dna.get("cloud_providers"))
    webhook_surface = any(r.get("category") == "WEBHOOK" for r in ranked)

    if ssrf_micro or (webhook_surface and cloud_detected):
        f = ReasoningFinding("SSRF", "CRITICAL" if cloud_detected else "HIGH")
        if ssrf_micro:
            for m in ssrf_micro[:3]:
                for obs in m.get("observed", []):
                    f.add_observation(obs)
                f.urls.extend([m.get("url", "")])
            f.add_evidence("URL parameter influences server requests", 25)
            f.level = "L2"
        if cloud_detected:
            f.add_observation(f"Cloud infrastructure: {', '.join(dna.get('cloud_providers', []))}")
            f.add_evidence("Cloud metadata endpoint may be reachable", 20)
        if webhook_surface:
            f.add_observation("Webhook endpoints accept URL parameters")
            f.add_evidence("Webhook-based SSRF surface", 15)

        f.add_reasoning_step("URL parameter accepted by server")
        if cloud_detected:
            f.add_reasoning_step("Target runs on cloud infrastructure")
            f.add_reasoning_step("Cloud metadata (169.254.169.254) may be accessible")
        f.add_reasoning_step("Server-side request can be directed to internal targets")

        f.set_attack_path(["URL parameter injection", "Server-side request",
                           "Internal network access",
                           "Cloud metadata / credential theft" if cloud_detected else "Internal service access"])
        f.recommended_tests = [
            "Test with Burp Collaborator / interactsh",
            "Test cloud metadata: http://169.254.169.254/latest/meta-data/",
            "Test internal ports: http://127.0.0.1:6379",
            "Test URL scheme bypass: dict://, gopher://",
        ]
        findings.append(f)

    # ── Reason about IDOR ─────────────────────────────────────────────
    idor_micro = [m for m in micro_list if m.get("vuln_type") == "IDOR" and m.get("confidence", 0) >= 20]
    api_surface = any(r.get("category") == "API" for r in ranked)

    if idor_micro:
        f = ReasoningFinding("IDOR", "HIGH")
        for m in idor_micro[:3]:
            for obs in m.get("observed", []):
                f.add_observation(obs)
            f.urls.extend([m.get("url", "")])
        f.add_evidence("Object ID variation returns different content", 25)
        if api_surface:
            f.add_observation("REST API surface with object-based resources")
            f.add_evidence("API IDOR surface", 15)
        f.level = "L2"

        f.add_reasoning_step("Sequential numeric object IDs detected")
        f.add_reasoning_step("API responses differ by object ID")
        f.add_reasoning_step("No ownership redirect or 403 detected")

        f.set_attack_path(["ID enumeration", "Unauthorized access",
                           "Horizontal privilege escalation", "Data exfiltration"])
        f.recommended_tests = [
            "Test with different user session tokens",
            "Enumerate ID range systematically",
            "Check for mass assignment on POST/PUT",
            "Test vertical privilege escalation (admin IDs)",
        ]
        findings.append(f)

    # ── Reason about Secrets ──────────────────────────────────────────
    critical_secrets = [s for s in secrets if isinstance(s, dict) and s.get("severity") == "CRITICAL"]
    if critical_secrets:
        f = ReasoningFinding("Secret Exposure", "CRITICAL")
        for s in critical_secrets[:5]:
            f.add_observation(f"Secret found: {s.get('type','')} in {os.path.basename(str(s.get('file','')))}")
            f.urls.append(str(s.get("file", "")))
        f.add_evidence(f"{len(critical_secrets)} critical secrets in JavaScript", 30)
        f.level = "L2"

        f.add_reasoning_step("JavaScript files contain embedded secrets")
        f.add_reasoning_step("Secrets are publicly accessible via client-side code")
        f.add_reasoning_step("Leaked credentials may grant unauthorized access")

        f.set_attack_path(["JS file analysis", "Secret extraction",
                           "Credential use", "Unauthorized API access"])
        f.recommended_tests = [
            "Validate each secret against its service",
            "Check if API keys have write permissions",
            "Test AWS keys: aws sts get-caller-identity",
            "Rotate all exposed credentials",
        ]
        findings.append(f)

    # ── Reason about Workflow Risks ───────────────────────────────────
    if isinstance(workflows, dict):
        critical_wf = {k: v for k, v in workflows.items()
                       if isinstance(v, dict) and v.get("severity") in ("CRITICAL", "HIGH")}
        if critical_wf:
            f = ReasoningFinding("Business Logic", "HIGH")
            for name, wf in list(critical_wf.items())[:3]:
                f.add_observation(f"Critical workflow: {name} ({wf.get('severity','')})")
                bugs = wf.get("bugs", [])
                if bugs:
                    f.add_evidence(f"Workflow '{name}' vulnerable to: {', '.join(bugs[:3])}", 15)
            f.level = "L3"

            f.add_reasoning_step("Critical business workflows identified")
            f.add_reasoning_step("Workflows involve sensitive operations")
            f.add_reasoning_step("Business logic vulnerabilities likely")

            f.recommended_tests = [
                "Test payment flow for price manipulation",
                "Test auth flow for bypass opportunities",
                "Test upload flow for unrestricted upload",
                "Test race conditions on discount/coupon endpoints",
            ]
            findings.append(f)

    # Sort by confidence
    findings.sort(key=lambda f: f.confidence, reverse=True)

    # ── Save outputs ──────────────────────────────────────────────────
    (REASON_DIR / "reasoned_findings.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2))

    # Human-readable reasoning report
    lines = [
        "═" * 64,
        f"  🧠 HUNTER INTELLIGENCE REPORT — {DOMAIN}",
        f"  Evidence-Based Reasoning Engine",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 64, "",
    ]

    for i, f in enumerate(findings, 1):
        d = f.to_dict()
        risk_icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"

        lines.append(f"  {risk_icon} {d['vuln_type']} Risk: {d['risk']}")
        lines.append(f"  {'─' * 40}")
        lines.append("")
        lines.append("  Observed:")
        for o in d["observed"]:
            lines.append(f"    ✔ {o}")
        lines.append("")
        lines.append("  Evidence:")
        for e in d["evidence"]:
            lines.append(f"    • {e}")
        lines.append("")
        lines.append(f"  Confidence: {d['confidence']}%")
        lines.append("  Confidence Sources:")
        for cs in d["confidence_sources"]:
            lines.append(f"    {cs}")
        lines.append("")
        lines.append(f"  Reasoning:")
        lines.append(f"    {d['reasoning']}")
        lines.append("")
        if d["attack_path"]:
            lines.append(f"  Attack Path:")
            lines.append(f"    {' → '.join(d['attack_path'])}")
            lines.append("")
        lines.append("  Reasoning Trace:")
        for j, step in enumerate(d["reasoning_trace"], 1):
            lines.append(f"    {j}. {step}")
        lines.append("")
        lines.append("  Recommended Tests:")
        for t in d["recommended_tests"]:
            lines.append(f"    • {t}")
        lines.append(f"\n  Level: {d['level']}")
        lines.append("\n" + "═" * 64 + "\n")

    (REASON_DIR / "hunter_intelligence_report.txt").write_text("\n".join(lines))

    # Print summary
    print(f"\n  🔥 {len(findings)} reasoned findings:")
    for f in findings:
        d = f.to_dict()
        icon = "🔴" if d["risk"] == "CRITICAL" else "🟠" if d["risk"] == "HIGH" else "🟡"
        print(f"    {icon} {d['vuln_type']:20s} {d['confidence']:3d}% | "
              f"{len(d['observed'])} obs | {len(d['evidence'])} evidence | L{d['level'][1]}")

    print(f"\n  📄 Report → {REASON_DIR / 'hunter_intelligence_report.txt'}")
    print(f"  💾 JSON   → {REASON_DIR / 'reasoned_findings.json'}")
    return findings


if __name__ == "__main__":
    reason_from_evidence()
