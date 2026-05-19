#!/usr/bin/env python3
"""
ReconX Ultra X — Target Understanding Engine
==============================================
The brain of behavioral intelligence.
Understands WHAT the application does, its business logic,
user workflows, auth models, object relationships, and API usage.

Aggregates all behavioral intelligence into a unified understanding.
Generates live hunter guidance from behavioral observations.
"""
import json, os, re, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: target_understanding.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
UNDERSTAND_DIR = OUT / "target_understanding"
GUIDANCE_DIR = OUT / "live_guidance"
UNDERSTAND_DIR.mkdir(parents=True, exist_ok=True)
GUIDANCE_DIR.mkdir(parents=True, exist_ok=True)


def lj(f):
    try:
        return json.loads(Path(f).read_text())
    except:
        return None


def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except:
        return []


class TargetUnderstanding:
    """Unified understanding of the target application."""

    def __init__(self, domain: str):
        self.domain = domain
        self.app_type = "unknown"
        self.business_functions = []
        self.auth_model = {}
        self.data_model = {}
        self.risk_profile = {}
        self.behavioral_insights = []
        self.hunter_guidance = []

    def build(self):
        """Build complete target understanding from all intelligence."""
        print("    🧠 Building target understanding...")

        self._understand_app_type()
        self._understand_business_functions()
        self._understand_auth_model()
        self._understand_data_model()
        self._build_risk_profile()
        self._generate_hunter_guidance()

    def _understand_app_type(self):
        """Classify the application type from observed behavior."""
        dna = lj(OUT / "target_dna/target_dna.json") or {}
        urls = rl(OUT / "urls/all_urls.txt")
        dom = lj(OUT / "dom_intelligence/dom_intelligence.json") or {}

        # Classify from technology + URL patterns
        techs = dna.get("technologies", {})
        backend = dna.get("frameworks", {}).get("backend", [])

        url_text = " ".join(urls[:200]).lower()

        classifications = {
            "e-commerce": len(re.findall(r"cart|shop|product|checkout|order|payment|price", url_text)),
            "saas": len(re.findall(r"dashboard|workspace|team|billing|subscribe|plan|api", url_text)),
            "social": len(re.findall(r"profile|post|feed|follow|message|chat|comment", url_text)),
            "fintech": len(re.findall(r"transaction|transfer|wallet|balance|payment|bank", url_text)),
            "healthcare": len(re.findall(r"patient|medical|health|appointment|doctor|record", url_text)),
            "cms": len(re.findall(r"admin|post|page|blog|editor|content|publish", url_text)),
            "api_platform": len(re.findall(r"/api/|/v\d+/|graphql|rest|swagger|openapi", url_text)),
        }

        if classifications:
            best = max(classifications, key=classifications.get)
            if classifications[best] >= 3:
                self.app_type = best
            else:
                self.app_type = "web_application"

        framework = dom.get("framework", "unknown")
        if framework != "unknown":
            self.app_type += f" ({framework})"

        self.behavioral_insights.append(f"Application type: {self.app_type}")

    def _understand_business_functions(self):
        """Map business functions from workflows and endpoints."""
        wf_data = lj(OUT / "workflow_transitions/workflow_transitions.json") or {}
        wf_evidence = lj(OUT / "workflows/workflow_evidence.json") or {}
        urls = rl(OUT / "urls/all_urls.txt")

        # Map from workflow transitions
        for wf in wf_data.get("workflows", []):
            self.business_functions.append({
                "function": wf["workflow"],
                "states": wf.get("detected_states", []),
                "confidence": wf.get("confidence", 0),
                "source": "workflow_transitions",
            })

        # Map from workflow evidence
        for wf in wf_evidence.get("workflows", []):
            if wf["workflow"] not in [f["function"] for f in self.business_functions]:
                self.business_functions.append({
                    "function": wf["workflow"],
                    "endpoints": wf.get("endpoint_count", 0),
                    "confidence": wf.get("confidence", 0),
                    "source": "workflow_evidence",
                })

        # Detect additional functions from URLs
        function_patterns = {
            "search": r"search|query|find|browse",
            "notification": r"notification|alert|inbox|bell",
            "analytics": r"analytics|stats|metrics|report",
            "integration": r"webhook|integration|connect|sync",
            "user_management": r"user|team|invite|role|permission",
        }
        url_text = " ".join(urls[:300]).lower()
        for func, pattern in function_patterns.items():
            if func not in [f["function"] for f in self.business_functions]:
                matches = len(re.findall(pattern, url_text))
                if matches >= 2:
                    self.business_functions.append({
                        "function": func,
                        "confidence": min(matches * 10, 60),
                        "source": "url_analysis",
                    })

    def _understand_auth_model(self):
        """Understand the authentication model."""
        auth_data = lj(OUT / "auth_intelligence/auth_behavior.json") or {}
        dna = lj(OUT / "target_dna/target_dna.json") or {}
        dom = lj(OUT / "dom_intelligence/dom_intelligence.json") or {}

        auth_systems = dna.get("auth_systems", [])
        auth_findings = auth_data.get("findings", [])

        self.auth_model = {
            "auth_systems": auth_systems,
            "has_oauth": any("oauth" in str(s).lower() for s in auth_systems),
            "has_jwt": any("jwt" in str(s).lower() for s in auth_systems),
            "has_session": any("session" in str(s).lower() or "cookie" in str(s).lower()
                              for s in auth_systems),
            "token_storage": "unknown",
            "auth_findings_count": len(auth_findings),
            "critical_findings": len([f for f in auth_findings if f.get("risk") == "CRITICAL"]),
        }

        # Check DOM intelligence for token storage
        for finding in dom.get("findings", []):
            if finding.get("category") == "state":
                value = finding.get("value", "").lower()
                if re.search(r"token|jwt|auth", value):
                    if "localStorage" in finding.get("type", ""):
                        self.auth_model["token_storage"] = "localStorage"
                        self.behavioral_insights.append(
                            "⚠ JWT/token stored in localStorage — XSS leads to account takeover")
                    elif "sessionStorage" in finding.get("type", ""):
                        self.auth_model["token_storage"] = "sessionStorage"

    def _understand_data_model(self):
        """Understand the data model from objects."""
        obj_data = lj(OUT / "object_relationships/object_relationships.json") or {}

        self.data_model = {
            "total_objects": obj_data.get("total_objects", 0),
            "exposed_objects": obj_data.get("exposed_objects", 0),
            "object_types": obj_data.get("by_type", {}),
            "relationships": obj_data.get("relationship_graph", {}),
        }

        if self.data_model["exposed_objects"] > 0:
            ratio = self.data_model["exposed_objects"] / max(self.data_model["total_objects"], 1)
            self.behavioral_insights.append(
                f"Object exposure: {self.data_model['exposed_objects']}/{self.data_model['total_objects']} "
                f"({ratio:.0%}) objects accessible without auth")

    def _build_risk_profile(self):
        """Build behavioral risk profile."""
        reasoning = lj(OUT / "reasoning/reasoned_findings.json") or {}
        attack_paths = lj(OUT / "attack_paths/justified_attack_paths.json") or {}
        signals = lj(OUT / "observed_signals/observed_signals.json") or {}

        findings = reasoning.get("findings", [])
        paths = attack_paths.get("paths", [])
        signal_list = signals.get("signals", [])

        # Calculate behavioral risk score
        risk_score = 0
        risk_factors = []

        if self.auth_model.get("token_storage") == "localStorage":
            risk_score += 20
            risk_factors.append("Token in localStorage (+20)")

        if self.data_model.get("exposed_objects", 0) > 5:
            risk_score += 15
            risk_factors.append(f"Many exposed objects (+15)")

        critical = len([f for f in findings if f.get("risk") == "CRITICAL"])
        if critical:
            risk_score += critical * 10
            risk_factors.append(f"{critical} critical findings (+{critical * 10})")

        if self.auth_model.get("critical_findings", 0) > 0:
            risk_score += 15
            risk_factors.append(f"Auth issues found (+15)")

        for path in paths:
            if path.get("confidence", 0) >= 40:
                risk_score += 10
                risk_factors.append(f"Attack path: {path['name']} (+10)")

        self.risk_profile = {
            "score": min(risk_score, 100),
            "level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM",
            "factors": risk_factors,
        }

    def _generate_hunter_guidance(self):
        """Generate actionable hunter guidance from behavioral understanding."""
        print("    🎯 Generating hunter guidance...")
        emitted = set()  # Dedup tracker

        # Auth guidance
        if self.auth_model.get("token_storage") == "localStorage":
            self.hunter_guidance.append({
                "priority": "CRITICAL",
                "insight": "JWT stored in localStorage",
                "action": "Find any XSS → steal JWT → impersonate user/admin",
                "evidence": "DOM analysis shows localStorage.setItem('token', ...)",
            })
            emitted.add("jwt_localstorage")

        if self.auth_model.get("has_oauth"):
            self.hunter_guidance.append({
                "priority": "HIGH",
                "insight": "OAuth authentication detected",
                "action": "Test redirect_uri manipulation for token theft",
                "evidence": "OAuth endpoints discovered in recon",
            })

        # Object guidance
        exposed = self.data_model.get("exposed_objects", 0)
        if exposed > 0:
            for obj_type, count in self.data_model.get("object_types", {}).items():
                if count > 0:
                    self.hunter_guidance.append({
                        "priority": "HIGH",
                        "insight": f"{obj_type} objects accessible ({count} detected)",
                        "action": f"Enumerate {obj_type} IDs to access other users' data",
                        "evidence": f"Object relationship analysis: {count} {obj_type} endpoints",
                    })

        # Workflow guidance (deduplicated)
        for func in self.business_functions:
            func_name = func["function"]
            if func_name in ("checkout", "payment") and "payment_flow" not in emitted:
                emitted.add("payment_flow")
                self.hunter_guidance.append({
                    "priority": "CRITICAL",
                    "insight": "Payment/checkout workflow detected",
                    "action": "Test price manipulation between cart and payment step",
                    "evidence": f"Workflow states: {func.get('states', [])}",
                })
            elif func_name == "file_upload" and "file_upload" not in emitted:
                emitted.add("file_upload")
                self.hunter_guidance.append({
                    "priority": "HIGH",
                    "insight": "File upload workflow detected",
                    "action": "Test SVG/HTML upload for stored XSS, SSRF via import URL",
                    "evidence": "Upload endpoints in workflow transition map",
                })
            elif func_name == "password_reset" and "password_reset" not in emitted:
                emitted.add("password_reset")
                self.hunter_guidance.append({
                    "priority": "HIGH",
                    "insight": "Password reset workflow detected",
                    "action": "Test token predictability, host header injection, rate limiting",
                    "evidence": "Password reset endpoints in workflow map",
                })

        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        self.hunter_guidance.sort(
            key=lambda g: priority_order.get(g["priority"], 3))

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "app_type": self.app_type,
            "business_functions": self.business_functions,
            "auth_model": self.auth_model,
            "data_model": self.data_model,
            "risk_profile": self.risk_profile,
            "behavioral_insights": self.behavioral_insights,
            "hunter_guidance": self.hunter_guidance,
        }

    def save(self):
        data = self.to_dict()
        (UNDERSTAND_DIR / "target_understanding.json").write_text(
            json.dumps(data, indent=2))

        # Human-readable understanding
        lines = [
            "═" * 64,
            f"  🧠 TARGET UNDERSTANDING — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
            f"  Application Type: {self.app_type}",
            f"  Risk Level: {self.risk_profile.get('level', 'UNKNOWN')} "
            f"({self.risk_profile.get('score', 0)}%)",
            "",
        ]

        if self.business_functions:
            lines.append("  ── BUSINESS FUNCTIONS ──")
            for f in self.business_functions:
                lines.append(f"    📋 {f['function']} (confidence: {f.get('confidence', 0)}%)")

        lines.append(f"\n  ── AUTH MODEL ──")
        lines.append(f"    Systems: {', '.join(self.auth_model.get('auth_systems', ['unknown']))}")
        lines.append(f"    Token storage: {self.auth_model.get('token_storage', 'unknown')}")
        lines.append(f"    Auth issues: {self.auth_model.get('auth_findings_count', 0)}")

        lines.append(f"\n  ── DATA MODEL ──")
        lines.append(f"    Objects: {self.data_model.get('total_objects', 0)} "
                     f"({self.data_model.get('exposed_objects', 0)} exposed)")
        for obj_type, count in self.data_model.get("object_types", {}).items():
            lines.append(f"      {obj_type}: {count}")

        lines.append(f"\n  ── RISK FACTORS ──")
        for factor in self.risk_profile.get("factors", []):
            lines.append(f"    ⚠ {factor}")

        lines.append(f"\n  ── BEHAVIORAL INSIGHTS ──")
        for insight in self.behavioral_insights:
            lines.append(f"    💡 {insight}")

        (UNDERSTAND_DIR / "target_understanding.txt").write_text("\n".join(lines))

        # Hunter guidance markdown
        guidance_lines = [
            f"# 🎯 Live Hunter Guidance — {self.domain}",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            f"*Risk Level: **{self.risk_profile.get('level', 'UNKNOWN')}** "
            f"({self.risk_profile.get('score', 0)}%)*",
            "",
            "---", "",
        ]

        for i, g in enumerate(self.hunter_guidance, 1):
            icon = "🔴" if g["priority"] == "CRITICAL" else "🟠" if g["priority"] == "HIGH" else "🟡"
            guidance_lines.append(f"## {icon} #{i} {g['insight']}")
            guidance_lines.append(f"**Priority**: {g['priority']}")
            guidance_lines.append(f"**Action**: {g['action']}")
            guidance_lines.append(f"**Evidence**: {g['evidence']}")
            guidance_lines.append("")

        (GUIDANCE_DIR / "live_hunter_guidance.md").write_text("\n".join(guidance_lines))


def main():
    print(f"\n  🧠 Target Understanding Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = TargetUnderstanding(DOMAIN)
    engine.build()
    engine.save()

    rp = engine.risk_profile
    icon = "🔴" if rp["level"] == "CRITICAL" else "🟠" if rp["level"] == "HIGH" else "🟡"
    print(f"\n  {icon} App: {engine.app_type} | Risk: {rp['level']} ({rp['score']}%)")
    print(f"  📋 {len(engine.business_functions)} business functions")
    print(f"  🔐 Auth: {', '.join(engine.auth_model.get('auth_systems', ['unknown']))}")
    print(f"  🎯 {len(engine.hunter_guidance)} hunter guidance items")
    for g in engine.hunter_guidance[:5]:
        gicon = "🔴" if g["priority"] == "CRITICAL" else "🟠"
        print(f"    {gicon} {g['insight']}")
    print(f"  💾 Understanding → {UNDERSTAND_DIR}/")
    print(f"  📝 Guidance → {GUIDANCE_DIR}/")


if __name__ == "__main__":
    main()
