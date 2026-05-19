#!/usr/bin/env python3
"""
ReconX Ultra X — Workflow Transition Engine
=============================================
Understands HOW workflows transition within the application.
Maps state machines: login→dashboard, upload→preview, checkout→payment.
Detects transition bypasses, state manipulation, and logic flaws.
"""
import json, os, re, sys, subprocess
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: workflow_transitions.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
WF_DIR = OUT / "workflow_transitions"
WF_DIR.mkdir(parents=True, exist_ok=True)

MAX_WORKERS = int(os.environ.get("RECONX_PROBE_WORKERS", "8"))


def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except:
        return []


def lj(f):
    try:
        return json.loads(Path(f).read_text())
    except:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Workflow State Machine Definitions
# ═══════════════════════════════════════════════════════════════════════════

WORKFLOW_MACHINES = {
    "authentication": {
        "states": ["login_page", "credential_submit", "auth_response", "dashboard"],
        "transitions": [
            {"from": "login_page", "to": "credential_submit", "trigger": "form_submit"},
            {"from": "credential_submit", "to": "auth_response", "trigger": "server_process"},
            {"from": "auth_response", "to": "dashboard", "trigger": "redirect"},
        ],
        "bypass_risks": [
            "Direct dashboard access without login",
            "Session fixation in login response",
            "Missing CSRF on login form",
            "Password reset token predictability",
        ],
        "url_markers": [r"login|signin|auth", r"dashboard|home|account"],
    },
    "registration": {
        "states": ["signup_page", "submit_registration", "verification", "account_created"],
        "transitions": [
            {"from": "signup_page", "to": "submit_registration", "trigger": "form_submit"},
            {"from": "submit_registration", "to": "verification", "trigger": "email_verify"},
            {"from": "verification", "to": "account_created", "trigger": "token_confirm"},
        ],
        "bypass_risks": [
            "Skip email verification",
            "Mass account creation",
            "Registration without rate limiting",
        ],
        "url_markers": [r"signup|register", r"verify|confirm"],
    },
    "file_upload": {
        "states": ["upload_form", "file_submit", "validation", "storage", "access"],
        "transitions": [
            {"from": "upload_form", "to": "file_submit", "trigger": "form_submit"},
            {"from": "file_submit", "to": "validation", "trigger": "server_validate"},
            {"from": "validation", "to": "storage", "trigger": "save_file"},
            {"from": "storage", "to": "access", "trigger": "generate_url"},
        ],
        "bypass_risks": [
            "File type bypass (e.g., SVG, HTML, PHP)",
            "Direct access to uploaded files",
            "Missing antivirus scan",
            "SSRF via file import URL",
        ],
        "url_markers": [r"upload|attach|import", r"media|files|cdn"],
    },
    "checkout": {
        "states": ["cart", "checkout", "payment", "confirmation"],
        "transitions": [
            {"from": "cart", "to": "checkout", "trigger": "proceed"},
            {"from": "checkout", "to": "payment", "trigger": "submit_order"},
            {"from": "payment", "to": "confirmation", "trigger": "payment_success"},
        ],
        "bypass_risks": [
            "Price manipulation between cart and payment",
            "Skip payment step",
            "Race condition on discount application",
            "Order creation without payment",
        ],
        "url_markers": [r"cart|basket", r"checkout|payment", r"confirm|success"],
    },
    "password_reset": {
        "states": ["forgot_page", "email_submit", "token_link", "new_password"],
        "transitions": [
            {"from": "forgot_page", "to": "email_submit", "trigger": "form_submit"},
            {"from": "email_submit", "to": "token_link", "trigger": "email_sent"},
            {"from": "token_link", "to": "new_password", "trigger": "token_valid"},
        ],
        "bypass_risks": [
            "Token brute force",
            "Host header injection in reset link",
            "Token reuse after password change",
            "Rate limiting bypass",
        ],
        "url_markers": [r"forgot|reset|recover", r"token|confirm"],
    },
    "export_report": {
        "states": ["report_config", "generation", "download"],
        "transitions": [
            {"from": "report_config", "to": "generation", "trigger": "submit"},
            {"from": "generation", "to": "download", "trigger": "complete"},
        ],
        "bypass_risks": [
            "SSRF via PDF generator",
            "SSTI in report template",
            "Information disclosure in exports",
            "Path traversal in download",
        ],
        "url_markers": [r"report|export|generate", r"download|pdf"],
    },
    "oauth_flow": {
        "states": ["authorize", "consent", "callback", "token_exchange"],
        "transitions": [
            {"from": "authorize", "to": "consent", "trigger": "redirect"},
            {"from": "consent", "to": "callback", "trigger": "approve"},
            {"from": "callback", "to": "token_exchange", "trigger": "code_received"},
        ],
        "bypass_risks": [
            "Open redirect via redirect_uri",
            "CSRF on authorization",
            "Token leakage in URL",
            "Code reuse attack",
        ],
        "url_markers": [r"oauth|authorize", r"callback|redirect"],
    },
}


class WorkflowTransition:
    """A detected workflow with transition evidence."""

    def __init__(self, workflow_type: str):
        self.workflow_type = workflow_type
        self.detected_states = []
        self.detected_transitions = []
        self.endpoints = {}       # state_name -> url
        self.observations = []
        self.bypass_risks = []
        self.confidence = 0
        self.confidence_sources = []

    def add_state(self, state: str, url: str):
        self.detected_states.append(state)
        self.endpoints[state] = url

    def add_transition(self, from_state: str, to_state: str, evidence: str):
        self.detected_transitions.append({
            "from": from_state, "to": to_state, "evidence": evidence,
        })

    def observe(self, what: str, weight: int = 10):
        self.observations.append(what)
        self.confidence += weight
        self.confidence_sources.append(f"+{weight} {what}")

    def to_dict(self) -> dict:
        config = WORKFLOW_MACHINES.get(self.workflow_type, {})
        total_states = len(config.get("states", []))
        coverage = len(self.detected_states) / max(total_states, 1)

        return {
            "workflow": self.workflow_type,
            "detected_states": self.detected_states,
            "total_states": total_states,
            "coverage": round(coverage, 2),
            "transitions": self.detected_transitions,
            "endpoints": self.endpoints,
            "observations": self.observations,
            "bypass_risks": self.bypass_risks,
            "confidence": min(self.confidence, 100),
            "confidence_sources": self.confidence_sources,
        }


def _probe_status(url: str) -> int:
    try:
        r = subprocess.run(
            ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}",
             "-m", "5", url],
            capture_output=True, text=True, timeout=7)
        return int(r.stdout.strip()) if r.returncode == 0 else 0
    except:
        return 0


class WorkflowTransitionEngine:
    """Maps workflow transitions from observed endpoints."""

    def __init__(self, domain: str):
        self.domain = domain
        self.workflows = []

    def detect_workflows(self, urls: list):
        """Detect workflow state machines from URL patterns."""
        print("    🔄 Detecting workflow transitions...")

        for wf_type, config in WORKFLOW_MACHINES.items():
            wf = WorkflowTransition(wf_type)
            wf.bypass_risks = config["bypass_risks"]

            # Match URL markers to states
            markers = config["url_markers"]
            for i, marker in enumerate(markers):
                matched_urls = [u for u in urls if re.search(marker, u, re.I)]
                if matched_urls:
                    state_name = config["states"][min(i, len(config["states"]) - 1)]
                    wf.add_state(state_name, matched_urls[0])
                    wf.observe(f"State '{state_name}' detected: {len(matched_urls)} endpoints", 10)

            if len(wf.detected_states) >= 2:
                # We have at least 2 states — detect transitions
                for i in range(len(wf.detected_states) - 1):
                    from_state = wf.detected_states[i]
                    to_state = wf.detected_states[i + 1]
                    wf.add_transition(from_state, to_state,
                                      f"Sequential endpoint detection")
                    wf.observe(f"Transition: {from_state} → {to_state}", 5)

                self.workflows.append(wf)
            elif wf.detected_states:
                wf.observe("Partial workflow — only 1 state detected", 3)
                self.workflows.append(wf)

    def probe_transition_bypasses(self):
        """Check if later states are accessible without earlier states."""
        print("    🔓 Probing for transition bypasses...")

        for wf in self.workflows:
            if len(wf.endpoints) < 2:
                continue

            # Get the last state endpoint — can we reach it directly?
            states_list = list(wf.endpoints.items())
            if len(states_list) >= 2:
                first_state, first_url = states_list[0]
                last_state, last_url = states_list[-1]

                last_status = _probe_status(last_url)
                if last_status == 200:
                    wf.observe(f"Final state '{last_state}' directly accessible (200)", 20)
                    wf.observe(f"Transition bypass risk: skip {first_state}", 15)
                elif last_status in (301, 302):
                    wf.observe(f"Final state redirects (transition enforced)", 5)
                elif last_status == 403:
                    wf.observe(f"Final state protected (403)", 3)

    def analyze_redirect_chains(self, urls: list):
        """Detect redirect-based transitions."""
        print("    🔀 Analyzing redirect chains...")

        auth_urls = [u for u in urls if re.search(
            r"login|signin|oauth|authorize|callback", u, re.I)][:10]

        for url in auth_urls:
            try:
                r = subprocess.run(
                    ["curl", "-sk", "-L", "-o", "/dev/null",
                     "-w", "%{url_effective}\n%{num_redirects}\n%{http_code}",
                     "-m", "8", url],
                    capture_output=True, text=True, timeout=10)
                if r.returncode == 0:
                    parts = r.stdout.strip().split("\n")
                    if len(parts) >= 3:
                        final_url = parts[0]
                        num_redirects = int(parts[1])
                        final_status = int(parts[2])

                        if num_redirects > 0:
                            for wf in self.workflows:
                                if wf.workflow_type in ("authentication", "oauth_flow"):
                                    wf.observe(
                                        f"Redirect chain: {num_redirects} hops → {urlparse(final_url).path}",
                                        8)
            except Exception:
                pass

    def run(self) -> list:
        urls = rl(OUT / "urls/all_urls.txt")
        if not urls:
            print("  ⚪ No URLs for workflow analysis")
            return []

        self.detect_workflows(urls)
        self.probe_transition_bypasses()
        self.analyze_redirect_chains(urls)

        self.workflows.sort(key=lambda w: w.confidence, reverse=True)
        return self.workflows

    def save(self):
        data = {
            "domain": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_workflows": len(self.workflows),
            "workflows": [w.to_dict() for w in self.workflows],
        }
        (WF_DIR / "workflow_transitions.json").write_text(json.dumps(data, indent=2))

        lines = [
            "═" * 64,
            f"  🔄 WORKFLOW TRANSITION MAP — {self.domain}",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "═" * 64, "",
        ]
        for wf in self.workflows:
            d = wf.to_dict()
            coverage_bar = "█" * int(d["coverage"] * 10) + "░" * (10 - int(d["coverage"] * 10))
            lines.append(f"  🔄 {d['workflow'].upper()}")
            lines.append(f"  Coverage: [{coverage_bar}] {d['coverage']:.0%} ({len(d['detected_states'])}/{d['total_states']} states)")
            lines.append(f"  Confidence: {d['confidence']}%")
            lines.append("")
            lines.append("  States:")
            for state in d["detected_states"]:
                url = d["endpoints"].get(state, "")
                lines.append(f"    ✔ {state}: {url[:60]}")
            if d["transitions"]:
                lines.append("  Transitions:")
                for t in d["transitions"]:
                    lines.append(f"    {t['from']} → {t['to']}")
            lines.append("")
            lines.append("  Observations:")
            for o in d["observations"]:
                lines.append(f"    ✔ {o}")
            lines.append("  Bypass Risks:")
            for r in d["bypass_risks"][:3]:
                lines.append(f"    ⚠ {r}")
            lines.append("\n" + "─" * 50)

        (WF_DIR / "workflow_transitions.txt").write_text("\n".join(lines))


def main():
    print(f"\n  🔄 Workflow Transition Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    engine = WorkflowTransitionEngine(DOMAIN)
    workflows = engine.run()
    engine.save()

    print(f"\n  📊 {len(workflows)} workflow transitions mapped:")
    for wf in workflows:
        d = wf.to_dict()
        print(f"    🔄 {d['workflow']:20s} {d['confidence']:3d}% | "
              f"{len(d['detected_states'])}/{d['total_states']} states | "
              f"{len(d['transitions'])} transitions")
    print(f"  💾 Transitions → {WF_DIR}/")


if __name__ == "__main__":
    main()
