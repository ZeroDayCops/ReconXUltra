#!/usr/bin/env python3
"""
ReconX Ultra X — Attack Path Justification Engine
===================================================
Evidence-backed attack path generation.
Every path step is justified by OBSERVED evidence.
"""
import json, os, sys
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: attack_paths.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
PATHS_DIR = OUT / "attack_paths"
PATHS_DIR.mkdir(parents=True, exist_ok=True)

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None


# Attack path templates — each step requires specific evidence
PATH_TEMPLATES = {
    "upload_stored_xss": {
        "name": "Upload → Stored XSS",
        "severity": "CRITICAL",
        "required_signals": {
            "upload_endpoint": {"weight": 20, "source": "workflow_evidence"},
            "svg_or_html_accepted": {"weight": 25, "source": "micro_validation"},
            "public_file_access": {"weight": 20, "source": "observed_signals"},
            "weak_csp": {"weight": 15, "source": "observed_signals"},
        },
        "steps": [
            "Upload endpoint accepts file submissions",
            "SVG/HTML file types are allowed",
            "Uploaded files are publicly accessible",
            "Inline rendering enables script execution",
            "CSP does not block inline scripts",
        ],
        "conclusion": "Stored XSS via file upload is likely",
        "recommended_tests": [
            "Upload SVG with embedded JavaScript",
            "Upload HTML file with script tag",
            "Test MIME type bypass: image/svg+xml with script",
            "Check if uploaded file renders inline in browser",
        ],
    },
    "oauth_account_takeover": {
        "name": "OAuth Redirect → Account Takeover",
        "severity": "CRITICAL",
        "required_signals": {
            "oauth_endpoint": {"weight": 15, "source": "workflow_evidence"},
            "redirect_parameter": {"weight": 20, "source": "observed_signals"},
            "open_redirect": {"weight": 25, "source": "micro_validation"},
            "token_in_url": {"weight": 20, "source": "observed_signals"},
        },
        "steps": [
            "OAuth authorization endpoint detected",
            "redirect_uri parameter accepts user input",
            "Redirect URI validation is weak",
            "Token/code is passed via URL fragment/query",
        ],
        "conclusion": "OAuth token theft via redirect manipulation is possible",
        "recommended_tests": [
            "Test redirect_uri with external domain",
            "Test path traversal in redirect_uri",
            "Test subdomain takeover + redirect_uri",
            "Capture authorization code via redirect",
        ],
    },
    "api_idor_data_theft": {
        "name": "API IDOR → Data Exfiltration",
        "severity": "HIGH",
        "required_signals": {
            "sequential_ids": {"weight": 20, "source": "micro_validation"},
            "response_variation": {"weight": 20, "source": "observed_signals"},
            "no_auth_check": {"weight": 25, "source": "micro_validation"},
            "api_surface": {"weight": 10, "source": "surface_ranking"},
        },
        "steps": [
            "API uses predictable sequential object IDs",
            "Response content varies per object ID",
            "No ownership/authorization check observed",
            "Objects contain sensitive user data",
        ],
        "conclusion": "Horizontal privilege escalation and data theft are likely",
        "recommended_tests": [
            "Enumerate IDs to access other users' data",
            "Test with unauthenticated request",
            "Test with different user's session token",
            "Automate mass data extraction",
        ],
    },
    "ssrf_cloud_compromise": {
        "name": "SSRF → Cloud Metadata → Credential Theft",
        "severity": "CRITICAL",
        "required_signals": {
            "url_parameter": {"weight": 15, "source": "micro_validation"},
            "server_side_request": {"weight": 25, "source": "micro_validation"},
            "cloud_infrastructure": {"weight": 20, "source": "target_dna"},
            "metadata_accessible": {"weight": 30, "source": "micro_validation"},
        },
        "steps": [
            "URL/webhook parameter accepts user input",
            "Server makes requests on behalf of user",
            "Target runs on cloud infrastructure",
            "Cloud metadata endpoint is reachable",
        ],
        "conclusion": "SSRF to cloud credential theft is possible",
        "recommended_tests": [
            "Request http://169.254.169.254/latest/meta-data/iam/",
            "Test DNS rebinding to bypass SSRF filters",
            "Test URL scheme alternatives: gopher://, dict://",
            "Test internal network scanning via SSRF",
        ],
    },
    "graphql_schema_abuse": {
        "name": "GraphQL Introspection → Mutation Abuse",
        "severity": "HIGH",
        "required_signals": {
            "graphql_endpoint": {"weight": 15, "source": "workflow_evidence"},
            "introspection_enabled": {"weight": 25, "source": "observed_signals"},
            "mutations_exposed": {"weight": 20, "source": "workflow_evidence"},
        },
        "steps": [
            "GraphQL endpoint detected and accessible",
            "Introspection query reveals full schema",
            "Sensitive mutations found (admin, delete, update)",
            "Mutations may bypass authorization",
        ],
        "conclusion": "GraphQL mutation abuse is likely",
        "recommended_tests": [
            "Run introspection and map all mutations",
            "Test admin mutations without admin session",
            "Test batch queries for brute force",
            "Test nested queries for DoS",
        ],
    },
    "ssti_rce": {
        "name": "Export/PDF → SSTI → RCE",
        "severity": "CRITICAL",
        "required_signals": {
            "export_endpoint": {"weight": 15, "source": "workflow_evidence"},
            "template_rendering": {"weight": 20, "source": "micro_validation"},
            "template_expression": {"weight": 30, "source": "micro_validation"},
        },
        "steps": [
            "Export/PDF/report generation endpoint detected",
            "Server uses template engine for rendering",
            "Template expressions are evaluated (e.g., {{7*7}}=49)",
        ],
        "conclusion": "Server-Side Template Injection leading to RCE is possible",
        "recommended_tests": [
            "Test {{7*7}} in template inputs",
            "Test Jinja2: {{config.items()}}",
            "Test Twig: {{_self.env.registerUndefinedFilterCallback('exec')}}",
            "Test Freemarker: ${7*7}",
        ],
    },
}


def build_attack_paths():
    """Build justified attack paths from evidence."""
    # Load evidence
    signals = lj(OUT / "observed_signals/observed_signals.json") or {}
    micro = lj(OUT / "evidence/micro_validation.json") or {}
    workflows = lj(OUT / "workflows/workflow_evidence.json") or {}
    dna = lj(OUT / "target_dna/target_dna.json") or {}
    ranked = lj(OUT / "prioritized/surface_ranking.json") or {}

    signal_list = signals.get("signals", []) if isinstance(signals, dict) else []
    micro_list = micro.get("findings", []) if isinstance(micro, dict) else []
    wf_list = workflows.get("workflows", []) if isinstance(workflows, dict) else []
    ranked_list = ranked.get("ranked_surfaces", []) if isinstance(ranked, dict) else []

    # Build evidence index
    evidence_index = {
        "weak_csp": any("csp" in str(s).lower() and
                        any("weak" in str(o).lower() or "missing" in str(o).lower()
                            for o in s.get("observations", []))
                        for s in signal_list),
        "upload_endpoint": any(w.get("workflow") == "upload" for w in wf_list),
        "oauth_endpoint": any(w.get("workflow") == "authentication" for w in wf_list),
        "graphql_endpoint": any(w.get("workflow") == "graphql" for w in wf_list),
        "export_endpoint": any(w.get("workflow") == "export" for w in wf_list),
        "cloud_infrastructure": bool(dna.get("cloud_providers")),
        "api_surface": any(r.get("category") == "API" for r in ranked_list),
        "introspection_enabled": any(
            "introspection" in str(s.get("observations", "")).lower()
            for s in signal_list),
        "sequential_ids": any(
            m.get("vuln_type") == "IDOR" and m.get("confidence", 0) >= 20
            for m in micro_list),
        "url_parameter": any(
            m.get("vuln_type") == "SSRF" and m.get("confidence", 0) >= 15
            for m in micro_list),
        "reflection": any(
            m.get("vuln_type") == "XSS" and m.get("confidence", 0) >= 20
            for m in micro_list),
    }

    paths = []

    for template_id, template in PATH_TEMPLATES.items():
        # Calculate how much evidence we have for this path
        total_weight = 0
        matched_signals = []
        total_possible = sum(s["weight"] for s in template["required_signals"].values())

        for signal_name, config in template["required_signals"].items():
            if evidence_index.get(signal_name, False):
                total_weight += config["weight"]
                matched_signals.append(signal_name)

        if total_weight < 15 or len(matched_signals) < 2:
            continue  # Need ≥2 evidence points + minimum weight

        confidence = min(int((total_weight / total_possible) * 100), 100)

        path = {
            "id": template_id,
            "name": template["name"],
            "severity": template["severity"],
            "confidence": confidence,
            "matched_evidence": matched_signals,
            "missing_evidence": [s for s in template["required_signals"]
                                 if s not in matched_signals],
            "steps": [],
            "conclusion": template["conclusion"],
            "recommended_tests": template["recommended_tests"],
        }

        # Build steps with observed/predicted status
        for i, step in enumerate(template["steps"]):
            signal_name = list(template["required_signals"].keys())[i] \
                if i < len(template["required_signals"]) else ""
            path["steps"].append({
                "step": step,
                "status": "OBSERVED" if signal_name in matched_signals else "PREDICTED",
            })

        paths.append(path)

    paths.sort(key=lambda p: p["confidence"], reverse=True)
    return paths


def main():
    print(f"\n  🔗 Attack Path Justification Engine — {DOMAIN}")
    print(f"  {'━' * 50}")

    paths = build_attack_paths()

    # Save
    (PATHS_DIR / "justified_attack_paths.json").write_text(json.dumps({
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "paths": paths,
    }, indent=2))

    # Human-readable
    lines = [
        "═" * 64,
        f"  🔗 JUSTIFIED ATTACK PATHS — {DOMAIN}",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "═" * 64, "",
    ]
    for path in paths:
        icon = "🔴" if path["severity"] == "CRITICAL" else "🟠"
        lines.append(f"  {icon} {path['name']}")
        lines.append(f"  Severity: {path['severity']} | Confidence: {path['confidence']}%")
        lines.append("")
        for step in path["steps"]:
            marker = "✔" if step["status"] == "OBSERVED" else "?"
            status = "OBSERVED" if step["status"] == "OBSERVED" else "PREDICTED"
            lines.append(f"    {marker} [{status}] {step['step']}")
        lines.append("")
        lines.append(f"  → {path['conclusion']}")
        lines.append("")
        if path["missing_evidence"]:
            lines.append(f"  Missing Evidence:")
            for me in path["missing_evidence"]:
                lines.append(f"    ⚪ {me}")
            lines.append("")
        lines.append("  Recommended Tests:")
        for t in path["recommended_tests"]:
            lines.append(f"    • {t}")
        lines.append("\n" + "─" * 50)

    (PATHS_DIR / "justified_attack_paths.txt").write_text("\n".join(lines))

    print(f"\n  🔗 {len(paths)} justified attack paths:")
    for p in paths:
        icon = "🔴" if p["severity"] == "CRITICAL" else "🟠"
        obs = len([s for s in p["steps"] if s["status"] == "OBSERVED"])
        total = len(p["steps"])
        print(f"    {icon} {p['name']:40s} {p['confidence']:3d}% | "
              f"{obs}/{total} steps observed")
    print(f"  💾 Paths → {PATHS_DIR}/")


if __name__ == "__main__":
    main()
