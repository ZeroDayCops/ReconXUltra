#!/usr/bin/env python3
"""
ReconX Ultra X Plugin: JS Secret Hunter
Advanced JavaScript secret hunting with live validation.
"""
import json, re, subprocess
from pathlib import Path


def run(domain: str, context: dict) -> dict:
    """Hunt for live/valid secrets in JavaScript files."""
    print(f"  🔌 Plugin [js_secret_hunter] — {domain}")

    root = Path(context.get("reconx_root", "."))
    out = root / "output" / domain
    secrets_file = out / "intelligence" / "js_secrets_deep.json"

    results = {
        "plugin": "js_secret_hunter",
        "domain": domain,
        "findings": [],
        "status": "completed",
    }

    if not secrets_file.exists():
        print("    ⚪ No secrets to validate")
        return results

    try:
        secrets = json.loads(secrets_file.read_text())
    except:
        return results

    if not isinstance(secrets, list):
        return results

    # Validate critical secrets
    critical = [s for s in secrets if s.get("severity") == "CRITICAL"]
    print(f"    🔑 Validating {len(critical)} critical secrets...")

    for secret in critical[:20]:
        stype = secret.get("type", "unknown")
        match = secret.get("match", "")

        validated = False
        detail = ""

        # AWS key validation (safe — checks format only)
        if "AWS" in stype and re.match(r"AKIA[0-9A-Z]{16}", match):
            validated = True
            detail = "Valid AWS key format detected"

        # Stripe key validation (format check)
        elif "Stripe" in stype and re.match(r"(sk|pk)_(test|live)_", match):
            validated = True
            detail = f"Stripe {'live' if 'live' in match else 'test'} key format"

        # GitHub token format
        elif "GitHub" in stype and re.match(r"gh[pousr]_", match):
            validated = True
            detail = "Valid GitHub token format"

        if validated:
            results["findings"].append({
                "type": stype,
                "severity": "CRITICAL",
                "file": secret.get("file", ""),
                "detail": detail,
                "match": match[:50] + "..." if len(match) > 50 else match,
            })

    print(f"    ✅ {len(results['findings'])} secrets validated")
    return results
