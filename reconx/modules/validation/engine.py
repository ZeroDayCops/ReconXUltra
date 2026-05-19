#!/usr/bin/env python3
"""ReconX Ultra X — Autonomous Validation Engine
Orchestrates all validation pipelines and generates confidence-scored findings."""
import json, subprocess, sys, os, time, hashlib
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: engine.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
VAL = OUT / "validated"
SS = OUT / "screenshots"
POCS = OUT / "pocs"
MOD = Path(__file__).parent

for d in [VAL, SS/"xss", SS/"sqli", SS/"ssrf", SS/"findings", POCS/"xss_pocs", POCS/"sqli_pocs"]:
    d.mkdir(parents=True, exist_ok=True)

# ── Confidence Scoring ─────────────────────────────────────────────────────
CONFIDENCE = {"POSSIBLE": (1,25), "LIKELY": (26,50), "VALIDATED": (51,75), "CONFIRMED": (76,100)}

def score_finding(base_score, validations):
    """Score a finding based on validation results."""
    s = base_score
    if validations.get("tool_confirmed"): s += 30
    if validations.get("reflection_found"): s += 15
    if validations.get("manual_confirmed"): s += 25
    if validations.get("browser_confirmed"): s += 25
    if validations.get("callback_received"): s += 35
    if validations.get("error_triggered"): s += 20
    if validations.get("time_delay_confirmed"): s += 25
    return min(s, 100)

def confidence_label(score):
    for label, (lo, hi) in CONFIDENCE.items():
        if lo <= score <= hi: return label
    return "POSSIBLE"

# ── Load Candidates ────────────────────────────────────────────────────────
def load_candidates(name, limit=25):
    f = OUT / "intelligence" / f"{name}_candidates.txt"
    if not f.exists(): return []
    return [l.strip() for l in f.read_text().splitlines() if l.strip()][:limit]

# ── Run Validator Script ───────────────────────────────────────────────────
def run_validator(script, domain, candidates_file, output_file, timeout=300):
    """Run a shell validator script."""
    script_path = MOD / script
    if not script_path.exists():
        print(f"  ⚠️  Validator not found: {script}")
        return []
    try:
        result = subprocess.run(
            ["bash", str(script_path), domain, str(candidates_file), str(output_file)],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "RECONX_ROOT": str(ROOT), "OUT_DIR": str(OUT)}
        )
        if output_file.exists():
            try: return json.loads(output_file.read_text())
            except: return []
    except subprocess.TimeoutExpired:
        print(f"  ⏰ Validator timeout: {script}")
    except Exception as e:
        print(f"  ❌ Validator error: {script}: {e}")
    return []

# ── Telegram Alert for Critical Findings ───────────────────────────────────
def send_critical_alert(finding):
    """Send Telegram alert for HIGH/CRITICAL validated findings."""
    alert_script = ROOT / "core" / "alert_engine.sh"
    if alert_script.exists():
        try:
            subprocess.run(["bash", str(alert_script), json.dumps(finding)],
                         timeout=10, capture_output=True)
        except: pass

# ── XSS Validation Pipeline ───────────────────────────────────────────────
def validate_xss(domain):
    print("  ⚡ XSS Deep Validation Pipeline")
    candidates = load_candidates("xss")
    if not candidates:
        print("    ⚪ No XSS candidates")
        return []

    # Write candidates to temp file
    tmp = VAL / "xss_input.txt"
    tmp.write_text("\n".join(candidates))

    validated = run_validator("xss_validator.sh", domain, tmp, VAL/"xss_raw.json", timeout=180)

    results = []
    for v in (validated if isinstance(validated, list) else []):
        base = 10  # GF pattern match baseline
        vals = {
            "reflection_found": v.get("reflected", False),
            "tool_confirmed": v.get("dalfox_confirmed", False) or v.get("xsstrike_confirmed", False),
            "browser_confirmed": v.get("browser_executed", False),
            "manual_confirmed": v.get("manual_confirmed", False),
        }
        sc = score_finding(base, vals)

        # Context-aware bonuses
        context = v.get("context", "")
        encoding = v.get("encoding", "")
        if v.get("manual_confirmed"):
            sc = max(sc, 60)  # Manual payload confirmed = at least VALIDATED
        if context in ("html", "attribute") and encoding == "decoded":
            sc += 10  # Unencoded reflection in dangerous context
        if v.get("dalfox_confirmed") and v.get("manual_confirmed"):
            sc = max(sc, 80)  # Multi-tool agreement = CONFIRMED

        sc = min(sc, 100)
        results.append({
            "type": "XSS",
            "url": v.get("url", ""),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "score": sc,
            "confidence": confidence_label(sc),
            "context": context,
            "encoding": encoding,
            "validations": vals,
            "screenshot": v.get("screenshot", ""),
            "timestamp": datetime.now().isoformat(),
            "source": v.get("tool", "multi-stage"),
        })
        if sc >= 51:
            send_critical_alert(results[-1])

    confirmed = len([r for r in results if r['score'] >= 51])
    verified = len([r for r in results if r['score'] >= 76])
    print(f"    ✅ {len(results)} XSS tested | {confirmed} confirmed | {verified} verified")
    return results

# ── SQLi Validation Pipeline ──────────────────────────────────────────────
def validate_sqli(domain):
    print("  ⚡ SQLi Validation Pipeline")
    candidates = load_candidates("sqli")
    if not candidates:
        print("    ⚪ No SQLi candidates")
        return []

    tmp = VAL / "sqli_input.txt"
    tmp.write_text("\n".join(candidates))

    validated = run_validator("sqli_validator.sh", domain, tmp, VAL/"sqli_raw.json", timeout=180)

    results = []
    for v in (validated if isinstance(validated, list) else []):
        base = 15
        vals = {
            "error_triggered": v.get("error_based", False),
            "time_delay_confirmed": v.get("time_based", False),
            "tool_confirmed": v.get("sqlmap_confirmed", False),
        }
        sc = score_finding(base, vals)
        results.append({
            "type": "SQLi",
            "url": v.get("url", ""),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "dbms": v.get("dbms", ""),
            "technique": v.get("technique", ""),
            "score": sc,
            "confidence": confidence_label(sc),
            "validations": vals,
            "timestamp": datetime.now().isoformat(),
            "source": v.get("tool", "sqlmap"),
        })
        if sc >= 51:
            send_critical_alert(results[-1])

    print(f"    ✅ {len(results)} SQLi validated ({len([r for r in results if r['score']>=51])} confirmed)")
    return results

# ── SSRF Validation Pipeline ──────────────────────────────────────────────
def validate_ssrf(domain):
    print("  ⚡ SSRF Validation Pipeline")
    candidates = load_candidates("ssrf")
    if not candidates:
        print("    ⚪ No SSRF candidates")
        return []

    tmp = VAL / "ssrf_input.txt"
    tmp.write_text("\n".join(candidates))

    validated = run_validator("ssrf_validator.sh", domain, tmp, VAL/"ssrf_raw.json", timeout=300)

    results = []
    for v in (validated if isinstance(validated, list) else []):
        base = 20
        vals = {
            "callback_received": v.get("callback", False),
            "tool_confirmed": v.get("confirmed", False),
        }
        sc = score_finding(base, vals)
        results.append({
            "type": "SSRF",
            "url": v.get("url", ""),
            "param": v.get("param", ""),
            "payload": v.get("payload", ""),
            "score": sc,
            "confidence": confidence_label(sc),
            "validations": vals,
            "timestamp": datetime.now().isoformat(),
        })
        if sc >= 51:
            send_critical_alert(results[-1])

    print(f"    ✅ {len(results)} SSRF validated")
    return results

# ── Open Redirect Validation ──────────────────────────────────────────────
def validate_redirect(domain):
    print("  ⚡ Open Redirect Validation Pipeline")
    candidates = load_candidates("redirect")
    if not candidates:
        print("    ⚪ No redirect candidates")
        return []

    tmp = VAL / "redirect_input.txt"
    tmp.write_text("\n".join(candidates))

    validated = run_validator("redirect_validator.sh", domain, tmp, VAL/"redirect_raw.json", timeout=300)

    results = []
    for v in (validated if isinstance(validated, list) else []):
        base = 20
        vals = {"tool_confirmed": v.get("confirmed", False)}
        sc = score_finding(base, vals)
        results.append({
            "type": "OpenRedirect",
            "url": v.get("url", ""),
            "param": v.get("param", ""),
            "redirect_to": v.get("redirect_to", ""),
            "score": sc,
            "confidence": confidence_label(sc),
            "timestamp": datetime.now().isoformat(),
        })

    print(f"    ✅ {len(results)} redirects validated")
    return results

# ── CORS Validation ───────────────────────────────────────────────────────
def validate_cors(domain):
    print("  ⚡ CORS Validation Pipeline")
    candidates = load_candidates("cors")
    if not candidates:
        print("    ⚪ No CORS candidates")
        return []

    tmp = VAL / "cors_input.txt"
    tmp.write_text("\n".join(candidates))

    validated = run_validator("cors_validator.sh", domain, tmp, VAL/"cors_raw.json", timeout=300)

    results = []
    for v in (validated if isinstance(validated, list) else []):
        base = 20
        vals = {"tool_confirmed": v.get("confirmed", False)}
        sc = score_finding(base, vals)
        if v.get("severity") == "High":
            sc += 20
        results.append({
            "type": "CORS",
            "url": v.get("url", ""),
            "origin": v.get("origin", ""),
            "severity": v.get("severity", ""),
            "detail": v.get("detail", ""),
            "score": sc,
            "confidence": confidence_label(sc),
            "timestamp": datetime.now().isoformat(),
        })

    print(f"    ✅ {len(results)} CORS issues validated")
    return results

# ── Main Orchestrator ─────────────────────────────────────────────────────
def main():
    print(f"\n  🔬 Autonomous Validation Engine — {DOMAIN}")
    print(f"  {'━'*50}")
    start = time.time()

    all_findings = []

    # Run validators
    all_findings.extend(validate_xss(DOMAIN))
    all_findings.extend(validate_sqli(DOMAIN))
    all_findings.extend(validate_ssrf(DOMAIN))
    all_findings.extend(validate_redirect(DOMAIN))

    # Sort by confidence score
    all_findings.sort(key=lambda x: x["score"], reverse=True)

    # Summary stats
    confirmed = [f for f in all_findings if f["score"] >= 51]
    critical = [f for f in all_findings if f["score"] >= 76]

    # Save results
    (VAL / "all_validated.json").write_text(json.dumps(all_findings, indent=2))
    (VAL / "validated_xss.json").write_text(json.dumps([f for f in all_findings if f["type"]=="XSS"], indent=2))
    (VAL / "validated_sqli.json").write_text(json.dumps([f for f in all_findings if f["type"]=="SQLi"], indent=2))
    (VAL / "validated_ssrf.json").write_text(json.dumps([f for f in all_findings if f["type"]=="SSRF"], indent=2))
    (VAL / "validated_redirects.json").write_text(json.dumps([f for f in all_findings if f["type"]=="OpenRedirect"], indent=2))

    # Confidence report
    report = {
        "domain": DOMAIN,
        "timestamp": datetime.now().isoformat(),
        "total_candidates": sum(len(load_candidates(c)) for c in ["xss","sqli","ssrf","redirect"]),
        "total_validated": len(all_findings),
        "confirmed_findings": len(confirmed),
        "critical_findings": len(critical),
        "by_type": {},
        "by_confidence": {"POSSIBLE":0, "LIKELY":0, "VALIDATED":0, "CONFIRMED":0},
    }
    for f in all_findings:
        t = f["type"]
        report["by_type"][t] = report["by_type"].get(t, 0) + 1
        report["by_confidence"][f["confidence"]] += 1

    (VAL / "confidence_report.json").write_text(json.dumps(report, indent=2))

    elapsed = time.time() - start
    print(f"\n  {'━'*50}")
    print(f"  🏁 Validation complete in {elapsed:.1f}s")
    print(f"  📊 Total: {len(all_findings)} | Confirmed: {len(confirmed)} | Critical: {len(critical)}")

if __name__ == "__main__": main()
