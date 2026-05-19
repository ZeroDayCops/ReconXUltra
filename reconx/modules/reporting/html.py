#!/usr/bin/env python3
"""
============================================================================
ReconX Ultra — Real-Time Intelligence Dashboard
============================================================================
Generates a premium HTML dashboard with:
  - Live recon stats
  - Attack surface graph (Chart.js)
  - Endpoint explorer with search/filter
  - JS intelligence panels
  - Vulnerability heatmaps
  - Wordlist usage stats
  - Interactive findings tables
============================================================================
"""

import json
import os
import sys
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    print("Usage: html.py <domain>")
    sys.exit(1)

RECONX_ROOT = Path(__file__).resolve().parent.parent.parent
OUTPUT_DIR = RECONX_ROOT / "output" / DOMAIN


def count_lines(filepath):
    try:
        with open(filepath) as f:
            return sum(1 for line in f if line.strip())
    except (FileNotFoundError, PermissionError):
        return 0


def read_lines(filepath, limit=None):
    try:
        with open(filepath) as f:
            lines = [l.strip() for l in f if l.strip()]
            return lines[:limit] if limit else lines
    except (FileNotFoundError, PermissionError):
        return []


def load_json(filepath):
    try:
        with open(filepath) as f:
            return json.load(f)
    except:
        return None


def escape_html(text):
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _render_wordlist_tags(wl_sel):
    """Render wordlist tags for the dashboard."""
    selected = wl_sel.get("wordlists_selected", {})
    if not selected:
        return ""
    tags = []
    for wl_key, wl_info in selected.items():
        fname = wl_info.get("file", wl_key) if isinstance(wl_info, dict) else str(wl_info)
        tags.append(f'<span class="tag tag-green">{escape_html(fname)}</span>')
    return "".join(tags)


def main():
    report_path = OUTPUT_DIR / "reports" / "report.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    # Gather all stats
    s = {
        "subdomains": count_lines(OUTPUT_DIR / "subs/all_subdomains.txt"),
        "live_hosts": count_lines(OUTPUT_DIR / "live/live_hosts.txt"),
        "total_urls": count_lines(OUTPUT_DIR / "urls/all_urls.txt"),
        "js_urls": count_lines(OUTPUT_DIR / "js/js_urls.txt"),
        "nuclei": count_lines(OUTPUT_DIR / "scans/nuclei_all_summary.txt"),
        "ports": count_lines(OUTPUT_DIR / "scans/open_ports.txt"),
        "takeover": count_lines(OUTPUT_DIR / "takeover/all_takeover_findings.txt"),
        "xss": count_lines(OUTPUT_DIR / "intelligence/xss_candidates.txt"),
        "sqli": count_lines(OUTPUT_DIR / "intelligence/sqli_candidates.txt"),
        "ssrf": count_lines(OUTPUT_DIR / "intelligence/ssrf_candidates.txt"),
        "lfi": count_lines(OUTPUT_DIR / "intelligence/lfi_candidates.txt"),
        "ssti": count_lines(OUTPUT_DIR / "intelligence/ssti_candidates.txt"),
        "idor": count_lines(OUTPUT_DIR / "intelligence/idor_candidates.txt"),
        "redirect": count_lines(OUTPUT_DIR / "intelligence/redirect_candidates.txt"),
        "resolved": count_lines(OUTPUT_DIR / "resolved/resolved_subdomains.txt"),
        "unique_ips": count_lines(OUTPUT_DIR / "resolved/unique_ips.txt"),
        "param_urls": count_lines(OUTPUT_DIR / "urls/parameterized_urls.txt"),
    }

    # Load intelligence data
    secrets_data = load_json(OUTPUT_DIR / "intelligence/js_secrets_deep.json") or load_json(OUTPUT_DIR / "secrets/js_secrets_report.json")
    secrets_count = len(secrets_data) if isinstance(secrets_data, list) else (secrets_data or {}).get("total_findings", 0)

    risk_matrix = load_json(OUTPUT_DIR / "intelligence/risk_matrix.json") or {}
    matrix = risk_matrix.get("matrix", {})
    cat_dist = risk_matrix.get("category_distribution", {})

    api_inv = load_json(OUTPUT_DIR / "intelligence/api_inventory.json") or {}
    wl_sel = load_json(OUTPUT_DIR / "intelligence/wordlist_selections.json") or {}
    workflows = load_json(OUTPUT_DIR / "intelligence/critical_workflows.json") or {}
    clusters = load_json(OUTPUT_DIR / "intelligence/response_clusters.json") or {}

    # Lists for tables
    nuclei_lines = read_lines(OUTPUT_DIR / "scans/nuclei_all_summary.txt", 50)
    suspicious = read_lines(OUTPUT_DIR / "intelligence/suspicious_endpoints.txt", 30)
    hvt = read_lines(OUTPUT_DIR / "intelligence/high_value_targets.txt", 30)
    admin_panels = read_lines(OUTPUT_DIR / "intelligence/admin_panels.txt", 20)
    dom_sinks = load_json(OUTPUT_DIR / "intelligence/dom_sinks.json") or []
    bypass_results = read_lines(OUTPUT_DIR / "exploits/403_bypass_results.txt", 20)

    # Vuln totals for chart
    vuln_labels = ["XSS","SQLi","SSRF","LFI","SSTI","IDOR","Redirect","CRLF"]
    vuln_values = [s["xss"],s["sqli"],s["ssrf"],s["lfi"],s["ssti"],s["idor"],s["redirect"],
                   count_lines(OUTPUT_DIR / "intelligence/crlf_candidates.txt")]

    # Risk levels for chart
    r_crit = matrix.get("CRITICAL",{}).get("count",0)
    r_high = matrix.get("HIGH",{}).get("count",0)
    r_med = matrix.get("MEDIUM",{}).get("count",0)
    r_low = matrix.get("LOW",{}).get("count",0)

    # Technologies detected
    techs = wl_sel.get("technologies_detected", [])
    wl_used = wl_sel.get("total_wordlists", 0)

    # API counts
    api_total = sum(len(v) if isinstance(v, list) else 0 for v in api_inv.values())
    graphql_count = len(api_inv.get("graphql_endpoints", []))
    swagger_count = len(api_inv.get("swagger_specs", []))

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ReconX Ultra Dashboard — {escape_html(DOMAIN)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --bg-0: #0a0e17; --bg-1: #0d1117; --bg-2: #161b22; --bg-3: #1c2333;
            --border: #30363d; --border-h: #58a6ff;
            --text-1: #e6edf3; --text-2: #8b949e; --text-3: #6e7681;
            --cyan: #39d2c0; --blue: #58a6ff; --purple: #bc8cff;
            --green: #3fb950; --red: #f85149; --orange: #d29922; --yellow: #e3b341;
            --pink: #f778ba;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; background:var(--bg-0); color:var(--text-1); line-height:1.6; }}
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        .container {{ max-width:1400px; margin:0 auto; padding:1.5rem; }}
        header {{
            background:linear-gradient(135deg, rgba(13,17,23,0.95) 0%, rgba(30,40,65,0.95) 50%, rgba(13,17,23,0.95) 100%);
            border-bottom:1px solid var(--border); padding:2rem 2rem 1.5rem; text-align:center;
            position:relative; overflow:hidden;
        }}
        header::before {{
            content:''; position:absolute; top:0; left:0; right:0; bottom:0;
            background:radial-gradient(ellipse at 50% 0%, rgba(57,210,192,0.08) 0%, transparent 60%);
        }}
        header h1 {{ font-size:2rem; font-weight:700; color:var(--cyan); position:relative; letter-spacing:-0.02em; }}
        header .meta {{ color:var(--text-2); font-size:0.85rem; margin-top:0.5rem; position:relative; }}
        header .meta strong {{ color:var(--blue); }}

        .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:0.75rem; margin:1.5rem 0; }}
        .stat-card {{
            background:var(--bg-3); border:1px solid var(--border); border-radius:10px;
            padding:1.2rem; text-align:center; transition:all 0.3s;
            position:relative; overflow:hidden;
        }}
        .stat-card::before {{
            content:''; position:absolute; top:0; left:0; right:0; height:2px;
            background:linear-gradient(90deg, var(--cyan), var(--blue));
            opacity:0; transition:opacity 0.3s;
        }}
        .stat-card:hover {{ transform:translateY(-3px); border-color:var(--border-h); box-shadow:0 8px 25px rgba(0,0,0,0.3); }}
        .stat-card:hover::before {{ opacity:1; }}
        .stat-card .number {{ font-size:1.8rem; font-weight:700; color:var(--cyan); font-family:'JetBrains Mono',monospace; }}
        .stat-card .label {{ color:var(--text-2); font-size:0.75rem; margin-top:0.3rem; text-transform:uppercase; letter-spacing:0.05em; }}

        .grid-2 {{ display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; margin:1.5rem 0; }}
        @media (max-width:900px) {{ .grid-2 {{ grid-template-columns:1fr; }} }}

        section {{ margin:1.5rem 0; }}
        .panel {{
            background:var(--bg-2); border:1px solid var(--border); border-radius:10px;
            padding:1.5rem; margin:1rem 0;
        }}
        .panel h2 {{
            color:var(--blue); font-size:1.1rem; font-weight:600; margin-bottom:1rem;
            padding-bottom:0.5rem; border-bottom:1px solid var(--border);
            display:flex; align-items:center; gap:0.5rem;
        }}
        .panel h3 {{ color:var(--text-1); font-size:0.95rem; margin:1rem 0 0.5rem; }}

        table {{ width:100%; border-collapse:collapse; font-size:0.85rem; }}
        th {{ background:var(--bg-3); color:var(--blue); text-align:left; padding:0.6rem 0.8rem; font-weight:600; font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; }}
        td {{ padding:0.5rem 0.8rem; border-bottom:1px solid rgba(48,54,61,0.5); }}
        tr:hover td {{ background:rgba(88,166,255,0.04); }}

        .badge {{
            display:inline-block; padding:0.15rem 0.5rem; border-radius:10px;
            font-size:0.7rem; font-weight:600; font-family:'JetBrains Mono',monospace;
        }}
        .badge-critical {{ background:rgba(248,81,73,0.15); color:var(--red); }}
        .badge-high {{ background:rgba(210,153,34,0.15); color:var(--orange); }}
        .badge-medium {{ background:rgba(88,166,255,0.15); color:var(--blue); }}
        .badge-low {{ background:rgba(63,185,80,0.15); color:var(--green); }}

        .vuln-grid {{ display:flex; gap:0.5rem; flex-wrap:wrap; }}
        .vuln-chip {{
            background:var(--bg-3); border:1px solid var(--border); border-radius:8px;
            padding:0.8rem 1rem; text-align:center; flex:1; min-width:100px;
            transition:all 0.2s;
        }}
        .vuln-chip:hover {{ border-color:var(--border-h); }}
        .vuln-chip .count {{ font-size:1.3rem; font-weight:700; font-family:'JetBrains Mono',monospace; }}
        .vuln-chip .name {{ font-size:0.7rem; color:var(--text-2); text-transform:uppercase; }}

        .tag {{ display:inline-block; padding:0.1rem 0.4rem; border-radius:4px; font-size:0.7rem; margin:0.1rem; background:rgba(88,166,255,0.1); color:var(--blue); }}
        .tag-green {{ background:rgba(63,185,80,0.1); color:var(--green); }}
        .tag-purple {{ background:rgba(188,140,255,0.1); color:var(--purple); }}
        .tag-red {{ background:rgba(248,81,73,0.1); color:var(--red); }}

        .mono {{ font-family:'JetBrains Mono',monospace; font-size:0.8rem; word-break:break-all; }}
        .list-item {{ background:var(--bg-3); border:1px solid var(--border); border-radius:6px; padding:0.5rem 0.8rem; margin:0.3rem 0; font-size:0.8rem; }}
        .chart-container {{ position:relative; height:250px; }}

        #search {{ width:100%; padding:0.6rem 1rem; background:var(--bg-3); border:1px solid var(--border); border-radius:8px; color:var(--text-1); font-size:0.85rem; outline:none; }}
        #search:focus {{ border-color:var(--cyan); box-shadow:0 0 0 3px rgba(57,210,192,0.1); }}

        footer {{ text-align:center; padding:2rem; color:var(--text-3); font-size:0.8rem; border-top:1px solid var(--border); margin-top:2rem; }}

        .risk-bar {{ display:flex; height:12px; border-radius:6px; overflow:hidden; margin:0.5rem 0; }}
        .risk-bar .seg {{ transition:width 0.5s; }}
    </style>
</head>
<body>
    <header>
        <h1>⚡ ReconX Ultra — Intelligence Dashboard</h1>
        <div class="meta">
            Target: <strong>{escape_html(DOMAIN)}</strong> &nbsp;|&nbsp;
            Generated: {now} &nbsp;|&nbsp;
            v2.0.0 Ultra
        </div>
    </header>

    <div class="container">

        <!-- Executive Stats -->
        <div class="stats-grid">
            <div class="stat-card"><div class="number">{s['subdomains']}</div><div class="label">Subdomains</div></div>
            <div class="stat-card"><div class="number">{s['live_hosts']}</div><div class="label">Live Hosts</div></div>
            <div class="stat-card"><div class="number">{s['total_urls']}</div><div class="label">URLs</div></div>
            <div class="stat-card"><div class="number">{s['param_urls']}</div><div class="label">Parameterized</div></div>
            <div class="stat-card"><div class="number">{s['js_urls']}</div><div class="label">JS Files</div></div>
            <div class="stat-card"><div class="number" style="color:var(--red)">{s['nuclei']}</div><div class="label">Nuclei Findings</div></div>
            <div class="stat-card"><div class="number" style="color:var(--orange)">{secrets_count}</div><div class="label">Secrets</div></div>
            <div class="stat-card"><div class="number">{api_total}</div><div class="label">API Endpoints</div></div>
        </div>

        <!-- Vuln Candidates -->
        <div class="panel">
            <h2>⚡ Vulnerability Candidates</h2>
            <div class="vuln-grid">
                <div class="vuln-chip"><div class="count" style="color:var(--red)">{s['xss']}</div><div class="name">XSS</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--orange)">{s['sqli']}</div><div class="name">SQLi</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--purple)">{s['ssrf']}</div><div class="name">SSRF</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--blue)">{s['lfi']}</div><div class="name">LFI</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--pink)">{s['ssti']}</div><div class="name">SSTI</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--yellow)">{s['idor']}</div><div class="name">IDOR</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--cyan)">{s['redirect']}</div><div class="name">Redirect</div></div>
                <div class="vuln-chip"><div class="count" style="color:var(--green)">{vuln_values[7]}</div><div class="name">CRLF</div></div>
            </div>
        </div>

        <div class="grid-2">
            <!-- Risk Distribution Chart -->
            <div class="panel">
                <h2>🎯 Risk Distribution</h2>
                <div class="chart-container"><canvas id="riskChart"></canvas></div>
            </div>
            <!-- Vuln Category Chart -->
            <div class="panel">
                <h2>🔥 Vulnerability Heatmap</h2>
                <div class="chart-container"><canvas id="vulnChart"></canvas></div>
            </div>
        </div>

        <div class="grid-2">
            <!-- Technologies -->
            <div class="panel">
                <h2>🔧 Technologies Detected</h2>
                <div>{''.join(f'<span class="tag">{escape_html(t)}</span>' for t in techs) if techs else '<span class="tag">Auto-detection pending</span>'}</div>
                <h3>Wordlists Applied: {wl_used}</h3>
                <div>{_render_wordlist_tags(wl_sel)}</div>
            </div>
            <!-- API Surface -->
            <div class="panel">
                <h2>🌐 API Intelligence</h2>
                <table>
                    <tr><td>GraphQL Endpoints</td><td class="mono" style="color:var(--cyan)">{graphql_count}</td></tr>
                    <tr><td>Swagger/OpenAPI Specs</td><td class="mono" style="color:var(--blue)">{swagger_count}</td></tr>
                    <tr><td>REST API Routes</td><td class="mono">{sum(len(v) for v in api_inv.get('rest_apis',{}).values() if isinstance(v,list))}</td></tr>
                    <tr><td>WebSocket Endpoints</td><td class="mono">{len(api_inv.get('websocket_endpoints',[]))}</td></tr>
                    <tr><td>Mobile API Hints</td><td class="mono">{len(api_inv.get('mobile_api_hints',[]))}</td></tr>
                    <tr><td>Actuator Endpoints</td><td class="mono" style="color:var(--red)">{len(api_inv.get('actuator_endpoints',[]))}</td></tr>
                </table>
            </div>
        </div>

        <!-- Critical Workflows -->
        <div class="panel">
            <h2>⚠️ Critical Workflows</h2>
            <table>
                <thead><tr><th>Workflow</th><th>Severity</th><th>Endpoints</th><th>Potential Bugs</th></tr></thead>
                <tbody>"""

    for wf_name, wf_data in sorted(workflows.items(), key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2}.get(x[1].get("severity",""),3)):
        sev = wf_data.get("severity","")
        badge = f'badge-{sev.lower()}' if sev.lower() in ["critical","high","medium"] else "badge-low"
        bugs = ", ".join(wf_data.get("bugs",[])[:3])
        html += f"""<tr><td class="mono">{escape_html(wf_name)}</td><td><span class="badge {badge}">{sev}</span></td>
            <td>{wf_data.get('total_endpoints',0)}</td><td style="font-size:0.75rem">{escape_html(bugs)}</td></tr>"""

    html += """</tbody></table></div>"""

    # High Value Targets
    if hvt:
        html += '<div class="panel"><h2>🎯 High-Value Targets</h2>'
        for line in hvt[:20]:
            html += f'<div class="list-item mono">{escape_html(line)}</div>'
        html += '</div>'

    # Admin Panels
    if admin_panels:
        html += '<div class="panel"><h2>🔑 Admin Panels Discovered</h2>'
        for line in admin_panels[:15]:
            html += f'<div class="list-item mono">{escape_html(line)}</div>'
        html += '</div>'

    # 403 Bypass Results
    if bypass_results:
        html += '<div class="panel"><h2>🔓 403 Bypass Results</h2>'
        for line in bypass_results[:15]:
            html += f'<div class="list-item mono" style="border-left:3px solid var(--red)">{escape_html(line)}</div>'
        html += '</div>'

    # DOM Sinks from JS
    if dom_sinks:
        crit_sinks = [d for d in dom_sinks if d.get("severity") in ("CRITICAL","HIGH")][:20]
        if crit_sinks:
            html += '<div class="panel"><h2>🕸️ JS DOM Sinks (XSS Vectors)</h2><table>'
            html += '<thead><tr><th>File</th><th>Sink</th><th>Severity</th><th>Type</th><th>Source Connected</th></tr></thead><tbody>'
            for sink in crit_sinks:
                badge = f'badge-{sink["severity"].lower()}'
                src = "✅ YES" if sink.get("source_connected") else "—"
                html += f'<tr><td class="mono">{escape_html(sink["file"])}</td><td class="mono">{escape_html(sink["sink"])}</td>'
                html += f'<td><span class="badge {badge}">{sink["severity"]}</span></td>'
                html += f'<td>{escape_html(sink.get("vuln_type",""))}</td><td>{src}</td></tr>'
            html += '</tbody></table></div>'

    # Endpoint Explorer
    html += f"""
        <div class="panel">
            <h2>🔍 Endpoint Explorer</h2>
            <input type="text" id="search" placeholder="Search endpoints... (type to filter)" oninput="filterEndpoints()">
            <div id="endpointList" style="max-height:400px;overflow-y:auto;margin-top:0.5rem">"""

    # Load prioritized targets for the explorer
    prio = load_json(OUTPUT_DIR / "intelligence/prioritized_targets.json") or []
    for ep in prio[:100]:
        score = ep.get("score",0)
        sens = ep.get("sensitivity","LOW")
        badge = f'badge-{sens.lower()}' if sens.lower() in ["critical","high","medium"] else "badge-low"
        cats = " ".join(f'<span class="tag tag-purple">{c}</span>' for c in ep.get("categories",[])[:3])
        html += f'<div class="list-item ep-item" style="display:flex;justify-content:space-between;align-items:center">'
        html += f'<span class="mono" style="flex:1">{escape_html(ep.get("url",""))}</span>'
        html += f'<span style="margin-left:0.5rem">{cats} <span class="badge {badge}">{score}</span></span></div>'

    html += """</div></div>"""

    # Charts JavaScript
    html += f"""
    </div>
    <footer>
        <p>Generated by ReconX Ultra v2.0.0 — {now}</p>
        <p style="margin-top:0.3rem">Attack Surface Intelligence Framework</p>
    </footer>

    <script>
        // Risk Distribution
        new Chart(document.getElementById('riskChart'), {{
            type: 'doughnut',
            data: {{
                labels: ['Critical','High','Medium','Low'],
                datasets: [{{ data: [{r_crit},{r_high},{r_med},{r_low}],
                    backgroundColor: ['#f85149','#d29922','#58a6ff','#3fb950'],
                    borderWidth: 0 }}]
            }},
            options: {{ responsive:true, maintainAspectRatio:false,
                plugins: {{ legend: {{ position:'right', labels: {{ color:'#8b949e', font: {{ size:11 }} }} }} }}
            }}
        }});

        // Vulnerability Heatmap
        new Chart(document.getElementById('vulnChart'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(vuln_labels)},
                datasets: [{{ label:'Candidates', data:{json.dumps(vuln_values)},
                    backgroundColor: ['#f85149','#d29922','#bc8cff','#58a6ff','#f778ba','#e3b341','#39d2c0','#3fb950'],
                    borderRadius: 4, borderWidth:0 }}]
            }},
            options: {{ responsive:true, maintainAspectRatio:false, indexAxis:'y',
                scales: {{ x: {{ grid: {{ color:'rgba(48,54,61,0.3)' }}, ticks: {{ color:'#8b949e' }} }},
                          y: {{ grid: {{ display:false }}, ticks: {{ color:'#e6edf3', font: {{ size:11 }} }} }} }},
                plugins: {{ legend: {{ display:false }} }}
            }}
        }});

        // Endpoint search filter
        function filterEndpoints() {{
            const q = document.getElementById('search').value.toLowerCase();
            document.querySelectorAll('.ep-item').forEach(el => {{
                el.style.display = el.textContent.toLowerCase().includes(q) ? 'flex' : 'none';
            }});
        }}
    </script>
</body>
</html>"""

    with open(report_path, 'w') as f:
        f.write(html)
    print(f"  ✅ HTML dashboard saved: {report_path}")


if __name__ == "__main__":
    main()
