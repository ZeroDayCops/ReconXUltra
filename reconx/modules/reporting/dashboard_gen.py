#!/usr/bin/env python3
"""ReconX Ultra X — Premium Dashboard Generator"""
import json, sys, os
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: dashboard_gen.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
CSS_PATH = Path(__file__).parent / "dashboard" / "styles.css"

def cl(f):
    try:
        with open(f) as fh: return sum(1 for l in fh if l.strip())
    except: return 0

def rl(f, n=None):
    try:
        with open(f) as fh:
            lines = [l.strip() for l in fh if l.strip()]
            return lines[:n] if n else lines
    except: return []

def lj(f):
    try:
        with open(f) as fh: return json.load(fh)
    except: return None

def esc(t): return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def _items(lst, cls="list-item"): return "".join(f'<div class="{cls}">{esc(l)}</div>' for l in lst)
def _api_items(eps, tag, color):
    return "".join(f'<div class="list-item"><span class="tag tag-{color}">{tag}</span> {esc(e.get("url",""))}</div>' for e in eps[:20])
def _cond_panel(title, body, show=True):
    if not show: return ""
    return f'<div class="panel"><div class="panel-header"><h3>{title}</h3></div><div class="panel-body">{body}</div></div>'

def main():
    rpt = OUT / "reports" / "report.html"
    rpt.parent.mkdir(parents=True, exist_ok=True)

    css = ""
    if CSS_PATH.exists():
        css = CSS_PATH.read_text()

    # Stats
    s = {k: cl(f) for k, f in {
        "subs": OUT/"subs/all_subdomains.txt", "live": OUT/"live/live_hosts.txt",
        "urls": OUT/"urls/all_urls.txt", "params": OUT/"urls/parameterized_urls.txt",
        "js": OUT/"js/js_urls.txt", "nuclei": OUT/"scans/nuclei_all_summary.txt",
        "xss": OUT/"intelligence/xss_candidates.txt", "sqli": OUT/"intelligence/sqli_candidates.txt",
        "ssrf": OUT/"intelligence/ssrf_candidates.txt", "lfi": OUT/"intelligence/lfi_candidates.txt",
        "ssti": OUT/"intelligence/ssti_candidates.txt", "idor": OUT/"intelligence/idor_candidates.txt",
        "redir": OUT/"intelligence/redirect_candidates.txt", "crlf": OUT/"intelligence/crlf_candidates.txt",
        "ports": OUT/"scans/open_ports.txt", "takeover": OUT/"takeover/all_takeover_findings.txt",
    }.items()}

    risk = lj(OUT/"intelligence/risk_matrix.json") or {}
    mx = risk.get("matrix",{})
    cats = risk.get("category_distribution",{}) if isinstance(risk.get("category_distribution"), dict) else {}
    api_raw = lj(OUT/"intelligence/api_inventory.json") or {}
    api = api_raw if isinstance(api_raw, dict) else {}
    wl_raw = lj(OUT/"intelligence/wordlist_selections.json") or {}
    wl = wl_raw if isinstance(wl_raw, dict) else {}
    wf_raw = lj(OUT/"intelligence/critical_workflows.json") or {}
    wf = wf_raw if isinstance(wf_raw, dict) else {}
    prio_raw = lj(OUT/"intelligence/prioritized_targets.json") or []
    prio = prio_raw if isinstance(prio_raw, list) else []
    perf = lj(OUT/"intelligence/performance_metrics.json") or {}
    # Load secrets — handle both formats
    secs_deep = lj(OUT/"intelligence/js_secrets_deep.json")
    secs_report = lj(OUT/"secrets/js_secrets_report.json")
    sec_findings = []
    if isinstance(secs_deep, list) and secs_deep:
        sec_findings = secs_deep
    elif isinstance(secs_report, dict) and secs_report.get("findings"):
        sec_findings = secs_report["findings"]
    elif isinstance(secs_report, list) and secs_report:
        sec_findings = secs_report
    sec_n = len(sec_findings)
    dom_raw = lj(OUT/"intelligence/dom_sinks.json") or []
    dom_sinks = dom_raw if isinstance(dom_raw, list) else []

    rc,rh,rm,rl_ = [mx.get(l,{}).get("count",0) for l in ["CRITICAL","HIGH","MEDIUM","LOW"]]
    techs = wl.get("technologies_detected",[])
    def safe_list(d, k): 
        v = d.get(k, [])
        return v if isinstance(v, list) else []
    def safe_dict(d, k):
        v = d.get(k, {})
        return v if isinstance(v, dict) else {}
    gql = len(safe_list(api, "graphql_endpoints"))
    swg = len(safe_list(api, "swagger_specs"))
    act = len(safe_list(api, "actuator_endpoints"))
    rest_raw = api.get("rest_apis", [])
    if isinstance(rest_raw, dict):
        rest_n = sum(len(v) for v in rest_raw.values() if isinstance(v, list))
    elif isinstance(rest_raw, list):
        rest_n = len(rest_raw)
    else:
        rest_n = 0
    vl = ["XSS","SQLi","SSRF","LFI","SSTI","IDOR","Redirect","CRLF"]
    vv = [s["xss"],s["sqli"],s["ssrf"],s["lfi"],s["ssti"],s["idor"],s["redir"],s["crlf"]]
    vc = ["#ef4444","#f59e0b","#8b5cf6","#3b82f6","#ec4899","#eab308","#06d6a0","#22c55e"]
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    total_vulns = sum(vv)
    api_total = gql+swg+act+rest_n

    # Validated findings
    val_all = lj(OUT/"validated/all_validated.json") or []
    val_all = val_all if isinstance(val_all, list) else []
    val_conf = lj(OUT/"validated/confidence_report.json") or {}
    val_conf = val_conf if isinstance(val_conf, dict) else {}
    val_confirmed = len([v for v in val_all if v.get("score",0) >= 51])
    val_critical = len([v for v in val_all if v.get("score",0) >= 76])

    # Attack chains
    chains_data = lj(OUT/"attack_chains/attack_chains.json") or {}
    chains_data = chains_data if isinstance(chains_data, dict) else {}
    chains = chains_data.get("chains", []) if isinstance(chains_data.get("chains"), list) else []

    # Target DNA
    dna = lj(OUT/"target_dna/target_dna.json") or {}
    dna_techs = dna.get("technologies", {})
    dna_risk = dna.get("risk_profile", "UNKNOWN")
    dna_surface = dna.get("attack_surface", {})
    dna_recs = dna.get("hunting_recommendations", [])
    dna_auth = dna.get("auth_systems", [])
    dna_cloud = dna.get("cloud_providers", [])
    dna_backend = dna.get("frameworks", {}).get("backend", [])
    dna_frontend = dna.get("frameworks", {}).get("frontend", [])

    # Hunter Strategy
    strategy = lj(OUT/"strategy/strategy.json") or {}
    strat_preds = strategy.get("predictions", {}) if isinstance(strategy.get("predictions"), dict) else {}
    strat_paths = strategy.get("attack_paths", []) if isinstance(strategy.get("attack_paths"), list) else []
    strat_order = strategy.get("strategy", {}).get("priority_order", []) if isinstance(strategy.get("strategy"), dict) else []

    # Surface ranking
    surface_data = lj(OUT/"prioritized/surface_ranking.json") or {}
    ranked_surfaces = surface_data.get("ranked_surfaces", []) if isinstance(surface_data.get("ranked_surfaces"), list) else []
    vuln_preds = lj(OUT/"prioritized/vulnerability_predictions.json") or {}
    pred_list = vuln_preds.get("predictions", []) if isinstance(vuln_preds.get("predictions"), list) else []

    # Build nav badges
    nb = {"overview":"","assets":s["subs"],"apis":api_total,"js":s["js"],
          "params":s["params"],"vulns":total_vulns,"validated":len(val_all),"secrets":sec_n,"tech":len(techs)}

    # Nuclei findings
    nuc_lines = rl(OUT/"scans/nuclei_all_summary.txt", 40)
    hvt = rl(OUT/"intelligence/high_value_endpoints.txt", 25)
    admin = rl(OUT/"intelligence/admin_panels.txt", 15)
    bypass = rl(OUT/"exploits/403_bypass_results.txt", 15)

    # Build sidebar
    nav_items = [
        ("overview","📊","Overview"),("assets","🌐","Assets"),("apis","🔌","APIs"),
        ("js","📜","JS Intel"),("params","🎯","Parameters"),("vulns","⚡","Vulnerabilities"),
        ("validated","🔬","Validated"),("chains","🔗","Attack Chains"),
        ("secrets","🔑","Secrets"),("tech","🔧","Technologies"),
        ("dna","🧬","Target DNA"),("strategy","🧠","Strategy"),("surface","🗺️","Surface Map"),
    ]
    sidebar_html = ""
    for nid,icon,label in nav_items:
        active = " active" if nid=="overview" else ""
        badge = f'<span class="badge">{nb.get(nid,"")}</span>' if nb.get(nid) else ""
        sidebar_html += f'<a class="nav-item{active}" onclick="showPage(\'{nid}\')" data-page="{nid}"><span class="icon">{icon}</span>{label}{badge}</a>\n'

    # Vuln chips HTML
    vchips = ""
    for i,vn in enumerate(vl):
        vchips += f'<div class="vuln-chip"><div class="n" style="color:{vc[i]}">{vv[i]}</div><div class="t">{vn}</div></div>'

    # Workflows table
    wf_rows = ""
    for wn,wd in sorted(wf.items(), key=lambda x: {"CRITICAL":0,"HIGH":1}.get(x[1].get("severity",""),9)):
        sv = wd.get("severity","")
        bc = f"badge-{sv.lower()}" if sv.lower() in ["critical","high","medium"] else "badge-low"
        bugs = ", ".join(wd.get("bugs",[])[:3])
        wf_rows += f'<tr><td>{esc(wn)}</td><td><span class="badge {bc}">{sv}</span></td><td>{wd.get("total_endpoints",0)}</td><td style="font-size:.7rem">{esc(bugs)}</td></tr>'

    # Prioritized endpoints
    ep_html = ""
    for ep in prio[:80]:
        sc = ep.get("score",0)
        sn = ep.get("sensitivity","LOW")
        bc = f"badge-{sn.lower()}" if sn.lower() in ["critical","high","medium"] else "badge-low"
        ct = " ".join(f'<span class="tag tag-purple">{c}</span>' for c in ep.get("categories",[])[:3])
        ep_html += f'<div class="list-item ep-item"><span style="flex:1">{esc(ep.get("url",""))}</span><span>{ct} <span class="badge {bc}">{sc}</span></span></div>'

    # HVT list
    hvt_html = "".join(f'<div class="list-item">{esc(l)}</div>' for l in hvt[:20])
    admin_html = "".join(f'<div class="list-item">{esc(l)}</div>' for l in admin[:15])
    bypass_html = "".join(f'<div class="list-item" style="border-left:3px solid var(--red)">{esc(l)}</div>' for l in bypass[:15])

    # Nuclei rows
    nuc_rows = "".join(f'<div class="list-item">{esc(l)}</div>' for l in nuc_lines[:30])

    # Tech tags
    tech_tags = "".join(f'<span class="tag tag-cyan">{esc(t)}</span>' for t in techs) or '<span class="tag">Pending detection</span>'

    # DOM sinks
    sink_rows = ""
    for sk in [d for d in dom_sinks if d.get("severity") in ("CRITICAL","HIGH")][:15]:
        bc = f"badge-{sk['severity'].lower()}"
        sink_rows += f'<tr><td style="font-size:.7rem">{esc(sk.get("file",""))}</td><td>{esc(sk.get("sink",""))}</td><td><span class="badge {bc}">{sk["severity"]}</span></td></tr>'

    # Secrets — render from sec_findings
    sec_html = ""
    for si in sec_findings[:30]:
        if isinstance(si, dict):
            pat = si.get("pattern", si.get("type", "secret"))
            fname = os.path.basename(str(si.get("file", "")))
            match_str = str(si.get("match", ""))[:80]
            sev = si.get("severity", "medium")
            bc = f"badge-{sev.lower()}" if sev.lower() in ["critical","high","medium"] else "badge-low"
            sec_html += f'<div class="list-item"><span class="badge {bc}">{esc(sev.upper())}</span> <span class="tag tag-red">{esc(pat)}</span> {esc(fname)} → <span style="color:var(--orange);font-size:.75rem">{esc(match_str)}</span></div>'

    # Vulnerability candidate URLs — load from .txt files
    vuln_files = {
        "XSS": rl(OUT/"intelligence/xss_candidates.txt", 20),
        "SQLi": rl(OUT/"intelligence/sqli_candidates.txt", 20),
        "SSRF": rl(OUT/"intelligence/ssrf_candidates.txt", 20),
        "LFI": rl(OUT/"intelligence/lfi_candidates.txt", 20),
        "SSTI": rl(OUT/"intelligence/ssti_candidates.txt", 20),
        "IDOR": rl(OUT/"intelligence/idor_candidates.txt", 20),
        "Redirect": rl(OUT/"intelligence/redirect_candidates.txt", 20),
        "CRLF": rl(OUT/"intelligence/crlf_candidates.txt", 20),
    }
    vuln_lists_html = ""
    for vname, vurls in vuln_files.items():
        if vurls:
            items = "".join(f'<div class="list-item">{esc(u)}</div>' for u in vurls)
            vuln_lists_html += f'<div class="panel"><div class="panel-header"><h3>🎯 {vname} Candidates</h3><span class="count">{len(vurls)}</span></div><div class="panel-body"><div class="scrollable">{items}</div></div></div>'

    # Validated findings rows
    val_rows = ""
    for vf in val_all[:50]:
        sc = vf.get("score", 0)
        conf = vf.get("confidence", "POSSIBLE")
        bc = "badge-critical" if sc >= 76 else "badge-high" if sc >= 51 else "badge-medium" if sc >= 26 else "badge-low"
        bar_color = "#ef4444" if sc >= 76 else "#f59e0b" if sc >= 51 else "#3b82f6" if sc >= 26 else "#22c55e"
        val_rows += f'''<div class="list-item" style="flex-direction:column;align-items:stretch;gap:4px">
<div style="display:flex;justify-content:space-between;align-items:center">
<span class="badge {bc}">{esc(conf)}</span>
<span class="tag tag-red">{esc(vf.get("type",""))}</span>
<span style="color:var(--text-secondary);font-size:.7rem">{esc(vf.get("source",""))}</span>
<span style="font-weight:700;color:{bar_color}">{sc}/100</span>
</div>
<div style="font-size:.75rem;color:var(--cyan);word-break:break-all">{esc(vf.get("url","")[:120])}</div>
<div style="display:flex;gap:8px;font-size:.7rem;color:var(--text-secondary)">
<span>Param: <b>{esc(vf.get("param","N/A"))}</b></span>
<span>Payload: <code>{esc(str(vf.get("payload",""))[:60])}</code></span>
</div>
<div style="background:rgba(255,255,255,0.05);height:4px;border-radius:2px"><div style="width:{sc}%;height:100%;background:{bar_color};border-radius:2px"></div></div>
</div>'''

    # Confidence summary stats
    by_conf = val_conf.get("by_confidence", {}) if isinstance(val_conf.get("by_confidence"), dict) else {}
    conf_stats = f'''<div class="stats-row">
<div class="stat" style="border-left:3px solid #ef4444"><div class="value">{by_conf.get("CONFIRMED",0)}</div><div class="label">Confirmed</div></div>
<div class="stat" style="border-left:3px solid #f59e0b"><div class="value">{by_conf.get("VALIDATED",0)}</div><div class="label">Validated</div></div>
<div class="stat" style="border-left:3px solid #3b82f6"><div class="value">{by_conf.get("LIKELY",0)}</div><div class="label">Likely</div></div>
<div class="stat" style="border-left:3px solid #22c55e"><div class="value">{by_conf.get("POSSIBLE",0)}</div><div class="label">Possible</div></div>
</div>'''

    # Attack chain cards
    chain_html = ""
    sev_colors = {"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#3b82f6","LOW":"#22c55e"}
    for ch in chains[:10]:
        sev = ch.get("severity","MEDIUM")
        steps_html = ""
        for step in ch.get("steps",[]):
            st_icon = "✅" if step.get("status")=="confirmed" else "🟡" if step.get("status")=="likely" else "⚪"
            steps_html += f'<div style="display:flex;gap:8px;align-items:center;padding:4px 0"><span>{st_icon}</span><span class="tag tag-cyan">{esc(step.get("type",""))}</span><span style="font-size:.75rem;color:var(--text-secondary)">{esc(step.get("detail",""))}</span></div>'
        chain_html += f'''<div class="panel" style="border-left:3px solid {sev_colors.get(sev,"#3b82f6")}">
<div class="panel-header"><h3>🔗 {esc(ch.get("name",""))}</h3><span class="badge badge-{sev.lower()}">{sev}</span></div>
<div class="panel-body">
{steps_html}
<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,0.1);border-radius:6px;font-size:.75rem;color:var(--red)">
💥 <b>Impact:</b> {esc(ch.get("impact",""))}
</div>
<div style="font-size:.7rem;color:var(--text-secondary);margin-top:4px">Confidence: <b>{ch.get("confidence",0)}/100</b></div>
</div></div>'''

    # Pre-build strategy HTML (avoid backslash in f-strings)
    strat_order_html = ""
    for p in strat_order[:10]:
        vt = esc(p.get("vuln_type", ""))
        tc = p.get("target_count", 0)
        ts = p.get("total_signal", 0)
        ra = esc(p.get("recommended_action", ""))
        strat_order_html += f'<div class="list-item"><span class="tag tag-red">{vt}</span> <span>{tc} targets</span> <span class="badge badge-high">Signal: {ts}</span><div style="font-size:.7rem;color:var(--text-secondary);margin-top:4px">{ra}</div></div>'
    if not strat_order_html:
        strat_order_html = '<p style="color:var(--text-3)">Run --strategy to generate</p>'

    strat_paths_html = ""
    for p in strat_paths[:8]:
        sev = p.get("severity", "MEDIUM")
        bc = "#ef4444" if sev == "CRITICAL" else "#f59e0b"
        nm = esc(p.get("name", ""))
        steps_str = " → ".join(p.get("steps", []))
        conf = p.get("confidence", 0)
        strat_paths_html += f'<div class="list-item" style="border-left:3px solid {bc}"><b>{nm}</b> <span class="badge badge-{sev.lower()}">{sev}</span><div style="font-size:.7rem;color:var(--cyan);margin-top:4px">{steps_str}</div><div style="font-size:.65rem;color:var(--text-secondary)">Confidence: {conf}%</div></div>'
    if not strat_paths_html:
        strat_paths_html = '<p style="color:var(--text-3)">No attack paths predicted yet</p>'

    # Pre-build surface ranking HTML
    surfaces_html = ""
    for rs in ranked_surfaces[:12]:
        sc = rs.get("score", 0)
        bc = "#ef4444" if sc >= 85 else "#f59e0b" if sc >= 70 else "#3b82f6"
        badge_cls = "critical" if sc >= 85 else "high" if sc >= 70 else "medium"
        icon = rs.get("icon", "")
        cat = esc(rs.get("category", ""))
        eps = rs.get("endpoints", 0)
        vtypes = ", ".join(rs.get("vuln_types", []))
        surfaces_html += f'<div class="list-item" style="border-left:3px solid {bc}"><div style="display:flex;justify-content:space-between;width:100%"><span>{icon} <b>{cat}</b> ({eps} endpoints)</span><span class="badge badge-{badge_cls}">Score: {sc}</span></div><div style="font-size:.65rem;color:var(--text-secondary);margin-top:4px">Test for: {vtypes}</div></div>'
    if not surfaces_html:
        surfaces_html = '<p style="color:var(--text-3)">Run the surface ranker first</p>'

    # Pre-build predictions HTML
    preds_html = ""
    for pr in pred_list[:10]:
        sev = pr.get("severity", "medium").lower()
        conf = pr.get("confidence", "")
        pred = esc(pr.get("prediction", ""))
        reason = esc(pr.get("reason", ""))
        preds_html += f'<div class="list-item"><span class="badge badge-{sev}">{pr.get("severity","")}</span> <span class="tag tag-purple">{conf}</span> {pred}<div style="font-size:.65rem;color:var(--text-secondary);margin-top:4px">{reason}</div></div>'
    if not preds_html:
        preds_html = '<p style="color:var(--text-3)">No predictions yet</p>'

    html = f'''<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ReconX Ultra X — {esc(DOMAIN)}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>{css}</style></head><body>

<aside class="sidebar">
<div class="sidebar-brand"><h1>⚡ ReconX Ultra X</h1><span>Attack Surface Intelligence</span></div>
<nav class="sidebar-nav">{sidebar_html}</nav>
<div class="sidebar-footer">v2.0.0 Ultra X · {now}</div>
</aside>

<div class="main">
<div class="topbar">
<h2><span class="live-dot"></span>{esc(DOMAIN)}</h2>
<div class="meta">Generated {now}</div>
</div>
<div class="content">

<!-- OVERVIEW PAGE -->
<div class="page active" id="page-overview">
<div class="stats-row">
<div class="stat"><div class="value">{s["subs"]}</div><div class="label">Subdomains</div></div>
<div class="stat"><div class="value">{s["live"]}</div><div class="label">Live Hosts</div></div>
<div class="stat"><div class="value">{s["urls"]:,}</div><div class="label">URLs</div></div>
<div class="stat"><div class="value">{s["params"]:,}</div><div class="label">Parameterized</div></div>
<div class="stat"><div class="value">{s["js"]:,}</div><div class="label">JS Files</div></div>
<div class="stat critical"><div class="value">{s["nuclei"]}</div><div class="label">Nuclei</div></div>
<div class="stat warning"><div class="value">{sec_n}</div><div class="label">Secrets</div></div>
<div class="stat info"><div class="value">{api_total}</div><div class="label">APIs</div></div>
</div>

<div class="panel"><div class="panel-header"><h3>⚡ Vulnerability Candidates</h3><span class="count">{total_vulns} total</span></div>
<div class="panel-body"><div class="vuln-row">{vchips}</div></div></div>

<div class="grid-2">
<div class="panel"><div class="panel-header"><h3>🎯 Risk Distribution</h3></div>
<div class="panel-body"><div class="chart-container"><canvas id="riskChart"></canvas></div></div></div>
<div class="panel"><div class="panel-header"><h3>🔥 Vulnerability Heatmap</h3></div>
<div class="panel-body"><div class="chart-container"><canvas id="vulnChart"></canvas></div></div></div>
</div>

<div class="grid-2">
<div class="panel"><div class="panel-header"><h3>⚠️ Critical Workflows</h3></div>
<div class="panel-body"><div class="scrollable"><table><thead><tr><th>Workflow</th><th>Severity</th><th>Endpoints</th><th>Bugs</th></tr></thead><tbody>{wf_rows}</tbody></table></div></div></div>
<div class="panel"><div class="panel-header"><h3>🎯 High-Value Targets</h3><span class="count">{len(hvt)}</span></div>
<div class="panel-body"><div class="scrollable">{hvt_html}</div></div></div>
</div>
</div>

<!-- ASSETS PAGE -->
<div class="page" id="page-assets">
<div class="stats-row">
<div class="stat"><div class="value">{s["subs"]}</div><div class="label">Subdomains</div></div>
<div class="stat"><div class="value">{s["live"]}</div><div class="label">Live Hosts</div></div>
<div class="stat"><div class="value">{s["ports"]}</div><div class="label">Open Ports</div></div>
<div class="stat"><div class="value">{s["takeover"]}</div><div class="label">Takeovers</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>🌐 Subdomains</h3></div>
<div class="panel-body"><input class="search-box" placeholder="Search subdomains..." oninput="filterList(this,'sub-list')">
<div class="scrollable" id="sub-list">{_items(rl(OUT/"subs/all_subdomains.txt",100), "list-item fi")}</div></div></div>
{_cond_panel("🔑 Admin Panels", admin_html, bool(admin))}
</div>

<!-- APIS PAGE -->
<div class="page" id="page-apis">
<div class="stats-row">
<div class="stat"><div class="value">{gql}</div><div class="label">GraphQL</div></div>
<div class="stat"><div class="value">{swg}</div><div class="label">Swagger</div></div>
<div class="stat"><div class="value">{rest_n}</div><div class="label">REST APIs</div></div>
<div class="stat"><div class="value">{act}</div><div class="label">Actuator</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>🔌 API Inventory</h3></div>
<div class="panel-body"><div class="scrollable">
{_api_items(safe_list(api,'graphql_endpoints'), 'GRAPHQL', 'purple')}
{_api_items(safe_list(api,'swagger_specs'), 'SWAGGER', 'green')}
{_api_items(safe_list(api,'actuator_endpoints'), 'ACTUATOR', 'cyan')}
</div></div></div>
</div>

<!-- JS INTEL PAGE -->
<div class="page" id="page-js">
<div class="stats-row">
<div class="stat"><div class="value">{s["js"]:,}</div><div class="label">JS Files</div></div>
<div class="stat critical"><div class="value">{len([d for d in dom_sinks if d.get("severity")=="CRITICAL"])}</div><div class="label">Critical Sinks</div></div>
<div class="stat warning"><div class="value">{sec_n}</div><div class="label">Secrets</div></div>
</div>
{_cond_panel('🕸️ DOM Sinks (XSS Vectors)', '<div class="scrollable"><table><thead><tr><th>File</th><th>Sink</th><th>Severity</th></tr></thead><tbody>' + sink_rows + '</tbody></table></div>', bool(sink_rows))}
</div>

<!-- PARAMS PAGE -->
<div class="page" id="page-params">
<div class="stats-row">
<div class="stat"><div class="value">{s["params"]:,}</div><div class="label">Parameterized URLs</div></div>
<div class="stat critical"><div class="value">{total_vulns}</div><div class="label">Vuln Candidates</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>🎯 Endpoint Explorer</h3></div>
<div class="panel-body"><input class="search-box" placeholder="Search endpoints..." oninput="filterList(this,'ep-list')">
<div class="scrollable" id="ep-list">{ep_html}</div></div></div>
</div>

<!-- VULNS PAGE -->
<div class="page" id="page-vulns">
<div class="panel"><div class="panel-header"><h3>⚡ Vulnerability Candidates</h3></div>
<div class="panel-body"><div class="vuln-row">{vchips}</div></div></div>
<div class="grid-2">
<div class="panel"><div class="panel-header"><h3>📊 Risk Matrix</h3></div>
<div class="panel-body"><div class="chart-container"><canvas id="riskChart2"></canvas></div></div></div>
<div class="panel"><div class="panel-header"><h3>📈 Category Distribution</h3></div>
<div class="panel-body"><div class="chart-container"><canvas id="catChart"></canvas></div></div></div>
</div>
{vuln_lists_html}
{_cond_panel('🔓 403 Bypass Results', bypass_html, bool(bypass))}
<div class="panel"><div class="panel-header"><h3>🔍 Nuclei Findings</h3><span class="count">{s["nuclei"]}</span></div>
<div class="panel-body"><div class="scrollable">{nuc_rows}</div></div></div>
</div>

<!-- VALIDATED FINDINGS PAGE -->
<div class="page" id="page-validated">
{conf_stats}
<div class="stats-row">
<div class="stat critical"><div class="value">{len(val_all)}</div><div class="label">Total Tested</div></div>
<div class="stat" style="border-left:3px solid #ef4444"><div class="value">{val_critical}</div><div class="label">Critical</div></div>
<div class="stat" style="border-left:3px solid #f59e0b"><div class="value">{val_confirmed}</div><div class="label">Confirmed</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>🔬 Validated Findings</h3><span class="count">{len(val_all)}</span></div>
<div class="panel-body"><div class="scrollable" id="validated-list">
{val_rows if val_rows else '<p style="color:var(--text-3)">No validated findings yet — run validation module</p>'}
</div></div></div>
</div>

<!-- ATTACK CHAINS PAGE -->
<div class="page" id="page-chains">
<div class="stats-row">
<div class="stat critical"><div class="value">{len(chains)}</div><div class="label">Attack Chains</div></div>
<div class="stat" style="border-left:3px solid #ef4444"><div class="value">{len([c for c in chains if c.get('severity')=='CRITICAL'])}</div><div class="label">Critical Chains</div></div>
</div>
{chain_html if chain_html else '<div class="panel"><div class="panel-body"><p style="color:var(--text-3)">No attack chains detected yet — run validation module</p></div></div>'}
</div>

<!-- SECRETS PAGE -->
<div class="page" id="page-secrets">
<div class="stats-row"><div class="stat critical"><div class="value">{sec_n}</div><div class="label">Secrets Found</div></div></div>
<div class="panel"><div class="panel-header"><h3>🔑 Detected Secrets</h3></div>
<div class="panel-body"><div class="scrollable">{sec_html if sec_html else "<p style=color:var(--text-3)>No secrets detected yet</p>"}</div></div></div>
</div>

<!-- TECH PAGE -->
<div class="page" id="page-tech">
<div class="panel"><div class="panel-header"><h3>🔧 Technologies Detected</h3></div>
<div class="panel-body">{tech_tags}<h3 style="margin-top:1rem;font-size:.85rem">Wordlists Applied: {wl.get("total_wordlists",0)}</h3></div></div>
<div class="panel"><div class="panel-header"><h3>📊 Tech Distribution</h3></div>
<div class="panel-body"><div class="chart-container"><canvas id="techChart"></canvas></div></div></div>
</div>

<!-- DNA PAGE -->
<div class="page" id="page-dna">
<div class="stats-row">
<div class="stat {'critical' if dna_risk=='CRITICAL' else 'warning' if dna_risk=='HIGH' else ''}"><div class="value">{dna_risk}</div><div class="label">Risk Profile</div></div>
<div class="stat"><div class="value">{len(dna_techs)}</div><div class="label">Technologies</div></div>
<div class="stat"><div class="value">{len(dna_auth)}</div><div class="label">Auth Systems</div></div>
<div class="stat"><div class="value">{len(dna_cloud)}</div><div class="label">Cloud Providers</div></div>
</div>
<div class="grid-2">
<div class="panel"><div class="panel-header"><h3>🔧 Backend Stack</h3></div>
<div class="panel-body">{''.join(f'<span class="tag tag-cyan">{esc(t)}</span>' for t in dna_backend) or '<span class="tag">Unknown</span>'}</div></div>
<div class="panel"><div class="panel-header"><h3>🎨 Frontend Stack</h3></div>
<div class="panel-body">{''.join(f'<span class="tag tag-purple">{esc(t)}</span>' for t in dna_frontend) or '<span class="tag">Unknown</span>'}</div></div>
</div>
<div class="grid-2">
<div class="panel"><div class="panel-header"><h3>🔐 Auth Systems</h3></div>
<div class="panel-body">{''.join(f'<span class="tag tag-red">{esc(a)}</span>' for a in dna_auth) or '<span class="tag">None detected</span>'}</div></div>
<div class="panel"><div class="panel-header"><h3>☁️ Cloud Providers</h3></div>
<div class="panel-body">{''.join(f'<span class="tag tag-green">{esc(c)}</span>' for c in dna_cloud) or '<span class="tag">None detected</span>'}</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>📤 Attack Surface Breakdown</h3></div>
<div class="panel-body"><div class="stats-row">
{''.join(f'<div class="stat"><div class="value">{v}</div><div class="label">{k}</div></div>' for k,v in dna_surface.items() if v)}
</div></div></div>
<div class="panel"><div class="panel-header"><h3>🎯 Hunting Recommendations</h3></div>
<div class="panel-body"><div class="scrollable">
{''.join(f'<div class="list-item" style="border-left:3px solid var(--red)">{esc(r)}</div>' for r in dna_recs) or '<p style="color:var(--text-3)">Run --dna to generate</p>'}
</div></div></div>
</div>

<!-- STRATEGY PAGE -->
<div class="page" id="page-strategy">
<div class="stats-row">
<div class="stat critical"><div class="value">{len(strat_order)}</div><div class="label">Priority Targets</div></div>
<div class="stat warning"><div class="value">{len(strat_paths)}</div><div class="label">Attack Paths</div></div>
<div class="stat info"><div class="value">{sum(len(v) for v in strat_preds.values() if isinstance(v, list))}</div><div class="label">Predictions</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>🔥 Priority Testing Order</h3></div>
<div class="panel-body"><div class="scrollable">
{strat_order_html}
</div></div></div>
<div class="panel"><div class="panel-header"><h3>🔗 Predicted Attack Paths</h3></div>
<div class="panel-body"><div class="scrollable">
{strat_paths_html}
</div></div></div>
</div>

<!-- SURFACE MAP PAGE -->
<div class="page" id="page-surface">
<div class="stats-row">
<div class="stat"><div class="value">{len(ranked_surfaces)}</div><div class="label">Surface Categories</div></div>
<div class="stat critical"><div class="value">{len([s for s in ranked_surfaces if s.get('score',0)>=85])}</div><div class="label">Critical</div></div>
<div class="stat warning"><div class="value">{len(pred_list)}</div><div class="label">Predictions</div></div>
</div>
<div class="panel"><div class="panel-header"><h3>📊 Ranked Attack Surfaces</h3></div>
<div class="panel-body"><div class="scrollable">
{surfaces_html}
</div></div></div>
<div class="panel"><div class="panel-header"><h3>🧠 AI Vulnerability Predictions</h3></div>
<div class="panel-body"><div class="scrollable">
{preds_html}
</div></div></div>
<div class="panel" style="text-align:center;padding:20px">
<a href="attack_surface.html" target="_blank" style="display:inline-block;padding:12px 24px;background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;border-radius:8px;text-decoration:none;font-weight:600;font-size:.85rem">🗺️ Open Interactive Attack Surface Map</a>
</div>
</div>

</div></div>

<script>
function showPage(id){{document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));document.getElementById('page-'+id).classList.add('active');document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));document.querySelector('[data-page="'+id+'"]').classList.add('active')}}
function filterList(el,id){{const q=el.value.toLowerCase();document.querySelectorAll('#'+id+' .list-item, #'+id+' .fi, #'+id+' .ep-item').forEach(e=>{{e.style.display=e.textContent.toLowerCase().includes(q)?'flex':'none'}})}}

const cOpts={{responsive:true,maintainAspectRatio:false,plugins:{{legend:{{labels:{{color:'#94a3b8',font:{{size:11}}}}}}}}}};
new Chart('riskChart',{{type:'doughnut',data:{{labels:['Critical','High','Medium','Low'],datasets:[{{data:[{rc},{rh},{rm},{rl_}],backgroundColor:['#ef4444','#f59e0b','#3b82f6','#22c55e'],borderWidth:0}}]}},options:{{...cOpts,plugins:{{legend:{{position:'right',labels:{{color:'#94a3b8'}}}}}}}}}});
new Chart('vulnChart',{{type:'bar',data:{{labels:{json.dumps(vl)},datasets:[{{data:{json.dumps(vv)},backgroundColor:{json.dumps(vc)},borderRadius:4,borderWidth:0}}]}},options:{{...cOpts,indexAxis:'y',scales:{{x:{{grid:{{color:'rgba(42,49,66,.3)'}},ticks:{{color:'#94a3b8'}}}},y:{{grid:{{display:false}},ticks:{{color:'#e2e8f0',font:{{size:11}}}}}}}},plugins:{{legend:{{display:false}}}}}}}});

try{{new Chart('riskChart2',{{type:'doughnut',data:{{labels:['Critical','High','Medium','Low'],datasets:[{{data:[{rc},{rh},{rm},{rl_}],backgroundColor:['#ef4444','#f59e0b','#3b82f6','#22c55e'],borderWidth:0}}]}},options:cOpts}})}}catch(e){{}}
try{{const cd={json.dumps(cats)};new Chart('catChart',{{type:'bar',data:{{labels:Object.keys(cd),datasets:[{{data:Object.values(cd),backgroundColor:'#3b82f6',borderRadius:4}}]}},options:{{...cOpts,scales:{{x:{{ticks:{{color:'#94a3b8'}}}},y:{{grid:{{color:'rgba(42,49,66,.3)'}},ticks:{{color:'#94a3b8'}}}}}},plugins:{{legend:{{display:false}}}}}}}})}}catch(e){{}}
try{{const tl={json.dumps(techs[:15])};const tw={json.dumps(wl.get("wordlists_per_tech", {k: wl.get("total_wordlists",1) for k in techs[:15]}))};if(tl.length){{new Chart('techChart',{{type:'polarArea',data:{{labels:tl,datasets:[{{data:tl.map(t=>tw[t]||1),backgroundColor:['#ef4444','#f59e0b','#3b82f6','#22c55e','#8b5cf6','#ec4899','#06d6a0','#14b8a6','#6366f1','#eab308','#f97316','#a855f7','#0ea5e9','#84cc16','#e11d48'],borderWidth:0}}]}},options:cOpts}})}}}}catch(e){{}}
</script></body></html>'''

    with open(rpt, 'w') as f: f.write(html)
    print(f"  ✅ Premium dashboard: {rpt}")

    # Also generate attack surface map
    try:
        import subprocess
        map_script = Path(__file__).parent / "attack_surface_map.py"
        if map_script.exists():
            subprocess.run(["python3", str(map_script), DOMAIN],
                          timeout=60, capture_output=True,
                          env={**os.environ, "RECONX_ROOT": str(ROOT)})
            print(f"  ✅ Attack surface map: {rpt.parent / 'attack_surface.html'}")
    except Exception:
        pass

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        print(f"  ❌ Dashboard generation failed: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        # Still create a minimal fallback report
        try:
            rpt = OUT / "reports" / "report.html"
            rpt.parent.mkdir(parents=True, exist_ok=True)
            rpt.write_text(f"""<!DOCTYPE html><html><head><title>ReconX — {DOMAIN}</title>
<style>body{{background:#080b12;color:#e2e8f0;font-family:sans-serif;padding:2rem}}
h1{{color:#ef4444}}pre{{background:#151b23;padding:1rem;border-radius:8px;overflow:auto}}</style></head>
<body><h1>⚠️ Dashboard Error</h1><p>Error generating premium dashboard for {DOMAIN}:</p>
<pre>{traceback.format_exc()}</pre>
<p>Run manually: <code>python3 modules/reporting/dashboard_gen.py {DOMAIN}</code></p></body></html>""")
            print(f"  ⚠️  Fallback error page created: {rpt}")
        except Exception:
            pass
        sys.exit(1)
