#!/usr/bin/env python3
"""
ReconX Ultra X — Visual Attack Surface Map Generator
======================================================
Generates interactive attack_surface.html with D3.js force-directed graph.
Visualizes: subdomains, APIs, uploads, GraphQL, auth, cloud, admin, workflows.
"""
import json, os, re, sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: attack_surface_map.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN

def rl(f, n=None):
    try:
        lines = [l.strip() for l in Path(f).read_text().splitlines() if l.strip()]
        return lines[:n] if n else lines
    except: return []

def lj(f):
    try: return json.loads(Path(f).read_text())
    except: return None

def classify_url(url):
    u = url.lower()
    cats = []
    if re.search(r"graphql|gql|playground", u): cats.append("graphql")
    if re.search(r"upload|attach|import|media|avatar|file", u): cats.append("upload")
    if re.search(r"admin|dashboard|console|panel|manage", u): cats.append("admin")
    if re.search(r"oauth|authorize|callback|sso|login|auth", u): cats.append("auth")
    if re.search(r"/api/|/v[0-9]+/|/rest/|swagger|openapi", u): cats.append("api")
    if re.search(r"webhook|hook|notify|event", u): cats.append("webhook")
    if re.search(r"s3\.|amazonaws|firebase|googleapis|azure", u): cats.append("cloud")
    if re.search(r"export|pdf|print|report|download|generate", u): cats.append("export")
    if re.search(r"payment|checkout|billing|invoice|cart", u): cats.append("payment")
    if re.search(r"ws://|wss://|socket", u): cats.append("websocket")
    if re.search(r"\.env|config|debug|phpinfo|actuator|\.git", u): cats.append("config")
    if re.search(r"reset|forgot|password|recover", u): cats.append("password_reset")
    return cats if cats else ["endpoint"]

def main():
    print(f"\n  🗺️  Attack Surface Map — {DOMAIN}")
    print(f"  {'━' * 50}")

    # Collect data
    urls = rl(OUT / "urls/all_urls.txt")
    live = rl(OUT / "live/live_hosts.txt")
    subs = rl(OUT / "subs/all_subdomains.txt")
    js_urls = rl(OUT / "js/js_urls.txt")
    
    dna = lj(OUT / "target_dna/target_dna.json") or {}
    wf = lj(OUT / "intelligence/critical_workflows.json") or {}
    chains = lj(OUT / "attack_chains/attack_chains.json") or {}
    ranking = lj(OUT / "prioritized/surface_ranking.json") or {}

    # Build graph nodes and links
    nodes = []
    links = []
    node_ids = {}
    
    # Category colors
    colors = {
        "domain": "#ef4444", "subdomain": "#f97316", "api": "#3b82f6",
        "graphql": "#8b5cf6", "upload": "#ec4899", "admin": "#ef4444",
        "auth": "#f59e0b", "webhook": "#06d6a0", "cloud": "#0ea5e9",
        "export": "#14b8a6", "payment": "#eab308", "websocket": "#a855f7",
        "config": "#ff6b6b", "endpoint": "#64748b", "password_reset": "#fb923c",
        "js": "#22c55e",
    }

    # Root node (domain)
    nodes.append({"id": DOMAIN, "group": "domain", "size": 40, "label": DOMAIN})
    node_ids[DOMAIN] = 0

    # Category hub nodes
    cat_counts = defaultdict(int)
    cat_urls = defaultdict(list)
    
    for url in urls[:500]:
        cats = classify_url(url)
        for c in cats:
            cat_counts[c] += 1
            if len(cat_urls[c]) < 15:
                cat_urls[c].append(url)

    # Add category nodes
    for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True):
        if count == 0: continue
        nid = len(nodes)
        node_ids[cat] = nid
        size = min(12 + count * 0.5, 35)
        nodes.append({"id": cat, "group": cat, "size": size,
                      "label": f"{cat} ({count})", "count": count})
        links.append({"source": 0, "target": nid, "value": min(count, 20)})

    # Add subdomain nodes (top 30)
    for sub in subs[:30]:
        nid = len(nodes)
        nodes.append({"id": sub, "group": "subdomain", "size": 8, "label": sub})
        links.append({"source": 0, "target": nid, "value": 1})

    # Add sample endpoint nodes under categories
    for cat, eurls in cat_urls.items():
        if cat not in node_ids: continue
        cat_nid = node_ids[cat]
        for url in eurls[:8]:
            short = re.sub(r'https?://[^/]+', '', url)[:60]
            nid = len(nodes)
            nodes.append({"id": url[:120], "group": cat, "size": 5,
                          "label": short or url[:40]})
            links.append({"source": cat_nid, "target": nid, "value": 1})

    # Add JS nodes
    for js in js_urls[:15]:
        fname = js.split("/")[-1][:40]
        nid = len(nodes)
        nodes.append({"id": js[:120], "group": "js", "size": 6, "label": fname})
        if "js" in node_ids:
            links.append({"source": node_ids.get("js", 0), "target": nid, "value": 1})
        else:
            links.append({"source": 0, "target": nid, "value": 1})

    graph_data = json.dumps({"nodes": nodes, "links": links})
    
    # Heatmap data
    heat_cats = sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:12]
    heat_labels = json.dumps([c[0] for c in heat_cats])
    heat_values = json.dumps([c[1] for c in heat_cats])
    heat_colors = json.dumps([colors.get(c[0], "#64748b") for c in heat_cats])

    # Tech stack
    techs = dna.get("technologies", {})
    tech_tags = " ".join(f'<span class="tech-tag">{t}</span>' for t in list(techs.keys())[:20])
    risk_profile = dna.get("risk_profile", "UNKNOWN")
    risk_color = {"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#3b82f6","LOW":"#22c55e"}.get(risk_profile,"#64748b")
    
    # Attack chains
    chain_list = chains.get("chains", []) if isinstance(chains, dict) else []
    chains_html = ""
    for ch in chain_list[:6]:
        sev = ch.get("severity","")
        sc = {"CRITICAL":"#ef4444","HIGH":"#f59e0b"}.get(sev,"#3b82f6")
        steps = " → ".join(s.get("type","") for s in ch.get("steps",[]))
        chains_html += f'<div class="chain-card" style="border-left:3px solid {sc}"><div class="chain-name">{ch.get("name","")}</div><div class="chain-steps">{steps}</div><div class="chain-meta"><span class="sev" style="color:{sc}">{sev}</span> <span class="conf">Confidence: {ch.get("confidence",0)}%</span></div></div>'

    # Hunting recommendations
    recs = dna.get("hunting_recommendations", [])
    recs_html = "".join(f'<div class="rec-item">{r}</div>' for r in recs[:8])

    # Stats
    n = lambda f: len(rl(f))
    stats = {
        "subs": len(subs), "live": len(live), "urls": len(urls),
        "js": len(js_urls), "apis": cat_counts.get("api",0),
        "graphql": cat_counts.get("graphql",0),
        "uploads": cat_counts.get("upload",0),
        "admin": cat_counts.get("admin",0),
    }

    html = f'''<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Surface Map — {DOMAIN}</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7.8.5/dist/d3.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:#060a13;color:#e2e8f0;overflow-x:hidden}}
.header{{background:linear-gradient(135deg,rgba(15,23,42,.95),rgba(30,41,59,.9));border-bottom:1px solid rgba(99,102,241,.2);padding:20px 32px;display:flex;align-items:center;justify-content:space-between;backdrop-filter:blur(20px)}}
.header h1{{font-size:1.4rem;font-weight:700;background:linear-gradient(135deg,#818cf8,#c084fc,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent}}
.header .domain{{font-size:.9rem;color:#94a3b8;font-weight:500}}
.header .risk{{padding:4px 14px;border-radius:20px;font-size:.75rem;font-weight:700;color:#fff;background:{risk_color}}}
.layout{{display:grid;grid-template-columns:1fr 380px;height:calc(100vh - 72px)}}
.map-container{{position:relative;overflow:hidden;background:radial-gradient(ellipse at center,rgba(99,102,241,.03) 0%,transparent 70%)}}
.sidebar{{background:rgba(15,23,42,.6);border-left:1px solid rgba(99,102,241,.15);overflow-y:auto;padding:0;backdrop-filter:blur(10px)}}
.sidebar::-webkit-scrollbar{{width:4px}}.sidebar::-webkit-scrollbar-thumb{{background:#334155;border-radius:2px}}
.panel{{border-bottom:1px solid rgba(99,102,241,.1);padding:16px 20px}}
.panel h3{{font-size:.8rem;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.stats-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}}
.stat-card{{background:rgba(99,102,241,.08);border:1px solid rgba(99,102,241,.15);border-radius:10px;padding:10px;text-align:center}}
.stat-card .v{{font-size:1.3rem;font-weight:800;color:#818cf8}}.stat-card .l{{font-size:.6rem;color:#64748b;margin-top:2px;text-transform:uppercase}}
.tech-tag{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:.65rem;font-weight:500;background:rgba(99,102,241,.15);color:#a5b4fc;margin:2px;border:1px solid rgba(99,102,241,.2)}}
.chain-card{{background:rgba(15,23,42,.5);border-radius:8px;padding:10px 12px;margin-bottom:8px;border:1px solid rgba(99,102,241,.1)}}
.chain-name{{font-size:.75rem;font-weight:600;color:#e2e8f0;margin-bottom:4px}}
.chain-steps{{font-size:.6rem;color:#64748b;margin-bottom:4px}}.chain-meta{{display:flex;gap:12px;font-size:.6rem}}
.sev{{font-weight:700}}.conf{{color:#64748b}}
.rec-item{{font-size:.7rem;padding:6px 0;border-bottom:1px solid rgba(99,102,241,.08);color:#cbd5e1}}
.legend{{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}}
.legend-item{{display:flex;align-items:center;gap:4px;font-size:.6rem;color:#94a3b8}}
.legend-dot{{width:8px;height:8px;border-radius:50%}}
.chart-box{{height:160px;margin-top:8px}}
svg text{{font-family:'Inter',sans-serif}}
.tooltip{{position:absolute;background:rgba(15,23,42,.95);border:1px solid rgba(99,102,241,.3);border-radius:8px;padding:8px 12px;font-size:.7rem;color:#e2e8f0;pointer-events:none;z-index:100;backdrop-filter:blur(10px);max-width:300px;word-break:break-all}}
.node-label{{font-size:9px;fill:#94a3b8;pointer-events:none}}
.watermark{{position:absolute;bottom:12px;left:16px;font-size:.6rem;color:rgba(99,102,241,.3);font-weight:600}}
</style></head><body>
<div class="header">
<div><h1>⚡ Attack Surface Map</h1><div class="domain">{DOMAIN} — {datetime.now().strftime("%Y-%m-%d %H:%M")}</div></div>
<div class="risk">{risk_profile} RISK</div>
</div>
<div class="layout">
<div class="map-container" id="map">
<div class="watermark">BitexRecon Ultra X — Hunter Intelligence OS</div>
</div>
<div class="sidebar">
<div class="panel">
<h3>📊 Surface Overview</h3>
<div class="stats-grid">
<div class="stat-card"><div class="v">{stats["subs"]}</div><div class="l">Subs</div></div>
<div class="stat-card"><div class="v">{stats["live"]}</div><div class="l">Live</div></div>
<div class="stat-card"><div class="v">{stats["urls"]}</div><div class="l">URLs</div></div>
<div class="stat-card"><div class="v">{stats["js"]}</div><div class="l">JS</div></div>
<div class="stat-card"><div class="v">{stats["apis"]}</div><div class="l">APIs</div></div>
<div class="stat-card"><div class="v">{stats["graphql"]}</div><div class="l">GraphQL</div></div>
<div class="stat-card"><div class="v">{stats["uploads"]}</div><div class="l">Uploads</div></div>
<div class="stat-card"><div class="v">{stats["admin"]}</div><div class="l">Admin</div></div>
</div>
</div>
<div class="panel">
<h3>🔥 Attack Surface Heatmap</h3>
<div class="chart-box"><canvas id="heatChart"></canvas></div>
</div>
<div class="panel">
<h3>🧬 Target DNA</h3>
<div>{tech_tags or '<span class="tech-tag">Pending scan</span>'}</div>
</div>
<div class="panel">
<h3>🔗 Attack Chains</h3>
{chains_html or '<div style="color:#475569;font-size:.7rem">No chains detected yet</div>'}
</div>
<div class="panel">
<h3>🎯 Hunting Recommendations</h3>
{recs_html or '<div style="color:#475569;font-size:.7rem">Run --dna to generate</div>'}
</div>
<div class="panel">
<h3>🏷️ Legend</h3>
<div class="legend">
{"".join(f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{n}</div>' for n,c in colors.items() if n in cat_counts or n in ("domain","subdomain","js"))}
</div>
</div>
</div>
</div>
<script>
const data = {graph_data};
const colors = {json.dumps(colors)};
const container = document.getElementById('map');
const W = container.clientWidth, H = container.clientHeight;
const svg = d3.select('#map').append('svg').attr('width',W).attr('height',H);
const tooltip = d3.select('body').append('div').attr('class','tooltip').style('display','none');

// Glow filter
const defs = svg.append('defs');
const glow = defs.append('filter').attr('id','glow');
glow.append('feGaussianBlur').attr('stdDeviation','3').attr('result','blur');
const merge = glow.append('feMerge');
merge.append('feMergeNode').attr('in','blur');
merge.append('feMergeNode').attr('in','SourceGraphic');

const sim = d3.forceSimulation(data.nodes)
  .force('link', d3.forceLink(data.links).id((d,i)=>i).distance(d=>60+d.value*3))
  .force('charge', d3.forceManyBody().strength(d=>d.size>20?-300:-80))
  .force('center', d3.forceCenter(W/2, H/2))
  .force('collision', d3.forceCollide().radius(d=>d.size+4));

const link = svg.append('g').selectAll('line').data(data.links).join('line')
  .attr('stroke','rgba(99,102,241,.15)').attr('stroke-width',d=>Math.max(1,d.value*.3));

const node = svg.append('g').selectAll('circle').data(data.nodes).join('circle')
  .attr('r',d=>d.size).attr('fill',d=>colors[d.group]||'#64748b')
  .attr('stroke','rgba(255,255,255,.1)').attr('stroke-width',1)
  .attr('filter',d=>d.size>15?'url(#glow)':null)
  .style('cursor','pointer')
  .on('mouseover',(e,d)=>{{tooltip.style('display','block').html(`<b>${{d.label}}</b><br><span style="color:${{colors[d.group]||'#818cf8'}}">${{d.group}}</span>${{d.count?' · '+d.count+' endpoints':''}}`);node.attr('opacity',n=>n===d||data.links.some(l=>(l.source===d&&l.target===n)||(l.target===d&&l.source===n))?.8:.15);link.attr('opacity',l=>l.source===d||l.target===d?.6:.05)}})
  .on('mousemove',e=>tooltip.style('left',e.pageX+12+'px').style('top',e.pageY-20+'px'))
  .on('mouseout',()=>{{tooltip.style('display','none');node.attr('opacity',.85);link.attr('opacity',.3)}})
  .call(d3.drag().on('start',(e,d)=>{{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y}}).on('drag',(e,d)=>{{d.fx=e.x;d.fy=e.y}}).on('end',(e,d)=>{{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null}}));

const labels = svg.append('g').selectAll('text').data(data.nodes.filter(d=>d.size>10)).join('text')
  .attr('class','node-label').attr('text-anchor','middle').attr('dy',d=>d.size+12).text(d=>d.label.substring(0,25));

sim.on('tick',()=>{{
  link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  node.attr('cx',d=>d.x=Math.max(d.size,Math.min(W-d.size,d.x))).attr('cy',d=>d.y=Math.max(d.size,Math.min(H-d.size,d.y)));
  labels.attr('x',d=>d.x).attr('y',d=>d.y);
}});

// Heatmap chart
new Chart('heatChart',{{type:'bar',data:{{labels:{heat_labels},datasets:[{{data:{heat_values},backgroundColor:{heat_colors},borderRadius:4,borderWidth:0}}]}},options:{{responsive:true,maintainAspectRatio:false,indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{color:'rgba(99,102,241,.1)'}},ticks:{{color:'#64748b',font:{{size:9}}}}}},y:{{grid:{{display:false}},ticks:{{color:'#94a3b8',font:{{size:9}}}}}}}}}}}});
</script></body></html>'''

    # Save
    map_dir = OUT / "reports"
    map_dir.mkdir(parents=True, exist_ok=True)
    (map_dir / "attack_surface.html").write_text(html)
    
    print(f"  🌐 Nodes: {len(nodes)} | Links: {len(links)}")
    print(f"  📊 Categories: {len(cat_counts)}")
    for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"    {cat:20s} {count:5d}")
    print(f"\n  💾 Map → {map_dir / 'attack_surface.html'}")

if __name__ == "__main__":
    main()
