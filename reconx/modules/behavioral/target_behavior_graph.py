#!/usr/bin/env python3
"""
ReconX Ultra X — Target Behavior Graph Generator
===================================================
Generates an interactive Cytoscape.js + D3.js visualization
of the entire target's behavioral intelligence:
  - Auth flows, upload workflows, APIs, objects
  - Workflow transitions, SPA routes, DOM sinks
  - Risk overlay with severity coloring
"""
import json, os, sys
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN:
    sys.exit("Usage: target_behavior_graph.py <domain>")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent.parent))
OUT = ROOT / "output" / DOMAIN
REPORTS_DIR = OUT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def lj(f):
    try:
        return json.loads(Path(f).read_text())
    except:
        return None


def build_graph_data():
    """Build graph data from all behavioral intelligence."""
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid, label, ntype, risk="low", details=""):
        if nid not in node_ids:
            nodes.append({
                "id": nid, "label": label[:40], "type": ntype,
                "risk": risk, "details": details[:200],
            })
            node_ids.add(nid)

    def add_edge(source, target, label="", etype="default"):
        edges.append({
            "source": source, "target": target,
            "label": label[:30], "type": etype,
        })

    # Central domain node
    add_node("domain", DOMAIN, "domain", "info", "Target application")

    # Workflow transitions
    wf_data = lj(OUT / "workflow_transitions/workflow_transitions.json") or {}
    for wf in wf_data.get("workflows", []):
        wf_id = f"wf_{wf['workflow']}"
        add_node(wf_id, wf["workflow"], "workflow", "medium")
        add_edge("domain", wf_id, "workflow", "workflow")
        for state in wf.get("detected_states", []):
            state_id = f"state_{wf['workflow']}_{state}"
            add_node(state_id, state, "state", "low")
            add_edge(wf_id, state_id, "state", "transition")

    # Object relationships
    obj_data = lj(OUT / "object_relationships/object_relationships.json") or {}
    for obj in obj_data.get("objects", [])[:20]:
        obj_id = f"obj_{obj['type']}_{obj.get('identifier', 'x')}"
        risk = "critical" if obj.get("risk") == "CRITICAL" else "high" if obj.get("risk") == "HIGH" else "medium"
        add_node(obj_id, f"{obj['type']}:{obj.get('identifier', '?')}", "object", risk,
                 " | ".join(obj.get("observations", [])[:2]))
        add_edge("domain", obj_id, obj["type"], "object")
        for rel in obj.get("relationships", []):
            rel_id = f"obj_{rel['target_type']}_rel"
            add_node(rel_id, rel["target_type"], "object", "medium")
            add_edge(obj_id, rel_id, rel["type"][:20], "relationship")

    # Auth findings
    auth_data = lj(OUT / "auth_intelligence/auth_behavior.json") or {}
    for i, finding in enumerate(auth_data.get("findings", [])[:10]):
        f_id = f"auth_{i}"
        risk = "critical" if finding.get("risk") == "CRITICAL" else "high" if finding.get("risk") == "HIGH" else "medium"
        add_node(f_id, finding["finding_type"], "auth", risk,
                 " | ".join(finding.get("observed", [])[:2]))
        add_edge("domain", f_id, "auth", "auth")

    # DOM sinks
    dom_data = lj(OUT / "dom_intelligence/dom_intelligence.json") or {}
    for i, finding in enumerate(dom_data.get("findings", [])[:15]):
        if finding.get("category") == "sink":
            f_id = f"sink_{i}"
            risk = "critical" if finding.get("severity") == "CRITICAL" else "high"
            add_node(f_id, finding["type"], "sink", risk, finding.get("risk", ""))
            add_edge("domain", f_id, "DOM sink", "sink")
        elif finding.get("category") == "route":
            f_id = f"route_{i}"
            add_node(f_id, finding.get("value", "/route"), "route", "low")
            add_edge("domain", f_id, "SPA route", "route")
        elif finding.get("category") == "api":
            f_id = f"api_{i}"
            add_node(f_id, finding.get("value", "/api")[:30], "api", "medium")
            add_edge("domain", f_id, "API", "api")

    # Reasoned findings
    reasoning = lj(OUT / "reasoning/reasoned_findings.json") or {}
    for i, finding in enumerate(reasoning.get("findings", [])[:8]):
        f_id = f"vuln_{finding['vuln_type']}_{i}"
        conf = finding.get("confidence", 0)
        risk = "critical" if conf >= 50 else "high" if conf >= 30 else "medium"
        add_node(f_id, f"{finding['vuln_type']} ({conf}%)", "vulnerability", risk,
                 finding.get("reasoning", ""))
        add_edge("domain", f_id, "finding", "vulnerability")

    # Attack paths
    paths = lj(OUT / "attack_paths/justified_attack_paths.json") or {}
    for path in paths.get("paths", []):
        path_id = f"path_{path['id']}"
        add_node(path_id, path["name"], "attack_path",
                 "critical" if path["severity"] == "CRITICAL" else "high")
        add_edge("domain", path_id, "attack path", "attack_path")

    return {"nodes": nodes, "edges": edges}


def generate_html(graph_data):
    """Generate interactive behavior graph HTML."""
    nodes_json = json.dumps(graph_data["nodes"])
    edges_json = json.dumps(graph_data["edges"])
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Behavior Graph — {DOMAIN}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            overflow: hidden;
        }}
        .header {{
            position: fixed; top: 0; left: 0; right: 0; z-index: 100;
            background: linear-gradient(135deg, rgba(15,15,25,0.95), rgba(20,10,35,0.95));
            backdrop-filter: blur(10px);
            padding: 12px 24px;
            display: flex; align-items: center; justify-content: space-between;
            border-bottom: 1px solid rgba(100,100,255,0.15);
        }}
        .header h1 {{
            font-size: 16px; font-weight: 600;
            background: linear-gradient(135deg, #7c5bf5, #5bc0f5);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }}
        .header .meta {{ font-size: 11px; color: #888; }}
        .stats {{
            display: flex; gap: 12px;
        }}
        .stat {{
            background: rgba(255,255,255,0.05); border-radius: 6px;
            padding: 4px 10px; font-size: 11px;
        }}
        .stat .val {{ color: #7c5bf5; font-weight: 700; }}
        #cy {{
            position: absolute; top: 50px; left: 0; right: 260px; bottom: 0;
        }}
        .sidebar {{
            position: fixed; top: 50px; right: 0; bottom: 0; width: 260px;
            background: rgba(15,15,25,0.95); border-left: 1px solid rgba(100,100,255,0.1);
            overflow-y: auto; padding: 16px;
        }}
        .sidebar h3 {{
            font-size: 12px; text-transform: uppercase; letter-spacing: 1px;
            color: #7c5bf5; margin: 12px 0 8px;
        }}
        .legend-item {{
            display: flex; align-items: center; gap: 8px;
            font-size: 11px; margin: 4px 0; color: #aaa;
        }}
        .legend-dot {{
            width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
        }}
        #detail-panel {{
            margin-top: 16px; padding: 10px;
            background: rgba(255,255,255,0.03); border-radius: 6px;
            font-size: 11px; line-height: 1.5; display: none;
        }}
        #detail-panel.active {{ display: block; }}
        #detail-panel h4 {{ color: #7c5bf5; margin-bottom: 6px; }}
        #detail-panel .field {{ color: #888; }}
        #detail-panel .value {{ color: #ddd; }}
        .controls {{
            margin-top: 12px;
        }}
        .controls button {{
            background: rgba(124,91,245,0.15); border: 1px solid rgba(124,91,245,0.3);
            color: #7c5bf5; padding: 6px 12px; border-radius: 6px;
            cursor: pointer; font-size: 11px; margin: 3px;
            transition: all 0.2s;
        }}
        .controls button:hover {{
            background: rgba(124,91,245,0.3);
        }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>🔬 Target Behavior Graph</h1>
            <div class="meta">{DOMAIN} — {now}</div>
        </div>
        <div class="stats">
            <div class="stat"><span class="val" id="node-count">0</span> nodes</div>
            <div class="stat"><span class="val" id="edge-count">0</span> edges</div>
        </div>
    </div>

    <div id="cy"></div>

    <div class="sidebar">
        <h3>Legend</h3>
        <div class="legend-item"><div class="legend-dot" style="background:#7c5bf5"></div> Domain</div>
        <div class="legend-item"><div class="legend-dot" style="background:#5bc0f5"></div> Workflow</div>
        <div class="legend-item"><div class="legend-dot" style="background:#34d399"></div> State</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f59e0b"></div> Object</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div> Vulnerability</div>
        <div class="legend-item"><div class="legend-dot" style="background:#ec4899"></div> Auth Finding</div>
        <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6"></div> DOM Sink</div>
        <div class="legend-item"><div class="legend-dot" style="background:#06b6d4"></div> API</div>
        <div class="legend-item"><div class="legend-dot" style="background:#a78bfa"></div> SPA Route</div>
        <div class="legend-item"><div class="legend-dot" style="background:#f97316"></div> Attack Path</div>

        <h3>Controls</h3>
        <div class="controls">
            <button onclick="cy.fit(50)">Fit</button>
            <button onclick="cy.zoom(cy.zoom()*1.3)">Zoom+</button>
            <button onclick="cy.zoom(cy.zoom()*0.7)">Zoom-</button>
            <button onclick="filterRisk('critical')">Critical</button>
            <button onclick="filterRisk('high')">High</button>
            <button onclick="resetFilter()">All</button>
        </div>

        <div id="detail-panel">
            <h4 id="detail-label"></h4>
            <div><span class="field">Type:</span> <span class="value" id="detail-type"></span></div>
            <div><span class="field">Risk:</span> <span class="value" id="detail-risk"></span></div>
            <div><span class="field">Details:</span> <span class="value" id="detail-info"></span></div>
        </div>
    </div>

    <script>
        const nodesData = {nodes_json};
        const edgesData = {edges_json};

        const colorMap = {{
            domain: '#7c5bf5', workflow: '#5bc0f5', state: '#34d399',
            object: '#f59e0b', vulnerability: '#ef4444', auth: '#ec4899',
            sink: '#8b5cf6', api: '#06b6d4', route: '#a78bfa',
            attack_path: '#f97316',
        }};
        const riskSize = {{ critical: 45, high: 35, medium: 28, low: 22, info: 20 }};
        const riskBorder = {{ critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#6b7280', info: '#4b5563' }};

        const elements = [];
        nodesData.forEach(n => {{
            elements.push({{
                data: {{
                    id: n.id, label: n.label, type: n.type,
                    risk: n.risk, details: n.details,
                    color: colorMap[n.type] || '#666',
                    size: riskSize[n.risk] || 22,
                    borderColor: riskBorder[n.risk] || '#444',
                }}
            }});
        }});
        edgesData.forEach(e => {{
            elements.push({{
                data: {{
                    source: e.source, target: e.target,
                    label: e.label, type: e.type,
                }}
            }});
        }});

        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: elements,
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'background-color': 'data(color)',
                        'label': 'data(label)',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'font-size': '9px',
                        'color': '#ccc',
                        'text-valign': 'bottom',
                        'text-margin-y': 5,
                        'border-width': 2,
                        'border-color': 'data(borderColor)',
                        'text-max-width': '80px',
                        'text-wrap': 'ellipsis',
                    }}
                }},
                {{
                    selector: 'node[type="domain"]',
                    style: {{
                        'width': 60, 'height': 60,
                        'font-size': '12px', 'font-weight': 'bold',
                        'color': '#fff',
                        'border-width': 3,
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 1.5,
                        'line-color': 'rgba(120,120,180,0.3)',
                        'target-arrow-color': 'rgba(120,120,180,0.5)',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '7px',
                        'color': 'rgba(150,150,200,0.6)',
                        'text-rotation': 'autorotate',
                    }}
                }},
                {{
                    selector: '.dimmed',
                    style: {{ 'opacity': 0.15 }}
                }},
            ],
            layout: {{
                name: 'cose',
                animate: true,
                animationDuration: 1000,
                nodeRepulsion: 8000,
                idealEdgeLength: 80,
                gravity: 0.5,
                padding: 50,
            }},
            wheelSensitivity: 0.3,
        }});

        document.getElementById('node-count').textContent = nodesData.length;
        document.getElementById('edge-count').textContent = edgesData.length;

        cy.on('tap', 'node', function(evt) {{
            const d = evt.target.data();
            document.getElementById('detail-panel').className = 'active';
            document.getElementById('detail-label').textContent = d.label;
            document.getElementById('detail-type').textContent = d.type;
            document.getElementById('detail-risk').textContent = d.risk || 'info';
            document.getElementById('detail-info').textContent = d.details || 'No details';
        }});

        function filterRisk(risk) {{
            cy.elements().addClass('dimmed');
            cy.nodes().filter(n => n.data('risk') === risk).removeClass('dimmed')
                .connectedEdges().removeClass('dimmed');
            cy.nodes('[type="domain"]').removeClass('dimmed');
        }}
        function resetFilter() {{
            cy.elements().removeClass('dimmed');
        }}
    </script>
</body>
</html>"""


def main():
    print(f"\n  🔬 Target Behavior Graph — {DOMAIN}")
    print(f"  {'━' * 50}")

    graph_data = build_graph_data()
    html = generate_html(graph_data)

    output_path = REPORTS_DIR / "behavior_graph.html"
    output_path.write_text(html)

    print(f"\n  📊 Graph: {len(graph_data['nodes'])} nodes, {len(graph_data['edges'])} edges")

    # Count by type
    from collections import Counter
    type_counts = Counter(n["type"] for n in graph_data["nodes"])
    for ntype, count in type_counts.most_common():
        print(f"    {ntype:20s} {count}")

    print(f"  💾 Graph → {output_path}")


if __name__ == "__main__":
    main()
