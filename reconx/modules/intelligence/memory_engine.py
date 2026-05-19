#!/usr/bin/env python3
"""ReconX Ultra X — Recon Memory Engine
Stores historical data and identifies newly exposed attack surface across scans."""
import sys, json, sqlite3
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: memory_engine.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
MEM = OUT / "historical_diff"
MEM.mkdir(parents=True, exist_ok=True)
DB_PATH = ROOT / "output" / "recon_memory.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS assets
                 (domain TEXT, asset_type TEXT, value TEXT, first_seen TEXT, last_seen TEXT, PRIMARY KEY (domain, asset_type, value))''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings
                 (domain TEXT, type TEXT, url TEXT, payload TEXT, first_seen TEXT, PRIMARY KEY (domain, type, url))''')
    conn.commit()
    return conn

def update_memory(conn, asset_type, items):
    c = conn.cursor()
    now = datetime.now().isoformat()
    new_items = []
    
    for item in items:
        # Check if exists
        c.execute("SELECT first_seen FROM assets WHERE domain=? AND asset_type=? AND value=?", (DOMAIN, asset_type, item))
        row = c.fetchone()
        
        if row:
            c.execute("UPDATE assets SET last_seen=? WHERE domain=? AND asset_type=? AND value=?", (now, DOMAIN, asset_type, item))
        else:
            c.execute("INSERT INTO assets (domain, asset_type, value, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)", (DOMAIN, asset_type, item, now, now))
            new_items.append(item)
            
    conn.commit()
    return new_items

def load_lines(path):
    try:
        p = Path(path)
        return [l.strip() for l in p.read_text().splitlines() if l.strip()] if p.exists() else []
    except: return []

def load_json(path):
    try:
        p = Path(path)
        return json.loads(p.read_text()) if p.exists() else []
    except: return []

def run_memory_diff():
    print("  🧠 Recon Memory Engine — Diff Analysis")
    conn = init_db()
    
    # Check Subdomains
    subs = load_lines(OUT / "subs/all_subdomains.txt")
    new_subs = update_memory(conn, "subdomain", subs)
    
    # Check JS files
    js_files = load_lines(OUT / "js/js_urls.txt")
    new_js = update_memory(conn, "js_file", js_files)
    
    # Check APIs (Endpoints)
    api_data = load_json(OUT / "intelligence/api_inventory.json")
    apis = []
    if isinstance(api_data, dict):
        apis.extend(api_data.get("graphql_endpoints", []))
        apis.extend(api_data.get("actuator_endpoints", []))
        rest = api_data.get("rest_apis", {})
        if isinstance(rest, dict):
            for eps in rest.values(): apis.extend(eps)
    new_apis = update_memory(conn, "api_endpoint", apis)
    
    # Check Secrets
    sec_data = load_json(OUT / "secrets/js_secrets_report.json")
    secrets = []
    if isinstance(sec_data, dict) and "findings" in sec_data:
        for f in sec_data["findings"]:
            secrets.append(f"{f.get('type','')}:::{f.get('value','')}")
    new_secrets = update_memory(conn, "secret", secrets)
    
    conn.close()
    
    # Save diff
    diff_report = {
        "timestamp": datetime.now().isoformat(),
        "domain": DOMAIN,
        "new_subdomains": new_subs,
        "new_js_files": new_js,
        "new_api_endpoints": new_apis,
        "new_secrets": [s.split(":::", 1) for s in new_secrets]
    }
    
    (MEM / "latest_diff.json").write_text(json.dumps(diff_report, indent=2))
    
    if any([new_subs, new_js, new_apis, new_secrets]):
        print(f"    ⚠️  NEW EXPOSURE DETECTED:")
        print(f"      - {len(new_subs)} new subdomains")
        print(f"      - {len(new_js)} new JS files")
        print(f"      - {len(new_apis)} new API endpoints")
        print(f"      - {len(new_secrets)} new secrets")
    else:
        print("    ✓ No new attack surface detected compared to historical data.")

if __name__ == "__main__":
    run_memory_diff()
