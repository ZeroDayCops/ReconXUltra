#!/usr/bin/env python3
"""ReconX Ultra X — XSS Results Merger
Merges results from manual, dalfox, loxs, and reflection-only into unified JSON."""
import json, os, sys

HIT_FILE = sys.argv[1] if len(sys.argv) > 1 else ""
DALFOX_FILE = sys.argv[2] if len(sys.argv) > 2 else ""
LOXS_FILE = sys.argv[3] if len(sys.argv) > 3 else ""
REFLECT_FILE = sys.argv[4] if len(sys.argv) > 4 else ""
OUTPUT = sys.argv[5] if len(sys.argv) > 5 else ""

results = []
seen = set()

# Manual hits (highest confidence)
if HIT_FILE and os.path.exists(HIT_FILE):
    for line in open(HIT_FILE):
        try:
            d = json.loads(line.strip())
            url = d.get("url", "")
            if url and url not in seen:
                seen.add(url)
                results.append(d)
        except:
            pass

# Dalfox hits
if DALFOX_FILE and os.path.exists(DALFOX_FILE):
    for line in open(DALFOX_FILE):
        line = line.strip().rstrip(",")
        if not line or line in "[]":
            continue
        try:
            d = json.loads(line)
            url = d.get("data", d.get("inject_url", ""))
            existing = [r for r in results if r.get("url") == url]
            if existing:
                existing[0]["dalfox_confirmed"] = True
                if not existing[0].get("payload"):
                    existing[0]["payload"] = d.get("poc", d.get("payload", ""))
            elif url and url not in seen:
                seen.add(url)
                results.append({
                    "url": url, "param": d.get("param", ""),
                    "payload": d.get("poc", d.get("payload", "")),
                    "reflected": True, "dalfox_confirmed": True,
                    "manual_confirmed": False, "browser_executed": False,
                    "tool": "dalfox",
                })
        except:
            pass

# LOXS hits
if LOXS_FILE and os.path.exists(LOXS_FILE):
    try:
        loxs_data = json.load(open(LOXS_FILE))
        for d in (loxs_data if isinstance(loxs_data, list) else []):
            url = d.get("url", "")
            existing = [r for r in results if r.get("url") == url]
            if existing:
                existing[0]["loxs_confirmed"] = True
            elif url and url not in seen:
                seen.add(url)
                d["loxs_confirmed"] = True
                d["tool"] = "loxs"
                results.append(d)
    except:
        pass

# Reflection-only (low confidence)
if REFLECT_FILE and os.path.exists(REFLECT_FILE):
    for line in open(REFLECT_FILE):
        try:
            d = json.loads(line.strip())
            url = d.get("url", "")
            if url and url not in seen:
                seen.add(url)
                results.append({
                    "url": url, "param": d.get("param", ""),
                    "payload": "", "reflected": True,
                    "dalfox_confirmed": False, "manual_confirmed": False,
                    "browser_executed": False, "loxs_confirmed": False,
                    "context": d.get("context", ""), "encoding": d.get("encoding", ""),
                    "tool": "reflection-only",
                })
        except:
            pass

# Write output
if OUTPUT:
    with open(OUTPUT, "w") as f:
        json.dump(results, f, indent=2)

# Print summary
confirmed = len([r for r in results if any(r.get(k) for k in
    ["manual_confirmed", "dalfox_confirmed", "confirmed", "loxs_confirmed"])])
print(f"    ✅ XSS RESULTS: {confirmed} CONFIRMED | {len(results)} total")
for r in results:
    if any(r.get(k) for k in ["confirmed", "manual_confirmed", "dalfox_confirmed", "loxs_confirmed"]):
        p = r.get("param", "?")
        pl = str(r.get("payload", "?"))[:50]
        t = r.get("tool", "?")
        print(f"      🔥 {p} → {pl} ({t})")
