#!/usr/bin/env python3
"""ReconX Ultra X — Headless Browser Engine
Validates DOM XSS, captures screenshots, and monitors runtime API calls."""
import json, sys, os, time
from pathlib import Path
from datetime import datetime

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
if not DOMAIN: sys.exit("Usage: browser_engine.py <domain>")

ROOT = Path(__file__).resolve().parent.parent.parent
OUT = ROOT / "output" / DOMAIN
VAL = OUT / "browser_validation"
VAL.mkdir(parents=True, exist_ok=True)

try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

def run_browser_validation():
    print("    ⏳ Starting Headless Browser Engine...")
    
    if not HAS_PLAYWRIGHT:
        print("    ⚠️  Playwright not installed (pip install playwright && playwright install). Skipping browser engine.")
        return []

    xss_candidates = []
    try:
        cand_file = OUT / "intelligence" / "xss_candidates.txt"
        if cand_file.exists():
            xss_candidates = [l.strip() for l in cand_file.read_text().splitlines() if l.strip()][:15]
    except: pass

    if not xss_candidates:
        print("    ⚪ No XSS candidates for browser validation.")
        return []

    results = []
    runtime_apis = set()

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
        context = browser.new_context(ignore_https_errors=True)
        
        for url in xss_candidates:
            page = context.new_page()
            
            # Hook dialogs (alerts)
            alert_triggered = {"triggered": False, "msg": ""}
            def handle_dialog(dialog):
                alert_triggered["triggered"] = True
                alert_triggered["msg"] = dialog.message
                dialog.dismiss()
            
            page.on("dialog", handle_dialog)
            
            # Hook API requests (fetch/XHR)
            def handle_request(request):
                if request.resource_type in ['fetch', 'xhr']:
                    runtime_apis.add(request.url)
            
            page.on("request", handle_request)
            
            try:
                # Add a test payload to the URL if not present
                if "?" in url and "RX" not in url:
                    test_url = url + "&rx_test=%22%3E%3Cscript%3Ealert('RX_DOM_XSS')%3C%2Fscript%3E"
                else:
                    test_url = url
                    
                page.goto(test_url, timeout=10000, wait_until="load")
                
                # Take screenshot
                ss_path = VAL / f"browser_{time.time() * 1000:.0f}.png"
                page.screenshot(path=str(ss_path), full_page=True)
                
                res = {
                    "url": url,
                    "test_url": test_url,
                    "alert_triggered": alert_triggered["triggered"],
                    "alert_msg": alert_triggered["msg"],
                    "screenshot": str(ss_path),
                    "timestamp": datetime.now().isoformat()
                }
                results.append(res)
                
                if alert_triggered["triggered"]:
                    print(f"    🔥 Browser DOM XSS Executed: {url}")
                
            except Exception as e:
                pass
            finally:
                page.close()
                
        browser.close()

    # Save results
    (VAL / "browser_findings.json").write_text(json.dumps(results, indent=2))
    
    if runtime_apis:
        (OUT / "runtime_hooks" / "runtime_api_inventory.json").parent.mkdir(parents=True, exist_ok=True)
        (OUT / "runtime_hooks" / "runtime_api_inventory.json").write_text(json.dumps(list(runtime_apis), indent=2))
        print(f"    ✓ Hooked {len(runtime_apis)} runtime API calls.")

    print(f"    ✅ Browser validation complete. {len([r for r in results if r['alert_triggered']])} XSS executed.")
    return results

if __name__ == "__main__":
    run_browser_validation()
