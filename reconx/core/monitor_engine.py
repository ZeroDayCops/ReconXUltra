#!/usr/bin/env python3
"""
ReconX Ultra X — Continuous Monitoring Engine
===============================================
Continuously monitors target for changes:
  - New APIs, JS files, uploads, GraphQL changes
  - New secrets, workflow changes, subdomains
  - Sends Telegram alerts on detection

Usage: monitor_engine.py <domain> [interval_minutes]
"""
import json, os, sys, time, subprocess, hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else ""
INTERVAL = int(sys.argv[2]) if len(sys.argv) > 2 else 30  # minutes

if not DOMAIN:
    sys.exit("Usage: monitor_engine.py <domain> [interval_minutes]")

ROOT = Path(os.environ.get("RECONX_ROOT", Path(__file__).resolve().parent.parent))
OUT = ROOT / "output" / DOMAIN
MONITOR_DIR = OUT / "monitor"
MONITOR_DIR.mkdir(parents=True, exist_ok=True)


def hash_file(path: Path) -> str:
    """Get MD5 hash of file content."""
    if not path.exists():
        return ""
    return hashlib.md5(path.read_bytes()).hexdigest()


def count_lines(path: Path) -> int:
    try:
        return sum(1 for l in path.read_text().splitlines() if l.strip())
    except:
        return 0


def load_snapshot() -> dict:
    """Load the last monitoring snapshot."""
    path = MONITOR_DIR / "last_snapshot.json"
    if path.exists():
        try:
            return json.loads(path.read_text())
        except:
            pass
    return {}


def save_snapshot(snapshot: dict):
    """Save current monitoring snapshot."""
    (MONITOR_DIR / "last_snapshot.json").write_text(
        json.dumps(snapshot, indent=2))


def take_snapshot() -> dict:
    """Take a snapshot of current state."""
    files_to_track = {
        "subdomains": OUT / "subs" / "all_subdomains.txt",
        "live_hosts": OUT / "live" / "live_hosts.txt",
        "urls": OUT / "urls" / "all_urls.txt",
        "js_files": OUT / "js" / "js_urls.txt",
        "params": OUT / "urls" / "parameterized_urls.txt",
        "secrets": OUT / "intelligence" / "js_secrets_deep.json",
        "api_inventory": OUT / "intelligence" / "api_inventory.json",
        "workflows": OUT / "intelligence" / "critical_workflows.json",
    }

    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "files": {},
    }

    for name, path in files_to_track.items():
        snapshot["files"][name] = {
            "hash": hash_file(path),
            "lines": count_lines(path),
            "exists": path.exists(),
        }

    return snapshot


def detect_changes(old: dict, new: dict) -> list:
    """Detect changes between two snapshots."""
    changes = []
    old_files = old.get("files", {})
    new_files = new.get("files", {})

    for name in new_files:
        nf = new_files[name]
        of = old_files.get(name, {})

        if not of.get("exists") and nf.get("exists"):
            changes.append({
                "type": "NEW_FILE",
                "name": name,
                "detail": f"New {name} detected ({nf['lines']} entries)",
                "severity": "HIGH",
            })
        elif of.get("hash") != nf.get("hash") and nf.get("exists"):
            diff = nf.get("lines", 0) - of.get("lines", 0)
            if diff > 0:
                changes.append({
                    "type": "NEW_ENTRIES",
                    "name": name,
                    "detail": f"{diff} new entries in {name}",
                    "old_count": of.get("lines", 0),
                    "new_count": nf.get("lines", 0),
                    "severity": "MEDIUM" if diff < 10 else "HIGH",
                })
            elif diff < 0:
                changes.append({
                    "type": "REMOVED_ENTRIES",
                    "name": name,
                    "detail": f"{abs(diff)} entries removed from {name}",
                    "severity": "LOW",
                })

    return changes


def send_alert(changes: list):
    """Send Telegram alert for detected changes."""
    if not changes:
        return

    alert_lines = [f"🔔 *Monitor Alert — {DOMAIN}*", ""]
    for c in changes[:10]:
        icon = "🔴" if c["severity"] == "HIGH" else "🟠" if c["severity"] == "MEDIUM" else "🟡"
        alert_lines.append(f"{icon} *{c['type']}*: {c['detail']}")

    alert_lines.append(f"\n🕐 `{datetime.now().strftime('%H:%M:%S')}`")
    message = "\n".join(alert_lines)

    # Use existing telegram.sh
    tg_script = ROOT / "core" / "telegram.sh"
    if tg_script.exists():
        try:
            subprocess.run(
                ["bash", "-c", f'source "{tg_script}" && tg_send "{message}"'],
                timeout=10, capture_output=True,
                env={**os.environ, "RECONX_ROOT": str(ROOT)})
        except:
            pass


def run_quick_scan():
    """Run a lightweight recon refresh."""
    print(f"  🔄 Running quick scan refresh...")
    try:
        subprocess.run(
            ["bash", str(ROOT / "reconx.sh"), "-d", DOMAIN,
             "--modules", "subdomains,live,urls,js", "--no-deps"],
            timeout=1800, capture_output=True,
            env={**os.environ, "RECONX_ROOT": str(ROOT)})
    except subprocess.TimeoutExpired:
        print("  ⏰ Quick scan timeout")
    except Exception as e:
        print(f"  ❌ Quick scan error: {e}")


def monitor_loop():
    """Main monitoring loop."""
    print(f"\n  👁️  Monitor Engine — {DOMAIN}")
    print(f"  {'━' * 50}")
    print(f"  Interval: {INTERVAL} minutes")
    print(f"  Press Ctrl+C to stop\n")

    cycle = 0
    while True:
        cycle += 1
        print(f"  ─── Cycle {cycle} — {datetime.now().strftime('%H:%M:%S')} ───")

        # Take baseline snapshot
        old_snapshot = load_snapshot()

        # Run quick scan
        run_quick_scan()

        # Take new snapshot
        new_snapshot = take_snapshot()

        # Detect changes
        if old_snapshot:
            changes = detect_changes(old_snapshot, new_snapshot)
            if changes:
                print(f"  🔔 {len(changes)} changes detected!")
                for c in changes:
                    icon = "🔴" if c["severity"] == "HIGH" else "🟠"
                    print(f"    {icon} {c['detail']}")
                send_alert(changes)

                # Log changes
                log_path = MONITOR_DIR / "changes_log.jsonl"
                with open(log_path, "a") as f:
                    for c in changes:
                        c["cycle"] = cycle
                        c["timestamp"] = datetime.now().isoformat()
                        f.write(json.dumps(c) + "\n")
            else:
                print("  ⚪ No changes detected")

        # Save snapshot
        save_snapshot(new_snapshot)

        # Wait
        print(f"  ⏳ Next scan in {INTERVAL} minutes...\n")
        time.sleep(INTERVAL * 60)


if __name__ == "__main__":
    try:
        monitor_loop()
    except KeyboardInterrupt:
        print("\n  🛑 Monitor stopped")
